# relay_vless.py
# ══════════════════════════════════════════════════════════════════════════════
# Panel Technamooz v1.0.0.0 stable
# ماژول رله VLESS و Trojan با پشتیبانی از WebSocket، TCP Keep-Alive و کنترل کیفیت اتصال
# توسعه‌یافته توسط تیم Technamooz با مدیریت amirparsa
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import uuid as uuidlib
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from main import (
    LINKS,
    LINKS_LOCK,
    connections,
    error_logs,
    hourly_traffic,
    is_link_allowed,
    log_activity,
    logger,
    now_ir,
    save_state,
    stats,
    TRUST_PROXY_HEADERS,
)
from speed_limit import is_ip_within_limit, record_ip_active, throttle

RELAY_BUF = 256 * 1024  # 256 KB high-throughput buffer


def _ws_client_ip(ws: WebSocket) -> str:
    if TRUST_PROXY_HEADERS:
        cf_ip = ws.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()
        fwd = ws.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
        real_ip = ws.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return ws.client.host if ws.client else "نامشخص"


async def open_public_connection(host: str, port: int, timeout: float = 10.0):
    """Resolve and connect only to public addresses to prevent relay SSRF."""
    if os.environ.get("ALLOW_PRIVATE_TARGETS", "false").lower() in {"1", "true", "yes"}:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

    loop = asyncio.get_running_loop()
    infos = await loop.run_in_executor(None, socket.getaddrinfo, host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    candidates = []
    for family, socktype, proto, _, sockaddr in infos:
        addr = ipaddress.ip_address(sockaddr[0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
            continue
        candidates.append((family, sockaddr))
    if not candidates:
        raise ValueError("target resolves to a non-public address")
    family, sockaddr = candidates[0]
    return await asyncio.wait_for(asyncio.open_connection(sockaddr[0], sockaddr[1], family=family), timeout=timeout)


async def parse_vless_header(chunk: bytes, expected_uuid: str | None = None):
    """
    آنپک کردن هدر استاندارد VLESS
    """
    if len(chunk) < 24:
        raise ValueError("chunk too small for VLESS")
    if chunk[0] != 1:
        raise ValueError("unsupported VLESS version")
    if expected_uuid is not None:
        try:
            expected_bytes = uuidlib.UUID(expected_uuid).bytes
        except (ValueError, AttributeError):
            raise ValueError("invalid expected UUID")
        if not hmac.compare_digest(chunk[1:17], expected_bytes):
            raise ValueError("VLESS UUID mismatch")
    pos = 1
    pos += 16  # UUID
    addon_len = chunk[pos]
    pos += 1 + addon_len
    command = chunk[pos]
    pos += 1
    port = int.from_bytes(chunk[pos:pos + 2], "big")
    pos += 2
    addr_type = chunk[pos]
    pos += 1

    if addr_type == 1:  # IPv4
        address = ".".join(str(b) for b in chunk[pos:pos + 4])
        pos += 4
    elif addr_type == 2:  # Domain
        dlen = chunk[pos]
        pos += 1
        address = chunk[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif addr_type == 3:  # IPv6
        ab = chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")

    return command, address, port, chunk[pos:]


async def parse_trojan_header(chunk: bytes, expected_uuid: str):
    """
    آنپک کردن هدر استاندارد پروتکل Trojan
    Trojan: 56 hex chars (sha224) + \r\n + command (1:TCP, 3:UDP) + addr_type + addr + port + \r\n + payload
    """
    if len(chunk) < 62:
        raise ValueError("chunk too small for Trojan")

    expected_hash = hashlib.sha224(expected_uuid.encode()).hexdigest().lower()
    recv_hash = chunk[:56].decode("ascii", errors="ignore").lower()

    if not hmac.compare_digest(recv_hash, expected_hash):
        raise ValueError("Trojan authentication hash mismatch")

    pos = 56
    if chunk[pos:pos + 2] == b"\r\n":
        pos += 2

    command = chunk[pos]
    pos += 1
    addr_type = chunk[pos]
    pos += 1

    if addr_type == 1:  # IPv4
        address = ".".join(str(b) for b in chunk[pos:pos + 4])
        pos += 4
    elif addr_type == 2:  # Domain
        dlen = chunk[pos]
        pos += 1
        address = chunk[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif addr_type == 3:  # IPv6
        ab = chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown Trojan addr type: {addr_type}")

    port = int.from_bytes(chunk[pos:pos + 2], "big")
    pos += 2

    if chunk[pos:pos + 2] == b"\r\n":
        pos += 2

    return command, address, port, chunk[pos:]


async def check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[now_ir().strftime("%H:00")] += n
    return True


async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data), LINKS)
            stats["total_requests"] += 1
            if conn_id in connections:
                connections[conn_id]["bytes"] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str, is_trojan: bool = False):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data), LINKS)
            if conn_id in connections:
                connections[conn_id]["bytes"] += len(data)

            if first:
                first = False
                payload = data if is_trojan else (b"\x00\x00" + data)
            else:
                payload = data
            await ws.send_bytes(payload)
    except Exception:
        pass


def _tune_socket_tcp(writer: asyncio.StreamWriter):
    sock = writer.transport.get_extra_info("socket")
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Linux TCP keepalive settings
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except Exception:
            pass


async def websocket_tunnel(ws: WebSocket, uuid: str):
    """
    هندلر اصلی اتصال WebSocket برای VLESS و Trojan
    """
    await ws.accept()
    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 [Technamooz] WS rejected uuid={uuid[:8]}… (inactive/expired)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)

    if not is_ip_within_limit(link, uuid, ip):
        logger.warning(f"🚫 [Technamooz] WS rejected uuid={uuid[:8]}… ip={ip} (ip limit exceeded)")
        log_activity("connection", f"اتصال {ip} به کانفیگ «{link.get('label', '?')}» رد شد (سقف مجاز آی‌پی)", "warn")
        await ws.close(code=1008, reason="ip limit reached")
        return

    record_ip_active(uuid, ip)
    is_trojan_link = (link.get("protocol") == "trojan-ws")
    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "trojan-ws" if is_trojan_link else "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"✅ [Technamooz] WS [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    log_activity("connection", f"اتصال جدید از {ip} (کانفیگ {link.get('label', '?')})", "info")

    writer = None
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        is_trojan = is_trojan_link
        # Try unpacking as Trojan if link is Trojan, else VLESS
        if is_trojan:
            command, address, port, payload = await parse_trojan_header(first_chunk, uuid)
        else:
            command, address, port, payload = await parse_vless_header(first_chunk, uuid)

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return
        await throttle(uuid, len(first_chunk), LINKS)

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"➡️ [Technamooz] [{conn_id}] → {address}:{port} ({'Trojan' if is_trojan else 'VLESS'})")

        if command != 1:
            raise ValueError("only TCP relay commands are supported")
        reader, writer = await open_public_connection(address, port)
        _tune_socket_tcp(writer)

        if payload:
            writer.write(payload)
            await writer.drain()

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid, is_trojan=is_trojan)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(save_state())
    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 [Technamooz] WS closed [{conn_id}] total={len(connections)}")
