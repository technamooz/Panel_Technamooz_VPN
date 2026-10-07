# speed_limit.py
# ══════════════════════════════════════════════════════════════════════════════
# Panel Technamooz v1.0.0.0 stable
# ماژول کنترل پهنای باند و ردیابی آی‌پی‌های فعال با الگوریتم Token Bucket و Sliding TTL
# توسعه‌یافته توسط تیم Technamooz با مدیریت amirparsa
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import time

_buckets: dict = {}
_ip_activity: dict = {}  # {uuid: {ip: last_active_timestamp}}

MIN_RATE = 1024          # 1 KB/s minimum
MIN_BURST = 32 * 1024    # 32 KB burst buffer
IP_TTL_SECONDS = 300     # 5 minutes TTL for active IPs


class _Bucket:
    __slots__ = ("capacity", "last", "rate", "tokens")

    def __init__(self, rate_bytes_per_sec: float):
        self.rate = max(float(rate_bytes_per_sec), float(MIN_RATE))
        self.capacity = max(self.rate, float(MIN_BURST))
        self.tokens = self.capacity
        self.last = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last
        if elapsed > 0:
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

    async def consume(self, n: int):
        while True:
            self._refill()
            if self.tokens >= n:
                self.tokens -= n
                return
            deficit = n - self.tokens
            wait = deficit / self.rate
            await asyncio.sleep(min(max(wait, 0.002), 0.3))


def _get_bucket(uuid: str, rate: int) -> _Bucket:
    b = _buckets.get(uuid)
    if b is None or b.rate != max(float(rate), float(MIN_RATE)):
        b = _Bucket(rate)
        _buckets[uuid] = b
    return b


async def throttle(uuid: str, nbytes: int, links_dict: dict | None = None):
    if nbytes <= 0:
        return
    if links_dict is None:
        try:
            from main import LINKS
            links_dict = LINKS
        except Exception:
            return
    link = (links_dict or {}).get(uuid)
    rate = int((link or {}).get("speed_limit_bytes", 0) or 0)
    if rate <= 0:
        return
    bucket = _get_bucket(uuid, rate)
    await bucket.consume(nbytes)


def reset_bucket(uuid: str):
    _buckets.pop(uuid, None)


# ── Active IP Tracking with Auto-Expiring TTL ─────────────────────────────────

def record_ip_active(uuid: str, ip: str):
    if not uuid or not ip or ip == "نامشخص":
        return
    now = time.time()
    user_ips = _ip_activity.setdefault(uuid, {})
    user_ips[ip] = now


def get_active_ips_for_uuid(uuid: str) -> set:
    now = time.time()
    user_ips = _ip_activity.get(uuid, {})
    active = {ip for ip, last_seen in user_ips.items() if now - last_seen < IP_TTL_SECONDS}
    if len(user_ips) > len(active) + 10:
        _ip_activity[uuid] = {ip: t for ip, t in user_ips.items() if ip in active}
    return active


def is_ip_within_limit(link: dict | None, uuid: str, ip: str) -> bool:
    if not link:
        return False
    limit = int(link.get("ip_limit", 0) or 0)
    if limit <= 0:
        return True
    active_ips = get_active_ips_for_uuid(uuid)
    if ip in active_ips:
        return True
    return len(active_ips) < limit
