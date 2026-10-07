# گزارش ممیزی، ریشه‌یابی و اصلاح پروژه Panel Technamooz

تاریخ ممیزی: 2026-09-29

## دامنهٔ بررسی

تمام 16 فایل موجود در آرشیو بررسی شدند:

- `main.py`, `relay_vless.py`, `xhttp_siz10.py`, `speed_limit.py`, `telegram_bot.py`, `pages.py`
- `requirements.txt`, `Procfile`, `railway.json`
- `README.md`, `SECURITY.md`, `CHANGELOG_FIXES_FA.md`, `TECHNAMOOZ_CHANGELOG.md`, `LICENSE`, `SHA256SUMS`

بررسی شامل syntax/AST، import و route registration، جریان state و persistence، احراز هویت، APIها، subscription، WebSocket/XHTTP relay، محدودیت IP/سرعت، ربات Telegram، frontend endpointها، deployment و الگوهای امنیتی بود.

## یافته‌های مهم و ریشهٔ مشکل

### بحرانی/بالا

1. **رمز پیش‌فرض در production فعال بود.** اگر `ADMIN_PASSWORD` تنظیم نمی‌شد، رمز `Technamooz` قابل حدس بود. این با ادعای README دربارهٔ الزامی بودن رمز امن ناسازگار بود.
   - اصلاح: در صورت وجود `RAILWAY_ENVIRONMENT`، نبودن `ADMIN_PASSWORD` باعث توقف عمدی برنامه می‌شود. مقدار پیش‌فرض فقط برای اجرای محلی باقی مانده است.

2. **توکن Telegram در backup صادر می‌شد.** مسیر `/api/backup` کل `BOT_SETTINGS` را export می‌کرد، در حالی که restore آن را حذف می‌کرد؛ بنابراین backup می‌توانست secret را نشت دهد.
   - اصلاح: token از backup حذف شد؛ restore نیز token ورودی را نادیده می‌گیرد.

3. **SSRF در relayهای VLESS/Trojan/XHTTP.** مقصد TCP از header کلاینت گرفته می‌شد و بدون محدودیت به `asyncio.open_connection` می‌رسید؛ این اجازهٔ اتصال به loopback، شبکهٔ خصوصی، link-local و سرویس‌های metadata را می‌داد.
   - اصلاح: resolve عمومی و اتصال فقط به آدرس‌های public. مقصدهای خصوصی فقط با `ALLOW_PRIVATE_TARGETS=true` و مسئولیت مدیر قابل فعال‌سازی‌اند.

4. **دور زدن احراز هویت Trojan با fallback به VLESS.** برای لینک Trojan، اگر parse هدر Trojan شکست می‌خورد، کد به‌صورت fallback هدر VLESS را قبول می‌کرد.
   - اصلاح: هر پروتکل فقط parser خودش را استفاده می‌کند و Trojan فقط SHA-224 معتبر را می‌پذیرد.

5. **عدم تطبیق UUID داخل هدر VLESS با UUID مسیر.** لینک انتخاب‌شده از URL احراز می‌شد اما UUID binary داخل header بررسی نمی‌شد.
   - اصلاح: UUID header با UUID لینک با مقایسهٔ constant-time تطبیق داده می‌شود؛ XHTTP نیز همین کنترل را دارد.

6. **اعتماد بدون شرط به headerهای IP proxy.** `X-Forwarded-For`، `CF-Connecting-IP` و `X-Real-IP` بدون فعال‌سازی proxy مورد اعتماد پذیرفته می‌شدند و محدودیت IP را قابل جعل می‌کردند.
   - اصلاح: این headerها فقط با `TRUST_PROXY_HEADERS=true` معتبرند؛ در حالت پیش‌فرض IP اتصال مستقیم استفاده می‌شود.

### متوسط

7. **CORS پیش‌فرض wildcard بود.** برای پنل دارای cookie session، wildcard سطح حمله را بی‌جهت زیاد می‌کرد.
   - اصلاح: CORS پیش‌فرض بسته است؛ originهای دقیق فقط از `CORS_ORIGINS` خوانده می‌شوند و method/headerها محدود شده‌اند.

8. **Host header poisoning در URLهای خروجی.** دامنهٔ URL از Host درخواست خوانده و در `CONFIG` ذخیره می‌شد؛ یک Host دلخواه می‌توانست URLهای اشتباه برای subscription تولید کند.
   - اصلاح: فقط hostname تنظیم‌شده یا hostnameهای صریح `ALLOWED_PUBLIC_HOSTS` پذیرفته می‌شوند.

9. **مجوز فایل state و secret صریح نبود.** فایل‌های JSON و secret با mode پیش‌فرض سیستم ایجاد می‌شدند.
   - اصلاح: secret، فایل state و فایل موقت state با mode `0600` ذخیره می‌شوند.

10. **پورت ورودی همیشه range-check نمی‌شد.** ساخت یا ویرایش لینک می‌توانست پورت خارج از 1..65535 را در state ذخیره کند.
    - اصلاح: `normalize_port` اضافه شد و همهٔ مسیرهای ساخت/ویرایش از آن استفاده می‌کنند.

11. **endpoint frontend برای تغییر رمز با backend هم‌نام نبود.** frontend از `/api/change-password` استفاده می‌کرد اما backend فقط `/api/change-credentials` داشت.
    - اصلاح: endpoint سازگار `/api/change-password` اضافه شد؛ endpoint جدید نیز sessionها را invalidate و session فعلی را دوباره صادر می‌کند.

12. **گزینهٔ enabled ربات Telegram نادیده گرفته می‌شد.** backend فقط وجود token را ملاک فعال بودن می‌گرفت.
    - اصلاح: `enabled` از payload رعایت می‌شود و بدون token هرگز فعال نمی‌گردد.

## فایل‌هایی که تغییری لازم نداشتند

- `speed_limit.py`: منطق token bucket و TTL از نظر syntax و مسیرهای اصلی سالم بود؛ فقط مصرف‌کننده‌های آن در relay سخت‌گیرتر شدند.
- `pages.py`: endpointهای استفاده‌شده با backend تطبیق داده شدند؛ rendering پیام‌ها و خطاهای اصلی کاربر escape می‌شوند.
- `requirements.txt`, `Procfile`, `railway.json`: برای اجرای فعلی سازگار بودند؛ الزامات امنیتی جدید در README و SECURITY مستند شد.
- changelogها و license صرفاً مستنداتی بودند و منطق اجرایی نداشتند.

## آزمون‌های انجام‌شده

- `python -m compileall`: موفق برای همهٔ فایل‌های Python.
- AST parse: موفق برای `main.py`, `pages.py`, `relay_vless.py`, `speed_limit.py`, `telegram_bot.py`, `xhttp_siz10.py`.
- import برنامه و ثبت routeها: موفق؛ 45 route پس از اضافه‌شدن endpoint سازگار.
- runtime smoke test با state خالی: موفق؛ state پیش‌فرض ساخته شد.
- تست تطبیق UUID صحیح/غلط VLESS: موفق.
- تست رد مقصد `127.0.0.1` در relay: موفق.
- تست login با captcha، backup، restore نامعتبر و تغییر رمز: موفق.
- تست guard production بدون `ADMIN_PASSWORD`: برنامه با خطای صریح متوقف می‌شود.
- Bandit: فقط هشدارهای LOW مربوط به `pass` در cleanup و مقدار خالی token گزارش شد؛ مورد High/Medium گزارش نشد.

## تنظیمات لازم برای production

```text
ADMIN_PASSWORD=<رمز قوی و یکتا، اجباری در Railway>
SECRET_KEY=<secret ثابت و امن>
RAILWAY_PUBLIC_DOMAIN=<دامنه عمومی واقعی>
ALLOWED_PUBLIC_HOSTS=<دامنه‌ها با کاما، در صورت نیاز>
TRUST_PROXY_HEADERS=false   # فقط پشت proxy مورد اعتماد true شود
CORS_ORIGINS=<originهای دقیق در صورت نیاز، بدون *>
ALLOW_PRIVATE_TARGETS=false # توصیهٔ اکید برای production
```

## ریسک‌های باقیمانده و پیشنهاد مرحلهٔ بعد

- state هنوز JSON و in-memory است؛ برای چند worker یا مقیاس افقی، SQLite/PostgreSQL و قفل توزیع‌شده لازم است.
- sessionها و rate-limit login در حافظه‌اند و با restart پاک می‌شوند؛ برای چند replica باید Redis یا session store مرکزی استفاده شود.
- captcha فعلی ضدربات واقعی نیست، چون کد برای frontend ارسال می‌شود؛ برای اینترنت عمومی CAPTCHA واقعی یا challenge سمت سرور لازم است.
- relay عمومی ذاتاً پرریسک و resource-intensive است؛ در production باید rate limit سطح درخواست، سقف هم‌زمانی، timeoutهای کامل‌تر و observability مرکزی اضافه شود.
- اجرای چند worker با state فعلی توصیه نمی‌شود مگر اینکه لایهٔ persistence و coordination ارتقا یابد.
