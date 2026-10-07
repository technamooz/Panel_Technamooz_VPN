# گزارش نهایی دیباگ Panel Technamooz

## علت اصلی Deploy نشدن روی Railway

برنامه در محیط production عمداً بدون متغیر `ADMIN_PASSWORD` متوقف می‌شود تا رمز پیش‌فرض `Technamooz` روی اینترنت فعال نشود. در تست شبیه‌سازی Railway خطای زیر بازتولید شد:

```text
RuntimeError: ADMIN_PASSWORD must be set in production
```

این رفتار امنیتی است، اما باعث می‌شود Deploy ظاهراً fail شود اگر متغیرهای لازم در Railway تعریف نشده باشند.

## اصلاحات اعمال‌شده

1. تشخیص محیط Railway علاوه بر `RAILWAY_ENVIRONMENT`، متغیرهای استانداردتر `RAILWAY_ENVIRONMENT_NAME` و `RAILWAY_PROJECT_ID` را نیز بررسی می‌کند.
2. در Railway، مسیر داده به‌صورت پیش‌فرض `/data` انتخاب می‌شود؛ برای پایداری، در سرویس Railway یک Volume با mount path `/data` بسازید.
3. `railway.json` اکنون `startCommand` صریح دارد:

```text
uvicorn main:app --host 0.0.0.0 --port $PORT
```

4. خطای circular import بین `main.py`، `relay_vless.py` و `xhttp_siz10.py` رفع شد؛ import مستقیم ماژول‌ها نیز اکنون سالم است.
5. باگ XHTTP که در زمان بازکردن TCP به متغیر تعریف‌نشده `uuid` ارجاع می‌داد رفع شد.
6. تولید Clash YAML برای labelهایی که نقل‌قول یا backslash داشتند اصلاح شد و خروجی با parser معتبر YAML تست شد.
7. ورودی‌های عددی نامعتبر API دیگر باعث HTTP 500 نمی‌شوند و پاسخ کنترل‌شده HTTP 400 برمی‌گردانند.
8. بارگذاری state دیگر توکن Telegram موجود در environment را با مقدار خالیِ backup جایگزین نمی‌کند.
9. endpoint افزودن/حذف کانفیگ از گروه اکنون هم‌زمان `sub.link_ids` و `link.sub_id` را به‌روزرسانی می‌کند.
10. قرارداد `/api/telegram/status` با Frontend کامل شد (`enabled`, `configured`, `admin_ids` و وضعیت polling).
11. گزینهٔ غیرفعال‌سازی Telegram اکنون واقعاً از اجرای bot جلوگیری می‌کند؛ startup نیز فقط در حالت enabled ربات را اجرا می‌کند.
12. importهای بلااستفاده حذف و lint بحرانی (`E9`, `F`) بدون خطا شد.

## متغیرهای ضروری Railway

در بخش **Variables** سرویس Railway این موارد را تنظیم کنید:

```text
ADMIN_PASSWORD=<یک رمز قوی و یکتا، حداقل ۶ کاراکتر>
SECRET_KEY=<یک مقدار تصادفی ثابت و طولانی>
DATA_DIR=/data
```

اختیاری:

```text
RAILWAY_PUBLIC_DOMAIN=<دامنه عمومی Railway یا دامنه سفارشی بدون https://>
ALLOWED_PUBLIC_HOSTS=<دامنه‌های مجاز، جداشده با کاما>
TRUST_PROXY_HEADERS=false
CORS_ORIGINS=<originهای دقیق در صورت نیاز، جداشده با کاما>
TELEGRAM_BOT_TOKEN=<در صورت استفاده>
TELEGRAM_ADMIN_IDS=<شناسه ادمین‌ها با کاما>
```

## مراحل Deploy صحیح

1. Repository یا ZIP اصلاح‌شده را در Railway قرار دهید.
2. در سرویس، یک **Volume** بسازید و مسیر آن را `/data` تنظیم کنید.
3. متغیرهای `ADMIN_PASSWORD` و `SECRET_KEY` را در Variables ذخیره کنید.
4. Deploy جدید را اجرا کنید.
5. Railway باید endpoint زیر را health-check کند:

```text
GET /health
```

پاسخ موفق:

```json
{"status":"ok","app":"Panel Technamooz","version":"1.0.0.0"}
```

## تست‌های انجام‌شده

- `python3 -m py_compile *.py`: موفق
- نصب clean-build از `requirements.txt`: موفق
- import مستقیم `main`, `relay_vless`, `xhttp_siz10`: موفق
- ثبت ۴۵ route: موفق
- اجرای واقعی Uvicorn روی پورت تزریق‌شده با `PORT`: موفق
- health-check روی سرویس اجراشده: HTTP 200
- login، CAPTCHA، CRUD کانفیگ، backup و subscription: موفق
- parsing خروجی Clash برای هر چهار پروتکل: موفق
- رد UUID اشتباه در VLESS/XHTTP: موفق
- ورودی نامعتبر API: HTTP 400 به‌جای HTTP 500
- حفظ تنظیمات Telegram بعد از restart و state load
- اعتبارسنجی و همگام‌سازی رابطه کانفیگ/گروه
- قرارداد کامل وضعیت و lifecycle ربات Telegram
- lint بحرانی و بررسی نام‌های تعریف‌نشده: موفق
- guard production بدون `ADMIN_PASSWORD`: توقف امن و پیام خطای صریح

> نکته: رمز واقعی و `SECRET_KEY` را هرگز داخل ZIP، Git یا پیام عمومی قرار ندهید.
