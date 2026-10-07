# Security Policy

برای اجرای عمومی Panel Technamooz، مقدارهای `ADMIN_PASSWORD`، `SECRET_KEY`، `TELEGRAM_BOT_TOKEN` و `TELEGRAM_ADMIN_IDS` را فقط در Variables امن Railway یا secret manager قرار دهید و هرگز در repository commit نکنید. در محیط Railway نبودن `ADMIN_PASSWORD` باعث توقف عمدی برنامه می‌شود.

رمز اولیهٔ توسعه `Technamooz` و نام کاربری اولیه `Amirparsa` فقط برای اجرای محلی هستند. پس از اولین ورود، از بخش Settings مشخصات ورود را تغییر دهید. CORS، اعتماد به `X-Forwarded-*` و اتصال relay به مقصدهای خصوصی به‌صورت پیش‌فرض محدود هستند و فقط باید با تنظیم صریح محیطی باز شوند. در صورت مشاهدهٔ مشکل امنیتی، اطلاعات حساس را در issue عمومی منتشر نکنید و از کانال پشتیبانی رسمی Technamooz استفاده کنید.
