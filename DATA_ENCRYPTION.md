# تشفير بيانات BLRX

النسخة تستخدم Fernet (AES-128-CBC + HMAC-SHA256 عبر مكتبة cryptography) لتشفير البيانات الحساسة أثناء التخزين.

## ماذا يتم تشفيره
- `users.json`
- `settings.json`
- `user_activity.log` (يخزن الآن كبيانات JSON مشفرة)

## المفتاح
الأفضل تعيين:
`DATA_ENCRYPTION_KEY`

أنشئ مفتاحًا مرة واحدة:
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

ضع الناتج في Railway Environment Variables، ولا تضعه داخل ZIP أو GitHub.

إذا لم يتم تعيين DATA_ENCRYPTION_KEY، يتم اشتقاق مفتاح ثابت من SECRET_KEY. لذلك يجب تغيير SECRET_KEY الافتراضي وعدم تسريبه.

## ملفات المستخدمين والبوتات
ملفات المشروع التي يجب أن يعمل بها Python لا يمكن أن تبقى مشفرة على القرص أثناء تشغيل البوت ثم يتوقع النظام تشغيلها مباشرة. النسخة الحالية تحمي بيانات الحسابات والإعدادات والسجلات الحساسة. لتشفير ملفات المشروع نفسها أثناء السكون نحتاج Vault/Container منفصل يقوم بفكها مؤقتًا عند التشغيل ثم يعيد تشفيرها عند الإيقاف.
