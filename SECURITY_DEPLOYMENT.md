# تعليمات الحماية والنشر

## مهم
حماية Flask وRate Limiting داخل التطبيق تقلل إساءة الاستخدام، لكنها **لا توقف DDoS الحجمي** قبل وصوله إلى الخادم. استخدم دومينًا خلف Cloudflare Proxy أو مزود WAF مشابه، ولا تكشف رابط Railway/الخادم المباشر.

## المتغيرات الإلزامية
- `SECRET_KEY`: قيمة عشوائية طويلة وثابتة.
- `DATA_ENCRYPTION_KEY`: مفتاح Fernet محفوظ في Environment Variables فقط.
- `ADMIN_PASSWORD`: مطلوب عند إنشاء قاعدة مستخدمين جديدة.
- `HOSTING_BOT_API_KEY`: مطلوب إذا كانت واجهات `/api/bot/*` مستخدمة.
- اترك `BLOCK_SENSITIVE_PROJECT_FILES=1` لمنع قراءة/تنزيل `.env` وملفات المفاتيح و`.git`.
- النسخة المسلّمة لا تتضمن `users.json` الحقيقي؛ اضبط `ADMIN_PASSWORD` قبل أول تشغيل، وسيُنشئ التطبيق ملف الحالة المشفّر تلقائيًا.
- اترك `REQUIRE_HTTPS=1` في الإنتاج، واضبط `ALLOWED_HOSTS` على دومينك إذا كان ثابتًا.

توليد المفتاح:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Cloudflare/WAF
1. فعّل Proxy (السحابة البرتقالية) للدومين.
2. فعّل Managed WAF وDDoS Protection.
3. أضف Rate Limit على `/api/*`، خصوصًا POST/PUT/PATCH/DELETE.
4. اسمح فقط بالـ methods: GET, POST, PUT, PATCH, DELETE, OPTIONS.
5. امنع الوصول إلى `/.env`, `/.git/*`, `/users.json`, `/settings.json`, وملفات المفاتيح.
6. لا تسجل Access Tokens أو كلمات المرور في سجلات الـWAF.

## عزل تنفيذ كود المستخدم
التطبيق يشغّل مشاريع المستخدمين على حساب العملية نفسه. لا تعتبره عزلًا آمنًا متعدد المستأجرين. للعزل الحقيقي شغّل كل مشروع داخل Container/VM منفصل مع مستخدم غير root، مساحة ملفات منفصلة، CPU/RAM/PID limits، منع Docker socket، وتقييد الشبكة.

## ما تم تقويته داخل التطبيق
- تحقق canonical من المسارات ومنع traversal والروابط الرمزية.
- منع عرض/تنزيل الملفات الحساسة افتراضيًا.
- مصادقة مسارات GitHub logs/deploy/clear.
- حدود عدد الملفات وحجم فك الأرشيف والتنزيل والضغط.
- Rate limiting، حد الطلبات المتزامنة، وحجم body.
- تشفير users/settings/activity log أثناء التخزين عند ضبط المفتاح.
