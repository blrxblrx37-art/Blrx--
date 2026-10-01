# Railway Deployment

## Start
The app is configured for Railway with:
- `Procfile`
- `railway.toml`
- `requirements.txt` including `gunicorn` and `psutil`

## Environment variables
- `SECRET_KEY` (recommended)
- `PORT` (Railway sets this automatically)
- `DATA_DIR` (optional persistent storage mount)

## Notes
- The app binds to `0.0.0.0`
- Files and users are stored relative to `DATA_DIR` when provided

- `settings.json` stores the default max projects per user (editable from admin panel)
- The admin panel includes a Project Limit control and template presets


## 🛡️ حماية IP التلقائية
تمت إضافة حماية عامة للتطبيق:
- Rate Limit افتراضي: 120 طلبًا لكل IP خلال 60 ثانية.
- بعد 3 مرات تجاوز للحد يتم حظر IP تلقائيًا لمدة 15 دقيقة.
- الحظر والرفع التلقائي للحظر يُسجلان في `security_ban.log`.
- الحظر النشط محفوظ في `security_bans.json`.
- يمكن للأدمن عرض الحظر من `GET /admin/security/bans` وإلغاء حظر IP عبر `POST /admin/security/unban`.
- الإعدادات: `SECURITY_RATE_LIMIT`, `SECURITY_RATE_WINDOW`, `SECURITY_BAN_AFTER`, `SECURITY_BAN_SECONDS`.
- خلف Railway/Proxy يتم استخدام `X-Forwarded-For` تلقائيًا عندما تكون `RAILWAY_ENVIRONMENT` موجودة. يمكن التحكم بذلك عبر `SECURITY_TRUST_PROXY`.

Security hardening: see SECURITY_DDOS.md for Cloudflare/WAF and environment configuration.
