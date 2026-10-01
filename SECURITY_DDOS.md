# حماية DDoS للمشروع

هذه الحماية تقلل إساءة الاستخدام داخل تطبيق Flask، لكنها **ليست بديلاً عن CDN/WAF**. هجمات DDoS الحجمية يجب إيقافها قبل وصولها إلى Railway/الخادم.

## المتغيرات المقترحة

```text
SECRET_KEY=<قيمة عشوائية قوية>
TRUSTED_PROXY_HOPS=1
MAX_CONTENT_LENGTH=52428800
MAX_ACTIVE_REQUESTS=120
GLOBAL_RATE_LIMIT=300
GLOBAL_RATE_WINDOW=60
SCRAPE_GET_LIMIT=120
SCRAPE_GET_WINDOW=60
HSTS_PRELOAD=0
```

## Cloudflare

- اجعل الدومين يمر عبر Cloudflare Proxy (السحابة البرتقالية).
- فعّل DDoS Protection وWAF.
- أضف Rate Limiting على `/api/*`، خصوصًا `POST`, `PUT`, `PATCH`, `DELETE`.
- ضع تحديًا/حظرًا للطلبات الآلية غير الطبيعية بدل حظر المستخدمين الطبيعيين مباشرة.
- لا تضع Railway URL المباشر في صفحات عامة أو سجلات يمكن للمستخدمين الوصول إليها إذا كان بإمكانك تقييد الوصول إلى التطبيق عبر طبقة الحماية.

## Railway

- استخدم HTTPS فقط.
- اجعل الأسرار في Variables وليس داخل الكود.
- راقب CPU/RAM/network أثناء الهجمات.
- إذا استمر هجوم كبير، استخدم حماية مزود الاستضافة/CDN؛ Rate limiting داخل Python لا يستطيع امتصاص هجوم شبكي ضخم.
