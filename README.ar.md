# بوت بث ملفات Telegram — Cloudflare Workers

بث ملفات Telegram عبر HTTP Range مع توقيع HMAC.

> ## مبني على **reqly** — الركيزة الأساسية للمشروع
>
> كل عملية Telegram في هذا العامل تمر عبر
> **[reqly](https://github.com/JamalMellouki/reqly-mtproto)** (`reqlyproto` على npm)،
> مكتبة MTProto 2.0 المستقلة من المؤلف. مضمّنة في `vendor/reqly` ويستوردها
> `src/telegram.ts` مباشرة:
>
> ```ts
> import { Reqly, type RemoteDocument } from "../vendor/reqly/index"
> ```
>
> **لا توجد أي تبعية MTProto أخرى** (لا teleproto ولا gramjs) لا وقت التشغيل ولا وقت البناء.
> هذا المشروع إثبات عملي على أن reqly قادرة على تشغيل خدمة بث إنتاجية على الخطة المجانية.
>
> | واجهة reqly المستخدمة | دورها هنا |
> | --- | --- |
> | `Reqly.connect(session, { dcSessions })` | عميل مفوّض + إعادة محاولة عند `FILE_MIGRATE_X` |
> | `client.getMessages(...)` | استخراج معرّف الملف وaccess hash وfile reference |
> | `client.getFile(...)` | قراءة قطع 1MB محاذية وآمنة عند نهاية الملف |
> | `client.getFilesParallel(...)` | تجمع متكيّف 2→4 مع تراجع عند الفشل |
> | `parseSession` / `SessionStore` | جلسات لكل مركز بيانات |
> | AES-256-IGE بـ TypeScript | نقل مشفّر ضمن ميزانية الـ 10ms |

## المزايا
- روابط بث موقّعة HMAC-SHA256 تنتهي صلاحيتها تلقائياً.
- دعم `Range` واستجابات `206` مع `Content-Range` صحيحة.
- قطع MTProto بحجم 1MB محاذية لقواعد Telegram.
- تخزين القطع على حافة Cloudflare عبر `caches.default`.
- جلب متوازٍ متكيّف للقطع (2→4).
- تسخين ذيل الملف (moov) لبدء أسرع.
- انتقال تلقائي بين مراكز البيانات عبر جلسات DC مفوّضة.

## النشر
```sh
npm install
cp .env.example .env
npm run typecheck
npm run deploy
```

يُنشئ السكربت KV لكل عامل وينشر `str1` و`str2`… لكل حساب Cloudflare على حدة.
استخدم `ONLY_WORKER=str1` للنشر التجريبي أولاً.

## الترخيص
ASYNCTRIC-3.0 — Mellouki Jamal / Asynctric.

Made by Mellouki Jamal for Asynctric.
