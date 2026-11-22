# بوت بث ملفات Telegram — Cloudflare Workers

بث ملفات Telegram عبر HTTP Range مع توقيع HMAC، مبني على
[reqly](https://github.com/JamalMellouki/reqly-mtproto) المضمّن في `vendor/reqly`.

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
