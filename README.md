# Telegram File Stream Bot (Cloudflare Workers)

HMAC-signed HTTP Range streaming of Telegram files through Cloudflare Workers.
The MTProto layer is [reqly](https://github.com/JamalMellouki/reqly-mtproto) —
vendored under `vendor/reqly`, with no third-party MTProto runtime dependency.

## Features

- Signed stream URLs (`id`, `messageId`, `expiry`, `nonce`, `title`) with HMAC-SHA256.
- HTTP Range / 206 partial responses with correct `Content-Range`.
- 1 MB MTProto chunks aligned to Telegram's 1 MB block rule.
- Edge caching of individual chunks with `caches.default`.
- Adaptive parallel chunk fetching (2 → 4 workers) inside `reqly`.
- Pre-warming of the file tail (MP4 `moov`) for fast startup.
- Automatic DC migration via per-DC authorized sessions.
- Optional Durable Object coordinator for sticky streaming sessions.

## Architecture

```
Browser ──Range──▶ Worker (strN) ──MTProto──▶ Telegram DC
                      │
                      └── caches.default (1 MB chunks)
```

A separate `main-str` worker issues signed URLs; this worker only validates
them and streams bytes.

## Deploy

```sh
npm install
cp .env.example .env   # fill in credentials
npm run typecheck
npm run deploy
```

`scripts/deploy.ts` creates a KV namespace per worker and deploys `str1`,
`str2`, … one per Cloudflare account (`CF_ACCOUNT_2_*` → `str1`, etc.).
Set `ONLY_WORKER=str1` to deploy a single worker first.

## Environment

See `.env.example`. Important values:

| Variable | Purpose |
| --- | --- |
| `SIGNING_SECRET` | HMAC secret shared with the URL signer |
| `MTPROTO_SESSION` | Pre-authorized StringSession for the home DC |
| `DC1_SESSION`… | Additional authorized sessions for `FILE_MIGRATE_X` |
| `CHANNEL_ACCESS_HASH` | Access hash of the archive channel |
| `ARCHIVE_CHANNEL_ID` | `-100...` channel id |
| `CHUNK_SIZE` / `MAX_BYTES` | 1 MB / 2 MB by default |

## Quota

At 2 MB per HTTP response, a 2 GB file needs about 1,000 requests — roughly
**1%** of the free 100,000 requests/day. Cached ranges need no Telegram call.

## License

ASYNCTRIC-3.0. Author: Mellouki Jamal. Platform: Asynctric.

Made by Mellouki Jamal for Asynctric.
