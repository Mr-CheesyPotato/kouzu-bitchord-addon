# Muzo Data → BitChord addon (Vercel)

This project exposes BitChord's `/manifest.json`, `/search`, and `/stream/:id` contract, plus optional JSON endpoints for lyrics, metadata, Canvas, artist, and album data.

## Important setup

1. The project includes BitChord's official reference verifier unchanged as `bitchord-addon-auth.mjs`. Its SHA-256 matches the file published at https://bitchord.kushagrasingh.in/addon-auth/bitchord-addon-auth.mjs. See the official protocol at https://bitchord.kushagrasingh.in/docs.
2. Set these Vercel Environment Variables for Production (and Preview only if needed):
   - `MUZO_API_KEY`: your private Muzo key
   - `MEDIA_SECRET`: a random secret of at least 32 characters
   - `ADDON_HOST`: the exact public hostname listeners use, e.g. `kouzu-bitchord-addon.vercel.app` (no scheme, path, or port). For multiple public hostnames, list them comma-separated; the first is used for generated media URLs.
3. Redeploy after adding or changing environment variables.
4. Test `https://YOUR_HOST/manifest.json`, then add `https://YOUR_HOST` in BitChord → Settings → Sources → Add an addon.

Do not put the Muzo key in GitHub, source code, a URL, or the BitChord app.

## Routes

- `GET /manifest.json` — public manifest
- `GET /search?q=...` — BitChord search; official BitChord auth required
- `GET /stream/ytm:VIDEO_ID?quality=lossless|aac|high|low` — resolves a stream and returns an opaque, encrypted media URL valid for 30 minutes
- `GET /media?token=...` — signed media proxy; forwards byte ranges and does not require BitChord headers
- `GET /extras/lyrics?id=VIDEO_ID`
- `GET /extras/metadata?id=VIDEO_ID`
- `GET /extras/canvas?id=VIDEO_ID`
- `GET /extras/artist?id=ARTIST_CHANNEL_ID`
- `GET /extras/album?id=ALBUM_ID`
- `GET /extras/ytm-lyrics?id=VIDEO_ID`

BitChord currently consumes only the manifest, search, and stream contracts. `/extras/*` is auxiliary JSON, not a built-in lyrics or Canvas UI.

## Implementation caveats

- This is a raw Vercel Functions project, not a Next.js app. Dynamic public stream and extras routes rewrite to one-segment function paths and carry IDs/resources in query parameters; they do not rely on framework catch-all routing.
- No official Muzo API reference or OpenAPI document was available. The existing `data.kouzu.in` base URL, `X-API-Key` header, endpoint paths, query names, and response-field normalization are retained as implementation hypotheses; they are not represented as verified vendor specifications. The current search call uses `/api/v1/ytm/search`; stream resolution uses `/api/v1/stream/lossless`, `/api/v1/stream/aac`, and the existing `/api/v1/stream` lossless fallback.
- Lossless and AAC use the existing resolver paths. High and low requests both map to the same AAC resolver path because the available implementation provides no evidence of separate AAC renditions. The manifest therefore offers one AAC choice instead of presenting High and Low as distinct capabilities. Returned codec, bitrate, and sample-rate fields are passed through only when the response contains them.
- Media URLs must be absolute HTTPS URLs without embedded credentials or a nonstandard port. The proxy resolves hosts, rejects non-public addresses, pins the HTTPS connection to a validated address, and revalidates each redirect. This accepts public Muzo/CDN hostnames without a hardcoded `workers.dev` restriction while blocking private-network SSRF targets. The Muzo API key is not forwarded to media hosts.
- Media URL tokens use AES-GCM encryption and expire after 30 minutes, so the upstream signed URL is not readable in the BitChord response.
- The BitChord manifest is public. Search, stream, and extras use the official hardware-backed verifier; the signed media route is intentionally exempt because BitChord's player does not send addon-auth headers.
- Run the built-in route and security tests with `npm test` (Node.js 20+).
