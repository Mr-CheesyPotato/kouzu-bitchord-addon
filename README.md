# Muzo Data → BitChord addon (Vercel)

This project exposes BitChord's `/manifest.json`, `/search`, and `/stream/:id` contract, plus optional JSON endpoints for Muzo lyrics, metadata, Canvas, artist and album data.

## Important setup

1. Add the official BitChord verifier file unchanged to the project root as `bitchord-addon-auth.mjs`.
   Download it from: https://bitchord.kushagrasingh.in/addon-auth/bitchord-addon-auth.mjs
   The reference docs are: https://bitchord.kushagrasingh.in/docs
2. Push the repository to GitHub and import it into Vercel.
3. Set these Vercel Environment Variables for Production (and Preview only if needed):
   - `MUZO_API_KEY`: your private Muzo key
   - `MEDIA_SECRET`: a random secret of at least 32 characters
   - `ADDON_HOST`: your exact deployed hostname, e.g. `your-project.vercel.app` (no scheme, path or port). If the addon is reachable through multiple hostnames, list them comma-separated; the first hostname is used for generated media URLs.
4. Redeploy after adding/changing environment variables.
5. Test `https://YOUR_HOST/manifest.json`, then add `https://YOUR_HOST` in BitChord → Settings → Sources → Add an addon.

Do not put your Muzo key in GitHub, source code, a query string, or the BitChord app.

## Routes

- `GET /manifest.json` — public manifest
- `GET /search?q=...` — BitChord search (official BitChord auth required)
- `GET /stream/ytm:VIDEO_ID?quality=lossless|high|low` — resolves a stream and returns a signed, 30-minute media URL
- `GET /media?token=...` — signed media proxy; forwards Range requests and Muzo Bearer authentication
- `GET /extras/lyrics?id=VIDEO_ID`
- `GET /extras/metadata?id=VIDEO_ID`
- `GET /extras/canvas?id=VIDEO_ID`
- `GET /extras/artist?id=ARTIST_CHANNEL_ID`
- `GET /extras/album?id=ALBUM_ID`
- `GET /extras/ytm-lyrics?id=VIDEO_ID`

BitChord currently consumes only the manifest, search and stream contracts. The `/extras/*` routes expose data for future/native UI integration; they do not automatically add lyrics or Canvas screens inside BitChord.

## Notes

- The API key is only used server-side.
- Muzo resolver calls consume quota; CDN media bytes do not.
- The media proxy uses signed URLs that expire after 30 minutes and forwards HTTP byte ranges for seeking.
- The `lossless` choice requests Muzo's lossless resolver; the returned codec/format reflects the actual response where detectable. It is not a guarantee that every track has a lossless source.
- Official BitChord addon authentication is enforced on JSON routes except the public manifest and signed media route.
