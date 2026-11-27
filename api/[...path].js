import { createHmac, timingSafeEqual } from "node:crypto";
import { Readable } from "node:stream";
import { createBitChordAuth } from "../bitchord-addon-auth.mjs";

const BASE = "https://data.kouzu.in";
const API_KEY = process.env.MUZO_API_KEY;
const MEDIA_SECRET = process.env.MEDIA_SECRET;
const ADDON_HOSTS = [...new Set((process.env.ADDON_HOST || "").split(",").map(host => host.trim().toLowerCase()).filter(Boolean))];
const ADDON_HOST = ADDON_HOSTS[0];

// Official BitChord request verifier. Keep the manifest public; guard all other JSON routes.
const auth = ADDON_HOSTS.length ? createBitChordAuth({ hosts: ADDON_HOSTS }) : null;

const manifest = {
  id: "in.kouzu.muzo",
  name: "Muzo Data",
  version: "1.0.0",
  resources: ["search", "stream"],
  bitchordAuth: true,
  allowDownloads: 1,
  settings: [
    {
      key: "quality",
      type: "select",
      label: "Audio quality",
      default: "lossless",
      options: [
        { "label": "Max · Lossless FLAC", "value": "lossless" },
        { "label": "High · AAC", "value": "high" },
        { "label": "Low · AAC", "value": "low" }
      ]
    }
  ]
};

function json(res, status, body, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

function apiHeaders() {
  if (!API_KEY) throw Object.assign(new Error("Server is missing MUZO_API_KEY"), { status: 503 });
  return { "X-API-Key": API_KEY, "Accept": "application/json" };
}

async function muzo(path, params = {}) {
  const url = new URL(`${BASE}${path}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
  }
  const response = await fetch(url, { headers: apiHeaders(), signal: AbortSignal.timeout(15000) });
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: "Invalid JSON from Muzo" }; }
  if (!response.ok) {
    const error = new Error(data?.error || `Muzo returned HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    error.rateRemaining = response.headers.get("X-RateLimit-Remaining");
    throw error;
  }
  return data;
}

function videoIdFrom(value) {
  const raw = String(value || "").replace(/^ytm:/, "");
  return /^[A-Za-z0-9_-]{11}$/.test(raw) ? raw : null;
}

function firstText(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(v => typeof v === "string" ? v : v?.name || v?.title || "").filter(Boolean).join(", ");
  if (value && typeof value === "object") return value.name || value.title || "";
  return "";
}

function trackFrom(item) {
  if (!item || typeof item !== "object") return null;
  const rawId = item.videoId || item.video_id || item.id || item.playlistItemData?.videoId;
  const id = videoIdFrom(rawId);
  if (!id) return null;
  const thumbs = item.thumbnails || item.thumbnail || item.thumbnails?.[0];
  const artworkURL = Array.isArray(thumbs)
    ? (thumbs.at(-1)?.url || thumbs[0]?.url || "")
    : (typeof thumbs === "string" ? thumbs : thumbs?.url || "");
  const durationRaw = item.durationSeconds ?? item.duration ?? item.lengthSeconds;
  let duration = Number(durationRaw);
  if (!Number.isFinite(duration) && typeof durationRaw === "string") {
    const parts = durationRaw.split(":").map(Number);
    if (parts.every(Number.isFinite)) duration = parts.reduce((n, p) => n * 60 + p, 0);
  }
  const artists = item.artists || item.artist || item.author || item.subtitle;
  return {
    id: `ytm:${id}`,
    title: item.title || item.name || "Unknown title",
    artist: firstText(artists) || "Unknown artist",
    ...(item.album ? { album: firstText(item.album) } : {}),
    ...(Number.isFinite(duration) && duration > 0 ? { duration } : {}),
    ...(artworkURL ? { artworkURL } : {})
  };
}

function signPayload(payload) {
  if (!MEDIA_SECRET) throw Object.assign(new Error("Server is missing MEDIA_SECRET"), { status: 503 });
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", MEDIA_SECRET).update(encoded).digest("base64url");
  return `${encoded}.${sig}`;
}

function verifyPayload(token) {
  if (!MEDIA_SECRET || typeof token !== "string") return null;
  const [encoded, signature, extra] = token.split(".");
  if (!encoded || !signature || extra) return null;
  const expected = createHmac("sha256", MEDIA_SECRET).update(encoded).digest();
  let supplied;
  try { supplied = Buffer.from(signature, "base64url"); } catch { return null; }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")); } catch { return null; }
  if (!payload?.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
  if (!videoIdFrom(payload.id) || typeof payload.upstream !== "string") return null;
  // Prevent a signed token from being used to make this server fetch arbitrary URLs.
  let upstream;
  try { upstream = new URL(payload.upstream); } catch { return null; }
  if (upstream.protocol !== "https:" || (upstream.hostname !== "workers.dev" && !upstream.hostname.endsWith(".workers.dev"))) return null;
  return payload;
}

function numberFrom(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const match = String(value || "").match(/[\d.]+/);
  return match ? Number(match[0]) : undefined;
}

function sampleRateFrom(value) {
  const match = String(value || "").match(/([\d.]+)\s*k?hz/i);
  if (!match) return undefined;
  const n = Number(match[1]);
  return /khz/i.test(match[0]) || n < 1000 ? Math.round(n * 1000) : Math.round(n);
}

async function streamResolve(res, id, qualityValue) {
  const videoId = videoIdFrom(id);
  if (!videoId) return json(res, 400, { error: "Expected an 11-character YouTube video ID" });
  const requested = String(qualityValue || "lossless").toLowerCase();
  const quality = requested === "low" ? "low" : requested === "high" ? "high" : "lossless";
  const endpoint = quality === "lossless" ? "/api/v1/stream/lossless" : "/api/v1/stream/aac";

  try {
    let result;
    try {
      result = await muzo(endpoint, { id: videoId });
    } catch (err) {
      if (quality === "lossless" && [404, 400].includes(err.status)) {
        result = await muzo("/api/v1/stream", { id: videoId });
      } else throw err;
    }
    const upstream = result.streamUrl || result.url;
    if (!upstream) return json(res, 502, { error: "Muzo did not return a stream URL" });
    const token = signPayload({ id: videoId, quality, upstream, exp: Math.floor(Date.now() / 1000) + 1800 });
    const mediaUrl = `https://${ADDON_HOST}/media?token=${encodeURIComponent(token)}`;

    // Catalog ingestion is open, free and does not use the API key. Best effort after resolving.
    fetch(`${BASE}/api/v1/stream/add?id=${encodeURIComponent(videoId)}`).catch(() => {});

    const formatText = String(result.format || "").toLowerCase();
    const qualityText = String(result.bitrate || result.quality || "");
    const isFlac = formatText.includes("flac") || String(upstream).includes("/flac/");
    const codec = isFlac ? "flac" : "aac";
    const sampleRate = sampleRateFrom(qualityText);
    const bitDepth = numberFrom(qualityText.match(/\d+\s*[- ]?bit/i)?.[0]);
    let bitrate;
    if (typeof result.bitrate === "number" && Number.isFinite(result.bitrate)) bitrate = result.bitrate;
    else if (typeof result.bitrate === "string") {
      const match = result.bitrate.match(/([\d.]+)\s*(kbps|mbps|bps)\b/i);
      if (match) {
        const n = Number(match[1]);
        bitrate = /mbps/i.test(match[2]) ? n * 1000000 : /kbps/i.test(match[2]) ? n * 1000 : n;
      }
    }
    return json(res, 200, {
      url: mediaUrl,
      format: isFlac ? "flac" : "m4a",
      quality: result.bitrate || (quality === "lossless" ? "Lossless (actual source reported by Muzo)" : "AAC"),
      codec,
      container: isFlac ? "flac" : "m4a",
      manifest: "none",
      encrypted: false,
      ...(sampleRate ? { sampleRate } : {}),
      ...(bitDepth ? { bitDepth } : {}),
      ...(bitrate ? { bitrate: bitrate < 10000 ? Math.round(bitrate * 1000) : Math.round(bitrate) } : {})
    });
  } catch (err) {
    const status = err.status === 401 ? 502 : err.status === 429 ? 429 : err.status === 404 ? 404 : err.status === 503 ? 503 : 502;
    return json(res, status, { error: err.message || "Unable to resolve stream", ...(err.rateRemaining ? { rateLimitRemaining: err.rateRemaining } : {}) }, status === 429 ? { "Retry-After": "3600" } : {});
  }
}

async function proxyMedia(req, res, token) {
  if (!API_KEY) return json(res, 503, { error: "Server is missing MUZO_API_KEY" });
  const payload = verifyPayload(token);
  if (!payload) return json(res, 403, { error: "Invalid or expired media link" });
  try {
    const headers = { Authorization: `Bearer ${API_KEY}` };
    if (req.headers.range) headers.Range = req.headers.range;
    const upstream = await fetch(payload.upstream, { headers, signal: AbortSignal.timeout(60000) });
    if (!upstream.ok && upstream.status !== 206) return json(res, upstream.status, { error: `Media CDN returned HTTP ${upstream.status}` });
    res.statusCode = upstream.status;
    for (const name of ["content-type", "content-length", "content-range", "accept-ranges", "last-modified", "etag"]) {
      const value = upstream.headers.get(name);
      if (value) res.setHeader(name, value);
    }
    res.setHeader("Cache-Control", "private, no-store");
    if (!upstream.body) return res.end();
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (err) {
    if (!res.headersSent) json(res, 502, { error: "Unable to fetch media from CDN" });
    else res.destroy(err);
  }
}

export default async function handler(req, res) {
  const url = new URL(req.url, `https://${req.headers.host || "localhost"}`);
  const path = url.pathname.replace(/^\/api(?=\/|$)/, "") || "/";

  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" }, { Allow: "GET" });
  if (path === "/manifest.json") return json(res, 200, manifest);
  if (path === "/media") return proxyMedia(req, res, url.searchParams.get("token"));

  // BitChord's official hardware-backed request verification protects API/quota endpoints.
  const authHeaders = new Headers();
  for (const name of ["x-bitchord-token", "x-bitchord-proof"]) {
    const value = req.headers[name];
    if (typeof value === "string") authHeaders.set(name, value);
  }
  if (!auth) return json(res, 503, { error: "Server is missing ADDON_HOST" });
  const denied = await auth.guard(new Request(url, { method: "GET", headers: authHeaders }));
  if (denied) {
    res.statusCode = denied.status;
    denied.headers.forEach((value, key) => res.setHeader(key, value));
    return res.end(await denied.text());
  }

  if (path === "/search") {
    const q = String(url.searchParams.get("q") || "").trim();
    if (!q) return json(res, 200, { tracks: [] });
    try {
      const data = await muzo("/api/v1/ytm/search", { q, filter: "songs", limit: 25 });
      const raw = [data?.items, data?.results, data?.tracks].find(Array.isArray) || [];
      const tracks = raw.map(trackFrom).filter(Boolean);
      return json(res, 200, { tracks });
    } catch (err) {
      const status = err.status === 429 ? 429 : err.status === 503 ? 503 : 502;
      return json(res, status, { error: err.message || "Search failed" }, status === 429 ? { "Retry-After": "3600" } : {});
    }
  }

  if (path.startsWith("/stream/")) {
    let id;
    try { id = decodeURIComponent(path.slice("/stream/".length)); }
    catch { return json(res, 400, { error: "Malformed track ID" }); }
    return streamResolve(res, id, url.searchParams.get("quality"));
  }

  // Extra Muzo data endpoints. These return data; BitChord's current addon UI does not render them.
  const extraRoutes = {
    "/extras/lyrics": ["/api/v1/lyrics", "id"],
    "/extras/metadata": ["/api/v1/metadata", "id"],
    "/extras/canvas": ["/api/v1/canvas", "id"],
    "/extras/artist": ["/api/v1/ytm/artist", "id"],
    "/extras/album": ["/api/v1/ytm/album", "id"],
    "/extras/ytm-lyrics": ["/api/v1/ytm/lyrics", "id"]
  };
  if (extraRoutes[path]) {
    const [endpoint, param] = extraRoutes[path];
    const id = url.searchParams.get(param);
    if (!id) return json(res, 400, { error: `Missing ${param}` });
    try { return json(res, 200, await muzo(endpoint, { [param]: id })); }
    catch (err) { return json(res, err.status === 429 ? 429 : err.status === 404 ? 404 : err.status === 503 ? 503 : 502, { error: err.message }); }
  }

  return json(res, 404, { error: "Not found" });
}
