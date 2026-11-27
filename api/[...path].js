import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import https from "node:https";
import { pipeline } from "node:stream/promises";
import { createBitChordAuth } from "../bitchord-addon-auth.mjs";

const BASE = "https://data.kouzu.in";
const API_KEY = process.env.MUZO_API_KEY;
const MEDIA_SECRET = process.env.MEDIA_SECRET;

function stripTrailingDot(value) {
  return value.endsWith(".") ? value.slice(0, -1) : value;
}

function normalizeAddonHost(value) {
  const candidate = String(value || "").trim();
  if (!candidate || [...candidate].some(character => character.trim() === "" || "/?#@:".includes(character))) return null;
  try {
    const parsed = new URL(`https://${candidate}`);
    const hostname = stripTrailingDot(parsed.hostname.toLowerCase());
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash) return null;
    if (stripTrailingDot(candidate.toLowerCase()) !== hostname) return null;
    return hostname;
  } catch {
    return null;
  }
}

const configuredAddonHosts = (process.env.ADDON_HOST || "").split(",").map(host => host.trim()).filter(Boolean);
const normalizedAddonHosts = configuredAddonHosts.map(normalizeAddonHost);
const ADDON_HOST_CONFIG_VALID = normalizedAddonHosts.length > 0 && normalizedAddonHosts.every(Boolean);
const ADDON_HOSTS = ADDON_HOST_CONFIG_VALID ? [...new Set(normalizedAddonHosts)] : [];
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
        { "label": "Lossless request · if available", "value": "lossless" },
        { "label": "High/Low AAC · shared rendition", "value": "aac" }
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
    const error = new Error(`Muzo returned HTTP ${response.status}`);
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
  const title = firstText(item.title || item.name).trim();
  if (!id || !title) return null;
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
    title,
    artist: firstText(artists) || "Unknown artist",
    ...(item.album ? { album: firstText(item.album) } : {}),
    ...(Number.isFinite(duration) && duration > 0 ? { duration } : {}),
    ...(artworkURL ? { artworkURL } : {})
  };
}

function parseMediaUrl(value) {
  if (typeof value !== "string" || value.length > 8192) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.port) return null;
    return url;
  } catch {
    return null;
  }
}

function mediaEncryptionKey() {
  return createHash("sha256").update("muzo-media-token:v1:key").update(MEDIA_SECRET).digest();
}

function signPayload(payload) {
  if (!MEDIA_SECRET || MEDIA_SECRET.length < 32) throw Object.assign(new Error("MEDIA_SECRET must be configured with at least 32 characters"), { status: 503 });
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", mediaEncryptionKey(), iv);
  cipher.setAAD(Buffer.from("muzo-media-token:v1"));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()]);
  return ["v1", iv.toString("base64url"), ciphertext.toString("base64url"), cipher.getAuthTag().toString("base64url")].join(".");
}

function verifyPayload(token) {
  if (!MEDIA_SECRET || MEDIA_SECRET.length < 32 || typeof token !== "string" || token.length > 16384) return null;
  const [version, encodedIv, encodedCiphertext, encodedTag, extra] = token.split(".");
  if (version !== "v1" || !/^[A-Za-z0-9_-]{16}$/.test(encodedIv || "") || !/^[A-Za-z0-9_-]+$/.test(encodedCiphertext || "") || !/^[A-Za-z0-9_-]{22}$/.test(encodedTag || "") || extra) return null;
  let payload;
  try {
    const decipher = createDecipheriv("aes-256-gcm", mediaEncryptionKey(), Buffer.from(encodedIv, "base64url"));
    decipher.setAAD(Buffer.from("muzo-media-token:v1"));
    decipher.setAuthTag(Buffer.from(encodedTag, "base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(encodedCiphertext, "base64url")), decipher.final()]);
    payload = JSON.parse(plaintext.toString("utf8"));
  } catch {
    return null;
  }
  if (!Number.isSafeInteger(payload?.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null;
  if (!videoIdFrom(payload.id) || !parseMediaUrl(payload.upstream)) return null;
  return payload;
}

function stripIpv6Brackets(hostname) {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

const blockedIpv4 = new BlockList();
for (const [subnet, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]
]) blockedIpv4.addSubnet(subnet, prefix, "ipv4");

const globalIpv6 = new BlockList();
globalIpv6.addSubnet("2000::", 3, "ipv6");
const blockedIpv6 = new BlockList();
for (const [subnet, prefix] of [["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20]]) {
  blockedIpv6.addSubnet(subnet, prefix, "ipv6");
}

function isPublicAddress(address, family) {
  if (family === 4) return !blockedIpv4.check(address, "ipv4");
  return family === 6 && globalIpv6.check(address, "ipv6") && !blockedIpv6.check(address, "ipv6");
}

async function resolvePublicAddress(hostname) {
  const normalizedHost = stripIpv6Brackets(hostname);
  const literalFamily = isIP(normalizedHost);
  if (literalFamily) {
    if (!isPublicAddress(normalizedHost, literalFamily)) throw new Error("Upstream host is not publicly routable");
    return { address: normalizedHost, family: literalFamily };
  }
  const addresses = await lookup(normalizedHost, { all: true, verbatim: true });
  const address = addresses.find(entry => isPublicAddress(entry.address, entry.family));
  if (!address) throw new Error("Upstream host has no publicly routable address");
  return address;
}

function requestHttps(url, address, headers) {
  const hostname = stripIpv6Brackets(url.hostname).toLowerCase();
  const agent = new https.Agent({
    keepAlive: false,
    lookup: (requestedHost, options, callback) => {
      if (stripIpv6Brackets(requestedHost).toLowerCase() !== hostname) return callback(new Error("Unexpected upstream hostname"));
      if (options?.all) return callback(null, [address]);
      return callback(null, address.address, address.family);
    }
  });
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      method: "GET",
      headers,
      agent,
      ...(isIP(hostname) ? {} : { servername: hostname }),
      signal: AbortSignal.timeout(60000)
    }, response => resolve({ response, agent }));
    request.once("error", error => {
      agent.destroy();
      reject(error);
    });
    request.end();
  });
}

async function requestMedia(value, headers, redirects = 0) {
  const url = parseMediaUrl(value);
  if (!url) throw new Error("Invalid HTTPS media URL");
  const address = await resolvePublicAddress(url.hostname);
  const result = await requestHttps(url, address, headers);
  const status = result.response.statusCode || 502;
  if ([301, 302, 303, 307, 308].includes(status)) {
    const location = result.response.headers.location;
    result.response.destroy();
    result.agent.destroy();
    if (!location || redirects >= 5) throw new Error("Media redirect was invalid or exceeded the limit");
    return requestMedia(new URL(location, url).toString(), headers, redirects + 1);
  }
  return result;
}

function numberFrom(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const match = String(value || "").match(/[\d.]+/);
  return match ? Number(match[0]) : undefined;
}

function sampleRateFrom(value) {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.round(value < 1000 ? value * 1000 : value);
  }
  const match = String(value || "").match(/([\d.]+)\s*k?hz/i);
  if (!match) return undefined;
  const n = Number(match[1]);
  return /khz/i.test(match[0]) || n < 1000 ? Math.round(n * 1000) : Math.round(n);
}

async function streamResolve(res, id, qualityValue) {
  const videoId = videoIdFrom(id);
  if (!videoId) return json(res, 400, { error: "Expected an 11-character YouTube video ID" });
  const requested = String(qualityValue || "lossless").trim().toLowerCase();
  if (!["lossless", "aac", "high", "low"].includes(requested)) {
    return json(res, 400, { error: "Unsupported quality. Use lossless, aac, high, or low" });
  }
  const quality = requested === "lossless" ? "lossless" : "aac";
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
    const mediaUrlFromMuzo = parseMediaUrl(upstream);
    if (!mediaUrlFromMuzo) return json(res, 502, { error: "Muzo did not return a valid HTTPS media URL" });
    const token = signPayload({ id: videoId, quality, upstream: mediaUrlFromMuzo.toString(), exp: Math.floor(Date.now() / 1000) + 1800 });
    const mediaUrl = `https://${ADDON_HOST}/media?token=${encodeURIComponent(token)}`;

    const qualityText = String(result.quality || result.audioQuality || result.bitrate || "");
    const sampleRate = sampleRateFrom(result.sampleRate ?? qualityText);
    const bitDepth = numberFrom(result.bitDepth ?? qualityText.match(/\d+\s*[- ]?bit/i)?.[0]);
    const stream = { url: mediaUrl };
    for (const field of ["format", "codec", "container"]) {
      if (typeof result[field] === "string" && result[field].trim() && !result[field].includes("://")) {
        stream[field] = result[field].trim().toLowerCase();
      }
    }
    const manifestType = typeof result.manifest === "string" ? result.manifest.trim().toLowerCase() : "";
    if (["none", "hls", "dash"].includes(manifestType)) stream.manifest = manifestType;
    const qualityLabel = result.quality ?? result.audioQuality;
    if (typeof qualityLabel === "string" && qualityLabel.trim()) stream.quality = qualityLabel.trim();
    if (typeof result.encrypted === "boolean") stream.encrypted = result.encrypted;
    if (sampleRate) stream.sampleRate = sampleRate;
    if (bitDepth) stream.bitDepth = bitDepth;
    let bitrate;
    if (typeof result.bitrate === "number" && Number.isFinite(result.bitrate) && result.bitrate > 0) bitrate = result.bitrate;
    else if (typeof result.bitrate === "string") {
      const match = result.bitrate.match(/([\d.]+)\s*(kbps|mbps|bps)\b/i);
      if (match) {
        const n = Number(match[1]);
        bitrate = /mbps/i.test(match[2]) ? n * 1000000 : /kbps/i.test(match[2]) ? n * 1000 : n;
      }
    }
    if (bitrate) stream.bitrate = Math.round(bitrate);
    return json(res, 200, stream);
  } catch (err) {
    const status = err.status === 401 ? 502 : err.status === 429 ? 429 : err.status === 404 ? 404 : err.status === 503 ? 503 : 502;
    return json(res, status, { error: err.message || "Unable to resolve stream", ...(err.rateRemaining ? { rateLimitRemaining: err.rateRemaining } : {}) }, status === 429 ? { "Retry-After": "3600" } : {});
  }
}

async function proxyMedia(req, res, token) {
  const payload = verifyPayload(token);
  if (!payload) return json(res, 403, { error: "Invalid or expired media link" });
  let agent;
  try {
    const headers = {};
    if (req.headers.range) headers.range = req.headers.range;
    const upstreamResult = await requestMedia(payload.upstream, headers);
    const upstream = upstreamResult.response;
    agent = upstreamResult.agent;
    const status = upstream.statusCode || 502;
    if (status !== 200 && status !== 206) {
      upstream.destroy();
      return json(res, status, { error: `Media CDN returned HTTP ${status}` });
    }
    res.statusCode = status;
    for (const name of ["content-type", "content-length", "content-range", "accept-ranges", "last-modified", "etag"]) {
      const value = upstream.headers[name];
      if (value) res.setHeader(name, value);
    }
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    await pipeline(upstream, res);
  } catch (err) {
    if (!res.headersSent) json(res, 502, { error: "Unable to fetch media from CDN" });
    else res.destroy(err);
  } finally {
    agent?.destroy();
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
  if (!auth) return json(res, 503, { error: "Server is missing or has invalid ADDON_HOST" });
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

  if (path === "/stream" || path.startsWith("/stream/")) {
    let id;
    try {
      id = path === "/stream" ? url.searchParams.get("id") : decodeURIComponent(path.slice("/stream/".length));
    } catch {
      return json(res, 400, { error: "Malformed track ID" });
    }
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
  const extraPath = path === "/extras" ? `/extras/${url.searchParams.get("resource") || ""}` : path;
  if (extraRoutes[extraPath]) {
    const [endpoint, param] = extraRoutes[extraPath];
    const id = url.searchParams.get(param);
    if (!id) return json(res, 400, { error: `Missing ${param}` });
    try { return json(res, 200, await muzo(endpoint, { [param]: id })); }
    catch (err) { return json(res, err.status === 429 ? 429 : err.status === 404 ? 404 : err.status === 503 ? 503 : 502, { error: err.message }); }
  }

  return json(res, 404, { error: "Not found" });
}
