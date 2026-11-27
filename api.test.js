import assert from "node:assert/strict";
import { after, test } from "node:test";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";

process.env.ADDON_HOST = "addon.example.test";
process.env.MUZO_API_KEY = "unit-test-api-key";
process.env.MEDIA_SECRET = "unit-test-media-secret-value-longer-than-thirty-two-characters";

const signingPair = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const devicePair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const signingJwk = await webcrypto.subtle.exportKey("jwk", signingPair.publicKey);
const deviceJwk = await webcrypto.subtle.exportKey("jwk", devicePair.publicKey);
const originalFetch = globalThis.fetch;
const muzoCalls = [];
const muzoResponses = new Map();

function setMuzoResponse(path, status, body) {
  muzoResponses.set(path, { status, body });
}

function resetMuzo() {
  muzoCalls.length = 0;
  muzoResponses.clear();
  setMuzoResponse("/api/v1/ytm/search", 200, {
    items: [{
      videoId: "abcdefghijk",
      title: "Midnight Signal",
      artists: [{ name: "Example Artist" }],
      album: { name: "Night Drive" },
      durationSeconds: 242,
      thumbnails: [{ url: "https://images.example.test/small.jpg" }, { url: "https://images.example.test/large.jpg" }]
    }]
  });
  setMuzoResponse("/api/v1/stream/lossless", 200, { streamUrl: "https://media.example.test/lossless?sig=unit-private-signature", codec: "flac" });
  setMuzoResponse("/api/v1/stream/aac", 200, { streamUrl: "https://media.example.test/aac?sig=unit-private-signature", codec: "aac", bitrate: "256kbps", sampleRate: 44.1, manifest: "https://media.example.test/secret.m3u8?sig=private" });
  setMuzoResponse("/api/v1/stream", 200, { streamUrl: "https://media.example.test/default?sig=unit-private-signature" });
}

resetMuzo();
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(input instanceof Request ? input.url : input);
  if (url.hostname === "bitchord-auth.kushagrasingh.in") {
    return new Response(JSON.stringify({ keys: [{ ...signingJwk, kid: "test-signing-key" }] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  }
  if (url.hostname !== "data.kouzu.in") throw new Error("Unexpected external fetch in unit test");
  const requestHeaders = new Headers(init.headers);
  muzoCalls.push({ pathname: url.pathname, params: url.searchParams, apiKey: requestHeaders.get("x-api-key") });
  const fixture = muzoResponses.get(url.pathname) || { status: 404, body: { error: "not found" } };
  return new Response(JSON.stringify(fixture.body), {
    status: fixture.status,
    headers: { "content-type": "application/json" }
  });
};

const { default: handler } = await import("./api/[...path].js");

after(() => {
  globalThis.fetch = originalFetch;
});

const toBase64Url = value => Buffer.from(value).toString("base64url");

async function bitChordHeaders() {
  const now = Date.now();
  const header = toBase64Url(JSON.stringify({ alg: "EdDSA", kid: "test-signing-key", typ: "JWT" }));
  const claims = toBase64Url(JSON.stringify({
    iss: "https://bitchord-auth.kushagrasingh.in",
    aud: "bitchord-addons",
    sub: "unit-test-device",
    iat: Math.floor(now / 1000),
    exp: Math.floor(now / 1000) + 3600,
    ver: 1,
    sl: "tee",
    cnf: { jwk: deviceJwk }
  }));
  const unsignedToken = `${header}.${claims}`;
  const tokenSignature = await webcrypto.subtle.sign("Ed25519", signingPair.privateKey, Buffer.from(unsignedToken));
  const token = `${unsignedToken}.${toBase64Url(tokenSignature)}`;
  const timestamp = String(now);
  const tokenHash = await webcrypto.subtle.digest("SHA-256", Buffer.from(token));
  const proofMessage = `bitchord-addon-proof/v1\naddon.example.test\n${timestamp}\n${toBase64Url(tokenHash)}`;
  const proofSignature = await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    devicePair.privateKey,
    Buffer.from(proofMessage)
  );
  return {
    "x-bitchord-token": token,
    "x-bitchord-proof": `v1.${timestamp}.${toBase64Url(proofSignature)}`
  };
}

async function invoke(path, { method = "GET", headers = {} } = {}) {
  const response = {
    statusCode: 200,
    headers: {},
    headersSent: false,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = String(value);
    },
    end(body = "") {
      this.body = String(body);
      this.headersSent = true;
    },
    destroy(error) {
      this.destroyed = true;
      this.destroyError = error;
    }
  };
  await handler({ method, url: path, headers: { host: "addon.example.test", ...headers } }, response);
  let body;
  try { body = JSON.parse(response.body || "{}"); } catch { body = response.body; }
  return { status: response.statusCode, headers: response.headers, body };
}

test("Vercel dynamic rewrites target the catch-all API function", () => {
  const config = JSON.parse(readFileSync(new URL("./vercel.json", import.meta.url), "utf8"));
  assert.ok(config.rewrites.some(route => route.source === "/stream/:id" && route.destination === "/api/stream/:id"));
  assert.ok(config.rewrites.some(route => route.source === "/extras/:path*" && route.destination === "/api/extras/:path*"));
});

test("manifest is public and advertises only supported quality selections", async () => {
  const response = await invoke("/manifest.json");
  assert.equal(response.status, 200);
  assert.equal(response.body.bitchordAuth, true);
  assert.deepEqual(response.body.settings[0].options.map(option => option.value), ["lossless", "aac"]);
  assert.match(response.body.settings[0].options[1].label, /High\/Low/);
});

test("search, stream, and extras reject unauthenticated requests with the BitChord challenge", async () => {
  for (const path of ["/search?q=signal", "/stream/ytm:abcdefghijk", "/extras/lyrics?id=abcdefghijk", "/api/stream/ytm:abcdefghijk", "/api/extras/lyrics?id=abcdefghijk"]) {
    const response = await invoke(path);
    assert.equal(response.status, 401);
    assert.match(response.headers["www-authenticate"], /^BitChord realm=/);
    assert.equal(response.body.code, "missing");
  }
  assert.equal(muzoCalls.length, 0);
});

test("search maps the existing Muzo response shape and keeps its key in the server request", async () => {
  resetMuzo();
  const response = await invoke("/search?q=signal", { headers: await bitChordHeaders() });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.tracks[0], {
    id: "ytm:abcdefghijk",
    title: "Midnight Signal",
    artist: "Example Artist",
    album: "Night Drive",
    duration: 242,
    artworkURL: "https://images.example.test/large.jpg"
  });
  assert.equal(muzoCalls[0].apiKey, "unit-test-api-key");
});

test("lossless uses its resolver path while high and low share the single AAC path", async () => {
  resetMuzo();
  const headers = await bitChordHeaders();
  const lossless = await invoke("/stream/ytm:abcdefghijk?quality=lossless", { headers });
  const high = await invoke("/stream/ytm:abcdefghijk?quality=high", { headers });
  const low = await invoke("/stream/ytm:abcdefghijk?quality=low", { headers });
  assert.equal(lossless.status, 200);
  assert.equal(high.status, 200);
  assert.equal(low.status, 200);
  assert.equal(high.body.codec, "aac");
  assert.equal(high.body.bitrate, 256000);
  assert.equal(high.body.sampleRate, 44100);
  assert.equal(high.body.manifest, undefined);
  assert.deepEqual(muzoCalls.map(call => call.pathname), [
    "/api/v1/stream/lossless",
    "/api/v1/stream/aac",
    "/api/v1/stream/aac"
  ]);
});

test("lossless fallback is retained and unknown quality values are rejected", async () => {
  resetMuzo();
  setMuzoResponse("/api/v1/stream/lossless", 404, { error: "not found" });
  const headers = await bitChordHeaders();
  const fallback = await invoke("/stream/ytm:abcdefghijk?quality=lossless", { headers });
  assert.equal(fallback.status, 200);
  assert.deepEqual(muzoCalls.map(call => call.pathname), ["/api/v1/stream/lossless", "/api/v1/stream"]);
  const invalid = await invoke("/stream/ytm:abcdefghijk?quality=ultra", { headers });
  assert.equal(invalid.status, 400);
});

test("media links hide upstream signatures and block private-network targets", async () => {
  resetMuzo();
  setMuzoResponse("/api/v1/stream/aac", 200, { streamUrl: "https://127.0.0.1/audio?sig=unit-private-signature" });
  const stream = await invoke("/stream/ytm:abcdefghijk?quality=aac", { headers: await bitChordHeaders() });
  assert.equal(stream.status, 200);
  const mediaUrl = new URL(stream.body.url);
  const token = mediaUrl.searchParams.get("token");
  assert.ok(token);
  assert.equal(token.includes("127.0.0.1"), false);
  assert.equal(token.includes("unit-private-signature"), false);
  const blocked = await invoke(`/media?token=${encodeURIComponent(token)}`);
  assert.equal(blocked.status, 502);
  const tokenParts = token.split(".");
  tokenParts[3] = `${tokenParts[3].startsWith("a") ? "b" : "a"}${tokenParts[3].slice(1)}`;
  const tamperedToken = tokenParts.join(".");
  const tampered = await invoke(`/media?token=${encodeURIComponent(tamperedToken)}`);
  assert.equal(tampered.status, 403);
});

test("invalid resolver URLs are rejected and non-GET methods are blocked before Muzo", async () => {
  resetMuzo();
  setMuzoResponse("/api/v1/stream/aac", 200, { streamUrl: "http://127.0.0.1/audio" });
  const invalidUrl = await invoke("/stream/ytm:abcdefghijk?quality=aac", { headers: await bitChordHeaders() });
  assert.equal(invalidUrl.status, 502);
  const method = await invoke("/search?q=signal", { method: "POST" });
  assert.equal(method.status, 405);
});
