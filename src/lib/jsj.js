// Helpers for the JSJ request protocols: Sm-Token request signing,
// SM2 anti-replay params, and SM2+SM4 encrypted-body envelopes.
import {
  SmError, sm2Encrypt, sm2Decrypt, sm3Hash, sm4Encrypt, sm4Decrypt, randomHex,
} from "./sm.js";

const SIGN_RESERVED = new Set(["nonce", "timestamp", "sign", "token"]);

function splitRequestUrl(text) {
  const raw = String(text ?? "").trim();
  if (!raw) throw new SmError("badUrl");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      return { path: u.pathname, query: [...u.searchParams.entries()] };
    } catch {
      throw new SmError("badUrl");
    }
  }
  const hash = raw.indexOf("#");
  const noHash = hash === -1 ? raw : raw.slice(0, hash);
  const q = noHash.indexOf("?");
  if (q === -1) return { path: noHash, query: [] };
  return {
    path: noHash.slice(0, q),
    query: [...new URLSearchParams(noHash.slice(q + 1)).entries()],
  };
}

function parseParamLines(text) {
  const raw = String(text ?? "").trim();
  if (!raw) return [];
  if (raw.startsWith("{")) {
    let obj;
    try {
      obj = JSON.parse(raw);
    } catch {
      throw new SmError("badParams");
    }
    return Object.entries(obj).map(([k, v]) => [
      k,
      Array.isArray(v) ? (v.length ? String(v[0]) : "") : v == null ? "" : String(v),
    ]);
  }
  if (!raw.includes("\n") && raw.includes("&")) {
    return [...new URLSearchParams(raw)];
  }
  const out = [];
  for (const line of raw.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    const i = s.indexOf("=");
    if (i === -1) continue;
    out.push([s.slice(0, i).trim(), s.slice(i + 1).trim()]);
  }
  return out;
}

// Request signing: params are sorted by key, the first non-empty value is
// used, and nonce/timestamp/sign/token are dropped.
export function buildSmToken({ method = "POST", url, params = "", body = "" } = {}) {
  const { path, query } = splitRequestUrl(url);
  const merged = new Map();
  for (const [k, v] of [...query, ...parseParamLines(params)]) {
    if (!merged.has(k)) merged.set(k, v);
  }
  const keys = [...merged.keys()]
    .filter((k) => !SIGN_RESERVED.has(k) && merged.get(k) !== "")
    .sort();
  let canonical = "";
  for (const k of keys) canonical += `${k}=${merged.get(k)}&`;
  if (String(method).toUpperCase() !== "GET" && body) canonical += `requestBody=${body}&`;
  canonical += `signReqUrl=${path}`;
  return { canonical, sign: sm3Hash(canonical) };
}

function uuidv4() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// Anti-replay signing: sign is SM2(publicKey, Base64) over compact JSON
// {"t":ms,"n":uuid[,"u":name]}.
export function buildReplayParams({ publicKey, timestamp = "", nonce = "", username = "" } = {}) {
  const t = String(timestamp ?? "").trim() || String(Date.now());
  if (!/^\d+$/.test(t)) throw new SmError("badTimestamp");
  const n = String(nonce ?? "").trim() || uuidv4();
  const payload = { t, n };
  const u = String(username ?? "").trim();
  if (u) payload.u = u;
  const json = JSON.stringify(payload);
  const sign = sm2Encrypt(json, publicKey, { cipherMode: 1, outEncoding: "base64", c1Prefix: true });
  return {
    timestamp: t,
    nonce: n,
    payload: json,
    sign,
    signEncoded: encodeURIComponent(sign),
  };
}

function extractEncData(text) {
  const raw = String(text ?? "").trim();
  if (!raw) throw new SmError("badPayload");
  if (raw.startsWith("{")) {
    try {
      const obj = JSON.parse(raw);
      if (obj && typeof obj.encData === "string") return obj.encData;
    } catch {
      throw new SmError("badPayload");
    }
  }
  return raw;
}

// Mixed encryption: a random SM4 key (hex text) is SM2-wrapped into
// cr-ca-key and the payload is SM4-CBC/PKCS7 encrypted with IV = key,
// then Base64-encoded into encData.
export function jsjEncrypt({ plaintext, publicKey } = {}) {
  if (!plaintext) throw new SmError("badPayload");
  const sm4KeyHex = randomHex(16);
  const eck = sm2Encrypt(sm4KeyHex, publicKey, { cipherMode: 1, outEncoding: "base64", c1Prefix: true });
  const encData = sm4Encrypt(plaintext, sm4KeyHex, {
    inputEncoding: "text", keyEncoding: "hex", mode: "cbc",
    iv: sm4KeyHex, ivEncoding: "hex", padding: "pkcs7", outputEncoding: "base64",
  });
  return { sm4KeyHex, eck, encData, body: JSON.stringify({ encData }) };
}

export function jsjDecrypt({ privateKey, eck, encData } = {}) {
  const keyText = String(eck ?? "").trim();
  if (!keyText) throw new SmError("badKey");
  const sm4KeyHex = sm2Decrypt(keyText, privateKey, { cipherMode: 1, inEncoding: "base64", outEncoding: "text" }).trim();
  if (!/^[0-9a-f]{32}$/i.test(sm4KeyHex)) throw new SmError("badKey");
  const plaintext = sm4Decrypt(extractEncData(encData), sm4KeyHex, {
    inputEncoding: "base64", keyEncoding: "hex", mode: "cbc",
    iv: sm4KeyHex, ivEncoding: "hex", padding: "pkcs7", outputEncoding: "text",
  });
  return { sm4KeyHex: sm4KeyHex.toLowerCase(), plaintext };
}

export { uuidv4 };
