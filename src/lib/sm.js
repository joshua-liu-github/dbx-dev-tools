// Chinese national cryptography (SM2/SM3/SM4) on top of sm-crypto.
// Long-term keys and hybrid envelope keys come from WebCrypto; sm-crypto
// supplies the curve/block primitives.
import smCrypto from "sm-crypto";

const { sm2, sm3, sm4 } = smCrypto;

const SM2_N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n;
const te = new TextEncoder();
const td = new TextDecoder();
const tdStrict = new TextDecoder("utf-8", { fatal: true });

export class SmError extends Error {
  constructor(code, detail) {
    super(code);
    this.name = "SmError";
    this.code = code;
    this.detail = detail;
  }
}

// ---- encoding helpers ----

export function hexToBytes(text) {
  const s = String(text).trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (!s) return new Uint8Array(0);
  if (s.length % 2 || !/^[0-9a-f]+$/i.test(s)) throw new SmError("badEncoding");
  return Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));
}

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64ToBytes(text) {
  try {
    return Uint8Array.from(atob(String(text).replace(/\s+/g, "")), (c) => c.charCodeAt(0));
  } catch {
    throw new SmError("badEncoding");
  }
}

export function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function decodeData(text, enc = "text") {
  if (enc === "hex") return hexToBytes(text);
  if (enc === "base64") return b64ToBytes(text);
  return te.encode(text);
}

export function encodeOutput(bytes, enc = "text") {
  if (enc === "hex") return bytesToHex(bytes);
  if (enc === "base64") return bytesToB64(bytes);
  try {
    return tdStrict.decode(bytes);
  } catch {
    throw new SmError("badUtf8");
  }
}

export function randomHex(nBytes = 16) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(nBytes)));
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---- minimal DER reader/writer (SM2 PEM only) ----

class DerReader {
  constructor(bytes, start = 0, end = bytes.length) {
    this.b = bytes;
    this.pos = start;
    this.end = end;
  }

  read() {
    if (this.pos >= this.end) return null;
    const tag = this.b[this.pos++];
    let len = this.b[this.pos++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (!n || n > 3 || this.pos + n > this.end) throw new SmError("badKey");
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | this.b[this.pos++];
    }
    if (this.pos + len > this.end) throw new SmError("badKey");
    const node = { tag, start: this.pos, end: this.pos + len };
    this.pos += len;
    return node;
  }

  sub(node) {
    return new DerReader(this.b, node.start, node.end);
  }

  bytes(node) {
    return this.b.slice(node.start, node.end);
  }
}

function derTlv(tag, content) {
  const len = content.length;
  let head;
  if (len < 0x80) head = Uint8Array.of(tag, len);
  else if (len < 0x100) head = Uint8Array.of(tag, 0x81, len);
  else head = Uint8Array.of(tag, 0x82, (len >> 8) & 0xff, len & 0xff);
  return concatBytes(head, content);
}

const derSeq = (content) => derTlv(0x30, content);
const derInt = (bytes) => derTlv(0x02, bytes[0] & 0x80 ? concatBytes(Uint8Array.of(0), bytes) : bytes);
const derOctet = (bytes) => derTlv(0x04, bytes);
const derBit = (bytes) => derTlv(0x03, concatBytes(Uint8Array.of(0), bytes));
const derOid = (bytes) => derTlv(0x06, bytes);
const derCtx = (n, content) => derTlv(0xa0 + n, content);

const OID_EC_PUBLIC_KEY = Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);
const OID_SM2 = Uint8Array.of(0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d);
const SM2_ALG_ID = derSeq(concatBytes(derOid(OID_EC_PUBLIC_KEY), derOid(OID_SM2)));

function pemBytes(text) {
  const m = /-----BEGIN ([^-]+)-----([\s\S]+?)-----END \1-----/.exec(text);
  if (!m) throw new SmError("badKey");
  if (/ENCRYPTED/.test(m[1])) throw new SmError("badKey");
  try {
    return { label: m[1].trim(), der: b64ToBytes(m[2]) };
  } catch {
    throw new SmError("badKey");
  }
}

function pemEncode(label, der) {
  const body = bytesToB64(der).match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

function normalizePrivate(bytes) {
  let hex = bytesToHex(bytes).replace(/^0+/, "");
  if (!hex || hex.length > 64) throw new SmError("badKey");
  hex = hex.padStart(64, "0");
  const d = BigInt(`0x${hex}`);
  if (d <= 0n || d >= SM2_N - 1n) throw new SmError("badKey");
  return hex;
}

function parseEcPrivate(der) {
  const top = new DerReader(der).read();
  if (!top || top.tag !== 0x30) throw new SmError("badKey");
  const seq = new DerReader(der, top.start, top.end);
  const version = seq.read();
  const key = seq.read();
  if (!version || version.tag !== 0x02 || !key || key.tag !== 0x04) throw new SmError("badKey");
  return normalizePrivate(seq.bytes(key));
}

function parsePrivateDer(der) {
  const top = new DerReader(der).read();
  if (!top || top.tag !== 0x30) throw new SmError("badKey");
  const seq = new DerReader(der, top.start, top.end);
  const first = seq.read();
  if (!first || first.tag !== 0x02) throw new SmError("badKey");
  const second = seq.read();
  if (!second) throw new SmError("badKey");
  if (second.tag === 0x04) return normalizePrivate(seq.bytes(second)); // SEC1 EC PRIVATE KEY
  if (second.tag !== 0x30) throw new SmError("badKey");
  const inner = seq.read();
  if (!inner || inner.tag !== 0x04) throw new SmError("badKey");
  return parseEcPrivate(seq.bytes(inner));
}

function normalizePublic(bytes) {
  let hex = bytesToHex(bytes);
  if (hex.length === 128) hex = `04${hex}`;
  else if (hex.length === 64) hex = `04${hex}`;
  else if (!((hex.length === 130 && hex.startsWith("04")) || (hex.length === 66 && /^0[23]/.test(hex)))) {
    throw new SmError("badKey");
  }
  if (!sm2.verifyPublicKey(hex)) throw new SmError("badKey");
  return hex;
}

function parsePublicDer(der) {
  const top = new DerReader(der).read();
  if (!top || top.tag !== 0x30) throw new SmError("badKey");
  const seq = new DerReader(der, top.start, top.end);
  const alg = seq.read();
  const bit = seq.read();
  if (!alg || alg.tag !== 0x30 || !bit || bit.tag !== 0x03) throw new SmError("badKey");
  const content = seq.bytes(bit);
  if (!content.length || content[0] !== 0) throw new SmError("badKey");
  return normalizePublic(content.subarray(1));
}

function hasPem(text) {
  return /-----BEGIN [^-]+-----/.test(text);
}

export function parseSm2PrivateKey(text) {
  const raw = String(text ?? "").trim();
  if (!raw) throw new SmError("badKey");
  if (hasPem(raw)) {
    const { label, der } = pemBytes(raw);
    if (/PUBLIC/i.test(label)) throw new SmError("needPriv");
    return { hex: parsePrivateDer(der), format: "pem" };
  }
  const compact = raw.replace(/^0x/i, "").replace(/\s+/g, "");
  if (/^[0-9a-f]+$/i.test(compact) && compact.length <= 64) {
    return { hex: normalizePrivate(hexToBytes(compact)), format: "hex" };
  }
  try {
    const bytes = b64ToBytes(raw);
    // PKCS#8 / SEC1 DER is much longer than a raw 32-byte scalar. Raw
    // Base64 scalars are still accepted for older tool output.
    if (bytes.length > 64 && bytes[0] === 0x30) return { hex: parsePrivateDer(bytes), format: "base64" };
    return { hex: normalizePrivate(bytes), format: "base64" };
  } catch {
    throw new SmError("badKey");
  }
}

export function parseSm2PublicKey(text) {
  const raw = String(text ?? "").trim();
  if (!raw) throw new SmError("badKey");
  if (hasPem(raw)) {
    const { label, der } = pemBytes(raw);
    if (/PRIVATE/i.test(label)) throw new SmError("needPub");
    return { hex: parsePublicDer(der), format: "pem" };
  }
  const compact = raw.replace(/^0x/i, "").replace(/\s+/g, "");
  if (/^[0-9a-f]+$/i.test(compact) && [64, 66, 128, 130].includes(compact.length)) {
    return { hex: normalizePublic(hexToBytes(compact)), format: "hex" };
  }
  try {
    const bytes = b64ToBytes(raw);
    // SPKI DER is longer than a raw 64/65-byte point; keep accepting the
    // latter for older tool output.
    if (bytes.length > 66 && bytes[0] === 0x30) return { hex: parsePublicDer(bytes), format: "base64" };
    return { hex: normalizePublic(bytes), format: "base64" };
  } catch {
    throw new SmError("badKey");
  }
}

function privateDer(privHex) {
  const pubPoint = hexToBytes(sm2.getPublicKeyFromPrivateKey(privHex));
  const ecPrivate = derSeq(concatBytes(
    derInt(Uint8Array.of(1)),
    derOctet(hexToBytes(privHex)),
    derCtx(0, derOid(OID_SM2)),
    derCtx(1, derBit(pubPoint)),
  ));
  return derSeq(concatBytes(derInt(Uint8Array.of(0)), SM2_ALG_ID, derOctet(ecPrivate)));
}

function publicDer(pubHex) {
  return derSeq(concatBytes(SM2_ALG_ID, derBit(hexToBytes(pubHex))));
}

function privatePem(privHex) {
  return pemEncode("PRIVATE KEY", privateDer(privHex));
}

function publicPem(pubHex) {
  return pemEncode("PUBLIC KEY", publicDer(pubHex));
}

export function formatSm2PrivateKey(privHex, format = "hex") {
  if (format === "pem") return privatePem(privHex);
  // Base64 is PKCS#8 DER (the PEM body): what Java/BouncyCastle key APIs take.
  if (format === "base64") return bytesToB64(privateDer(privHex));
  return privHex;
}

export function formatSm2PublicKey(pubHex, format = "hex") {
  if (format === "pem") return publicPem(pubHex);
  // Base64 is SPKI DER (the PEM body) for Java/BouncyCastle interop.
  if (format === "base64") return bytesToB64(publicDer(pubHex));
  return pubHex;
}

export function sm2KeyToPem(privHex) {
  return { privatePem: privatePem(privHex), publicPem: publicPem(sm2.getPublicKeyFromPrivateKey(privHex)) };
}

export function sm2GenerateKeyPair() {
  let priv;
  do {
    priv = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  } while (BigInt(`0x${priv}`) <= 0n || BigInt(`0x${priv}`) >= SM2_N - 1n);
  return { privateKey: priv, publicKey: sm2.getPublicKeyFromPrivateKey(priv) };
}

// ---- SM2 operations ----

const cipherModeValue = (mode) => (mode === 0 || mode === "C1C2C3" ? 0 : 1);

export function sm2Encrypt(msg, publicKeyText, { cipherMode = 1, outEncoding = "hex", c1Prefix = false } = {}) {
  if (!msg) throw new SmError("badPayload");
  const { hex: pub } = parseSm2PublicKey(publicKeyText);
  let hex;
  try {
    hex = sm2.doEncrypt(msg, pub, cipherModeValue(cipherMode));
  } catch (e) {
    throw new SmError("failed", e?.message);
  }
  if (!hex) throw new SmError("failed");
  if (c1Prefix) hex = `04${hex}`;
  return encodeOutput(hexToBytes(hex), outEncoding);
}

function sm2DecryptBytes(cipherHex, privHex, mode) {
  let out = sm2.doDecrypt(cipherHex, privHex, mode, { output: "array" });
  if ((!out || !out.length) && cipherHex.startsWith("04") && cipherHex.length > 130) {
    out = sm2.doDecrypt(cipherHex.slice(2), privHex, mode, { output: "array" });
  }
  return out && out.length ? Uint8Array.from(out) : null;
}

export function sm2Decrypt(cipherText, privateKeyText, { cipherMode = 1, inEncoding = "hex", outEncoding = "text" } = {}) {
  const { hex: priv } = parseSm2PrivateKey(privateKeyText);
  let hex;
  try {
    hex = bytesToHex(decodeData(cipherText, inEncoding));
  } catch (e) {
    throw e instanceof SmError ? e : new SmError("badEncoding");
  }
  if (!hex) throw new SmError("badPayload");
  const out = sm2DecryptBytes(hex, priv, cipherModeValue(cipherMode));
  if (!out) throw new SmError("badKey");
  return encodeOutput(out, outEncoding);
}

export function sm2Sign(msg, privateKeyText, { userId = "", sigFormat = "raw" } = {}) {
  const { hex: priv } = parseSm2PrivateKey(privateKeyText);
  const opts = { hash: true, publicKey: sm2.getPublicKeyFromPrivateKey(priv), der: sigFormat !== "raw" };
  if (userId) opts.userId = userId;
  let sig;
  try {
    sig = sm2.doSignature(msg, priv, opts);
  } catch (e) {
    throw new SmError("failed", e?.message);
  }
  if (!sig) throw new SmError("failed");
  return sigFormat === "der-b64" ? bytesToB64(hexToBytes(sig)) : sig;
}

export function sm2Verify(msg, signatureText, publicKeyText, { userId = "", sigFormat = "raw" } = {}) {
  const { hex: pub } = parseSm2PublicKey(publicKeyText);
  let sig;
  try {
    if (sigFormat === "der-b64") sig = bytesToHex(b64ToBytes(signatureText));
    else {
      sig = String(signatureText).trim().replace(/^0x/i, "").replace(/\s+/g, "").toLowerCase();
      if (!/^[0-9a-f]+$/.test(sig) || (sigFormat === "raw" && sig.length !== 128)) {
        throw new SmError("badSignature");
      }
    }
  } catch {
    throw new SmError("badSignature");
  }
  const opts = { hash: true, der: sigFormat !== "raw" };
  if (userId) opts.userId = userId;
  return sm2.doVerifySignature(msg, sig, pub, opts);
}

// ---- SM3 ----

export function sm3Hash(input, { inputEncoding = "text", outEncoding = "hex" } = {}) {
  const digest = sm3(decodeData(input, inputEncoding));
  return outEncoding === "base64" ? encodeOutput(hexToBytes(digest), "base64") : digest;
}

export function sm3Hmac(input, key, { inputEncoding = "text", keyEncoding = "hex", outEncoding = "hex" } = {}) {
  const keyBytes = decodeData(key, keyEncoding);
  if (!keyBytes.length) throw new SmError("badKey");
  let digest;
  try {
    digest = sm3(decodeData(input, inputEncoding), { mode: "hmac", key: keyBytes });
  } catch (e) {
    throw new SmError("failed", e?.message);
  }
  return outEncoding === "base64" ? encodeOutput(hexToBytes(digest), "base64") : digest;
}

// ---- SM4 ----

function sm4KeyBytes(keyText, enc) {
  const key = decodeData(keyText, enc);
  if (key.length !== 16) throw new SmError("badKey");
  return key;
}

function sm4IvBytes(ivText, enc) {
  const iv = decodeData(ivText, enc);
  if (iv.length !== 16) throw new SmError("badIv");
  return iv;
}

function sm4Options(mode, iv, padding) {
  const opts = { output: "array", padding: padding === "none" ? "none" : "pkcs#7" };
  if (mode === "cbc") {
    opts.mode = "cbc";
    opts.iv = [...iv];
  }
  return opts;
}

export function sm4Encrypt(input, keyText, {
  inputEncoding = "text", keyEncoding = "hex", mode = "cbc", iv = "", ivEncoding = "hex",
  padding = "pkcs7", outputEncoding = "hex",
} = {}) {
  const key = sm4KeyBytes(keyText, keyEncoding);
  const data = decodeData(input, inputEncoding);
  if (padding === "none" && (!data.length || data.length % 16)) throw new SmError("padMultiple");
  const ivBytes = mode === "cbc" ? sm4IvBytes(iv, ivEncoding) : null;
  let out;
  try {
    out = sm4.encrypt([...data], [...key], sm4Options(mode, ivBytes, padding));
  } catch (e) {
    throw new SmError("failed", e?.message);
  }
  return encodeOutput(Uint8Array.from(out), outputEncoding);
}

export function sm4Decrypt(input, keyText, {
  inputEncoding = "hex", keyEncoding = "hex", mode = "cbc", iv = "", ivEncoding = "hex",
  padding = "pkcs7", outputEncoding = "text",
} = {}) {
  const key = sm4KeyBytes(keyText, keyEncoding);
  const data = decodeData(input, inputEncoding);
  if (!data.length) throw new SmError("badPayload");
  if (data.length % 16) throw new SmError(padding === "none" ? "padMultiple" : "badPayload");
  const ivBytes = mode === "cbc" ? sm4IvBytes(iv, ivEncoding) : null;
  let out;
  try {
    out = sm4.decrypt([...data], [...key], sm4Options(mode, ivBytes, padding));
  } catch (e) {
    throw new SmError("badPad", e?.message);
  }
  return encodeOutput(Uint8Array.from(out), outputEncoding);
}

// ---- SM2 + SM4 hybrid envelope ----

const HYBRID_ALG = "SM2-SM4";
const HYBRID_MAC_LABEL = te.encode("SM2-SM4|v1|");

function hmacBytes(key, data) {
  return hexToBytes(sm3(data, { mode: "hmac", key }));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function sm2sm4Encrypt(plaintext, publicKeyText, { cipherMode = 1, fieldEncoding = "base64", pretty = true } = {}) {
  const { hex: pub } = parseSm2PublicKey(publicKeyText);
  const enc = fieldEncoding === "hex" ? "hex" : "base64";
  const mode = cipherModeValue(cipherMode);
  const sm4Key = crypto.getRandomValues(new Uint8Array(16));
  const macKey = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  let data;
  try {
    data = Uint8Array.from(sm4.encrypt([...te.encode(plaintext)], [...sm4Key], sm4Options("cbc", iv, "pkcs7")));
  } catch (e) {
    throw new SmError("failed", e?.message);
  }
  const keyMaterial = concatBytes(sm4Key, macKey);
  let wrapped;
  try {
    wrapped = sm2.doEncrypt([...keyMaterial], pub, mode);
  } catch (e) {
    throw new SmError("failed", e?.message);
  }
  if (!wrapped) throw new SmError("failed");
  const tag = hmacBytes(macKey, concatBytes(HYBRID_MAC_LABEL, iv, data));
  const envelope = {
    v: 1,
    alg: HYBRID_ALG,
    sm4: "CBC",
    pad: "PKCS7",
    cm: mode === 0 ? "C1C2C3" : "C1C3C2",
    enc,
    iv: encodeOutput(iv, enc),
    key: encodeOutput(hexToBytes(wrapped), enc),
    data: encodeOutput(data, enc),
    tag: encodeOutput(tag, enc),
  };
  return JSON.stringify(envelope, null, pretty ? 2 : 0);
}

export function sm2sm4Decrypt(envelopeText, privateKeyText) {
  let env;
  try {
    env = JSON.parse(envelopeText);
  } catch {
    throw new SmError("badPayload");
  }
  if (!env || typeof env !== "object" || env.v !== 1 || env.alg !== HYBRID_ALG) throw new SmError("badPayload");
  if (env.sm4 !== "CBC" || env.pad !== "PKCS7") throw new SmError("badPayload");
  const enc = env.enc === "hex" ? "hex" : env.enc === "base64" ? "base64" : null;
  if (!enc || (env.cm !== "C1C3C2" && env.cm !== "C1C2C3")) throw new SmError("badPayload");
  if (typeof env.iv !== "string" || typeof env.key !== "string" || typeof env.data !== "string" || typeof env.tag !== "string") {
    throw new SmError("badPayload");
  }
  const iv = decodeData(env.iv, enc);
  const wrapped = decodeData(env.key, enc);
  const data = decodeData(env.data, enc);
  const tag = decodeData(env.tag, enc);
  if (iv.length !== 16 || tag.length !== 32 || !data.length || data.length % 16) throw new SmError("badPayload");
  const { hex: priv } = parseSm2PrivateKey(privateKeyText);
  const keyMaterial = sm2DecryptBytes(bytesToHex(wrapped), priv, cipherModeValue(env.cm));
  if (!keyMaterial || keyMaterial.length !== 32) throw new SmError("badKey");
  const expected = hmacBytes(keyMaterial.subarray(16), concatBytes(HYBRID_MAC_LABEL, iv, data));
  if (!timingSafeEqual(expected, tag)) throw new SmError("macMismatch");
  let out;
  try {
    out = Uint8Array.from(sm4.decrypt([...data], [...keyMaterial.subarray(0, 16)], sm4Options("cbc", iv, "pkcs7")));
  } catch (e) {
    throw new SmError("badPad", e?.message);
  }
  return encodeOutput(out, "text");
}
