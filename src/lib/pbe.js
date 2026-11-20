import md5 from "md5";
import DES from "des.js/lib/des/des.js";
import CBC from "des.js/lib/des/cbc.js";

// PBEWithMD5AndDES (PKCS#5 v1.5 / PBES1): PBKDF1 with MD5, then DES-CBC
// with PKCS#5 padding. The JCE derives the key and IV from the password and
// 8-byte salt, so both sides must agree on salt, iteration count and password
// byte handling. Java truncates each UTF-16 code unit to its low 8 bits.

const DesCbc = CBC.instantiate(DES);
const SALT_BYTES = 8;
const MAX_ITERATIONS = 10_000_000;

export class PbeError extends Error {
  constructor(code) {
    super(code);
    this.name = "PbeError";
    this.code = code;
  }
}

export function hexToBytes(text) {
  const clean = String(text).replace(/\s+/g, "");
  if (clean.length % 2 || /[^0-9a-f]/i.test(clean)) throw new PbeError("badEncoding");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64ToBytes(text) {
  const clean = String(text).replace(/\s+/g, "");
  try {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    throw new PbeError("badEncoding");
  }
}

export function bytesToB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function decodeBytes(text, encoding) {
  if (encoding === "base64") return b64ToBytes(text);
  if (encoding === "hex") return hexToBytes(text);
  return new TextEncoder().encode(text);
}

function encodeBytes(bytes, encoding) {
  return encoding === "base64" ? bytesToB64(bytes) : bytesToHex(bytes);
}

export function randomSaltHex() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(SALT_BYTES)));
}

function parseSalt(text, encoding) {
  let bytes;
  try {
    bytes = decodeBytes(text, encoding);
  } catch {
    throw new PbeError("badSalt");
  }
  if (bytes.length !== SALT_BYTES) throw new PbeError("badSalt");
  return bytes;
}

function parseIterations(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > MAX_ITERATIONS) throw new PbeError("badIterations");
  return n;
}

function passwordBytes(password, mode) {
  const text = String(password);
  if (mode === "utf8") return new TextEncoder().encode(text);
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

// PBKDF1: D_1 = MD5(password || salt), D_i = MD5(D_{i-1}); key = D_c[0..8],
// IV = D_c[8..16]. Iteration count 1 means a single MD5 pass.
function derive(password, salt, iterations, passwordMode) {
  const pwd = passwordBytes(password, passwordMode);
  let digest = new Uint8Array(pwd.length + salt.length);
  digest.set(pwd);
  digest.set(salt, pwd.length);
  for (let i = 0; i < iterations; i++) digest = hexToBytes(md5(digest));
  return { key: digest.slice(0, 8), iv: digest.slice(8, 16) };
}

function desCrypt(bytes, key, iv, type) {
  const cipher = DesCbc.create({ key, iv, type, padding: false });
  // des.js holds back the final block when decrypting, so both calls matter.
  const head = cipher.update(bytes);
  const tail = cipher.final();
  return Uint8Array.from([...head, ...(tail || [])]);
}

function pad(bytes) {
  const n = 8 - (bytes.length % 8);
  const out = new Uint8Array(bytes.length + n);
  out.set(bytes);
  out.fill(n, bytes.length);
  return out;
}

function unpad(bytes) {
  const n = bytes[bytes.length - 1];
  if (!n || n > 8 || n > bytes.length) throw new PbeError("badPad");
  for (let i = 1; i <= n; i++) {
    if (bytes[bytes.length - i] !== n) throw new PbeError("badPad");
  }
  return bytes.slice(0, bytes.length - n);
}

export function pbeEncrypt(plaintext, password, saltText, iterations, opts = {}) {
  const { passwordMode = "java", saltEncoding = "hex", outEncoding = "hex" } = opts;
  const salt = parseSalt(saltText, saltEncoding);
  const rounds = parseIterations(iterations);
  return encodeBytes(encryptBytes(plaintext, password, salt, rounds, passwordMode), outEncoding);
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

function decryptBytes(cipher, password, salt, rounds, passwordMode) {
  const { key, iv } = derive(password, salt, rounds, passwordMode);
  const plain = unpad(desCrypt(cipher, key, iv, "decrypt"));
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(plain);
  } catch {
    throw new PbeError("badUtf8");
  }
}

function encryptBytes(plaintext, password, salt, rounds, passwordMode) {
  const { key, iv } = derive(password, salt, rounds, passwordMode);
  const data = pad(new TextEncoder().encode(String(plaintext)));
  return desCrypt(data, key, iv, "encrypt");
}

// jasypt StandardPBEStringEncryptor default output: Base64(salt(8) || DES-CBC
// ciphertext) with a fresh random salt per message and 1000 KDF iterations.
export function jasyptEncrypt(plaintext, password, { passwordMode = "java", iterations = 1000 } = {}) {
  const rounds = parseIterations(iterations);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  return bytesToB64(concatBytes(salt, encryptBytes(plaintext, password, salt, rounds, passwordMode)));
}

export function jasyptDecrypt(cipherText, password, { passwordMode = "java", iterations = 1000 } = {}) {
  const raw = b64ToBytes(cipherText);
  if (raw.length <= SALT_BYTES || (raw.length - SALT_BYTES) % 8) throw new PbeError("badCipher");
  const rounds = parseIterations(iterations);
  const salt = raw.slice(0, SALT_BYTES);
  return decryptBytes(raw.slice(SALT_BYTES), password, salt, rounds, passwordMode);
}

export function pbeDecrypt(cipherText, password, saltText, iterations, opts = {}) {
  const { passwordMode = "java", saltEncoding = "hex", inEncoding = "hex" } = opts;
  const salt = parseSalt(saltText, saltEncoding);
  const rounds = parseIterations(iterations);
  let cipher;
  try {
    cipher = decodeBytes(cipherText, inEncoding);
  } catch {
    throw new PbeError("badEncoding");
  }
  if (!cipher.length || cipher.length % 8) throw new PbeError("badCipher");
  return decryptBytes(cipher, password, salt, rounds, passwordMode);
}