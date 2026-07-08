/**
 * crypto.js — Client-side zero-knowledge crypto for the vault.
 *
 * Everything here runs in the browser. The vault password and secret code
 * NEVER leave this file as plaintext, and the derived encryption keys
 * (key1, key2, secret vault key) never leave this file at all — only
 * HKDF-derived "verifiers" (one-way, non-reversible back to the key) are
 * sent to the server.
 *
 * Dependencies:
 *   - hash-wasm (Argon2id) — SELF-HOST this under your own /static/vendor/.
 *     The app's CSP only allows script-src 'self' (+ nonce, +
 *     wasm-unsafe-eval for the WASM module itself). Loading from a public
 *     CDN will be blocked by CSP — and even if you relaxed the policy,
 *     pulling crypto dependencies from a third-party CDN is a supply-chain
 *     risk you don't want in a security product.
 *   - Web Crypto API (crypto.subtle) — built into every modern browser,
 *     used for AES-GCM and HKDF. No dependency needed.
 *
 * Setup (one-time, before self-hosting):
 *   npm install hash-wasm
 *   // then either bundle this file with your existing bundler (webpack/
 *   // vite/esbuild), or copy the UMD build to static/vendor/ and use the
 *   // global-script fallback noted below.
 */

import { argon2id } from 'hash-wasm';
// No-bundler fallback: replace the import above with a script tag —
//   <script src="/static/vendor/hash-wasm.umd.min.js"></script>
// — and replace every `argon2id(...)` call below with `hashwasm.argon2id(...)`.

// ---------------------------------------------------------------------
// Tunable Argon2id cost. The old server-side cost (128MB / time=4) assumed
// a beefy server CPU. In a browser tab — especially on a mid-range phone —
// that can hang for many seconds or exhaust available WASM memory. Tuned
// down here; raise these if your users are mostly desktop and you want
// more brute-force resistance per unlock attempt.
const ARGON2_MEMORY_KB = 65536;   // 64 MB
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 1;     // hash-wasm's WASM build is single-threaded
const ARGON2_HASH_LEN = 32;       // 256-bit key

// HKDF "info" labels — these provide cryptographic domain separation so
// the same input key material never produces the same output for two
// different purposes (e.g. an encryption key vs. a value sent to the server).
const INFO_LOGIN_VERIFIER = 'login-verifier';
const INFO_SECRET_VAULT_KEY = 'secret-vault-key';
const INFO_SECRET_VERIFIER = 'secret-vault-verifier';

// ---------------------------------------------------------------------
// Encoding helpers

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

function utf8(str) {
  return new TextEncoder().encode(str);
}

// ---------------------------------------------------------------------
// Argon2id key derivation (the expensive step — runs once per
// unlock/signup/password-change, never per record)

/**
 * Derive a 32-byte key from a password and a base64-encoded salt.
 * @param {string} password
 * @param {string} saltB64 - base64-encoded salt, as returned by the server
 * @returns {Promise<Uint8Array>} 32-byte raw key
 */
export async function deriveKeyFromPassword(password, saltB64) {
  const salt = base64ToBytes(saltB64);
  const hash = await argon2id({
    password,
    salt,
    parallelism: ARGON2_PARALLELISM,
    iterations: ARGON2_ITERATIONS,
    memorySize: ARGON2_MEMORY_KB,
    hashLength: ARGON2_HASH_LEN,
    outputType: 'binary',
  });
  return new Uint8Array(hash);
}

/**
 * Generate a fresh random salt for signup / password-change.
 * Salts are not secret — this is safe to send to the server in the clear.
 */
export function generateSalt() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
}

// ---------------------------------------------------------------------
// HKDF — derives non-reversible "verifiers" sent to the server, and the
// secret vault's combined encryption key.

async function hkdf(ikm, infoStr, length = 32) {
  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: utf8(infoStr),
    },
    baseKey,
    length * 8
  );
  return new Uint8Array(bits);
}

/**
 * Derive the value sent to the server to prove knowledge of the vault
 * password, WITHOUT revealing key1 itself. The server only ever sees this
 * verifier — it cannot reverse it back into key1, and key1 is what
 * actually encrypts your data, so the server can never decrypt anything.
 */
export async function deriveLoginVerifier(key1) {
  const v = await hkdf(key1, INFO_LOGIN_VERIFIER, 32);
  return bytesToBase64(v);
}

/**
 * Derive the secret vault's combined encryption key from key1 + key2.
 * This key never leaves the browser.
 */
export async function deriveSecretVaultKey(key1, key2) {
  return hkdf(concatBytes(key1, key2), INFO_SECRET_VAULT_KEY, 32);
}

/**
 * Derive the value sent to the server to prove knowledge of BOTH the
 * vault password and the secret code, without revealing either key.
 */
export async function deriveSecretVerifier(key1, key2) {
  const v = await hkdf(concatBytes(key1, key2), INFO_SECRET_VERIFIER, 32);
  return bytesToBase64(v);
}

// ---------------------------------------------------------------------
// AES-GCM encryption — this is what actually protects the data. Keys are
// raw 32-byte arrays, imported as CryptoKey objects on demand, never
// persisted anywhere (no localStorage, no IndexedDB — just an in-memory
// variable that dies when the tab closes or refreshes).

async function importAesKey(rawKeyBytes) {
  return crypto.subtle.importKey('raw', rawKeyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Encrypt a UTF-8 string (typically JSON.stringify of a record) with a
 * raw 32-byte key. Returns base64(iv || ciphertext) — IV is the first
 * 12 bytes, matching the format the original server-side encrypt_aes_gcm()
 * used, so existing tooling/inspection scripts still parse it the same way.
 */
export async function encryptString(rawKeyBytes, plaintext) {
  const key = await importAesKey(rawKeyBytes);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(plaintext));
  return bytesToBase64(concatBytes(iv, new Uint8Array(ciphertext)));
}

/**
 * Decrypt base64(iv || ciphertext) back into a UTF-8 string.
 * Throws if the key is wrong or the data was tampered with — AES-GCM's
 * built-in authentication tag catches that automatically.
 */
export async function decryptString(rawKeyBytes, base64Combined) {
  const key = await importAesKey(rawKeyBytes);
  const combined = base64ToBytes(base64Combined);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

/**
 * Encrypt a File/Blob's raw bytes — used for photo/video attachments.
 * The file's bytes are encrypted client-side before being embedded
 * (base64) inside the record's JSON payload.
 */
export async function encryptFileBytes(rawKeyBytes, fileBytes) {
  const key = await importAesKey(rawKeyBytes);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, fileBytes);
  return bytesToBase64(concatBytes(iv, new Uint8Array(ciphertext)));
}

export async function decryptFileBytes(rawKeyBytes, base64Combined) {
  const key = await importAesKey(rawKeyBytes);
  const combined = base64ToBytes(base64Combined);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------
// Record-level helpers — encrypt/decrypt a whole record object (title,
// notes, files[]) in one shot, matching the JSON envelope shape the old
// server-side code used to build before encryption moved client-side.

/**
 * @param {Uint8Array} rawKeyBytes
 * @param {{title?: string, notes?: string, files?: Array<{filename: string, mime_type: string, bytes: Uint8Array}>}} record
 * @returns {Promise<string>} base64 ciphertext ready to POST as { ciphertext }
 */
export async function encryptRecord(rawKeyBytes, record) {
  const files = await Promise.all((record.files || []).map(async (f) => {
    const rawBytes = f.bytes || f.decryptedBytes || new Uint8Array(0);
    return {
      filename: f.filename,
      mime_type: f.mime_type,
      size: rawBytes.length,
      data: await encryptFileBytes(rawKeyBytes, rawBytes),
    };
  }));
  const payload = JSON.stringify({ title: record.title || '', notes: record.notes || '', files });
  return encryptString(rawKeyBytes, payload);
}

/**
 * @returns {Promise<{title: string, notes: string, files: Array<{filename: string, mime_type: string, size: number, decryptedBytes: Uint8Array}>}>}
 */
export async function decryptRecord(rawKeyBytes, base64Ciphertext) {
  const json = await decryptString(rawKeyBytes, base64Ciphertext);
  const data = JSON.parse(json);
  const files = await Promise.all((data.files || []).map(async (f) => ({
    filename: f.filename,
    mime_type: f.mime_type,
    size: f.size,
    decryptedBytes: await decryptFileBytes(rawKeyBytes, f.data),
  })));
  return { title: data.title || '', notes: data.notes || '', files };
}

// ---------------------------------------------------------------------
// Client-side validation — the server can no longer see the password to
// validate it, so this MUST run before deriveKeyFromPassword on signup
// and password-change. Mirrors the original server-side regex checks.

export function validateVaultPassword(password) {
  const errors = [];
  if (!password || typeof password !== 'string') {
    return ['Password is required.'];
  }
  if (password.length < 12) errors.push('At least 12 characters.');
  if (!/[A-Z]/.test(password)) errors.push('At least one uppercase letter.');
  if (!/[a-z]/.test(password)) errors.push('At least one lowercase letter.');
  if (!/[0-9]/.test(password)) errors.push('At least one digit.');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('At least one special character.');
  return errors; // empty array = valid
}

export function validateSecretCode(code) {
  const errors = [];
  if (!/^[A-Z2-7]{12,}$/.test(code.toUpperCase())) {
    errors.push('At least 12 characters, A-Z and 2-7 only (Base32).');
  }
  return errors;
}

// ---------------------------------------------------------------------
// In-memory key store — this IS the entire "vault unlocked" state on the
// client. Deliberately no persistence layer: no localStorage, no
// sessionStorage, no IndexedDB. Closing the tab or refreshing destroys
// these keys; the user re-derives them by re-entering their password.
// That's the point — it's what makes this zero-knowledge instead of
// "encryption with a key sitting in a stale tab forever."

const vaultKeys = {
  key1: null,       // Uint8Array | null — main vault key
  secretKey: null,  // Uint8Array | null — combined secret-vault key
};

export function setVaultKey1(rawKeyBytes) { vaultKeys.key1 = rawKeyBytes; }
export function getVaultKey1() { return vaultKeys.key1; }
export function setSecretVaultKey(rawKeyBytes) { vaultKeys.secretKey = rawKeyBytes; }
export function getSecretVaultKey() { return vaultKeys.secretKey; }

export function clearVaultKeys() {
  // Best-effort zeroing — JS doesn't guarantee immediate memory wipe, but
  // this drops the only reference so the bytes are eligible for GC.
  if (vaultKeys.key1) vaultKeys.key1.fill(0);
  if (vaultKeys.secretKey) vaultKeys.secretKey.fill(0);
  vaultKeys.key1 = null;
  vaultKeys.secretKey = null;
}

// Clear keys automatically when the tab is closed, refreshed, or navigated away.
window.addEventListener('pagehide', clearVaultKeys);