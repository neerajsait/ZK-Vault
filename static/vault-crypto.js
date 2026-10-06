/**
 * vault-crypto.js — Client-side crypto functions.
 */

import { argon2id } from 'hash-wasm';
// No-bundler fallback: replace the import above with a script tag —
//   <script src="/static/vendor/hash-wasm.umd.min.js"></script>
// — and replace every `argon2id(...)` call below with `hashwasm.argon2id(...)`.

// Cost parameters
const ARGON2_MEMORY_KB = 65536;   // 64 MB
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 1;     // hash-wasm's WASM build is single-threaded
const ARGON2_HASH_LEN = 32;       // 256-bit key

// Labels
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

// Key derivation functions

/**
 * @param {string} password
 * @param {string} saltB64
 * @returns {Promise<Uint8Array>}
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
 * @returns {string}
 */
export function generateSalt() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
}

// HKDF derivation

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
 * @param {Uint8Array} key1
 * @returns {Promise<string>}
 */
export async function deriveLoginVerifier(key1) {
  const v = await hkdf(key1, INFO_LOGIN_VERIFIER, 32);
  return bytesToBase64(v);
}

/**
 * @param {Uint8Array} key1
 * @param {Uint8Array} key2
 * @returns {Promise<Uint8Array>}
 */
export async function deriveSecretVaultKey(key1, key2) {
  return hkdf(concatBytes(key1, key2), INFO_SECRET_VAULT_KEY, 32);
}

/**
 * @param {Uint8Array} key1
 * @param {Uint8Array} key2
 * @returns {Promise<string>}
 */
export async function deriveSecretVerifier(key1, key2) {
  const v = await hkdf(concatBytes(key1, key2), INFO_SECRET_VERIFIER, 32);
  return bytesToBase64(v);
}

// Cipher routines

async function importAesKey(rawKeyBytes) {
  return crypto.subtle.importKey('raw', rawKeyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * @param {Uint8Array} rawKeyBytes
 * @param {string} plaintext
 * @returns {Promise<string>}
 */
export async function encryptString(rawKeyBytes, plaintext) {
  const key = await importAesKey(rawKeyBytes);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(plaintext));
  return bytesToBase64(concatBytes(iv, new Uint8Array(ciphertext)));
}

/**
 * @param {Uint8Array} rawKeyBytes
 * @param {string} base64Combined
 * @returns {Promise<string>}
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
 * @param {Uint8Array} rawKeyBytes
 * @param {Uint8Array} fileBytes
 * @returns {Promise<string>}
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

// Record helpers

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

// Validation helpers

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

// Key storage

const vaultKeys = {
  key1: null,       // Uint8Array | null — main vault key
  secretKey: null,  // Uint8Array | null — combined secret-vault key
};

export function setVaultKey1(rawKeyBytes) { vaultKeys.key1 = rawKeyBytes; }
export function getVaultKey1() { return vaultKeys.key1; }
export function setSecretVaultKey(rawKeyBytes) { vaultKeys.secretKey = rawKeyBytes; }
export function getSecretVaultKey() { return vaultKeys.secretKey; }

export function clearVaultKeys() {
  // Best-effort zeroing
  if (vaultKeys.key1) vaultKeys.key1.fill(0);
  if (vaultKeys.secretKey) vaultKeys.secretKey.fill(0);
  vaultKeys.key1 = null;
  vaultKeys.secretKey = null;
}

// Event listener
window.addEventListener('pagehide', clearVaultKeys);