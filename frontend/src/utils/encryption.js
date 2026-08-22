/**
 * CipherDrop — client-side cryptography.
 *
 * AES-256-GCM over the native Web Crypto API. No third-party crypto, no React,
 * no network calls, no persistence: every function here is pure input -> output.
 *
 * INVARIANT: the AES key produced by generateKey() and consumed by the
 * encrypt/decrypt functions must never be sent to the backend. It travels only
 * inside the URL fragment (`/s/{id}#AES_KEY`), which browsers do not include in
 * HTTP requests. Nothing in this module writes to localStorage, sessionStorage,
 * cookies, or any module-level mutable state.
 *
 * Wire formats:
 *   - key             base64url, unpadded (URL-fragment safe)
 *   - encryptedContent / iv   standard base64 (matches the frozen REST API)
 *
 * The GCM authentication tag (128-bit) is appended to the ciphertext by the
 * Web Crypto API, so `encryptedContent` is ciphertext||tag and needs no
 * separate field.
 */

const ALGORITHM = 'AES-GCM';
const KEY_LENGTH_BITS = 256;
const KEY_LENGTH_BYTES = KEY_LENGTH_BITS / 8;
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BITS = 128;
const KEY_USAGES = ['encrypt', 'decrypt'];

/** Base class for every error this module raises deliberately. */
export class CipherDropCryptoError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** The runtime has no Web Crypto (non-secure context, or an unsupported browser). */
export class CryptoUnavailableError extends CipherDropCryptoError {}

/** The supplied key string is absent, not Base64, or not 32 bytes long. */
export class InvalidKeyError extends CipherDropCryptoError {}

/**
 * Decryption failed. AES-GCM cannot distinguish a wrong key from a tampered
 * ciphertext or IV — both surface as the same authentication failure — so this
 * single error covers all three cases on purpose.
 */
export class DecryptionError extends CipherDropCryptoError {}

function getCrypto() {
  const webcrypto = globalThis.crypto;
  if (!webcrypto || !webcrypto.subtle) {
    throw new CryptoUnavailableError(
      'Web Crypto is unavailable. CipherDrop requires a secure context (HTTPS or localhost).',
    );
  }
  return webcrypto;
}

// --- Base64 helpers -------------------------------------------------------
// btoa/atob operate on binary strings, so conversion runs in chunks to avoid
// blowing the argument limit of String.fromCharCode on large secrets.

const BINARY_STRING_CHUNK = 0x8000;

/** Uint8Array -> standard Base64 (padded, `+` and `/`). */
export function bytesToBase64(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('bytesToBase64 expects a Uint8Array.');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i += BINARY_STRING_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + BINARY_STRING_CHUNK));
  }
  return btoa(binary);
}

/** Uint8Array -> base64url (unpadded, `-` and `_`) for use in a URL fragment. */
export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64 -> Uint8Array. Accepts both the standard and URL-safe alphabets and
 * tolerates missing padding, so it round-trips either helper above.
 */
export function base64ToBytes(value) {
  if (typeof value !== 'string') {
    throw new TypeError('base64ToBytes expects a string.');
  }
  const normalized = value.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(padded)) {
    throw new TypeError('Value is not valid Base64.');
  }
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// --- Key handling ---------------------------------------------------------

/**
 * Generate a fresh AES-256-GCM key.
 *
 * @returns {Promise<string>} the raw key as an unpadded base64url string,
 *   ready to be placed after the `#` of a share link.
 */
export async function generateKey() {
  const { subtle } = getCrypto();
  const key = await subtle.generateKey(
    { name: ALGORITHM, length: KEY_LENGTH_BITS },
    true, // extractable: the creator has to be able to put it in the URL fragment
    KEY_USAGES,
  );
  const raw = new Uint8Array(await subtle.exportKey('raw', key));
  return bytesToBase64Url(raw);
}

/**
 * Import a Base64 key string as a non-extractable CryptoKey. Non-extractable
 * means a caller that receives the imported key cannot read the bytes back out
 * of it — the only copy of the material stays the string the caller passed in.
 */
async function importKey(base64Key) {
  if (typeof base64Key !== 'string' || base64Key.length === 0) {
    throw new InvalidKeyError('A Base64 AES key string is required.');
  }

  let raw;
  try {
    raw = base64ToBytes(base64Key);
  } catch (cause) {
    throw new InvalidKeyError('The AES key is not valid Base64.', { cause });
  }

  if (raw.length !== KEY_LENGTH_BYTES) {
    throw new InvalidKeyError(
      `The AES key must be ${KEY_LENGTH_BYTES} bytes (AES-${KEY_LENGTH_BITS}); received ${raw.length}.`,
    );
  }

  const { subtle } = getCrypto();
  try {
    return await subtle.importKey('raw', raw, { name: ALGORITHM }, false, KEY_USAGES);
  } catch (cause) {
    throw new InvalidKeyError('The AES key could not be imported.', { cause });
  }
}

// --- Encrypt / decrypt ----------------------------------------------------

/**
 * Encrypt a plaintext secret.
 *
 * A fresh 12-byte IV is drawn from crypto.getRandomValues() on every call —
 * reusing an IV under the same key would break GCM entirely.
 *
 * @param {string} plaintext
 * @param {string} base64Key key from generateKey()
 * @returns {Promise<{ encryptedContent: string, iv: string }>} both standard Base64
 */
export async function encryptSecret(plaintext, base64Key) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('plaintext must be a string.');
  }

  const webcrypto = getCrypto();
  const key = await importKey(base64Key);
  const iv = webcrypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await webcrypto.subtle.encrypt(
    { name: ALGORITHM, iv, tagLength: TAG_LENGTH_BITS },
    key,
    encoded,
  );

  return {
    encryptedContent: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv),
  };
}

/**
 * Decrypt a secret retrieved from the backend.
 *
 * @param {string} base64Ciphertext `encryptedContent` from the access endpoint
 * @param {string} base64Iv `iv` from the access endpoint
 * @param {string} base64Key key taken from the URL fragment
 * @returns {Promise<string>} the original plaintext
 * @throws {DecryptionError} wrong key, or modified ciphertext/IV
 * @throws {InvalidKeyError} malformed key string
 */
export async function decryptSecret(base64Ciphertext, base64Iv, base64Key) {
  const key = await importKey(base64Key);

  let ciphertext;
  let iv;
  try {
    ciphertext = base64ToBytes(base64Ciphertext);
    iv = base64ToBytes(base64Iv);
  } catch (cause) {
    throw new DecryptionError('The ciphertext or IV is not valid Base64.', { cause });
  }

  if (iv.length !== IV_LENGTH_BYTES) {
    throw new DecryptionError(
      `The IV must be ${IV_LENGTH_BYTES} bytes; received ${iv.length}.`,
    );
  }

  let plaintext;
  try {
    plaintext = await getCrypto().subtle.decrypt(
      { name: ALGORITHM, iv, tagLength: TAG_LENGTH_BITS },
      key,
      ciphertext,
    );
  } catch (cause) {
    // GCM authentication failed: wrong key, or the ciphertext/IV was altered.
    throw new DecryptionError(
      'Decryption failed: the key is incorrect, or the ciphertext or IV was modified.',
      { cause },
    );
  }

  return new TextDecoder().decode(plaintext);
}
