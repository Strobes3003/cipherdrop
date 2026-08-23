import { describe, expect, it } from 'vitest';

import {
  DecryptionError,
  InvalidKeyError,
  base64ToBytes,
  bytesToBase64,
  bytesToBase64Url,
  decryptSecret,
  encryptSecret,
  generateKey,
} from './encryption.js';

const PLAINTEXT = 'hello';

/** Flip one bit inside a Base64 payload and hand the payload back as Base64. */
function tamper(base64Value, byteIndex = 0) {
  const bytes = base64ToBytes(base64Value);
  bytes[byteIndex] ^= 0x01;
  return bytesToBase64(bytes);
}

describe('generateKey', () => {
  it('returns a 32-byte (AES-256) key', async () => {
    const key = await generateKey();
    expect(base64ToBytes(key)).toHaveLength(32);
  });

  it('returns an unpadded base64url string that is safe in a URL fragment', async () => {
    const key = await generateKey();
    expect(key).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('returns a different key on every call', async () => {
    const keys = await Promise.all(Array.from({ length: 25 }, () => generateKey()));
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe('Base64 helpers', () => {
  it('round-trips arbitrary bytes through standard Base64', () => {
    const bytes = crypto.getRandomValues(new Uint8Array(257));
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('round-trips arbitrary bytes through unpadded base64url', () => {
    const bytes = crypto.getRandomValues(new Uint8Array(257));
    expect(base64ToBytes(bytesToBase64Url(bytes))).toEqual(bytes);
  });

  it('produces URL-safe output containing no +, / or = characters', () => {
    // 0xFB 0xFF encodes to "+/" in the standard alphabet.
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);
    expect(bytesToBase64(bytes)).toMatch(/[+/]/);
    expect(bytesToBase64Url(bytes)).not.toMatch(/[+/=]/);
  });

  it('round-trips an empty byte array', () => {
    expect(base64ToBytes(bytesToBase64(new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });

  it('rejects a string that is not Base64', () => {
    expect(() => base64ToBytes('not base64!!')).toThrow(TypeError);
  });
});

describe('encryptSecret / decryptSecret round trip', () => {
  it('decrypts back to the exact original plaintext', async () => {
    const key = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(PLAINTEXT, key);

    expect(await decryptSecret(encryptedContent, iv, key)).toBe(PLAINTEXT);
  });

  it.each([
    ['empty string', ''],
    ['single character', 'a'],
    ['unicode and emoji', 'pässwörd — 秘密 🔐'],
    ['JSON-ish credentials', '{"DATABASE_URL":"postgres://u:p@host:5432/db"}'],
    ['multiline PEM-ish block', '-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----'],
    ['large secret', 'x'.repeat(100_000)],
  ])('preserves %s byte-for-byte', async (_label, plaintext) => {
    const key = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(plaintext, key);

    expect(await decryptSecret(encryptedContent, iv, key)).toBe(plaintext);
  });
});

describe('ciphertext output', () => {
  it('is not the plaintext', async () => {
    const key = await generateKey();
    const { encryptedContent } = await encryptSecret(PLAINTEXT, key);

    expect(encryptedContent).not.toBe(PLAINTEXT);
    expect(encryptedContent).not.toContain(PLAINTEXT);
  });

  it('does not contain the plaintext bytes anywhere in the payload', async () => {
    const key = await generateKey();
    const { encryptedContent } = await encryptSecret(PLAINTEXT, key);

    const cipherBytes = base64ToBytes(encryptedContent);
    const plainBytes = new TextEncoder().encode(PLAINTEXT);
    const haystack = Array.from(cipherBytes).join(',');
    const needle = Array.from(plainBytes).join(',');

    expect(haystack).not.toContain(needle);
  });

  it('appends the 128-bit GCM tag, so ciphertext is plaintext length + 16', async () => {
    const key = await generateKey();
    const { encryptedContent } = await encryptSecret(PLAINTEXT, key);

    expect(base64ToBytes(encryptedContent)).toHaveLength(PLAINTEXT.length + 16);
  });

  it('emits a fresh 12-byte IV on every call', async () => {
    const key = await generateKey();
    const results = await Promise.all(
      Array.from({ length: 25 }, () => encryptSecret(PLAINTEXT, key)),
    );

    for (const { iv } of results) {
      expect(base64ToBytes(iv)).toHaveLength(12);
    }
    expect(new Set(results.map((r) => r.iv)).size).toBe(results.length);
  });

  it('produces different ciphertext for the same plaintext and key', async () => {
    const key = await generateKey();
    const first = await encryptSecret(PLAINTEXT, key);
    const second = await encryptSecret(PLAINTEXT, key);

    expect(first.encryptedContent).not.toBe(second.encryptedContent);
  });
});

describe('authentication failure', () => {
  it('throws DecryptionError when the key is wrong', async () => {
    const key = await generateKey();
    const wrongKey = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(PLAINTEXT, key);

    await expect(decryptSecret(encryptedContent, iv, wrongKey)).rejects.toThrow(DecryptionError);
  });

  it('throws DecryptionError when a single bit of the key is flipped', async () => {
    const key = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(PLAINTEXT, key);
    const nearMissKey = tamper(key, 31);

    await expect(decryptSecret(encryptedContent, iv, nearMissKey)).rejects.toThrow(DecryptionError);
  });

  it('never leaks plaintext through a failed decryption', async () => {
    const key = await generateKey();
    const wrongKey = await generateKey();
    const { encryptedContent, iv } = await encryptSecret('super-secret-value', key);

    await expect(decryptSecret(encryptedContent, iv, wrongKey)).rejects.toThrow(
      /key is incorrect, or the ciphertext or IV was modified/,
    );
  });
});

describe('integrity failure', () => {
  it('throws DecryptionError when the ciphertext body is modified', async () => {
    const key = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(PLAINTEXT, key);

    await expect(decryptSecret(tamper(encryptedContent, 0), iv, key)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('throws DecryptionError when the GCM tag is modified', async () => {
    const key = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(PLAINTEXT, key);
    const lastByte = base64ToBytes(encryptedContent).length - 1;

    await expect(decryptSecret(tamper(encryptedContent, lastByte), iv, key)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('throws DecryptionError when the IV is modified', async () => {
    const key = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(PLAINTEXT, key);

    await expect(decryptSecret(encryptedContent, tamper(iv, 0), key)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('throws DecryptionError when the ciphertext is truncated', async () => {
    const key = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(PLAINTEXT, key);
    const truncated = bytesToBase64(base64ToBytes(encryptedContent).subarray(0, 8));

    await expect(decryptSecret(truncated, iv, key)).rejects.toThrow(DecryptionError);
  });

  it('throws DecryptionError when the IV is the wrong length', async () => {
    const key = await generateKey();
    const { encryptedContent } = await encryptSecret(PLAINTEXT, key);
    const shortIv = bytesToBase64(new Uint8Array(8));

    await expect(decryptSecret(encryptedContent, shortIv, key)).rejects.toThrow(
      /IV must be 12 bytes/,
    );
  });

  it('throws DecryptionError when the ciphertext is not Base64', async () => {
    const key = await generateKey();
    const { iv } = await encryptSecret(PLAINTEXT, key);

    await expect(decryptSecret('not base64!!', iv, key)).rejects.toThrow(DecryptionError);
  });
});

describe('key validation', () => {
  it.each([
    ['undefined', undefined],
    ['empty string', ''],
    ['non-string', 42],
  ])('rejects a %s key with InvalidKeyError', async (_label, badKey) => {
    await expect(encryptSecret(PLAINTEXT, badKey)).rejects.toThrow(InvalidKeyError);
  });

  it('rejects a key that is not Base64', async () => {
    await expect(encryptSecret(PLAINTEXT, 'not base64!!')).rejects.toThrow(InvalidKeyError);
  });

  it('rejects a key of the wrong length (AES-128)', async () => {
    const shortKey = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16)));

    await expect(encryptSecret(PLAINTEXT, shortKey)).rejects.toThrow(/must be 32 bytes/);
  });

  it('rejects a non-string plaintext', async () => {
    const key = await generateKey();

    await expect(encryptSecret({ secret: 'oops' }, key)).rejects.toThrow(TypeError);
  });
});

describe('key transport shape', () => {
  it('survives a round trip through a URL fragment', async () => {
    const key = await generateKey();
    const { encryptedContent, iv } = await encryptSecret(PLAINTEXT, key);

    const shareUrl = new URL(`https://cipherdrop.app/s/abc123#${key}`);
    const keyFromFragment = shareUrl.hash.slice(1);

    expect(keyFromFragment).toBe(key);
    expect(await decryptSecret(encryptedContent, iv, keyFromFragment)).toBe(PLAINTEXT);
  });

  it('is unchanged by encodeURIComponent (no escaping needed)', async () => {
    const key = await generateKey();
    expect(encodeURIComponent(key)).toBe(key);
  });
});
