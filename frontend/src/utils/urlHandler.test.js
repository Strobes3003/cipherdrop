import { describe, expect, it } from 'vitest';

import { generateKey } from './encryption.js';
import {
  ManagementUrlError,
  ShareUrlError,
  buildManagementUrl,
  buildShareUrl,
  parseManagementUrl,
  parseShareUrl,
} from './urlHandler.js';

const ORIGIN = 'https://cipherdrop.app';
const ID = 'abc123';
const KEY = 'zH1pQ8Xk-4nR_bV2sT7yU0mL3wJ6cD9fG5hK8jN1qA0';
const TOKEN = 'mgmt-Token_9876543210';

describe('buildShareUrl', () => {
  it('builds the exact documented share URL', () => {
    expect(buildShareUrl(ORIGIN, ID, KEY)).toBe(`https://cipherdrop.app/s/${ID}#${KEY}`);
  });

  it('keeps the key out of the path and the query string', () => {
    const beforeFragment = buildShareUrl(ORIGIN, ID, KEY).split('#')[0];

    expect(beforeFragment).toBe('https://cipherdrop.app/s/abc123');
    expect(beforeFragment).not.toContain(KEY);
    expect(beforeFragment).not.toContain('?');
  });

  it('strips a trailing slash from the origin', () => {
    expect(buildShareUrl('https://cipherdrop.app/', ID, KEY)).toBe(
      `https://cipherdrop.app/s/${ID}#${KEY}`,
    );
  });

  it('preserves a base path when the app is hosted under a subdirectory', () => {
    expect(buildShareUrl('https://example.com/app', ID, KEY)).toBe(
      `https://example.com/app/s/${ID}#${KEY}`,
    );
  });

  it('supports a localhost dev origin with a port', () => {
    expect(buildShareUrl('http://localhost:5173', ID, KEY)).toBe(
      `http://localhost:5173/s/${ID}#${KEY}`,
    );
  });

  it.each([
    ['a missing origin', undefined],
    ['an empty origin', ''],
    ['a non-absolute origin', 'cipherdrop.app'],
    ['a non-http scheme', 'javascript:alert(1)'],
    ['an origin carrying a query string', 'https://cipherdrop.app?key=leak'],
    ['an origin carrying a fragment', 'https://cipherdrop.app#leak'],
  ])('rejects %s', (_label, origin) => {
    expect(() => buildShareUrl(origin, ID, KEY)).toThrow(ShareUrlError);
  });

  it.each([
    ['a missing id', undefined],
    ['an empty id', ''],
    ['an id containing a slash', 'abc/123'],
    ['an id containing a percent escape', 'abc%2F123'],
    ['a path-traversal id', '..'],
  ])('rejects %s', (_label, id) => {
    expect(() => buildShareUrl(ORIGIN, id, KEY)).toThrow(ShareUrlError);
  });

  it.each([
    ['a missing key', undefined],
    ['an empty key', ''],
    ['a key in key=value form', 'key=abc123'],
    ['a key containing standard Base64 padding', 'abc123=='],
    ['a key containing a + character', 'abc+123'],
    ['a key containing a slash', 'abc/123'],
  ])('rejects %s', (_label, key) => {
    expect(() => buildShareUrl(ORIGIN, ID, key)).toThrow(ShareUrlError);
  });
});

describe('parseShareUrl', () => {
  it('extracts the id and key from a valid share URL', () => {
    expect(parseShareUrl(`https://cipherdrop.app/s/${ID}#${KEY}`)).toEqual({ id: ID, key: KEY });
  });

  it('parses an origin-relative URL (React Router pathname + hash)', () => {
    expect(parseShareUrl(`/s/${ID}#${KEY}`)).toEqual({ id: ID, key: KEY });
  });

  it('parses a URL hosted under a base path', () => {
    expect(parseShareUrl(`https://example.com/app/s/${ID}#${KEY}`)).toEqual({ id: ID, key: KEY });
  });

  it('tolerates a trailing slash before the fragment', () => {
    expect(parseShareUrl(`https://cipherdrop.app/s/${ID}/#${KEY}`)).toEqual({ id: ID, key: KEY });
  });

  it('keeps a harmless tracking parameter from breaking the link', () => {
    expect(parseShareUrl(`https://cipherdrop.app/s/${ID}?utm_source=mail#${KEY}`)).toEqual({
      id: ID,
      key: KEY,
    });
  });

  it.each([
    ['a missing fragment', `https://cipherdrop.app/s/${ID}`],
    ['an empty fragment', `https://cipherdrop.app/s/${ID}#`],
  ])('throws on %s', (_label, url) => {
    expect(() => parseShareUrl(url)).toThrow(ShareUrlError);
  });

  it('explains that the link was truncated when the fragment is missing', () => {
    expect(() => parseShareUrl(`https://cipherdrop.app/s/${ID}`)).toThrow(/no fragment/i);
  });

  it.each([
    ['the key sits in a path segment', `https://cipherdrop.app/s/${ID}/${KEY}`],
    ['the path prefix is wrong', `https://cipherdrop.app/secret/${ID}#${KEY}`],
    ['there is no id segment', `https://cipherdrop.app/s#${KEY}`],
    ['the id segment is empty', `https://cipherdrop.app/s/#${KEY}`],
    ['the path is the bare origin', `https://cipherdrop.app#${KEY}`],
    ['the id contains a percent escape', `https://cipherdrop.app/s/ab%2Fc#${KEY}`],
  ])('throws when %s', (_label, url) => {
    expect(() => parseShareUrl(url)).toThrow(ShareUrlError);
  });

  it.each([
    ['?key=', `https://cipherdrop.app/s/${ID}?key=${KEY}#${KEY}`],
    ['?aesKey=', `https://cipherdrop.app/s/${ID}?aesKey=${KEY}#${KEY}`],
    ['?aes_key=', `https://cipherdrop.app/s/${ID}?aes_key=${KEY}#${KEY}`],
    ['?token=', `https://cipherdrop.app/s/${ID}?token=${TOKEN}#${KEY}`],
    ['?password=', `https://cipherdrop.app/s/${ID}?password=hunter2#${KEY}`],
    ['?iv=', `https://cipherdrop.app/s/${ID}?iv=abc#${KEY}`],
  ])('refuses a credential leaked into the query string via %s', (_label, url) => {
    expect(() => parseShareUrl(url)).toThrow(/query string|credential/i);
  });

  it.each([
    ['a fragment in key=value form', `https://cipherdrop.app/s/${ID}#key=${KEY}`],
    ['a percent-encoded fragment', `https://cipherdrop.app/s/${ID}#abc%2F123`],
    ['a fragment with standard Base64 padding', `https://cipherdrop.app/s/${ID}#abc123==`],
  ])('throws on %s', (_label, url) => {
    expect(() => parseShareUrl(url)).toThrow(ShareUrlError);
  });

  it.each([
    ['undefined', undefined],
    ['an empty string', ''],
    ['a non-string', 42],
  ])('throws on %s input', (_label, url) => {
    expect(() => parseShareUrl(url)).toThrow(ShareUrlError);
  });
});

describe('buildManagementUrl', () => {
  it('builds the exact documented management URL', () => {
    expect(buildManagementUrl(ORIGIN, ID, TOKEN)).toBe(
      `https://cipherdrop.app/manage/${ID}#${TOKEN}`,
    );
  });

  it('keeps the token out of the path and the query string', () => {
    const beforeFragment = buildManagementUrl(ORIGIN, ID, TOKEN).split('#')[0];

    expect(beforeFragment).toBe('https://cipherdrop.app/manage/abc123');
    expect(beforeFragment).not.toContain(TOKEN);
  });

  it('uses a different path prefix from the share URL, so the two cannot be confused', () => {
    const share = buildShareUrl(ORIGIN, ID, KEY);
    const manage = buildManagementUrl(ORIGIN, ID, TOKEN);

    expect(share).not.toBe(manage);
    expect(() => parseShareUrl(manage)).toThrow(ShareUrlError);
    expect(() => parseManagementUrl(share)).toThrow(ManagementUrlError);
  });

  it.each([
    ['a missing token', undefined],
    ['an empty token', ''],
    ['a token in key=value form', 'token=abc'],
    ['a token containing a slash', 'abc/123'],
  ])('rejects %s', (_label, token) => {
    expect(() => buildManagementUrl(ORIGIN, ID, token)).toThrow(ManagementUrlError);
  });

  it('rejects an invalid origin with a ManagementUrlError', () => {
    expect(() => buildManagementUrl('not-a-url', ID, TOKEN)).toThrow(ManagementUrlError);
  });
});

describe('parseManagementUrl', () => {
  it('extracts the id and management token', () => {
    expect(parseManagementUrl(`https://cipherdrop.app/manage/${ID}#${TOKEN}`)).toEqual({
      id: ID,
      managementToken: TOKEN,
    });
  });

  it('parses an origin-relative URL', () => {
    expect(parseManagementUrl(`/manage/${ID}#${TOKEN}`)).toEqual({
      id: ID,
      managementToken: TOKEN,
    });
  });

  it.each([
    ['the fragment is missing', `https://cipherdrop.app/manage/${ID}`],
    ['the token sits in a path segment', `https://cipherdrop.app/manage/${ID}/${TOKEN}`],
    ['the token sits in the query string', `https://cipherdrop.app/manage/${ID}?token=${TOKEN}`],
    ['the path prefix is wrong', `https://cipherdrop.app/management/${ID}#${TOKEN}`],
    ['there is no id segment', `https://cipherdrop.app/manage#${TOKEN}`],
  ])('throws when %s', (_label, url) => {
    expect(() => parseManagementUrl(url)).toThrow(ManagementUrlError);
  });
});

describe('build -> parse round trip', () => {
  it('round-trips a real generated AES key', async () => {
    const key = await generateKey();
    const url = buildShareUrl(ORIGIN, 'Xk9_bV2-sT7', key);

    expect(parseShareUrl(url)).toEqual({ id: 'Xk9_bV2-sT7', key });
  });

  it('round-trips 50 generated keys without mangling a single character', async () => {
    const keys = await Promise.all(Array.from({ length: 50 }, () => generateKey()));

    for (const key of keys) {
      expect(parseShareUrl(buildShareUrl(ORIGIN, ID, key)).key).toBe(key);
    }
  });

  it('round-trips through the browser URL/location model unchanged', async () => {
    const key = await generateKey();
    const built = buildShareUrl(ORIGIN, ID, key);
    const asLocation = new URL(built);

    expect(asLocation.search).toBe('');
    expect(asLocation.pathname).toBe(`/s/${ID}`);
    expect(asLocation.hash.slice(1)).toBe(key);
    expect(parseShareUrl(asLocation.href)).toEqual({ id: ID, key });
  });

  it('round-trips a management URL', () => {
    const url = buildManagementUrl(ORIGIN, ID, TOKEN);

    expect(parseManagementUrl(url)).toEqual({ id: ID, managementToken: TOKEN });
  });
});
