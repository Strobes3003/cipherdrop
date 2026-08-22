/**
 * CipherDrop — share and management URL construction/parsing.
 *
 * Share URL:       {origin}/s/{id}#{AES_KEY}
 * Management URL:  {origin}/manage/{id}#{MANAGEMENT_TOKEN}
 *
 * The whole point of this module is the `#`. A URL fragment is never placed in
 * the request line by a browser, so the AES key and the management token stay
 * on the client. Put either of them in the path or the query string instead and
 * they land in server access logs, proxy logs, and the Referer header — which
 * would defeat the entire architecture.
 *
 * Every function here is pure: no `window`, no `location`, no storage. Callers
 * that need the current URL pass `window.location.href` in themselves.
 */

const SHARE_SEGMENT = 's';
const MANAGE_SEGMENT = 'manage';

/**
 * Secret IDs are opaque strings minted by the backend. The architecture does
 * not pin a format, so we accept the base64url/base62 alphabet that ID
 * generators produce and reject everything else — including `/`, `.` and `%`,
 * which keeps path traversal and percent-encoding tricks out of the parser.
 */
const SECRET_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

/**
 * Fragment credentials (AES key, management token) must survive a URL round
 * trip untouched, so they are restricted to the unreserved base64url alphabet.
 * Length is deliberately not checked here — `encryption.js` owns key-size
 * policy and reports it precisely.
 */
const FRAGMENT_VALUE_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Query parameter names that would indicate a credential leaked out of the
 * fragment. Defence in depth, not the primary guarantee: the primary guarantee
 * is that the build functions never emit a query string at all. Normalised by
 * lowercasing and stripping non-alphanumerics before comparison.
 */
const CREDENTIAL_QUERY_KEYS = new Set([
  'key',
  'keys',
  'aes',
  'aeskey',
  'k',
  'secret',
  'secretkey',
  'token',
  'accesstoken',
  'managementtoken',
  'mgmttoken',
  't',
  'password',
  'passwd',
  'pass',
  'pwd',
  'iv',
]);

/** Base class for every error this module raises deliberately. */
export class CipherDropUrlError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** A share URL could not be built or parsed. */
export class ShareUrlError extends CipherDropUrlError {}

/** A management URL could not be built or parsed. */
export class ManagementUrlError extends CipherDropUrlError {}

// --- Validation helpers ---------------------------------------------------

/**
 * Reduce an origin to `scheme://host[:port][/base/path]` with no trailing
 * slash, rejecting anything that already carries a query or fragment.
 */
function normalizeOrigin(origin, ErrorClass) {
  if (typeof origin !== 'string' || origin.trim() === '') {
    throw new ErrorClass('An origin is required, e.g. "https://cipherdrop.app".');
  }

  let parsed;
  try {
    parsed = new URL(origin);
  } catch (cause) {
    throw new ErrorClass(`"${origin}" is not a valid absolute origin.`, { cause });
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new ErrorClass(`The origin must be http or https; received "${parsed.protocol}".`);
  }
  if (parsed.search) {
    throw new ErrorClass('The origin must not contain a query string.');
  }
  if (parsed.hash) {
    throw new ErrorClass('The origin must not contain a fragment.');
  }

  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`;
}

function assertSecretId(secretId, ErrorClass) {
  if (typeof secretId !== 'string' || secretId === '') {
    throw new ErrorClass('A secret ID is required.');
  }
  if (!SECRET_ID_PATTERN.test(secretId)) {
    throw new ErrorClass(
      `"${secretId}" is not a valid secret ID (expected 1-128 characters from A-Z a-z 0-9 _ -).`,
    );
  }
  return secretId;
}

function assertFragmentValue(value, label, ErrorClass) {
  if (typeof value !== 'string' || value === '') {
    throw new ErrorClass(`A ${label} is required.`);
  }
  if (!FRAGMENT_VALUE_PATTERN.test(value)) {
    throw new ErrorClass(
      `The ${label} must be a URL-safe Base64 string (A-Z a-z 0-9 _ -); ` +
        'it must never be percent-encoded or wrapped in key=value syntax.',
    );
  }
  return value;
}

/**
 * Resolve a possibly-relative URL. React Router hands out `pathname + hash`
 * without an origin, so a placeholder base is used purely to make parsing
 * work — the origin is never read back out.
 */
function toUrl(url, ErrorClass) {
  if (typeof url !== 'string' || url.trim() === '') {
    throw new ErrorClass('A URL string is required.');
  }
  try {
    return new URL(url);
  } catch {
    try {
      return new URL(url, 'https://cipherdrop.invalid');
    } catch (cause) {
      throw new ErrorClass(`"${url}" is not a parseable URL.`, { cause });
    }
  }
}

/**
 * Refuse a URL that carries a credential-shaped query parameter. A link like
 * `/s/abc?key=...` means someone bypassed the fragment and has already leaked
 * the key to the server; failing loudly is better than decrypting anyway.
 */
function assertNoCredentialsInQuery(parsed, ErrorClass) {
  for (const name of parsed.searchParams.keys()) {
    const normalized = name.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (CREDENTIAL_QUERY_KEYS.has(normalized)) {
      throw new ErrorClass(
        `The query parameter "${name}" looks like a credential. Keys and tokens ` +
          'must travel only in the URL fragment, never in the query string.',
      );
    }
  }
}

/**
 * Pull `{id}` out of a `.../{segment}/{id}` path. Anchoring the match to the
 * end of the path is what rejects `/s/{id}/{key}` — a trailing segment cannot
 * be mistaken for part of the ID — while still allowing the app to be hosted
 * under a base path such as `/app/s/{id}`.
 */
function extractId(parsed, segment, ErrorClass) {
  const path = parsed.pathname.replace(/\/+$/, '');
  const match = new RegExp(`(?:^|/)${segment}/([^/]+)$`).exec(path);

  if (!match) {
    throw new ErrorClass(
      `"${parsed.pathname}" is not a /${segment}/{id} path. ` +
        `Expected exactly one segment after /${segment}/.`,
    );
  }
  return assertSecretId(match[1], ErrorClass);
}

function extractFragment(parsed, label, ErrorClass) {
  const raw = parsed.hash.startsWith('#') ? parsed.hash.slice(1) : parsed.hash;
  if (raw === '') {
    throw new ErrorClass(
      `This URL has no fragment, so it carries no ${label}. ` +
        'The link was probably truncated when it was copied or forwarded.',
    );
  }
  return assertFragmentValue(raw, label, ErrorClass);
}

// --- Share URLs -----------------------------------------------------------

/**
 * Build the link the creator sends to the recipient.
 *
 * @param {string} origin e.g. "https://cipherdrop.app" (a base path is allowed)
 * @param {string} secretId the ID returned by POST /api/secrets
 * @param {string} base64Key the key from generateKey()
 * @returns {string} `{origin}/s/{id}#{key}`
 * @throws {ShareUrlError}
 */
export function buildShareUrl(origin, secretId, base64Key) {
  const base = normalizeOrigin(origin, ShareUrlError);
  const id = assertSecretId(secretId, ShareUrlError);
  const key = assertFragmentValue(base64Key, 'AES key', ShareUrlError);

  return `${base}/${SHARE_SEGMENT}/${id}#${key}`;
}

/**
 * Parse a share link, typically `window.location.href` on /s/:id.
 *
 * @param {string} url absolute or origin-relative
 * @returns {{ id: string, key: string }}
 * @throws {ShareUrlError} bad path, missing fragment, or a credential in the query
 */
export function parseShareUrl(url) {
  const parsed = toUrl(url, ShareUrlError);
  assertNoCredentialsInQuery(parsed, ShareUrlError);

  return {
    id: extractId(parsed, SHARE_SEGMENT, ShareUrlError),
    key: extractFragment(parsed, 'AES key', ShareUrlError),
  };
}

// --- Management URLs ------------------------------------------------------

/**
 * Build the creator's private management link.
 *
 * This URL must never be handed to a recipient: the management token authorises
 * deletion. It is deliberately a different path prefix from the share link so
 * the two cannot be confused for one another.
 *
 * @param {string} origin
 * @param {string} secretId
 * @param {string} managementToken the raw token returned once at creation
 * @returns {string} `{origin}/manage/{id}#{token}`
 * @throws {ManagementUrlError}
 */
export function buildManagementUrl(origin, secretId, managementToken) {
  const base = normalizeOrigin(origin, ManagementUrlError);
  const id = assertSecretId(secretId, ManagementUrlError);
  const token = assertFragmentValue(managementToken, 'management token', ManagementUrlError);

  return `${base}/${MANAGE_SEGMENT}/${id}#${token}`;
}

/**
 * Parse a management link.
 *
 * @param {string} url absolute or origin-relative
 * @returns {{ id: string, managementToken: string }}
 * @throws {ManagementUrlError}
 */
export function parseManagementUrl(url) {
  const parsed = toUrl(url, ManagementUrlError);
  assertNoCredentialsInQuery(parsed, ManagementUrlError);

  return {
    id: extractId(parsed, MANAGE_SEGMENT, ManagementUrlError),
    managementToken: extractFragment(parsed, 'management token', ManagementUrlError),
  };
}
