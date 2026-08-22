/**
 * CipherDrop — sensitive data detection.
 *
 * Scans a plaintext secret and reports which categories of credential it
 * appears to contain, so the Security Advisor can recommend stricter policies.
 *
 * The text analysed here is the user's plaintext secret — the single most
 * sensitive value in the entire system. This module therefore:
 *   - performs every match locally, synchronously, in memory;
 *   - never transmits, stores, or logs the input or any matched substring;
 *   - returns only category labels, never the matched text itself.
 *
 * Returning only `{ type, severity }` is a deliberate security decision. If a
 * finding carried the matched value, that value would flow into React state,
 * error boundaries, and eventually somebody's logging or analytics pipeline.
 * The UI never needs the match — only the category.
 *
 * Detection is heuristic. False negatives are expected (a bare high-entropy
 * string is indistinguishable from a random note) and the Advisor is built to
 * recommend, never to block — see §9 of the execution plan.
 */

// --- Public constants -----------------------------------------------------

/** Credential categories this module can report. */
export const SENSITIVE_TYPE = Object.freeze({
  PRIVATE_KEY: 'PRIVATE_KEY',
  DATABASE_URL: 'DATABASE_URL',
  API_KEY: 'API_KEY',
  OAUTH_TOKEN: 'OAUTH_TOKEN',
  PASSWORD: 'PASSWORD',
});

/** Severity labels, ordered by how much damage the leak enables. */
export const SEVERITY = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
});

/**
 * Numeric ordering for severities, exported so `securityScore.js` can weight
 * findings without re-deriving the ranking.
 */
export const SEVERITY_RANK = Object.freeze({
  [SEVERITY.CRITICAL]: 3,
  [SEVERITY.HIGH]: 2,
  [SEVERITY.MEDIUM]: 1,
});

/**
 * Severity is a property of the category, not of the individual pattern, so
 * the same type always reports the same severity regardless of which rule fired.
 *
 * CRITICAL — a complete, directly usable path into a system: a private key, or
 *            a connection string that bundles host, database, and credentials.
 * HIGH     — a bearer credential for a specific service.
 * MEDIUM   — a bare password with no host or service attached, detected by the
 *            weakest heuristic in the set.
 */
const SEVERITY_BY_TYPE = Object.freeze({
  [SENSITIVE_TYPE.PRIVATE_KEY]: SEVERITY.CRITICAL,
  [SENSITIVE_TYPE.DATABASE_URL]: SEVERITY.CRITICAL,
  [SENSITIVE_TYPE.API_KEY]: SEVERITY.HIGH,
  [SENSITIVE_TYPE.OAUTH_TOKEN]: SEVERITY.HIGH,
  [SENSITIVE_TYPE.PASSWORD]: SEVERITY.MEDIUM,
});

// --- Placeholder filtering ------------------------------------------------

/**
 * Values that look like a credential assignment but are obviously a stand-in.
 * Applied only to the generic `name = value` rules, where the value is
 * arbitrary; the vendor-specific patterns are precise enough to skip this.
 */
const PLACEHOLDER_VALUE =
  /^(?:[*x•._-]+|<[^>]*>|\{\{?[^}]*\}?\}|\$\{[^}]*\}|%[^%]*%|your[_-]?\w*|my[_-]?\w*|some[_-]?\w*|changeme|change[_-]?me|redacted|placeholder|example|sample|dummy|secret|password|test|todo|tbd|none|null|nil|undefined|true|false)$/i;

function isRealValue(value) {
  return typeof value === 'string' && value.length > 0 && !PLACEHOLDER_VALUE.test(value);
}

// --- Pattern catalogue ----------------------------------------------------

/**
 * Each rule is `{ type, name, pattern, validate? }`.
 *
 * Patterns are stored WITHOUT the `g` flag: a global regex carries a mutable
 * `lastIndex`, which would make repeated calls to `detectSensitiveData` return
 * different answers for the same input. Rules that need to walk every match
 * (the ones with a `validate`) compile a throwaway global copy per scan.
 *
 * Generic `name = value` rules deliberately omit a leading `\b`, because `_` is
 * a word character and `\b` would fail to match inside `DB_API_KEY=…`.
 */
const RULES = Object.freeze([
  // --- PRIVATE_KEY --------------------------------------------------------
  {
    type: SENSITIVE_TYPE.PRIVATE_KEY,
    name: 'PEM private key block (RSA, EC, DSA, OPENSSH, PGP, ENCRYPTED)',
    pattern: /-----BEGIN(?:\s[A-Z0-9]+)*\sPRIVATE KEY(?:\sBLOCK)?-----/,
  },
  {
    type: SENSITIVE_TYPE.PRIVATE_KEY,
    name: 'PuTTY private key file',
    pattern: /PuTTY-User-Key-File-\d/,
  },

  // --- DATABASE_URL -------------------------------------------------------
  {
    type: SENSITIVE_TYPE.DATABASE_URL,
    name: 'database connection URI',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|cockroachdb|clickhouse|cassandra|db2|oracle):\/\/[^\s"'<>]+/i,
  },
  {
    type: SENSITIVE_TYPE.DATABASE_URL,
    name: 'JDBC connection URL',
    pattern: /\bjdbc:[a-z0-9]+:\/\/[^\s"'<>]+/i,
  },

  // --- API_KEY ------------------------------------------------------------
  {
    type: SENSITIVE_TYPE.API_KEY,
    name: 'AWS access key ID',
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/,
  },
  {
    type: SENSITIVE_TYPE.API_KEY,
    name: 'Google API key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
  },
  {
    type: SENSITIVE_TYPE.API_KEY,
    name: 'Stripe API key',
    pattern: /\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b/,
  },
  {
    type: SENSITIVE_TYPE.API_KEY,
    name: 'SendGrid API key',
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,
  },
  {
    type: SENSITIVE_TYPE.API_KEY,
    name: 'OpenAI/Anthropic-style secret key',
    pattern: /\bsk-(?:[A-Za-z0-9]{2,20}-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    type: SENSITIVE_TYPE.API_KEY,
    name: 'generic API key assignment',
    pattern:
      /(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?key(?:[_-]?id)?|secret[_-]?key|client[_-]?secret|private[_-]?token)["']?\s*[:=]\s*["']?([^\s"',;]{8,})/i,
    validate: isRealValue,
  },

  // --- OAUTH_TOKEN --------------------------------------------------------
  {
    type: SENSITIVE_TYPE.OAUTH_TOKEN,
    name: 'Slack token',
    pattern: /\bxox[baprse]-[A-Za-z0-9-]{10,}/,
  },
  {
    type: SENSITIVE_TYPE.OAUTH_TOKEN,
    name: 'GitHub personal access / app token',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/,
  },
  {
    type: SENSITIVE_TYPE.OAUTH_TOKEN,
    name: 'GitHub fine-grained PAT',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/,
  },
  {
    type: SENSITIVE_TYPE.OAUTH_TOKEN,
    name: 'JSON Web Token (JWT)',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  },
  {
    type: SENSITIVE_TYPE.OAUTH_TOKEN,
    name: 'Google OAuth access token',
    pattern: /\bya29\.[A-Za-z0-9_-]{20,}/,
  },
  {
    type: SENSITIVE_TYPE.OAUTH_TOKEN,
    name: 'npm access token',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/,
  },
  {
    type: SENSITIVE_TYPE.OAUTH_TOKEN,
    name: 'HTTP Bearer credential',
    pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/i,
  },
  {
    type: SENSITIVE_TYPE.OAUTH_TOKEN,
    name: 'OAuth token assignment',
    pattern:
      /(?:access[_-]?token|auth[_-]?token|refresh[_-]?token|oauth[_-]?token|bearer[_-]?token|id[_-]?token)["']?\s*[:=]\s*["']?([^\s"',;]{8,})/i,
    validate: isRealValue,
  },

  // --- PASSWORD -----------------------------------------------------------
  {
    type: SENSITIVE_TYPE.PASSWORD,
    name: 'password assignment',
    pattern: /(?:password|passwd|pwd)["']?\s*[:=]\s*["']?([^\s"',;]{4,})/i,
    validate: isRealValue,
  },
  {
    type: SENSITIVE_TYPE.PASSWORD,
    name: 'credentials embedded in a URL',
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s:@/]{3,}@[^\s/]+/i,
  },
]);

// --- Engine ---------------------------------------------------------------

/**
 * Walk every match for a rule that has a validator, stopping at the first one
 * whose captured value is not an obvious placeholder.
 */
function ruleMatches(rule, text) {
  if (!rule.validate) {
    return rule.pattern.test(text);
  }

  const scanner = new RegExp(rule.pattern.source, `${rule.pattern.flags}g`);
  let match = scanner.exec(text);
  while (match !== null) {
    if (rule.validate(match[1])) {
      return true;
    }
    if (match[0] === '') {
      scanner.lastIndex += 1; // guard against a zero-length match looping forever
    }
    match = scanner.exec(text);
  }
  return false;
}

function compareFindings(a, b) {
  const bySeverity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  return bySeverity !== 0 ? bySeverity : a.type.localeCompare(b.type);
}

/**
 * Detect sensitive credentials in a plaintext secret.
 *
 * At most one finding is returned per category, no matter how many times that
 * category matches. Results are ordered most severe first, then alphabetically,
 * so the Advisor renders deterministically.
 *
 * @param {string} text the user's plaintext (never leaves this function)
 * @returns {Array<{ type: string, severity: string }>} empty when nothing matched
 * @throws {TypeError} if given a non-string that is not null/undefined
 */
export function detectSensitiveData(text) {
  if (text === null || text === undefined || text === '') {
    return [];
  }
  if (typeof text !== 'string') {
    throw new TypeError('detectSensitiveData expects a string.');
  }

  const detected = new Set();
  for (const rule of RULES) {
    if (detected.has(rule.type)) {
      continue; // this category is already reported; skip redundant scanning
    }
    if (ruleMatches(rule, text)) {
      detected.add(rule.type);
    }
  }

  return [...detected]
    .map((type) => ({ type, severity: SEVERITY_BY_TYPE[type] }))
    .sort(compareFindings);
}

/**
 * The pattern catalogue in human-readable form, for the team documentation
 * required by §29. Returns names only — never the compiled regexes, so callers
 * cannot mutate detection behaviour at a distance.
 *
 * @returns {Array<{ type: string, severity: string, name: string }>}
 */
export function describePatterns() {
  return RULES.map((rule) => ({
    type: rule.type,
    severity: SEVERITY_BY_TYPE[rule.type],
    name: rule.name,
  }));
}
