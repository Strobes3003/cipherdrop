# Frontend Security Decisions

Decisions taken on the **frontend crypto & intelligence** track (Pranav), covering the items §29 of the execution plan deliberately left open. This is the reference for the other three tracks — read the sections marked **⚠️ Cross-team requirement**, they constrain work outside the frontend.

Owned files: `frontend/src/utils/{encryption,urlHandler,sensitiveDetector,securityScore,securityAdvisor,index}.js`

Everything here is enforced by tests: `npm test` from `frontend/`.

---

## 1. Cryptography wire format

AES-256-GCM via the native Web Crypto API. No third-party crypto library.

| Value | Format | Notes |
|---|---|---|
| AES key | base64url, unpadded (`A-Za-z0-9_-`) | 32 bytes. Lives only in the URL fragment |
| `encryptedContent` | standard base64 (padded, `+/=`) | ciphertext **with the 128-bit GCM tag appended** |
| `iv` | standard base64 | exactly 12 bytes, freshly generated per encryption |

Two different alphabets on purpose: the key has to survive a URL fragment untouched, while the two API fields travel in a JSON body where standard base64 is conventional. The decoder accepts either alphabet, so mixing them cannot break anything.

**⚠️ Cross-team requirement (Person 1 — Backend Core):** the GCM authentication tag is *inside* `encryptedContent`. Do **not** add a separate tag column, and do not attempt to split or re-encode the value — store and return the base64 string byte-for-byte as received. Any re-encoding breaks decryption for every existing secret.

The IV stays a separate field (not prepended to the ciphertext) because the frozen API in §14 defines it that way.

### Error model

`decryptSecret` throws a single `DecryptionError` for a wrong key, a modified ciphertext, and a modified IV alike. This is not laziness: AES-GCM genuinely cannot distinguish those cases — all three are the same authentication-tag failure. Reporting them separately would mean inventing a distinction the primitive does not provide.

**UI implication (Karan):** show one message for `DecryptionError`, along the lines of *"This link is invalid, incomplete, or has been tampered with."* Do not tell the user which.

---

## 2. Secret ID format

**⚠️ Cross-team requirement (Person 1 — Backend Core).** Secret IDs must match:

```
[A-Za-z0-9_-]{1,128}
```

That is the base64url alphabet: letters, digits, underscore, hyphen. Nothing else.

This is a **strict requirement, not a preference.** `parseShareUrl` and `parseManagementUrl` reject any ID outside this set, so an ID containing `/`, `.`, `%`, `+`, `=`, or any other character will produce a share link the frontend refuses to parse — the secret becomes unreadable, with no way for the recipient to recover it.

The restriction is what keeps path traversal and percent-encoding tricks out of the parser: `/s/..%2f..%2fadmin` cannot survive validation, because `.` and `%` are not in the alphabet.

UUIDs are **not** acceptable as-is — they contain hyphens (fine) but must not be wrapped in braces or contain any other punctuation. Plain nanoid, base62, and base64url-encoded random bytes all satisfy this.

If the backend needs a different format, change it *before* the first end-to-end test, and tell this track — it is a one-line constant in `urlHandler.js`.

---

## 3. URL handling

```
Share:      {origin}/s/{id}#{AES_KEY}
Management: {origin}/manage/{id}#{MANAGEMENT_TOKEN}
```

The fragment is the whole point: browsers never place it in the request line, so the key and the token stay on the client. Put either in the path or the query string and it lands in server access logs, proxy logs, and the `Referer` header.

### Query strings: denylist, not an outright ban

Parsing rejects a URL carrying a **credential-shaped** query parameter — `?key=`, `?aesKey=`, `?token=`, `?password=`, `?iv=`, `?secret=` and similar — but allows everything else through.

An outright ban was the obvious alternative and was rejected: mail clients, chat apps, and link shorteners routinely decorate URLs with `utm_source`, `utm_campaign`, and click-tracking parameters. Banning all query strings would silently break shared links in exactly the channels this product exists to serve. `https://cipherdrop.app/s/abc123?utm_source=mail#KEY` parses fine; `?key=…` throws.

The real guarantee is that the build functions never emit a query string at all. The denylist is defence in depth against a hand-rolled URL.

### Other parsing rules

- **Extra path segments are rejected.** `/s/{id}/{key}` throws — the ID pattern is anchored to the end of the path, so a trailing segment cannot be absorbed into the ID.
- **A base path is supported.** `https://example.com/app/s/{id}#KEY` works, so the app can be hosted under a subdirectory.
- **Relative URLs parse.** `/s/abc#KEY` is accepted, for React Router contexts that only have `pathname + hash`.
- **Fragment values must be URL-safe base64** (`A-Za-z0-9_-`). A fragment in `#key=VALUE` form, or one that is percent-encoded, is rejected — the fragment carries the bare credential and nothing else.
- **`http` is allowed** so `localhost` development works. Production must be HTTPS; that is a deployment concern this module cannot enforce.
- **Share and management URLs cannot be confused.** A management URL fails `parseShareUrl` and vice versa. The management token must never appear in a share link (§28.7).

---

## 4. Sensitive data detection

`detectSensitiveData(text)` returns `[{ type, severity }]`, **deduplicated to one entry per type**, sorted most-severe first then alphabetically. Empty array when nothing matched.

### Severity mapping

Severity is a property of the **category**, not of the individual pattern, so a given type always reports the same severity.

| Severity | Types | Rationale |
|---|---|---|
| `CRITICAL` | `PRIVATE_KEY`, `DATABASE_URL` | A complete, directly usable path into a system. A connection string bundles host, database *and* credentials |
| `HIGH` | `API_KEY`, `OAUTH_TOKEN` | A bearer credential for one specific service |
| `MEDIUM` | `PASSWORD` | A bare password with no host or service attached, found by the weakest heuristic in the set |

### Pattern set

Twenty rules. Vendor-specific formats are precise; the generic `name = value` rules are the workhorses for everyday pastes.

| Type | Detects |
|---|---|
| `PRIVATE_KEY` | PEM headers (`-----BEGIN [RSA/EC/DSA/OPENSSH/PGP/ENCRYPTED] PRIVATE KEY-----`), PuTTY key files |
| `DATABASE_URL` | 13 URI schemes — `postgres(ql)`, `mysql`, `mariadb`, `mongodb(+srv)`, `redis(s)`, `amqp(s)`, `mssql`, `sqlserver`, `cockroachdb`, `clickhouse`, `cassandra`, `db2`, `oracle` — plus `jdbc:*://` |
| `API_KEY` | AWS (`AKIA`/`ASIA`/`ABIA`/`ACCA` + 16), Google (`AIza` + 35), Stripe (`sk_live_`/`rk_test_`), SendGrid (`SG.x.y`), OpenAI/Anthropic (`sk-`), and generic `api_key` / `apikey` / `api_secret` / `access_key(_id)` / `secret_key` / `client_secret` / `private_token` assignments |
| `OAUTH_TOKEN` | Slack (`xox[baprse]-`), GitHub (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, `github_pat_`), npm (`npm_`), Google (`ya29.`), JWTs (`eyJ….….…`), `Bearer` headers, and generic `access_token` / `auth_token` / `refresh_token` / `oauth_token` / `id_token` assignments |
| `PASSWORD` | `password` / `passwd` / `pwd` assignments, and credentials embedded in a URL (`scheme://user:pass@host`) |

Generic assignment rules deliberately omit a leading `\b`, because `_` is a word character and `\b` would fail to match inside `DB_API_KEY=…`.

### Placeholder filtering

Generic rules discard obvious stand-ins: `<your-api-key>`, `${API_KEY}`, `{{token}}`, `****`, `REDACTED`, `changeme`, `TODO`, `null`, `example`. Values shorter than 8 characters (4 for passwords) are ignored.

### Known limitations — accepted deliberately

- **False positives are possible.** `password: please rotate it` flags as `PASSWORD`. Tightening the rule would cost real detections on legitimate `password: <value>` YAML. Since the Advisor only recommends and never blocks (§28.13), a false positive costs a dismissed suggestion; a false negative costs a leaked credential.
- **False negatives are expected.** A bare high-entropy string is indistinguishable from a random note. Detection is a helpful heuristic, never a guarantee, and must not be described to users as one.

### Confidentiality

Findings carry **only** `{ type, severity }` — never the matched text. This is deliberate: a finding that carried the matched value would flow into React state, error boundaries, and eventually somebody's logging or analytics pipeline. The UI never needs the match, only the category. The module writes nothing to `console` and makes no network call; both are asserted by tests.

---

## 5. Security score

`calculateSecurityScore(policies, findings)` → integer in `[0, 100]`.

| Adjustment | Points |
|---|---|
| Base score | **100** |
| Highest finding is `CRITICAL` | **−40** |
| Highest finding is `HIGH` | **−20** |
| Highest finding is `MEDIUM` | 0 |
| Password protection enabled | **+15** |
| Burn after reading enabled | **+15** |
| `maxViews === 1` | **+10** |
| `maxViews > 10` | **−10** |
| `expireHours <= 24` | **+10** |

Clamped to `[0, 100]` at the end.

**Penalties do not stack.** Only the single most severe finding is penalised. Three critical credentials are not six times worse than one — the exposure is already total — and stacking would floor every multi-credential paste at 0 regardless of how well the user protected it, making the score useless as feedback.

`explainSecurityScore()` returns the same number plus an itemised `adjustments` array and the pre-clamp `rawScore`, so the UI can show *why* a score is what it is.

### ⚠️ UI requirement (Karan): show the finding count next to the score

The formula gives **benign text with no policies** and **critical data with every protection enabled** the same score of **100**. The score alone therefore cannot distinguish *"nothing at risk here"* from *"maximum protection applied"*, and an unprotected harmless note scores as well as a hardened private key.

The Security Score component must display the finding count (or the findings themselves) alongside the number. `100 · no sensitive data found` and `100 · 1 critical finding, fully protected` are very different states and must not render identically.

If the team would rather fix this in the formula than in the UI, the two options are lowering the base score to ~70 so bonuses stay visible on benign secrets, or making `MEDIUM` carry a small penalty. Both are one-line changes in `SCORE_WEIGHTS` — but change them *before* the UI depends on the current numbers.

---

## 6. Security Advisor

`getRecommendations(findings)` returns recommended policies plus human-readable `reasons`. It **recommends and never applies** (§28.13) — the returned object is a suggestion payload for the UI to present, never state to write silently into the form.

| Highest severity | `hasPassword` | `expireHours` | `burnAfterReading` | `maxViews` |
|---|---|---|---|---|
| `CRITICAL` or `HIGH` | `true` | 24 | `true` | 1 |
| `MEDIUM` | `true` | 24 | `false` | 5 |
| none | `false` | 168 (7 days) | `false` | 100 |

`CRITICAL` and `HIGH` share one profile because there is nothing stricter to escalate to. Escalation is driven by the highest severity present, never by finding count — twenty `MEDIUM` findings still return the elevated profile.

Accepting the recommendation restores the score to 100 in both non-benign cases, so the advice and the score never contradict each other.

**UI note (Karan):** `getRecommendations` returns a fresh object each call, safe to bind directly into form state. The user must remain free to ignore it — a user who declines the recommendation for critical data scores 50 and can still share.

---

## 7. Importing

Everything is re-exported from one barrel:

```js
import {
  generateKey, encryptSecret, decryptSecret,
  buildShareUrl, parseShareUrl,
  detectSensitiveData, getRecommendations,
  calculateSecurityScore, explainSecurityScore,
  DecryptionError, ShareUrlError,
} from '../utils';
```

Error classes are exported too — `SecretViewer` needs `DecryptionError` to tell a broken link apart from a genuine backend failure.

---

## 8. Invariants this track guarantees

1. The plaintext never leaves the browser. It exists only as an argument to `encryptSecret` and as the return value of `decryptSecret`.
2. The AES key never reaches the backend. It is generated in-browser, travels only in the URL fragment, and is never placed in a path, query string, header, or request body.
3. Nothing is written to `localStorage`, `sessionStorage`, cookies, or any module-level mutable state.
4. Nothing is logged to `console`.
5. No module makes a network call.
6. Every function is pure — same input, same output, no argument mutation.

Items 3–6 are asserted by tests, not just documented.
