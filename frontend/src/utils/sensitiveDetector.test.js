import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  SENSITIVE_TYPE,
  SEVERITY,
  SEVERITY_RANK,
  describePatterns,
  detectSensitiveData,
} from './sensitiveDetector.js';

// Every credential below is a syntactically valid but fabricated fixture.
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const GOOGLE_API_KEY = 'AIzaSyD-EXAMPLE-KEY-1234567890abcdefghi';
const STRIPE_KEY = 'sk_test_0000000000000000FAKEKEY';
const SENDGRID_KEY = 'SG.aBcDeFgHiJkLmNoP.qRsTuVwXyZ0123456789';
const OPENAI_KEY = 'sk-ant-api03-AbCdEf1234567890GhIjKlMnOpQrStUvWx';
const SLACK_TOKEN = 'xoxb-FAKEFAKEFAKEFAKEFAKE';
const GITHUB_TOKEN = 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const GITHUB_PAT = 'github_pat_11ABCDEFG0abcdefghijk_LmNoPqRsTuVwXyZ0123456789';
const NPM_TOKEN = 'npm_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const GOOGLE_OAUTH = 'ya29.a0AfH6SMBExampleTokenValue1234567890';
const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const POSTGRES_URL = 'postgres://app_user:s3cr3t@db.internal:5432/production';
const PEM_KEY = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIEowIBAAKCAQEAx4fmExampleKeyMaterialNotReal0123456789abcdef',
  '-----END RSA PRIVATE KEY-----',
].join('\n');

/** Convenience: just the type strings, in the order returned. */
function typesOf(text) {
  return detectSensitiveData(text).map((finding) => finding.type);
}

describe('PRIVATE_KEY detection', () => {
  it.each([
    ['RSA PEM block', PEM_KEY],
    ['generic PKCS#8 header', '-----BEGIN PRIVATE KEY-----\nMIIEvQ...'],
    ['EC key header', '-----BEGIN EC PRIVATE KEY-----'],
    ['OpenSSH key header', '-----BEGIN OPENSSH PRIVATE KEY-----'],
    ['encrypted key header', '-----BEGIN ENCRYPTED PRIVATE KEY-----'],
    ['PGP key block', '-----BEGIN PGP PRIVATE KEY BLOCK-----'],
    ['PuTTY key file', 'PuTTY-User-Key-File-2: ssh-rsa'],
  ])('detects a %s', (_label, text) => {
    expect(typesOf(text)).toContain(SENSITIVE_TYPE.PRIVATE_KEY);
  });

  it('reports PRIVATE_KEY as CRITICAL', () => {
    expect(detectSensitiveData(PEM_KEY)).toEqual([
      { type: SENSITIVE_TYPE.PRIVATE_KEY, severity: SEVERITY.CRITICAL },
    ]);
  });

  it('does not fire on a public key header', () => {
    expect(typesOf('-----BEGIN PUBLIC KEY-----')).toEqual([]);
  });

  it('does not fire on a certificate header', () => {
    expect(typesOf('-----BEGIN CERTIFICATE-----')).toEqual([]);
  });
});

describe('DATABASE_URL detection', () => {
  it.each([
    ['PostgreSQL', POSTGRES_URL],
    ['postgresql scheme', 'postgresql://u:p@localhost/db'],
    ['MySQL', 'mysql://root:root@127.0.0.1:3306/wordpress'],
    ['MariaDB', 'mariadb://admin:pw@10.0.0.4/shop'],
    ['MongoDB SRV', 'mongodb+srv://u:p@cluster0.abc.mongodb.net/test?retryWrites=true'],
    ['Redis', 'rediss://default:token@cache.internal:6380'],
    ['SQL Server', 'sqlserver://sa:pw@10.0.0.9:1433;databaseName=app'],
    ['JDBC', 'jdbc:postgresql://db.internal:5432/production'],
    ['AMQP', 'amqps://guest:guest@rabbit.internal:5671'],
  ])('detects a %s connection string', (_label, text) => {
    expect(typesOf(text)).toContain(SENSITIVE_TYPE.DATABASE_URL);
  });

  it('reports DATABASE_URL as CRITICAL', () => {
    const finding = detectSensitiveData('mongodb://host/db').find(
      (f) => f.type === SENSITIVE_TYPE.DATABASE_URL,
    );

    expect(finding).toEqual({ type: SENSITIVE_TYPE.DATABASE_URL, severity: SEVERITY.CRITICAL });
  });

  it('does not fire on an ordinary https link', () => {
    expect(typesOf('The runbook lives at https://wiki.example.com/db/setup')).toEqual([]);
  });

  it('does not fire on the word postgres in prose', () => {
    expect(typesOf('We migrated from postgres 14 to postgres 16 last quarter.')).toEqual([]);
  });
});

describe('API_KEY detection', () => {
  it.each([
    ['AWS access key ID', `AWS_ACCESS_KEY_ID=${AWS_KEY}`],
    ['bare AWS key', AWS_KEY],
    ['AWS temporary key', 'ASIAIOSFODNN7EXAMPLE'],
    ['Google API key', GOOGLE_API_KEY],
    ['Stripe live key', STRIPE_KEY],
    ['Stripe restricted key', 'rk_test_51H8xExampleKey0123456789'],
    ['SendGrid key', SENDGRID_KEY],
    ['OpenAI/Anthropic-style key', OPENAI_KEY],
    ['generic api_key assignment', 'api_key=8f4b2c9e1d7a3056'],
    ['generic API-KEY assignment', 'API-KEY: 8f4b2c9e1d7a3056'],
    ['prefixed env var', 'STRIPE_SECRET_KEY=8f4b2c9e1d7a3056'],
    ['JSON client secret', '{"client_secret": "8f4b2c9e1d7a3056"}'],
    ['YAML apiKey', 'apiKey: 8f4b2c9e1d7a3056'],
  ])('detects a %s', (_label, text) => {
    expect(typesOf(text)).toContain(SENSITIVE_TYPE.API_KEY);
  });

  it('reports API_KEY as HIGH', () => {
    expect(detectSensitiveData(AWS_KEY)).toEqual([
      { type: SENSITIVE_TYPE.API_KEY, severity: SEVERITY.HIGH },
    ]);
  });

  it('does not fire on the phrase "API key" in prose', () => {
    expect(typesOf('The API key is stored in Vault, ask the platform team.')).toEqual([]);
  });

  it.each([
    ['an angle-bracket placeholder', 'api_key=<your-api-key-here>'],
    ['a template variable', 'api_key=${API_KEY}'],
    ['a mustache placeholder', 'api_key={{api_key}}'],
    ['a masked value', 'api_key=****************'],
    ['a redaction marker', 'api_key=REDACTED'],
  ])('does not fire on %s', (_label, text) => {
    expect(typesOf(text)).toEqual([]);
  });

  it('does not fire on a too-short value', () => {
    expect(typesOf('api_key=abc')).toEqual([]);
  });
});

describe('OAUTH_TOKEN detection', () => {
  it.each([
    ['Slack bot token', SLACK_TOKEN],
    ['GitHub PAT', GITHUB_TOKEN],
    ['GitHub fine-grained PAT', GITHUB_PAT],
    ['npm token', NPM_TOKEN],
    ['Google OAuth token', GOOGLE_OAUTH],
    ['JWT', JWT],
    ['Authorization header', 'Authorization: Bearer abcdef0123456789abcdef0123456789'],
    ['access_token assignment', 'access_token=abcdef0123456789'],
    ['refresh token JSON', '{"refresh_token": "abcdef0123456789"}'],
  ])('detects a %s', (_label, text) => {
    expect(typesOf(text)).toContain(SENSITIVE_TYPE.OAUTH_TOKEN);
  });

  it('reports OAUTH_TOKEN as HIGH', () => {
    expect(detectSensitiveData(JWT)).toEqual([
      { type: SENSITIVE_TYPE.OAUTH_TOKEN, severity: SEVERITY.HIGH },
    ]);
  });

  it('does not fire on the word token in prose', () => {
    expect(typesOf('Your token expires after an hour, then you re-authenticate.')).toEqual([]);
  });

  it('does not mistake a dotted filename for a JWT', () => {
    expect(typesOf('See eyes.wide.shut for details')).toEqual([]);
  });
});

describe('PASSWORD detection', () => {
  it.each([
    ['env-style assignment', 'DB_PASSWORD=Tr0ub4dor&3'],
    ['lowercase assignment', 'password=hunter2'],
    ['JSON field', '{"password": "hunter2"}'],
    ['YAML field', 'password: hunter2'],
    ['pwd abbreviation', 'pwd=hunter2'],
    ['passwd abbreviation', 'passwd=hunter2'],
    ['credentials embedded in a URL', 'https://deploy:s3cr3tvalue@git.internal/repo.git'],
    ['FTP credentials', 'ftp://backup:archive99@files.internal'],
  ])('detects a %s', (_label, text) => {
    expect(typesOf(text)).toContain(SENSITIVE_TYPE.PASSWORD);
  });

  it('reports PASSWORD as MEDIUM', () => {
    expect(detectSensitiveData('password=hunter2')).toEqual([
      { type: SENSITIVE_TYPE.PASSWORD, severity: SEVERITY.MEDIUM },
    ]);
  });

  it('does not fire on the word password in prose', () => {
    expect(typesOf('Please rotate your password before Friday.')).toEqual([]);
  });

  it.each([
    ['a placeholder', 'password=<your-password>'],
    ['a masked value', 'password=********'],
    ['an env template', 'password=${DB_PASSWORD}'],
    ['a too-short value', 'pwd=ab'],
  ])('does not fire on %s', (_label, text) => {
    expect(typesOf(text)).toEqual([]);
  });
});

describe('safe input', () => {
  it.each([
    ['an empty string', ''],
    ['null', null],
    ['undefined', undefined],
    ['whitespace only', '   \n\t  '],
    ['a plain sentence', 'Meeting moved to 3pm in the small room.'],
    ['a shopping list', 'milk, eggs, bread, coffee beans'],
    ['a public URL', 'Docs: https://example.com/getting-started'],
    ['a code snippet with no secrets', 'const total = items.reduce((a, b) => a + b, 0);'],
    ['a UUID', '550e8400-e29b-41d4-a716-446655440000'],
    ['an IP address and port', 'Service is on 10.0.0.4:8080'],
  ])('returns [] for %s', (_label, text) => {
    expect(detectSensitiveData(text)).toEqual([]);
  });

  it('throws a TypeError for a non-string input', () => {
    expect(() => detectSensitiveData(42)).toThrow(TypeError);
    expect(() => detectSensitiveData({ secret: 'x' })).toThrow(TypeError);
  });
});

describe('deduplication', () => {
  it('reports API_KEY once for three distinct API keys', () => {
    const text = `${AWS_KEY}\n${GOOGLE_API_KEY}\n${STRIPE_KEY}`;

    expect(detectSensitiveData(text)).toEqual([
      { type: SENSITIVE_TYPE.API_KEY, severity: SEVERITY.HIGH },
    ]);
  });

  it('reports OAUTH_TOKEN once when several token formats appear', () => {
    const text = `${SLACK_TOKEN}\n${GITHUB_TOKEN}\n${JWT}\n${NPM_TOKEN}`;

    expect(detectSensitiveData(text)).toEqual([
      { type: SENSITIVE_TYPE.OAUTH_TOKEN, severity: SEVERITY.HIGH },
    ]);
  });

  it('never returns the same type twice, whatever the input', () => {
    const kitchenSink = [PEM_KEY, POSTGRES_URL, AWS_KEY, AWS_KEY, JWT, JWT, 'password=hunter2'].join(
      '\n',
    );
    const types = typesOf(kitchenSink);

    expect(new Set(types).size).toBe(types.length);
  });
});

describe('multi-category detection', () => {
  const envFile = [
    '# production environment',
    'DATABASE_URL=postgres://app_user:s3cr3t@db.internal:5432/production',
    `AWS_ACCESS_KEY_ID=${AWS_KEY}`,
    `SLACK_BOT_TOKEN=${SLACK_TOKEN}`,
    'ADMIN_PASSWORD=Tr0ub4dor&3',
    'SSH_KEY="-----BEGIN OPENSSH PRIVATE KEY-----"',
  ].join('\n');

  it('finds all five categories in a realistic .env file', () => {
    expect(new Set(typesOf(envFile))).toEqual(
      new Set([
        SENSITIVE_TYPE.PRIVATE_KEY,
        SENSITIVE_TYPE.DATABASE_URL,
        SENSITIVE_TYPE.API_KEY,
        SENSITIVE_TYPE.OAUTH_TOKEN,
        SENSITIVE_TYPE.PASSWORD,
      ]),
    );
  });

  it('orders findings most severe first, then alphabetically', () => {
    expect(typesOf(envFile)).toEqual([
      SENSITIVE_TYPE.DATABASE_URL, // CRITICAL
      SENSITIVE_TYPE.PRIVATE_KEY, // CRITICAL
      SENSITIVE_TYPE.API_KEY, // HIGH
      SENSITIVE_TYPE.OAUTH_TOKEN, // HIGH
      SENSITIVE_TYPE.PASSWORD, // MEDIUM
    ]);
  });

  it('returns findings in non-increasing severity rank', () => {
    const ranks = detectSensitiveData(envFile).map((f) => SEVERITY_RANK[f.severity]);

    expect(ranks).toEqual([...ranks].sort((a, b) => b - a));
  });

  it('returns findings shaped exactly { type, severity }', () => {
    for (const finding of detectSensitiveData(envFile)) {
      expect(Object.keys(finding).sort()).toEqual(['severity', 'type']);
    }
  });
});

describe('purity and statelessness', () => {
  it('returns an identical result when called repeatedly on the same input', () => {
    const text = `${JWT}\n${POSTGRES_URL}`;
    const first = detectSensitiveData(text);

    for (let i = 0; i < 5; i += 1) {
      expect(detectSensitiveData(text)).toEqual(first);
    }
  });

  it('does not let one call influence the next', () => {
    const before = detectSensitiveData(AWS_KEY);
    detectSensitiveData(`${PEM_KEY}\n${POSTGRES_URL}\n${JWT}`);

    expect(detectSensitiveData(AWS_KEY)).toEqual(before);
  });

  it('returns a fresh array each call, so callers cannot corrupt shared state', () => {
    const first = detectSensitiveData(AWS_KEY);
    first.push({ type: 'INJECTED', severity: 'CRITICAL' });

    expect(detectSensitiveData(AWS_KEY)).toHaveLength(1);
  });

  it('does not mutate the input string', () => {
    const text = `${POSTGRES_URL} ${JWT}`;
    const copy = `${text}`;
    detectSensitiveData(text);

    expect(text).toBe(copy);
  });
});

describe('plaintext confidentiality', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('writes nothing to the console', () => {
    const spies = ['log', 'info', 'warn', 'error', 'debug', 'trace'].map((method) =>
      vi.spyOn(console, method).mockImplementation(() => {}),
    );

    detectSensitiveData([PEM_KEY, POSTGRES_URL, AWS_KEY, JWT, 'password=hunter2'].join('\n'));

    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });

  it('never returns the matched text in a finding', () => {
    const text = `${POSTGRES_URL}\n${AWS_KEY}\npassword=hunter2`;
    const serialized = JSON.stringify(detectSensitiveData(text));

    expect(serialized).not.toContain('s3cr3t');
    expect(serialized).not.toContain(AWS_KEY);
    expect(serialized).not.toContain('hunter2');
    expect(serialized).not.toContain('db.internal');
  });

  it('performs no network call (fetch is untouched)', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('network access attempted');
    });

    detectSensitiveData(`${PEM_KEY}\n${POSTGRES_URL}`);

    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('scale', () => {
  it('handles a 200KB document without hanging', () => {
    const haystack = `${'lorem ipsum dolor sit amet '.repeat(8000)}${AWS_KEY}`;

    expect(typesOf(haystack)).toEqual([SENSITIVE_TYPE.API_KEY]);
  });
});

describe('describePatterns', () => {
  it('documents every rule with a type, severity and name', () => {
    const described = describePatterns();

    expect(described.length).toBeGreaterThan(15);
    for (const entry of described) {
      expect(Object.values(SENSITIVE_TYPE)).toContain(entry.type);
      expect(Object.values(SEVERITY)).toContain(entry.severity);
      expect(entry.name).toBeTruthy();
    }
  });

  it('covers all five required categories', () => {
    const covered = new Set(describePatterns().map((entry) => entry.type));

    expect(covered).toEqual(new Set(Object.values(SENSITIVE_TYPE)));
  });

  it('exposes no compiled regex a caller could mutate', () => {
    for (const entry of describePatterns()) {
      expect(entry.pattern).toBeUndefined();
    }
  });
});
