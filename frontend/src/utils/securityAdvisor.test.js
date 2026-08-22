import { describe, expect, it } from 'vitest';

import { SENSITIVE_TYPE, SEVERITY, detectSensitiveData } from './sensitiveDetector.js';
import { calculateSecurityScore } from './securityScore.js';
import { RECOMMENDATION_PROFILE, getRecommendations } from './securityAdvisor.js';

const CRITICAL = { type: SENSITIVE_TYPE.PRIVATE_KEY, severity: SEVERITY.CRITICAL };
const HIGH = { type: SENSITIVE_TYPE.API_KEY, severity: SEVERITY.HIGH };
const MEDIUM = { type: SENSITIVE_TYPE.PASSWORD, severity: SEVERITY.MEDIUM };

const LOCKDOWN = {
  hasPassword: true,
  expireHours: 24,
  burnAfterReading: true,
  maxViews: 1,
  reasons: [
    'Highly sensitive data detected. We strongly recommend requiring a password, ' +
      'restricting to a single view, and burning after reading.',
  ],
};

const ELEVATED = {
  hasPassword: true,
  expireHours: 24,
  burnAfterReading: false,
  maxViews: 5,
  reasons: ['Sensitive data detected. A password and short expiration time are recommended.'],
};

const BENIGN = {
  hasPassword: false,
  expireHours: 168,
  burnAfterReading: false,
  maxViews: 100,
  reasons: [],
};

describe('the four acceptance scenarios', () => {
  it('returns benign defaults with no reasons for an empty array', () => {
    expect(getRecommendations([])).toEqual(BENIGN);
  });

  it('returns the elevated recommendations for a MEDIUM finding', () => {
    expect(getRecommendations([MEDIUM])).toEqual(ELEVATED);
  });

  it('returns the lockdown recommendations for a CRITICAL finding', () => {
    expect(getRecommendations([CRITICAL])).toEqual(LOCKDOWN);
  });

  it('scales up to lockdown when MEDIUM and HIGH appear together', () => {
    expect(getRecommendations([MEDIUM, HIGH])).toEqual(LOCKDOWN);
  });
});

describe('severity selection', () => {
  it('treats HIGH the same as CRITICAL', () => {
    expect(getRecommendations([HIGH])).toEqual(getRecommendations([CRITICAL]));
  });

  it.each([
    ['CRITICAL alone', [CRITICAL]],
    ['HIGH alone', [HIGH]],
    ['CRITICAL and MEDIUM', [CRITICAL, MEDIUM]],
    ['MEDIUM then HIGH', [MEDIUM, HIGH]],
    ['HIGH then MEDIUM', [HIGH, MEDIUM]],
    ['all three severities', [MEDIUM, CRITICAL, HIGH]],
    ['several CRITICALs', [CRITICAL, CRITICAL, CRITICAL]],
  ])('recommends lockdown for %s', (_label, findings) => {
    expect(getRecommendations(findings)).toEqual(LOCKDOWN);
  });

  it('recommends elevated only when MEDIUM is the highest severity', () => {
    expect(getRecommendations([MEDIUM, MEDIUM])).toEqual(ELEVATED);
  });

  it('is unaffected by the order of the findings', () => {
    const forward = getRecommendations([MEDIUM, HIGH, CRITICAL]);
    const reversed = getRecommendations([CRITICAL, HIGH, MEDIUM]);

    expect(forward).toEqual(reversed);
  });

  it('does not escalate on finding count alone', () => {
    const manyMediums = Array.from({ length: 20 }, () => MEDIUM);

    expect(getRecommendations(manyMediums)).toEqual(ELEVATED);
  });
});

describe('recommendation shape', () => {
  it.each([
    ['lockdown', [CRITICAL]],
    ['elevated', [MEDIUM]],
    ['benign', []],
  ])('returns exactly the five documented keys for %s', (_label, findings) => {
    expect(Object.keys(getRecommendations(findings)).sort()).toEqual([
      'burnAfterReading',
      'expireHours',
      'hasPassword',
      'maxViews',
      'reasons',
    ]);
  });

  it('always returns an array of strings for reasons', () => {
    for (const findings of [[], [MEDIUM], [HIGH], [CRITICAL]]) {
      const { reasons } = getRecommendations(findings);

      expect(Array.isArray(reasons)).toBe(true);
      for (const reason of reasons) {
        expect(typeof reason).toBe('string');
        expect(reason.length).toBeGreaterThan(0);
      }
    }
  });

  it('gives exactly one reason whenever something was detected', () => {
    expect(getRecommendations([CRITICAL]).reasons).toHaveLength(1);
    expect(getRecommendations([MEDIUM]).reasons).toHaveLength(1);
  });

  it('gives no reason when nothing was detected', () => {
    expect(getRecommendations([]).reasons).toHaveLength(0);
  });

  it('produces policies the score calculator accepts', () => {
    for (const findings of [[], [MEDIUM], [HIGH], [CRITICAL]]) {
      const score = calculateSecurityScore(getRecommendations(findings), findings);

      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    }
  });
});

describe('tolerant inputs', () => {
  it.each([
    ['null', null],
    ['undefined', undefined],
    ['no argument at all', undefined],
  ])('falls back to benign defaults for %s', (_label, findings) => {
    expect(getRecommendations(findings)).toEqual(BENIGN);
  });

  it('ignores malformed entries', () => {
    expect(getRecommendations([null, undefined, 'CRITICAL', 42, []])).toEqual(BENIGN);
  });

  it('ignores an unrecognised severity rather than throwing', () => {
    expect(getRecommendations([{ type: 'FUTURE_TYPE', severity: 'SPICY' }])).toEqual(BENIGN);
  });

  it('still honours a valid finding alongside malformed ones', () => {
    expect(getRecommendations([null, { severity: 'SPICY' }, CRITICAL])).toEqual(LOCKDOWN);
  });

  it.each([
    ['an object', { severity: SEVERITY.CRITICAL }],
    ['a string', 'CRITICAL'],
    ['a number', 3],
  ])('throws a TypeError when findings is %s', (_label, findings) => {
    expect(() => getRecommendations(findings)).toThrow(TypeError);
  });
});

describe('purity and isolation', () => {
  it('does not mutate the findings array', () => {
    const findings = [MEDIUM, CRITICAL];
    const snapshot = JSON.stringify(findings);

    getRecommendations(findings);

    expect(JSON.stringify(findings)).toBe(snapshot);
  });

  it('returns the same recommendation every time for the same input', () => {
    const first = getRecommendations([HIGH]);

    for (let i = 0; i < 5; i += 1) {
      expect(getRecommendations([HIGH])).toEqual(first);
    }
  });

  it('returns a fresh object each call, so the UI cannot corrupt the profile', () => {
    const first = getRecommendations([CRITICAL]);
    first.hasPassword = false;
    first.maxViews = 999;
    first.reasons.push('injected');

    expect(getRecommendations([CRITICAL])).toEqual(LOCKDOWN);
  });

  it('returns a reasons array that is not shared between calls', () => {
    const a = getRecommendations([MEDIUM]);
    const b = getRecommendations([MEDIUM]);

    expect(a.reasons).not.toBe(b.reasons);
    expect(a.reasons).toEqual(b.reasons);
  });

  it('keeps the exported profiles frozen', () => {
    expect(Object.isFrozen(RECOMMENDATION_PROFILE)).toBe(true);
    expect(Object.isFrozen(RECOMMENDATION_PROFILE.LOCKDOWN)).toBe(true);
    expect(Object.isFrozen(RECOMMENDATION_PROFILE.LOCKDOWN.reasons)).toBe(true);
  });
});

describe('advisory only', () => {
  it('recommends but does not apply: two calls with different findings are independent', () => {
    const strict = getRecommendations([CRITICAL]);
    const relaxed = getRecommendations([]);

    expect(strict.hasPassword).toBe(true);
    expect(relaxed.hasPassword).toBe(false);
  });

  it('leaves the user free to score lower than recommended', () => {
    const findings = [CRITICAL];
    const userChoice = {
      hasPassword: false,
      expireHours: 168,
      burnAfterReading: false,
      maxViews: 50,
    };

    // The advisor recommends lockdown, but a user who ignores it still gets a
    // working (merely lower) score rather than being blocked.
    expect(getRecommendations(findings).hasPassword).toBe(true);
    expect(calculateSecurityScore(userChoice, findings)).toBe(50);
  });

  it('leaks no secret material into the reasons', () => {
    const findings = detectSensitiveData('postgres://app:s3cr3tvalue@db.internal:5432/prod');
    const serialized = JSON.stringify(getRecommendations(findings));

    expect(serialized).not.toContain('s3cr3tvalue');
    expect(serialized).not.toContain('db.internal');
  });
});

describe('integration with the detector', () => {
  it('recommends lockdown for a pasted private key', () => {
    const findings = detectSensitiveData('-----BEGIN OPENSSH PRIVATE KEY-----');

    expect(getRecommendations(findings)).toEqual(LOCKDOWN);
  });

  it('recommends lockdown for a pasted AWS key', () => {
    const findings = detectSensitiveData('AKIAIOSFODNN7EXAMPLE');

    expect(getRecommendations(findings)).toEqual(LOCKDOWN);
  });

  it('recommends elevated settings for a bare password assignment', () => {
    const findings = detectSensitiveData('password=hunter2');

    expect(findings).toEqual([{ type: SENSITIVE_TYPE.PASSWORD, severity: SEVERITY.MEDIUM }]);
    expect(getRecommendations(findings)).toEqual(ELEVATED);
  });

  it('recommends benign defaults for a harmless note', () => {
    const findings = detectSensitiveData('Standup moved to 10:30.');

    expect(getRecommendations(findings)).toEqual(BENIGN);
  });

  it('scores 100 when the user accepts the recommendation for critical data', () => {
    const findings = detectSensitiveData('-----BEGIN RSA PRIVATE KEY-----');
    const accepted = getRecommendations(findings);

    // 100 - 40 (CRITICAL) + 15 + 15 + 10 + 10 = 110 -> clamped to 100
    expect(calculateSecurityScore(accepted, findings)).toBe(100);
  });

  it('scores 100 when the user accepts the recommendation for medium data', () => {
    const findings = detectSensitiveData('password=hunter2');
    const accepted = getRecommendations(findings);

    // 100 - 0 (MEDIUM is not penalised) + 15 (password) + 10 (24h) = 125 -> 100
    expect(calculateSecurityScore(accepted, findings)).toBe(100);
  });
});
