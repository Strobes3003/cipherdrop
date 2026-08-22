import { describe, expect, it } from 'vitest';

import { SENSITIVE_TYPE, SEVERITY, detectSensitiveData } from './sensitiveDetector.js';
import {
  MAX_SCORE,
  MIN_SCORE,
  SCORE_WEIGHTS,
  calculateSecurityScore,
  explainSecurityScore,
} from './securityScore.js';

/** Policies as the Create page renders them before the user touches anything. */
const NO_POLICIES = {
  hasPassword: false,
  expireHours: 168,
  burnAfterReading: false,
  maxViews: 5,
};

/** Everything the user can switch on. */
const MAX_POLICIES = {
  hasPassword: true,
  expireHours: 24,
  burnAfterReading: true,
  maxViews: 1,
};

const CRITICAL = [{ type: SENSITIVE_TYPE.PRIVATE_KEY, severity: SEVERITY.CRITICAL }];
const HIGH = [{ type: SENSITIVE_TYPE.API_KEY, severity: SEVERITY.HIGH }];
const MEDIUM = [{ type: SENSITIVE_TYPE.PASSWORD, severity: SEVERITY.MEDIUM }];

describe('the four acceptance scenarios', () => {
  it('scores 100 for benign text with no policies', () => {
    expect(calculateSecurityScore(NO_POLICIES, [])).toBe(100);
  });

  it('scores 60 for CRITICAL data with no policies', () => {
    expect(calculateSecurityScore(NO_POLICIES, CRITICAL)).toBe(60);
  });

  it('restores 100 for CRITICAL data with maximum protections', () => {
    expect(calculateSecurityScore(MAX_POLICIES, CRITICAL)).toBe(100);
  });

  it('clamps strictly between 0 and 100', () => {
    const worst = { hasPassword: false, expireHours: 8760, burnAfterReading: false, maxViews: 1000 };
    const best = { ...MAX_POLICIES, expireHours: 1 };

    expect(calculateSecurityScore(worst, CRITICAL)).toBeGreaterThanOrEqual(MIN_SCORE);
    expect(calculateSecurityScore(best, [])).toBeLessThanOrEqual(MAX_SCORE);
  });
});

describe('sensitivity penalty', () => {
  it('subtracts 40 for a CRITICAL finding', () => {
    expect(calculateSecurityScore(NO_POLICIES, CRITICAL)).toBe(100 - 40);
  });

  it('subtracts 20 for a HIGH finding', () => {
    expect(calculateSecurityScore(NO_POLICIES, HIGH)).toBe(100 - 20);
  });

  it('subtracts nothing for a MEDIUM finding', () => {
    expect(calculateSecurityScore(NO_POLICIES, MEDIUM)).toBe(100);
  });

  it('subtracts nothing for no findings', () => {
    expect(calculateSecurityScore(NO_POLICIES, [])).toBe(100);
  });

  it('applies only the CRITICAL penalty when both severities are present', () => {
    expect(calculateSecurityScore(NO_POLICIES, [...CRITICAL, ...HIGH, ...MEDIUM])).toBe(60);
  });

  it('does not stack penalties across several CRITICAL findings', () => {
    const many = [...CRITICAL, ...CRITICAL, ...CRITICAL, ...CRITICAL];

    expect(calculateSecurityScore(NO_POLICIES, many)).toBe(60);
  });

  it('does not stack penalties across several HIGH findings', () => {
    expect(calculateSecurityScore(NO_POLICIES, [...HIGH, ...HIGH, ...HIGH])).toBe(80);
  });

  it('ignores a finding with an unrecognised severity', () => {
    expect(calculateSecurityScore(NO_POLICIES, [{ severity: 'SPICY' }])).toBe(100);
  });

  it('ignores malformed entries in the findings array', () => {
    expect(calculateSecurityScore(NO_POLICIES, [null, undefined, 'CRITICAL', 42])).toBe(100);
  });
});

describe('policy bonuses and penalties', () => {
  it('adds 15 for password protection', () => {
    expect(calculateSecurityScore({ ...NO_POLICIES, hasPassword: true }, CRITICAL)).toBe(60 + 15);
  });

  it('adds 15 for burn after reading', () => {
    expect(calculateSecurityScore({ ...NO_POLICIES, burnAfterReading: true }, CRITICAL)).toBe(
      60 + 15,
    );
  });

  it('adds 10 for a single-view limit', () => {
    expect(calculateSecurityScore({ ...NO_POLICIES, maxViews: 1 }, CRITICAL)).toBe(60 + 10);
  });

  it('adds 10 for an expiry within 24 hours', () => {
    expect(calculateSecurityScore({ ...NO_POLICIES, expireHours: 24 }, CRITICAL)).toBe(60 + 10);
  });

  it('adds 10 for a very short expiry', () => {
    expect(calculateSecurityScore({ ...NO_POLICIES, expireHours: 1 }, CRITICAL)).toBe(60 + 10);
  });

  it('adds nothing for an expiry just past the cutoff', () => {
    expect(calculateSecurityScore({ ...NO_POLICIES, expireHours: 24.5 }, CRITICAL)).toBe(60);
  });

  it('subtracts 10 for more than 10 views', () => {
    expect(calculateSecurityScore({ ...NO_POLICIES, maxViews: 11 }, CRITICAL)).toBe(60 - 10);
  });

  it('neither rewards nor penalises exactly 10 views', () => {
    expect(calculateSecurityScore({ ...NO_POLICIES, maxViews: 10 }, CRITICAL)).toBe(60);
  });

  it.each([2, 3, 5, 9])('neither rewards nor penalises %i views', (maxViews) => {
    expect(calculateSecurityScore({ ...NO_POLICIES, maxViews }, CRITICAL)).toBe(60);
  });

  it('applies every bonus together', () => {
    // 100 - 20 (HIGH) + 15 + 15 + 10 + 10 = 130 -> clamped to 100
    expect(calculateSecurityScore(MAX_POLICIES, HIGH)).toBe(100);
  });

  it('combines a bonus and the many-views penalty', () => {
    const policies = { ...NO_POLICIES, hasPassword: true, maxViews: 50 };

    expect(calculateSecurityScore(policies, CRITICAL)).toBe(60 + 15 - 10);
  });
});

describe('clamping', () => {
  it('never exceeds 100 however many protections are enabled', () => {
    expect(calculateSecurityScore(MAX_POLICIES, [])).toBe(MAX_SCORE);
  });

  it('never drops below 0', () => {
    const policies = { ...NO_POLICIES, maxViews: 1000 };

    expect(calculateSecurityScore(policies, CRITICAL)).toBe(50);
    expect(calculateSecurityScore(policies, CRITICAL)).toBeGreaterThanOrEqual(MIN_SCORE);
  });

  it('stays within bounds across an exhaustive sweep of the input space', () => {
    const findingSets = [[], MEDIUM, HIGH, CRITICAL, [...CRITICAL, ...HIGH]];
    const viewCounts = [1, 2, 10, 11, 100, 1000];
    const expiries = [0, 1, 24, 25, 168, 8760];

    for (const findings of findingSets) {
      for (const hasPassword of [true, false]) {
        for (const burnAfterReading of [true, false]) {
          for (const maxViews of viewCounts) {
            for (const expireHours of expiries) {
              const score = calculateSecurityScore(
                { hasPassword, expireHours, burnAfterReading, maxViews },
                findings,
              );

              expect(score).toBeGreaterThanOrEqual(MIN_SCORE);
              expect(score).toBeLessThanOrEqual(MAX_SCORE);
              expect(Number.isInteger(score)).toBe(true);
            }
          }
        }
      }
    }
  });
});

describe('tolerant inputs', () => {
  it.each([
    ['both arguments omitted', undefined, undefined],
    ['null policies', null, []],
    ['null findings', NO_POLICIES, null],
    ['an empty policies object', {}, []],
  ])('returns 100 with %s', (_label, policies, findings) => {
    expect(calculateSecurityScore(policies, findings)).toBe(100);
  });

  it('ignores non-numeric policy values instead of throwing', () => {
    const policies = {
      hasPassword: 'yes',
      expireHours: '24',
      burnAfterReading: 1,
      maxViews: 'one',
    };

    expect(calculateSecurityScore(policies, CRITICAL)).toBe(60);
  });

  it('ignores NaN and Infinity policy values', () => {
    const policies = { ...NO_POLICIES, expireHours: Number.NaN, maxViews: Number.POSITIVE_INFINITY };

    expect(calculateSecurityScore(policies, CRITICAL)).toBe(60);
  });

  it.each([
    ['an array of policies', []],
    ['a string of policies', 'strict'],
    ['a number of policies', 7],
  ])('throws a TypeError for %s', (_label, policies) => {
    expect(() => calculateSecurityScore(policies, [])).toThrow(TypeError);
  });

  it('throws a TypeError when findings is not an array', () => {
    expect(() => calculateSecurityScore(NO_POLICIES, { severity: SEVERITY.CRITICAL })).toThrow(
      TypeError,
    );
  });
});

describe('purity', () => {
  it('does not mutate its arguments', () => {
    const policies = { ...MAX_POLICIES };
    const findings = [...CRITICAL];

    calculateSecurityScore(policies, findings);

    expect(policies).toEqual(MAX_POLICIES);
    expect(findings).toEqual(CRITICAL);
  });

  it('returns the same score for the same input every time', () => {
    const first = calculateSecurityScore(MAX_POLICIES, CRITICAL);

    for (let i = 0; i < 5; i += 1) {
      expect(calculateSecurityScore(MAX_POLICIES, CRITICAL)).toBe(first);
    }
  });
});

describe('explainSecurityScore', () => {
  it('agrees with calculateSecurityScore', () => {
    const cases = [
      [NO_POLICIES, []],
      [NO_POLICIES, CRITICAL],
      [MAX_POLICIES, CRITICAL],
      [{ ...NO_POLICIES, maxViews: 50 }, HIGH],
    ];

    for (const [policies, findings] of cases) {
      expect(explainSecurityScore(policies, findings).score).toBe(
        calculateSecurityScore(policies, findings),
      );
    }
  });

  it('itemises every adjustment that fired', () => {
    const { adjustments } = explainSecurityScore(MAX_POLICIES, CRITICAL);

    expect(adjustments.map((a) => a.points)).toEqual([
      SCORE_WEIGHTS.criticalFindingPenalty,
      SCORE_WEIGHTS.passwordBonus,
      SCORE_WEIGHTS.burnAfterReadingBonus,
      SCORE_WEIGHTS.singleViewBonus,
      SCORE_WEIGHTS.shortExpiryBonus,
    ]);
  });

  it('lists nothing when no adjustment applies', () => {
    expect(explainSecurityScore(NO_POLICIES, []).adjustments).toEqual([]);
  });

  it('reports the pre-clamp total so the UI can say "already maxed out"', () => {
    const explained = explainSecurityScore(MAX_POLICIES, []);

    expect(explained.rawScore).toBe(150);
    expect(explained.score).toBe(100);
  });

  it('gives every adjustment a human-readable label', () => {
    for (const adjustment of explainSecurityScore(MAX_POLICIES, CRITICAL).adjustments) {
      expect(typeof adjustment.label).toBe('string');
      expect(adjustment.label.length).toBeGreaterThan(0);
    }
  });

  it('leaks no secret material into the labels', () => {
    const findings = detectSensitiveData('postgres://app:s3cr3t@db.internal:5432/prod');
    const serialized = JSON.stringify(explainSecurityScore(NO_POLICIES, findings));

    expect(serialized).not.toContain('s3cr3t');
    expect(serialized).not.toContain('db.internal');
  });
});

describe('integration with the detector', () => {
  it('scores a real .env paste with no policies', () => {
    const findings = detectSensitiveData('DATABASE_URL=postgres://u:p@db.internal:5432/prod');

    expect(findings[0].severity).toBe(SEVERITY.CRITICAL);
    expect(calculateSecurityScore(NO_POLICIES, findings)).toBe(60);
  });

  it('scores an AWS key paste protected by a single-view burn link', () => {
    const findings = detectSensitiveData('AKIAIOSFODNN7EXAMPLE');
    const policies = { ...NO_POLICIES, burnAfterReading: true, maxViews: 1, expireHours: 1 };

    // 100 - 20 (HIGH) + 15 (burn) + 10 (single view) + 10 (short expiry) = 115 -> 100
    expect(calculateSecurityScore(policies, findings)).toBe(100);
  });

  it('scores a harmless note at 100 regardless of policies', () => {
    const findings = detectSensitiveData('Standup moved to 10:30.');

    expect(findings).toEqual([]);
    expect(calculateSecurityScore(NO_POLICIES, findings)).toBe(100);
  });
});
