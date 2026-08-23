/**
 * CipherDrop — security score.
 *
 * Turns the user's chosen policies and the detector's findings into a single
 * 0-100 number for the Security Score UI.
 *
 * The score is advisory. It never changes a policy, never blocks a share, and
 * never talks to the network — §9 and §28.13 of the execution plan require the
 * user to stay in control. It is a pure function of its two arguments.
 *
 * The weights below are the team's agreed formula (§29 leaves them to us) and
 * live in one exported object so the number in the UI and the number in the
 * docs can never drift apart.
 */

import { SEVERITY } from './sensitiveDetector.js';

/** Score bounds. */
export const MIN_SCORE = 0;
export const MAX_SCORE = 100;
const BASE_SCORE = 100;

/** View-count thresholds that trigger the bonus and the penalty. */
export const SINGLE_VIEW = 1;
export const MANY_VIEWS_THRESHOLD = 10;

/** Expiration cutoff, in hours, for the short-lifetime bonus. */
export const SHORT_EXPIRY_HOURS = 24;

/**
 * The agreed weights. Every adjustment the calculator can make is listed here;
 * nothing else moves the score.
 */
export const SCORE_WEIGHTS = Object.freeze({
  /** Highest-severity finding drives a single sensitivity penalty. */
  criticalFindingPenalty: -40,
  highFindingPenalty: -20,
  /** Policies that reduce exposure. */
  passwordBonus: 15,
  burnAfterReadingBonus: 15,
  singleViewBonus: 10,
  shortExpiryBonus: 10,
  /** A generous view budget leaves the ciphertext retrievable for longer. */
  manyViewsPenalty: -10,
});

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizePolicies(policies) {
  if (policies === null || policies === undefined) {
    return {};
  }
  if (!isPlainObject(policies)) {
    throw new TypeError('calculateSecurityScore expects policies to be an object.');
  }
  return policies;
}

function normalizeFindings(findings) {
  if (findings === null || findings === undefined) {
    return [];
  }
  if (!Array.isArray(findings)) {
    throw new TypeError('calculateSecurityScore expects findings to be an array.');
  }
  return findings;
}

/**
 * Only the most severe finding is penalised, not every finding. Sharing three
 * CRITICAL credentials is not six times worse than sharing one — the exposure
 * is already total — and stacking penalties would drive every multi-credential
 * secret to 0 regardless of how well the user protected it, which would make
 * the score useless as feedback.
 */
function sensitivityPenalty(findings) {
  const severities = new Set(
    findings.filter(isPlainObject).map((finding) => finding.severity),
  );

  if (severities.has(SEVERITY.CRITICAL)) {
    return SCORE_WEIGHTS.criticalFindingPenalty;
  }
  if (severities.has(SEVERITY.HIGH)) {
    return SCORE_WEIGHTS.highFindingPenalty;
  }
  return 0;
}

/**
 * Every adjustment for a given input, in the order the UI should list them.
 * Missing or non-numeric policy fields simply contribute nothing, so a
 * half-filled form still scores instead of throwing.
 *
 * @returns {Array<{ label: string, points: number }>}
 */
function buildAdjustments(policies, findings) {
  const { hasPassword, expireHours, burnAfterReading, maxViews } = policies;
  const adjustments = [];

  const penalty = sensitivityPenalty(findings);
  if (penalty !== 0) {
    const level =
      penalty === SCORE_WEIGHTS.criticalFindingPenalty ? SEVERITY.CRITICAL : SEVERITY.HIGH;
    adjustments.push({ label: `${level} sensitive data detected`, points: penalty });
  }

  if (hasPassword === true) {
    adjustments.push({ label: 'Password protection enabled', points: SCORE_WEIGHTS.passwordBonus });
  }

  if (burnAfterReading === true) {
    adjustments.push({
      label: 'Burn after reading enabled',
      points: SCORE_WEIGHTS.burnAfterReadingBonus,
    });
  }

  if (typeof maxViews === 'number' && Number.isFinite(maxViews)) {
    if (maxViews === SINGLE_VIEW) {
      adjustments.push({ label: 'Limited to a single view', points: SCORE_WEIGHTS.singleViewBonus });
    } else if (maxViews > MANY_VIEWS_THRESHOLD) {
      adjustments.push({
        label: `More than ${MANY_VIEWS_THRESHOLD} views allowed`,
        points: SCORE_WEIGHTS.manyViewsPenalty,
      });
    }
  }

  if (
    typeof expireHours === 'number' &&
    Number.isFinite(expireHours) &&
    expireHours <= SHORT_EXPIRY_HOURS
  ) {
    adjustments.push({
      label: `Expires within ${SHORT_EXPIRY_HOURS} hours`,
      points: SCORE_WEIGHTS.shortExpiryBonus,
    });
  }

  return adjustments;
}

function clamp(score) {
  return Math.min(MAX_SCORE, Math.max(MIN_SCORE, score));
}

/**
 * Calculate the 0-100 security score.
 *
 * @param {{ hasPassword?: boolean, expireHours?: number, burnAfterReading?: boolean, maxViews?: number }} policies
 * @param {Array<{ severity?: string }>} findings from detectSensitiveData()
 * @returns {number} an integer in [0, 100]
 * @throws {TypeError} if policies is not an object or findings is not an array
 */
export function calculateSecurityScore(policies, findings) {
  const safePolicies = normalizePolicies(policies);
  const safeFindings = normalizeFindings(findings);

  const total = buildAdjustments(safePolicies, safeFindings).reduce(
    (score, adjustment) => score + adjustment.points,
    BASE_SCORE,
  );

  return clamp(total);
}

/**
 * The same calculation, itemised, so the UI can show *why* a score is what it
 * is instead of presenting a bare number. `score` always equals
 * `calculateSecurityScore(policies, findings)`.
 *
 * `rawScore` is the total before clamping: the UI can use it to tell a user
 * whose protections already exceed 100 that adding more will not move the
 * needle.
 *
 * @returns {{ score: number, rawScore: number, baseScore: number, adjustments: Array<{ label: string, points: number }> }}
 */
export function explainSecurityScore(policies, findings) {
  const safePolicies = normalizePolicies(policies);
  const safeFindings = normalizeFindings(findings);
  const adjustments = buildAdjustments(safePolicies, safeFindings);
  const rawScore = adjustments.reduce(
    (score, adjustment) => score + adjustment.points,
    BASE_SCORE,
  );

  return {
    score: clamp(rawScore),
    rawScore,
    baseScore: BASE_SCORE,
    adjustments,
  };
}
