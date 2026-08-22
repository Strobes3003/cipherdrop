/**
 * CipherDrop — Security Advisor.
 *
 * Maps the detector's findings to a set of recommended policies plus the
 * human-readable reasons behind them.
 *
 * This module RECOMMENDS. It does not decide. §9 and §28.13 of the execution
 * plan are explicit that the user stays in control, so the returned object is a
 * suggestion payload for the UI to present — never state to apply silently. The
 * caller is responsible for showing the recommendation and letting the user
 * accept, adjust, or ignore it.
 *
 * Stateless and pure: no React, no storage, no network, no module-level
 * mutable state. Every call returns freshly built objects so a caller that
 * edits a recommendation cannot corrupt the next caller's copy.
 */

import { SEVERITY, SEVERITY_RANK } from './sensitiveDetector.js';

/**
 * The three recommendation profiles, keyed by the highest severity found.
 * Frozen so the templates cannot be edited at a distance; `getRecommendations`
 * copies them on the way out.
 */
export const RECOMMENDATION_PROFILE = Object.freeze({
  /** CRITICAL or HIGH — a directly usable credential. Lock it down. */
  LOCKDOWN: Object.freeze({
    hasPassword: true,
    expireHours: 24,
    burnAfterReading: true,
    maxViews: 1,
    reasons: Object.freeze([
      'Highly sensitive data detected. We strongly recommend requiring a password, ' +
        'restricting to a single view, and burning after reading.',
    ]),
  }),

  /** MEDIUM — sensitive, but weaker signal and lower blast radius. */
  ELEVATED: Object.freeze({
    hasPassword: true,
    expireHours: 24,
    burnAfterReading: false,
    maxViews: 5,
    reasons: Object.freeze([
      'Sensitive data detected. A password and short expiration time are recommended.',
    ]),
  }),

  /** Nothing detected. Sensible, unobtrusive defaults with no nagging. */
  BENIGN: Object.freeze({
    hasPassword: false,
    expireHours: 168, // 7 days
    burnAfterReading: false,
    maxViews: 100,
    reasons: Object.freeze([]),
  }),
});

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The rank of the most severe finding, or 0 when there is nothing to act on.
 * Entries that are malformed or carry an unrecognised severity are ignored
 * rather than throwing — a detector that grows a new category should not be
 * able to break the Create page.
 */
function highestSeverityRank(findings) {
  let highest = 0;
  for (const finding of findings) {
    if (!isPlainObject(finding)) {
      continue;
    }
    const rank = SEVERITY_RANK[finding.severity] ?? 0;
    if (rank > highest) {
      highest = rank;
    }
  }
  return highest;
}

function selectProfile(rank) {
  if (rank >= SEVERITY_RANK[SEVERITY.HIGH]) {
    return RECOMMENDATION_PROFILE.LOCKDOWN; // CRITICAL and HIGH share one profile
  }
  if (rank >= SEVERITY_RANK[SEVERITY.MEDIUM]) {
    return RECOMMENDATION_PROFILE.ELEVATED;
  }
  return RECOMMENDATION_PROFILE.BENIGN;
}

/**
 * Recommend policies for a secret, based on what the detector found.
 *
 * Recommendations are driven by the single highest severity present, not by how
 * many findings there are: one leaked private key already warrants the strictest
 * settings, and there is nothing stricter to escalate to for a second one.
 *
 * @param {Array<{ type?: string, severity?: string }>} findings from detectSensitiveData()
 * @returns {{ hasPassword: boolean, expireHours: number, burnAfterReading: boolean, maxViews: number, reasons: string[] }}
 * @throws {TypeError} if findings is neither an array nor null/undefined
 */
export function getRecommendations(findings) {
  let safeFindings;
  if (findings === null || findings === undefined) {
    safeFindings = [];
  } else if (Array.isArray(findings)) {
    safeFindings = findings;
  } else {
    throw new TypeError('getRecommendations expects an array of findings.');
  }

  const profile = selectProfile(highestSeverityRank(safeFindings));

  // Copied, not returned by reference: the UI binds these straight into form
  // state, and a shared object would leak one secret's edits into the next.
  return {
    hasPassword: profile.hasPassword,
    expireHours: profile.expireHours,
    burnAfterReading: profile.burnAfterReading,
    maxViews: profile.maxViews,
    reasons: [...profile.reasons],
  };
}
