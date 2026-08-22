/**
 * Guards the barrel file. The other suites import the modules directly, so
 * without this file a broken re-export in index.js would go unnoticed until
 * the UI failed at runtime.
 */
import { describe, expect, it } from 'vitest';

import * as utils from './index.js';

const EXPECTED_FUNCTIONS = [
  // encryption
  'generateKey',
  'encryptSecret',
  'decryptSecret',
  'bytesToBase64',
  'bytesToBase64Url',
  'base64ToBytes',
  // urlHandler
  'buildShareUrl',
  'parseShareUrl',
  'buildManagementUrl',
  'parseManagementUrl',
  // sensitiveDetector
  'detectSensitiveData',
  'describePatterns',
  // securityScore
  'calculateSecurityScore',
  'explainSecurityScore',
  // securityAdvisor
  'getRecommendations',
];

const EXPECTED_ERROR_CLASSES = [
  'CipherDropCryptoError',
  'CryptoUnavailableError',
  'InvalidKeyError',
  'DecryptionError',
  'CipherDropUrlError',
  'ShareUrlError',
  'ManagementUrlError',
];

const EXPECTED_CONSTANTS = [
  'SENSITIVE_TYPE',
  'SEVERITY',
  'SEVERITY_RANK',
  'SCORE_WEIGHTS',
  'MIN_SCORE',
  'MAX_SCORE',
  'SINGLE_VIEW',
  'MANY_VIEWS_THRESHOLD',
  'SHORT_EXPIRY_HOURS',
  'RECOMMENDATION_PROFILE',
];

describe('barrel exports', () => {
  it.each(EXPECTED_FUNCTIONS)('exports %s as a function', (name) => {
    expect(typeof utils[name]).toBe('function');
  });

  it.each(EXPECTED_ERROR_CLASSES)('exports %s as an Error subclass', (name) => {
    expect(typeof utils[name]).toBe('function');
    expect(Object.create(utils[name].prototype)).toBeInstanceOf(Error);
  });

  it.each(EXPECTED_CONSTANTS)('exports the constant %s', (name) => {
    expect(utils[name]).toBeDefined();
  });

  it('exports nothing beyond the documented surface', () => {
    const documented = new Set([
      ...EXPECTED_FUNCTIONS,
      ...EXPECTED_ERROR_CLASSES,
      ...EXPECTED_CONSTANTS,
    ]);

    expect(Object.keys(utils).filter((name) => !documented.has(name))).toEqual([]);
  });
});

describe('the full creator flow through the barrel', () => {
  it('detects, advises, scores, encrypts and builds a share link', async () => {
    const plaintext = 'AKIAIOSFODNN7EXAMPLE';

    const findings = utils.detectSensitiveData(plaintext);
    expect(findings).toEqual([
      { type: utils.SENSITIVE_TYPE.API_KEY, severity: utils.SEVERITY.HIGH },
    ]);

    const recommended = utils.getRecommendations(findings);
    expect(recommended.hasPassword).toBe(true);
    expect(utils.calculateSecurityScore(recommended, findings)).toBe(utils.MAX_SCORE);

    const key = await utils.generateKey();
    const { encryptedContent, iv } = await utils.encryptSecret(plaintext, key);
    expect(encryptedContent).not.toContain(plaintext);

    const shareUrl = utils.buildShareUrl('https://cipherdrop.app', 'abc123', key);
    expect(shareUrl.split('#')[0]).toBe('https://cipherdrop.app/s/abc123');

    // Recipient side.
    const { id, key: keyFromLink } = utils.parseShareUrl(shareUrl);
    expect(id).toBe('abc123');
    expect(await utils.decryptSecret(encryptedContent, iv, keyFromLink)).toBe(plaintext);
  });

  it('surfaces a tampered link as a DecryptionError through the barrel', async () => {
    const key = await utils.generateKey();
    const wrongKey = await utils.generateKey();
    const { encryptedContent, iv } = await utils.encryptSecret('hello', key);

    await expect(utils.decryptSecret(encryptedContent, iv, wrongKey)).rejects.toBeInstanceOf(
      utils.DecryptionError,
    );
  });
});
