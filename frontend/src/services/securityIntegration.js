/**
 * Explicit boundary for the frontend-security teammate's implementation.
 * This module intentionally contains no cryptography, detection, or scoring.
 *
 * Expected adapter contract:
 * - encryptSecret(plaintext) -> { encryptedContent, iv, key }
 * - decryptSecret({ encryptedContent, iv, key }) -> plaintext
 * - detectSensitiveData(plaintext) -> detection[]
 * - calculateSecurityScore({ detections, policies }) -> number | score object
 *
 * The security branch can register its implementation during integration with
 * configureSecurityAdapter(adapter), without changing page/component APIs.
 */
let activeAdapter = null;

export function configureSecurityAdapter(adapter) {
  activeAdapter = adapter;
}

export function getSecurityAdapter() {
  return activeAdapter;
}
