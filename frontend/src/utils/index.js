/**
 * CipherDrop — frontend security utilities.
 *
 * Single import path for the UI layer:
 *
 *   import { encryptSecret, buildShareUrl, detectSensitiveData } from '../utils';
 *
 * Exports are listed explicitly rather than with `export *`, so the public
 * surface of this track is a deliberate, reviewable list. Anything not named
 * here is internal and may change without warning.
 *
 * Nothing in these modules touches React, the network, or browser storage.
 */

// --- Cryptography ---------------------------------------------------------
export {
  generateKey,
  encryptSecret,
  decryptSecret,
  // Base64 helpers, exported for callers that need to handle raw bytes.
  bytesToBase64,
  bytesToBase64Url,
  base64ToBytes,
  // Errors — SecretViewer needs DecryptionError to tell a broken link apart
  // from a genuine backend failure.
  CipherDropCryptoError,
  CryptoUnavailableError,
  InvalidKeyError,
  DecryptionError,
} from './encryption.js';

// --- Share and management URLs --------------------------------------------
export {
  buildShareUrl,
  parseShareUrl,
  buildManagementUrl,
  parseManagementUrl,
  CipherDropUrlError,
  ShareUrlError,
  ManagementUrlError,
} from './urlHandler.js';

// --- Sensitive data detection ---------------------------------------------
export {
  detectSensitiveData,
  describePatterns,
  SENSITIVE_TYPE,
  SEVERITY,
  SEVERITY_RANK,
} from './sensitiveDetector.js';

// --- Security score -------------------------------------------------------
export {
  calculateSecurityScore,
  explainSecurityScore,
  SCORE_WEIGHTS,
  MIN_SCORE,
  MAX_SCORE,
  SINGLE_VIEW,
  MANY_VIEWS_THRESHOLD,
  SHORT_EXPIRY_HOURS,
} from './securityScore.js';

// --- Security advisor -----------------------------------------------------
export { getRecommendations, RECOMMENDATION_PROFILE } from './securityAdvisor.js';
