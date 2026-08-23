import {
  generateKey,
  encryptSecret as encryptWithKey,
  decryptSecret as decryptWithKey,
  detectSensitiveData,
  calculateSecurityScore,
} from '../utils/index.js';

/**
 * Compatibility boundary between the UI and frontend-security utilities.
 *
 * The UI gets a simple interface while the underlying crypto utilities retain
 * their explicit key-based API.
 */
const defaultAdapter = {
  async encryptSecret(plaintext) {
    const key = await generateKey();
    const encrypted = await encryptWithKey(plaintext, key);

    return {
      ...encrypted,
      key,
    };
  },

  async decryptSecret({ encryptedContent, iv, key }) {
    return decryptWithKey(encryptedContent, iv, key);
  },

  detectSensitiveData(plaintext) {
    return detectSensitiveData(plaintext);
  },

  calculateSecurityScore({ detections, policies }) {
    const expiration = policies?.expiration || '';
    const amount = Number(expiration.slice(0, -1));
    const unit = expiration.slice(-1);

    const unitHours = {
      m: 1 / 60,
      h: 1,
      d: 24,
    };

    const expireHours =
      Number.isFinite(amount) && unitHours[unit]
        ? amount * unitHours[unit]
        : undefined;

    return calculateSecurityScore(
      {
        hasPassword: Boolean(policies?.passwordEnabled),
        expireHours,
        burnAfterReading: policies?.burnAfterReading,
        maxViews: policies?.maxViews,
      },
      detections,
    );
  },
};

let activeAdapter = defaultAdapter;

export function configureSecurityAdapter(adapter) {
  activeAdapter = adapter;
}

export function getSecurityAdapter() {
  return activeAdapter;
}
