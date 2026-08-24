import {
  generateKey,
  encryptSecret as encryptWithKey,
  decryptSecret as decryptWithKey,
  detectSensitiveData,
  calculateSecurityScore,
} from '../utils/index.js';

export const securityAdapter = {
  async encryptSecret(plaintext) {
    const key = await generateKey();

    const { encryptedContent, iv } = await encryptWithKey(
      plaintext,
      key,
    );

    return {
      encryptedContent,
      iv,
      key,
    };
  },

  

  async decryptSecret({ encryptedContent, iv, key }) {
    return decryptWithKey(
      encryptedContent,
      iv,
      key,
    );
  },

  detectSensitiveData,

  calculateSecurityScore({ detections = [], policies = {} } = {}) {
    return calculateSecurityScore(policies, detections);
  },
};