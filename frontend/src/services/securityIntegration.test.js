import { describe, expect, it } from 'vitest';
import { getSecurityAdapter } from './securityIntegration.js';

describe('securityIntegration adapter', () => {
  const adapter = getSecurityAdapter();

  it('converts UI policies into security-score policies', () => {
    const findings = [{ type: 'API_KEY', severity: 'HIGH' }];

    const weak = adapter.calculateSecurityScore({
      detections: findings,
      policies: {
        expiration: '7d',
        maxViews: 5,
        burnAfterReading: false,
        passwordEnabled: false,
      },
    });

    const strong = adapter.calculateSecurityScore({
      detections: findings,
      policies: {
        expiration: '1h',
        maxViews: 1,
        burnAfterReading: true,
        passwordEnabled: true,
      },
    });

    expect(weak).toBe(80);
    expect(strong).toBe(100);
  });

  it('supports minute, hour, and day expiration values', () => {
    const findings = [{ type: 'API_KEY', severity: 'HIGH' }];

    const basePolicies = {
      maxViews: 5,
      burnAfterReading: false,
      passwordEnabled: false,
    };

    const minute = adapter.calculateSecurityScore({
      detections: findings,
      policies: { ...basePolicies, expiration: '30m' },
    });

    const hour = adapter.calculateSecurityScore({
      detections: findings,
      policies: { ...basePolicies, expiration: '1h' },
    });

    const day = adapter.calculateSecurityScore({
      detections: findings,
      policies: { ...basePolicies, expiration: '1d' },
    });

    expect(minute).toBe(90);
    expect(hour).toBe(90);
    expect(day).toBe(90);
  });

  it('handles missing or invalid expiration without throwing', () => {
    const findings = [{ type: 'API_KEY', severity: 'HIGH' }];

    const missing = adapter.calculateSecurityScore({
      detections: findings,
      policies: {
        expiration: '',
        maxViews: 5,
        burnAfterReading: false,
        passwordEnabled: false,
      },
    });

    const invalid = adapter.calculateSecurityScore({
      detections: findings,
      policies: {
        expiration: 'invalid',
        maxViews: 5,
        burnAfterReading: false,
        passwordEnabled: false,
      },
    });

    expect(missing).toBe(80);
    expect(invalid).toBe(80);
  });

  it('delegates sensitive-data detection to the security utility', () => {
    const findings = adapter.detectSensitiveData('AKIAIOSFODNN7EXAMPLE');

    expect(findings).toEqual([
      {
        type: 'API_KEY',
        severity: 'HIGH',
      },
    ]);
  });

  it('encrypts and decrypts through the compatibility interface', async () => {
    const plaintext = 'CipherDrop integration test';

    const encrypted = await adapter.encryptSecret(plaintext);

    expect(encrypted.encryptedContent).not.toContain(plaintext);
    expect(encrypted.iv).toBeDefined();
    expect(encrypted.key).toBeDefined();

    const decrypted = await adapter.decryptSecret(encrypted);

    expect(decrypted).toBe(plaintext);
  });
});
