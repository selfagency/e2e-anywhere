import { describe, it, expect, vi, beforeAll } from 'vitest';
import { createClientProfile, validateClientProfile, createNewClientProfile } from '$core/otr/client-profile.js';
import { generateKeypair } from '$core/crypto/ed448.js';

/**
 * Client Profile Lifecycle Tests (tests/phase3/profile.test.ts)
 */

describe('Client Profile Lifecycle', () => {
  let identityKeys: { publicKey: Uint8Array; privateKey: Uint8Array };
  let forgingKeys: { publicKey: Uint8Array; privateKey: Uint8Array };
  const instanceTag = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

  beforeAll(() => {
    identityKeys = generateKeypair();
    forgingKeys = generateKeypair();
  });

  it('creates and validates a valid client profile', () => {
    const profile = createClientProfile(
      instanceTag,
      identityKeys.publicKey,
      forgingKeys.publicKey,
      identityKeys.privateKey,
    );

    expect(profile.instanceTag).toEqual(instanceTag);
    expect(profile.publicKey).toEqual(identityKeys.publicKey);
    expect(profile.forgingKey).toEqual(forgingKeys.publicKey);
    expect(profile.signature.byteLength).toBe(114);
    expect(profile.expiration).toBeGreaterThan(BigInt(Math.floor(Date.now() / 1000)));

    const isValid = validateClientProfile(profile);
    expect(isValid).toBe(true);
  });

  it('performs full lifecycle including forging key generation', () => {
    const { profile, forgingSecret } = createNewClientProfile(
      instanceTag,
      identityKeys.publicKey,
      identityKeys.privateKey,
    );

    expect(profile.publicKey).toEqual(identityKeys.publicKey);
    expect(forgingSecret.byteLength).toBe(57);
    expect(validateClientProfile(profile)).toBe(true);

    // Manual cleanup simulation
    forgingSecret.fill(0);
    expect(forgingSecret).toEqual(new Uint8Array(57).fill(0));
  });

  it('rejects an expired client profile', () => {
    // Create a profile that expired 1 second ago
    const pastExpiration = BigInt(Math.floor(Date.now() / 1000) - 1);

    const profile = createClientProfile(
      instanceTag,
      identityKeys.publicKey,
      forgingKeys.publicKey,
      identityKeys.privateKey,
      pastExpiration,
    );

    const isValid = validateClientProfile(profile);
    expect(isValid).toBe(false);
  });

  it('rejects a profile with an invalid signature', () => {
    const profile = createClientProfile(
      instanceTag,
      identityKeys.publicKey,
      forgingKeys.publicKey,
      identityKeys.privateKey,
    );

    // Tamper with the signature
    profile.signature[0] ^= 0xff;

    const isValid = validateClientProfile(profile);
    expect(isValid).toBe(false);
  });

  it('rejects a profile if fields are tampered with', () => {
    const profile = createClientProfile(
      instanceTag,
      identityKeys.publicKey,
      forgingKeys.publicKey,
      identityKeys.privateKey,
    );

    // Tamper with the instance tag
    profile.instanceTag[0] ^= 0xff;

    const isValid = validateClientProfile(profile);
    expect(isValid).toBe(false);
  });

  it('validates 1-week default expiration', () => {
    vi.useFakeTimers();
    const startTime = 1000000000000; // Fixed timestamp
    vi.setSystemTime(startTime);

    const profile = createClientProfile(
      instanceTag,
      identityKeys.publicKey,
      forgingKeys.publicKey,
      identityKeys.privateKey,
    );

    const expectedExpiration = BigInt(Math.floor(startTime / 1000) + 7 * 24 * 60 * 60);
    expect(profile.expiration).toBe(expectedExpiration);

    vi.useRealTimers();
  });
});
