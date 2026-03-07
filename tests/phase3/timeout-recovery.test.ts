import { describe, expect, it } from 'vitest';
import { cleanupExpiredDAKEStates, DAKEStateStatus, type DAKEState } from '$core/otr/interactive-dake.js';
import { generateKeypair } from '$core/crypto/ed448.js';
import { createNewClientProfile } from '$core/otr/client-profile.js';

describe('DAKE Timeout Recovery (3.16.1)', () => {
  it('identifies and removes expired handshake states', () => {
    const states = new Map<string, DAKEState>();

    const instance = new Uint8Array([1, 2, 3, 4]);
    const keypair = generateKeypair();
    const profile = createNewClientProfile(instance, keypair.publicKey, keypair.privateKey);

    const expiredState: DAKEState = {
      status: DAKEStateStatus.WAITING_AUTH_R,
      instanceTag: new Uint8Array([1, 2, 3, 4]),
      ourProfile: profile,
      createdAt: Date.now() - 60000,
    };

    const freshState: DAKEState = {
      status: DAKEStateStatus.WAITING_AUTH_R,
      instanceTag: new Uint8Array([5, 6, 7, 8]),
      ourProfile: profile,
      createdAt: Date.now() - 5000,
    };

    states.set('expired', expiredState);
    states.set('fresh', freshState);

    const count = cleanupExpiredDAKEStates(states, 30000);

    expect(count).toBe(1);
    expect(states.has('expired')).toBe(false);
    expect(states.has('fresh')).toBe(true);
  });
});
