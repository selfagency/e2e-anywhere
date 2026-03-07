import { describe, expect, it } from 'vitest';
import { cleanupExpiredDAKEStates, DAKEStateStatus, type DAKEState } from '$core/otr/interactive-dake.js';

describe('DAKE Timeout Recovery (3.16.1)', () => {
  it('identifies and removes expired handshake states', () => {
    const states = new Map<string, DAKEState>();

    const expiredState: DAKEState = {
      status: DAKEStateStatus.WAITING_AUTH_R,
      instanceTag: new Uint8Array([1, 2, 3, 4]),
      ourProfile: { publicKey: new Uint8Array(57) } as any,
      createdAt: Date.now() - 60000,
    };

    const freshState: DAKEState = {
      status: DAKEStateStatus.WAITING_AUTH_R,
      instanceTag: new Uint8Array([5, 6, 7, 8]),
      ourProfile: { publicKey: new Uint8Array(57) } as any,
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
