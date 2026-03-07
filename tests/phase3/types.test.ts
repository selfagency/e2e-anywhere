import { OTRv4MessageType, PROTOCOL_VERSION } from '$core/types.js';
import { describe, expect, it } from 'vitest';

describe('OTRv4 Types', () => {
  it('should have correct protocol version 4', () => {
    // Cast explicitly if necessary for comparison
    const version: number = PROTOCOL_VERSION;
    expect(version).toBe(4);
  });

  it('should have the expected message type constants from spec', () => {
    // Spec:
    // 0x01: Client Profile
    // 0x06: Data
    expect(OTRv4MessageType.CLIENT_PROFILE).toBe(0x01);
    expect(OTRv4MessageType.QUERY).toBe(0x02);
    expect(OTRv4MessageType.DATA).toBe(0x06);
  });
});
