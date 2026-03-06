import { describe, expect, it } from 'vitest';
import {
  serializeHeader,
  deserializeHeader,
  serializeDataMessage,
  deserializeDataMessage,
  serializeClientProfile,
  deserializeClientProfile,
  serializeTLVs,
  deserializeTLVs,
  OTRv4MessageType,
  PROTOCOL_VERSION,
} from '$core/otr/wire.js';

describe('phase 3.14 — OTRv4 Header Serialization', () => {
  it('serializes a standard header correctly (4 bytes type, 4 bytes tag)', () => {
    const instanceTag = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const header = {
      protocolVersion: PROTOCOL_VERSION,
      messageType: OTRv4MessageType.DATA,
      instanceTag,
    };

    const bytes = serializeHeader(header);
    expect(bytes).toBeInstanceOf(Uint8Array);
    // 0x04 (version) + 0x06 (Data type) + [01,02,03,04] = 6 bytes
    expect(bytes.byteLength).toBe(6);
    expect(bytes[0]).toBe(0x04);
    expect(bytes[1]).toBe(0x06);
    expect(bytes.slice(2)).toEqual(instanceTag);
  });

  it('deserializes a header from a buffer', () => {
    const raw = new Uint8Array([0x04, 0x03, 0xaa, 0xbb, 0xcc, 0xdd]);
    const header = deserializeHeader(raw);
    expect(header.protocolVersion).toBe(4);
    expect(header.messageType).toBe(OTRv4MessageType.DAKE_IDENTITY);
    expect(header.instanceTag).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]));
  });

  it('throws for invalid protocol versions during deserialization', () => {
    const badRaw = new Uint8Array([0x03, 0x06, 0x00, 0x00, 0x00, 0x00]);
    expect(() => deserializeHeader(badRaw)).toThrow(/Invalid protocol version/);
  });
});

describe('phase 3.14 — OTRv4 Data Message Serialization', () => {
  it('serializes a data message correctly', () => {
    const header = {
      protocolVersion: PROTOCOL_VERSION,
      messageType: OTRv4MessageType.DATA,
      instanceTag: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
    };
    const ciphertext = new TextEncoder().encode('secret message');
    const mac = new Uint8Array(64).fill(0x55);
    const dataMessage = {
      header,
      flags: 0x00,
      ratchetKey: new Uint8Array(57).fill(0xaa),
      identifier: new Uint8Array(8).fill(0xbb),
      nonce: new Uint8Array(12).fill(0x00), // always 0 per spec
      ciphertext,
      mac,
    };

    const bytes = serializeDataMessage(dataMessage);
    expect(bytes).toBeInstanceOf(Uint8Array);
    // Header (6) + Flags (1) + RatchetKey (57) + Identifier (8) + Nonce (12) + CT Length (4) + CT (14) + MAC (64)
    // = 6 + 1 + 57 + 8 + 12 + 4 + 14 + 64 = 166
    expect(bytes.byteLength).toBe(166);
    expect(bytes[0]).toBe(0x04);
    expect(bytes[1]).toBe(0x06); // Data type
  });

  it('round-trips a data message serialization', () => {
    const dataMessage = {
      header: {
        protocolVersion: PROTOCOL_VERSION,
        messageType: OTRv4MessageType.DATA,
        instanceTag: new Uint8Array([0x11, 0x22, 0x33, 0x44]),
      },
      flags: 0x01,
      ratchetKey: new Uint8Array(57).fill(0x11),
      identifier: new Uint8Array(8).fill(0x22),
      nonce: new Uint8Array(12).fill(0x00),
      ciphertext: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
      mac: new Uint8Array(64).fill(0xff),
    };

    const bytes = serializeDataMessage(dataMessage);
    const decoded = deserializeDataMessage(bytes);

    expect(decoded.header.instanceTag).toEqual(dataMessage.header.instanceTag);
    expect(decoded.flags).toBe(dataMessage.flags);
    expect(decoded.ratchetKey).toEqual(dataMessage.ratchetKey);
    expect(decoded.identifier).toEqual(dataMessage.identifier);
    expect(decoded.nonce).toEqual(dataMessage.nonce);
    expect(decoded.ciphertext).toEqual(dataMessage.ciphertext);
    expect(decoded.mac).toEqual(dataMessage.mac);
  });
});

describe('phase 3.14 — OTRv4 Client Profile Serialization', () => {
  it('round-trips a client profile correctly', () => {
    const profile = {
      instanceTag: new Uint8Array([0x0a, 0x0b, 0x0c, 0x0d]),
      publicKey: new Uint8Array(57).fill(0x33),
      forgingKey: new Uint8Array(57).fill(0x44),
      expiration: BigInt(Math.floor(Date.now() / 1000) + 604800), // 1 week
      signature: new Uint8Array(114).fill(0x55),
    };

    const bytes = serializeClientProfile(profile);
    expect(bytes.byteLength).toBe(4 + 57 + 57 + 8 + 114);

    const decoded = deserializeClientProfile(bytes);
    expect(decoded.instanceTag).toEqual(profile.instanceTag);
    expect(decoded.publicKey).toEqual(profile.publicKey);
    expect(decoded.forgingKey).toEqual(profile.forgingKey);
    expect(decoded.expiration).toBe(profile.expiration);
    expect(decoded.signature).toEqual(profile.signature);
  });
});

describe('phase 3.14 — OTRv4 TLV Serialization', () => {
  it('round-trips multiple TLV records correctly', () => {
    const tlvs = [
      { type: 0x0001, value: new Uint8Array([0x01, 0x02]) },
      { type: 0x0005, value: new Uint8Array([0xff, 0xee, 0xdd]) },
    ];

    const bytes = serializeTLVs(tlvs);
    // (2 + 2 + 2) + (2 + 2 + 3) = 6 + 7 = 13
    expect(bytes.byteLength).toBe(13);

    const decoded = deserializeTLVs(bytes);
    expect(decoded).toHaveLength(2);
    expect(decoded[0]!.type).toBe(0x0001);
    expect(decoded[0]!.value).toEqual(new Uint8Array([0x01, 0x02]));
    expect(decoded[1]!.type).toBe(0x0005);
    expect(decoded[1]!.value).toEqual(new Uint8Array([0xff, 0xee, 0xdd]));
  });

  it('handles empty TLV list', () => {
    const bytes = serializeTLVs([]);
    expect(bytes.byteLength).toBe(0);
    const decoded = deserializeTLVs(bytes);
    expect(decoded).toHaveLength(0);
  });

  it('throws for truncated TLV buffer', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0x00, 0x05, 0xaa, 0xbb]); // claims 5 bytes, only has 2
    expect(() => deserializeTLVs(bytes)).toThrow(/TLV length 5 exceeds remaining buffer/);
  });
});
