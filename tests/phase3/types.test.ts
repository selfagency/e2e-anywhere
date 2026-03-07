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
  it('serializes a standard header correctly (1 byte version, 1 byte type, 4 bytes tag)', () => {
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

describe('phase 3.14 — OTRv4 wire-format rejection of malformed inputs', () => {
  it('serializeHeader throws for invalid instanceTag length', () => {
    expect(() =>
      serializeHeader({
        protocolVersion: PROTOCOL_VERSION,
        messageType: OTRv4MessageType.DATA,
        instanceTag: new Uint8Array(3), // too short
      }),
    ).toThrow(/Invalid instanceTag length/);
  });

  it('deserializeHeader throws for unknown message type', () => {
    const raw = new Uint8Array([0x04, 0xff, 0x00, 0x00, 0x00, 0x01]); // 0xff is not a valid type
    expect(() => deserializeHeader(raw)).toThrow(/Invalid message type/);
  });

  it('serializeDataMessage throws for wrong ratchetKey length', () => {
    expect(() =>
      serializeDataMessage({
        header: {
          protocolVersion: PROTOCOL_VERSION,
          messageType: OTRv4MessageType.DATA,
          instanceTag: new Uint8Array(4),
        },
        flags: 0,
        ratchetKey: new Uint8Array(56), // 56 instead of 57
        identifier: new Uint8Array(8),
        nonce: new Uint8Array(12),
        ciphertext: new Uint8Array(0),
        mac: new Uint8Array(64),
      }),
    ).toThrow(/Invalid ratchetKey length/);
  });

  it('serializeDataMessage throws for wrong identifier length', () => {
    expect(() =>
      serializeDataMessage({
        header: {
          protocolVersion: PROTOCOL_VERSION,
          messageType: OTRv4MessageType.DATA,
          instanceTag: new Uint8Array(4),
        },
        flags: 0,
        ratchetKey: new Uint8Array(57),
        identifier: new Uint8Array(7), // 7 instead of 8
        nonce: new Uint8Array(12),
        ciphertext: new Uint8Array(0),
        mac: new Uint8Array(64),
      }),
    ).toThrow(/Invalid identifier length/);
  });

  it('serializeDataMessage throws for wrong nonce length', () => {
    expect(() =>
      serializeDataMessage({
        header: {
          protocolVersion: PROTOCOL_VERSION,
          messageType: OTRv4MessageType.DATA,
          instanceTag: new Uint8Array(4),
        },
        flags: 0,
        ratchetKey: new Uint8Array(57),
        identifier: new Uint8Array(8),
        nonce: new Uint8Array(11), // 11 instead of 12
        ciphertext: new Uint8Array(0),
        mac: new Uint8Array(64),
      }),
    ).toThrow(/Invalid nonce length/);
  });

  it('serializeDataMessage throws for wrong MAC length', () => {
    expect(() =>
      serializeDataMessage({
        header: {
          protocolVersion: PROTOCOL_VERSION,
          messageType: OTRv4MessageType.DATA,
          instanceTag: new Uint8Array(4),
        },
        flags: 0,
        ratchetKey: new Uint8Array(57),
        identifier: new Uint8Array(8),
        nonce: new Uint8Array(12),
        ciphertext: new Uint8Array(0),
        mac: new Uint8Array(63), // 63 instead of 64
      }),
    ).toThrow(/Invalid MAC length/);
  });

  it('deserializeDataMessage throws for trailing bytes', () => {
    const validMsg = {
      header: { protocolVersion: PROTOCOL_VERSION, messageType: OTRv4MessageType.DATA, instanceTag: new Uint8Array(4) },
      flags: 0,
      ratchetKey: new Uint8Array(57),
      identifier: new Uint8Array(8),
      nonce: new Uint8Array(12),
      ciphertext: new Uint8Array(4),
      mac: new Uint8Array(64),
    };
    const serialized = serializeDataMessage(validMsg);
    const withTrailing = new Uint8Array(serialized.byteLength + 2);
    withTrailing.set(serialized);
    expect(() => deserializeDataMessage(withTrailing)).toThrow(/Trailing bytes in data message/);
  });

  it('serializeClientProfile throws for invalid instanceTag length', () => {
    expect(() =>
      serializeClientProfile({
        instanceTag: new Uint8Array(5), // wrong length
        publicKey: new Uint8Array(57),
        forgingKey: new Uint8Array(57),
        expiration: 0n,
        signature: new Uint8Array(114),
      }),
    ).toThrow(/Invalid instanceTag length/);
  });

  it('serializeClientProfile throws for invalid publicKey length', () => {
    expect(() =>
      serializeClientProfile({
        instanceTag: new Uint8Array(4),
        publicKey: new Uint8Array(56), // wrong length
        forgingKey: new Uint8Array(57),
        expiration: 0n,
        signature: new Uint8Array(114),
      }),
    ).toThrow(/Invalid publicKey length/);
  });

  it('serializeClientProfile throws for invalid forgingKey length', () => {
    expect(() =>
      serializeClientProfile({
        instanceTag: new Uint8Array(4),
        publicKey: new Uint8Array(57),
        forgingKey: new Uint8Array(58), // wrong length
        expiration: 0n,
        signature: new Uint8Array(114),
      }),
    ).toThrow(/Invalid forgingKey length/);
  });

  it('serializeClientProfile throws for invalid signature length', () => {
    expect(() =>
      serializeClientProfile({
        instanceTag: new Uint8Array(4),
        publicKey: new Uint8Array(57),
        forgingKey: new Uint8Array(57),
        expiration: 0n,
        signature: new Uint8Array(113), // wrong length
      }),
    ).toThrow(/Invalid signature length/);
  });

  it('serializeClientProfile throws for negative expiration', () => {
    expect(() =>
      serializeClientProfile({
        instanceTag: new Uint8Array(4),
        publicKey: new Uint8Array(57),
        forgingKey: new Uint8Array(57),
        expiration: -1n, // negative
        signature: new Uint8Array(114),
      }),
    ).toThrow(/Invalid expiration value/);
  });

  it('serializeClientProfile throws for expiration exceeding uint64 max', () => {
    expect(() =>
      serializeClientProfile({
        instanceTag: new Uint8Array(4),
        publicKey: new Uint8Array(57),
        forgingKey: new Uint8Array(57),
        expiration: 0x10000000000000000n, // exceeds uint64
        signature: new Uint8Array(114),
      }),
    ).toThrow(/Invalid expiration value/);
  });

  it('serializeTLVs throws for type out of uint16 range', () => {
    expect(() => serializeTLVs([{ type: 0x10000, value: new Uint8Array(1) }])).toThrow(
      /TLV type .* is out of uint16 range/,
    );
  });

  it('serializeTLVs throws for value length exceeding uint16', () => {
    // Create a value that's too long to fit in a uint16 length field
    expect(() => serializeTLVs([{ type: 1, value: new Uint8Array(0x10000) }])).toThrow(
      /TLV value length .* is out of uint16 range/,
    );
  });

  it('deserializeTLVs throws for trailing bytes after complete TLV records', () => {
    // One complete TLV: type=1, length=1, value=[0xaa], then one extra byte
    const bytes = new Uint8Array([0x00, 0x01, 0x00, 0x01, 0xaa, 0xff]);
    expect(() => deserializeTLVs(bytes)).toThrow(/Malformed TLV stream: 1 trailing byte/);
  });
});
