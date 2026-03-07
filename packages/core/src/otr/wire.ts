import { PROTOCOL_VERSION, type OTRv4Header, OTRv4MessageType } from '../types.js';

/**
 * Protocol Wire-format functions for OTRv4 (packages/core/src/otr/wire.ts).
 */

/**
 * Serialize a message header to bytes.
 * Layout: protocol_version (1byte) | message_type (1byte) | instance_tag (4bytes)
 */
export function serializeHeader(header: OTRv4Header): Uint8Array {
  if (header.instanceTag.byteLength !== 4) throw new Error('Invalid instance tag: expected 4 bytes');
  if (header.protocolVersion !== PROTOCOL_VERSION)
    throw new Error(`Invalid protocol version: expected ${PROTOCOL_VERSION}, got ${header.protocolVersion}`);
  const bytes = new Uint8Array(6);
  bytes[0] = header.protocolVersion;
  bytes[1] = header.messageType;
  bytes.set(header.instanceTag, 2);
  return bytes;
}

/**
 * Deserialize a message header from bytes.
 */
export function deserializeHeader(bytes: Uint8Array): OTRv4Header {
  if (bytes.byteLength < 6) {
    throw new Error('Header too short');
  }
  if (bytes[0] !== PROTOCOL_VERSION) {
    throw new Error(`Invalid protocol version: expected ${PROTOCOL_VERSION}, got ${bytes[0]}`);
  }

  return {
    protocolVersion: bytes[0],
    messageType: bytes[1] as OTRv4MessageType,
    instanceTag: bytes.slice(2, 6),
  };
}

/**
 * Serialize a data message to bytes.
 * Layout: Header (6) | Flags (1) | Ratchet Key (57) (Ed448 point) |
 *         Identifier (8) | Nonce (12) |
 *         Length of Ciphertext (4) | Ciphertext (len) | MAC (64)
 *
 * Note: Length is Big-Endian.
 */
export function serializeDataMessage(msg: {
  header: OTRv4Header;
  flags: number;
  ratchetKey: Uint8Array;
  identifier: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
}): Uint8Array {
  const headerBytes = serializeHeader(msg.header);
  const ctLength = msg.ciphertext.byteLength;

  if (msg.ratchetKey.byteLength !== 57) throw new Error('Invalid ratchet key: expected 57 bytes');
  if (msg.identifier.byteLength !== 8) throw new Error('Invalid identifier: expected 8 bytes');
  if (msg.nonce.byteLength !== 12) throw new Error('Invalid nonce: expected 12 bytes');
  if (msg.mac.byteLength !== 64) throw new Error('Invalid MAC: expected 64 bytes');

  const bytes = new Uint8Array(6 + 1 + 57 + 8 + 12 + 4 + ctLength + 64);
  let offset = 0;

  // Header (6)
  bytes.set(headerBytes, offset);
  offset += 6;

  // Flags (1)
  bytes[offset] = msg.flags;
  offset += 1;

  // RatchetKey (57)
  bytes.set(msg.ratchetKey, offset);
  offset += 57;

  // Identifier (8)
  bytes.set(msg.identifier, offset);
  offset += 8;

  // Nonce (12)
  bytes.set(msg.nonce, offset);
  offset += 12;

  // CT Length (4)
  const view = new DataView(bytes.buffer);
  view.setUint32(offset, ctLength, false); // big-endian
  offset += 4;

  // Ciphertext (len)
  bytes.set(msg.ciphertext, offset);
  offset += ctLength;

  // MAC (64)
  bytes.set(msg.mac, offset);
  offset += 64;

  return bytes;
}

/**
 * Deserialize a data message from bytes.
 */
export function deserializeDataMessage(bytes: Uint8Array): {
  header: OTRv4Header;
  flags: number;
  ratchetKey: Uint8Array;
  identifier: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
} {
  if (bytes.byteLength < 6 + 1 + 57 + 8 + 12 + 4 + 64) {
    throw new Error('Data message too short');
  }

  let offset = 0;
  const header = deserializeHeader(bytes.slice(0, 6));
  offset += 6;

  const flagsValue = bytes[offset];
  if (flagsValue === undefined) throw new Error('Truncated message header (flags)');
  const flags = flagsValue;
  offset += 1;

  const ratchetKey = bytes.slice(offset, offset + 57);
  offset += 57;

  const identifier = bytes.slice(offset, offset + 8);
  offset += 8;

  const nonce = bytes.slice(offset, offset + 12);
  offset += 12;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ctLength = view.getUint32(offset, false);
  offset += 4;

  if (bytes.byteLength < offset + ctLength + 64) {
    throw new Error('Invalid ciphertext length or truncated message');
  }

  const ciphertext = bytes.slice(offset, offset + ctLength);
  offset += ctLength;

  const mac = bytes.slice(offset, offset + 64);
  offset += 64;

  const trailingDataMsg = bytes.byteLength - offset;
  if (trailingDataMsg !== 0) {
    throw new Error(`Trailing ${trailingDataMsg} byte(s) after data message`);
  }

  return {
    header,
    flags,
    ratchetKey,
    identifier,
    nonce,
    ciphertext,
    mac,
  };
}

/**
 * Serialize a Client Profile to bytes.
 * Layout: Instance Tag (4) | Public Key (57) | Forging Key (57) |
 *         Expiration (8) (Big-Endian) | Signature (114)
 */
export function serializeClientProfile(profile: {
  instanceTag: Uint8Array;
  publicKey: Uint8Array;
  forgingKey: Uint8Array;
  expiration: bigint;
  signature: Uint8Array;
}): Uint8Array {
  if (profile.instanceTag.byteLength !== 4) throw new Error('Invalid instance tag: expected 4 bytes');
  if (profile.publicKey.byteLength !== 57) throw new Error('Invalid public key: expected 57 bytes');
  if (profile.forgingKey.byteLength !== 57) throw new Error('Invalid forging key: expected 57 bytes');
  if (profile.signature.byteLength !== 114) throw new Error('Invalid signature: expected 114 bytes');

  const bytes = new Uint8Array(4 + 57 + 57 + 8 + 114);
  let offset = 0;

  bytes.set(profile.instanceTag, offset);
  offset += 4;

  bytes.set(profile.publicKey, offset);
  offset += 57;

  bytes.set(profile.forgingKey, offset);
  offset += 57;

  const view = new DataView(bytes.buffer);
  view.setBigUint64(offset, profile.expiration, false);
  offset += 8;

  bytes.set(profile.signature, offset);
  return bytes;
}

/**
 * Deserialize a Client Profile from bytes.
 */
export function deserializeClientProfile(bytes: Uint8Array): {
  instanceTag: Uint8Array;
  publicKey: Uint8Array;
  forgingKey: Uint8Array;
  expiration: bigint;
  signature: Uint8Array;
} {
  if (bytes.byteLength < 4 + 57 + 57 + 8 + 114) {
    throw new Error('Client Profile too short');
  }

  let offset = 0;
  const instanceTag = bytes.slice(offset, offset + 4);
  offset += 4;

  const publicKey = bytes.slice(offset, offset + 57);
  offset += 57;

  const forgingKey = bytes.slice(offset, offset + 57);
  offset += 57;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const expiration = view.getBigUint64(offset, false);
  offset += 8;

  const signature = bytes.slice(offset, offset + 114);

  return { instanceTag, publicKey, forgingKey, expiration, signature };
}

/**
 * Serialize a list of TLV records to bytes.
 * Layout: Type (2) | Length (2) | Value (len)
 * All multi-byte fields are Big-Endian.
 */
export function serializeTLVs(tlvs: { type: number; value: Uint8Array }[]): Uint8Array {
  let totalLen = 0;
  for (const tlv of tlvs) {
    if (!Number.isInteger(tlv.type) || tlv.type < 0 || tlv.type > 65535)
      throw new Error(`TLV type ${tlv.type} out of range for uint16`);
    if (tlv.value.byteLength > 65535)
      throw new Error(`TLV value length ${tlv.value.byteLength} exceeds uint16 maximum (65535)`);
    totalLen += 4 + tlv.value.byteLength;
  }

  const bytes = new Uint8Array(totalLen);
  const view = new DataView(bytes.buffer);
  let offset = 0;

  for (const tlv of tlvs) {
    view.setUint16(offset, tlv.type, false);
    offset += 2;
    view.setUint16(offset, tlv.value.byteLength, false);
    offset += 2;
    bytes.set(tlv.value, offset);
    offset += tlv.value.byteLength;
  }

  return bytes;
}

/**
 * Deserialize TLV records from bytes.
 */
export function deserializeTLVs(bytes: Uint8Array): { type: number; value: Uint8Array }[] {
  const tlvs: { type: number; value: Uint8Array }[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;

  while (offset + 4 <= bytes.byteLength) {
    const type = view.getUint16(offset, false);
    offset += 2;
    const length = view.getUint16(offset, false);
    offset += 2;

    if (offset + length > bytes.byteLength) {
      throw new Error(`TLV length ${length} exceeds remaining buffer`);
    }

    const value = bytes.slice(offset, offset + length);
    offset += length;
    tlvs.push({ type, value });
  }

  if (offset !== bytes.byteLength) {
    const remaining = bytes.byteLength - offset;
    throw new Error(`Trailing ${remaining} byte(s) after TLV records`);
  }

  return tlvs;
}

// Additional serializers will be added here
export { OTRv4MessageType, PROTOCOL_VERSION };
