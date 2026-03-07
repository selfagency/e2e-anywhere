import { PROTOCOL_VERSION, type OTRv4Header, OTRv4MessageType } from '../types.js';
/**
 * Protocol Wire-format functions for OTRv4 (packages/core/src/otr/wire.ts).
 */
/**
 * Serialize a message header to bytes.
 * Layout: protocol_version (1byte) | message_type (1byte) | instance_tag (4bytes)
 */
export declare function serializeHeader(header: OTRv4Header): Uint8Array;
/**
 * Deserialize a message header from bytes.
 */
export declare function deserializeHeader(bytes: Uint8Array): OTRv4Header;
/**
 * Serialize a data message to bytes.
 * Layout: Header (6) | Flags (1) | Ratchet Key (57) (Ed448 point) |
 *         Identifier (8) | Nonce (12) |
 *         Length of Ciphertext (4) | Ciphertext (len) | MAC (64)
 *
 * Note: Length is Big-Endian.
 */
export declare function serializeDataMessage(msg: {
  header: OTRv4Header;
  flags: number;
  ratchetKey: Uint8Array;
  identifier: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
}): Uint8Array;
/**
 * Deserialize a data message from bytes.
 */
export declare function deserializeDataMessage(bytes: Uint8Array): {
  header: OTRv4Header;
  flags: number;
  ratchetKey: Uint8Array;
  identifier: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
};
/**
 * Serialize a Client Profile to bytes.
 * Layout: Instance Tag (4) | Public Key (57) | Forging Key (57) |
 *         Expiration (8) (Big-Endian) | Signature (114)
 */
export declare function serializeClientProfile(profile: {
  instanceTag: Uint8Array;
  publicKey: Uint8Array;
  forgingKey: Uint8Array;
  expiration: bigint;
  signature: Uint8Array;
}): Uint8Array;
/**
 * Deserialize a Client Profile from bytes.
 */
export declare function deserializeClientProfile(bytes: Uint8Array): {
  instanceTag: Uint8Array;
  publicKey: Uint8Array;
  forgingKey: Uint8Array;
  expiration: bigint;
  signature: Uint8Array;
};
/**
 * Serialize a list of TLV records to bytes.
 * Layout: Type (2) | Length (2) | Value (len)
 * All multi-byte fields are Big-Endian.
 */
export declare function serializeTLVs(
  tlvs: {
    type: number;
    value: Uint8Array;
  }[],
): Uint8Array;
/**
 * Deserialize TLV records from bytes.
 */
export declare function deserializeTLVs(bytes: Uint8Array): {
  type: number;
  value: Uint8Array;
}[];
export { OTRv4MessageType, PROTOCOL_VERSION };
