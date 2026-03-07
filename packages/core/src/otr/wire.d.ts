import {
  OTRv4MessageType,
  PROTOCOL_VERSION,
  type ClientProfile,
  type DataMessage,
  type OTRv4Header,
  type TLVRecord,
} from '../types.js';
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
export declare function serializeDataMessage(msg: DataMessage): Uint8Array;
/**
 * Deserialize a data message from bytes.
 */
export declare function deserializeDataMessage(bytes: Uint8Array): DataMessage;
/**
 * Serialize a Client Profile to bytes.
 * Layout: Instance Tag (4) | Public Key (57) | Forging Key (57) |
 *         Expiration (8) (Big-Endian) | Signature (114)
 */
export declare function serializeClientProfile(profile: ClientProfile): Uint8Array;
/**
 * Deserialize a Client Profile from bytes.
 */
export declare function deserializeClientProfile(bytes: Uint8Array): ClientProfile;
/**
 * Serialize a list of TLV records to bytes.
 * Layout: Type (2) | Length (2) | Value (len)
 * All multi-byte fields are Big-Endian.
 */
export declare function serializeTLVs(tlvs: TLVRecord[]): Uint8Array;
/**
 * Deserialize TLV records from bytes.
 */
export declare function deserializeTLVs(bytes: Uint8Array): TLVRecord[];
export { OTRv4MessageType, PROTOCOL_VERSION };
