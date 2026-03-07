/**
 * OTRv4 Protocol Type Definitions (packages/core/src/types.ts)
 *
 * Based on the OTRv4 Protocol Specification:
 * https://github.com/otrv4/otrv4/blob/master/otrv4.md
 */

/** All OTRv4 messages start with the protocol version (4). */
export const PROTOCOL_VERSION = 4;

/**
 * Common Header for all OTRv4 messages.
 */
export interface OTRv4Header {
  protocolVersion: typeof PROTOCOL_VERSION;
  messageType: OTRv4MessageType;
  instanceTag: Uint8Array; // 4 bytes
}

/**
 * OTRv4 Message Types (as specified in binary layout).
 */
export enum OTRv4MessageType {
  CLIENT_PROFILE = 0x01,
  QUERY = 0x02,
  DAKE_IDENTITY = 0x03,
  DAKE_AUTH_R = 0x04,
  DAKE_AUTH_I = 0x05,
  DATA = 0x06,
  FORGING_EDDSA_PUBLIC_KEY = 0x07, // (Often used in profiles)
}

/**
 * Client Profile (packages/core/src/otr/client-profile.ts)
 */
export interface ClientProfile {
  instanceTag: Uint8Array; // 4 bytes
  publicKey: Uint8Array; // 57 bytes (Ed448 H)
  forgingKey: Uint8Array; // 57 bytes (Ed448 forging)
  expiration: bigint; // 8 bytes (timestamp)
  signature: Uint8Array; // 114 bytes (EdDSA signature)
}

/**
 * DAKE Identity Message
 */
export interface IdentityMessage {
  header: OTRv4Header;
  clientProfile: ClientProfile;
  Y: Uint8Array; // 57 bytes (Ed448 ephemeral)
  B: Uint8Array; // 384 bytes (DH3072 ephemeral)
}

/**
 * DAKE Auth-R Message
 */
export interface AuthRMessage {
  header: OTRv4Header;
  clientProfile: ClientProfile;
  Y: Uint8Array; // 57 bytes (Ed448 ephemeral)
  B: Uint8Array; // 384 bytes (DH3072 ephemeral)
  sigma: Uint8Array; // Ring Signature
}

/**
 * DAKE Auth-I Message
 */
export interface AuthIMessage {
  header: OTRv4Header;
  sigma: Uint8Array; // Ring Signature
}

/**
 * Data Message
 */
export interface DataMessage {
  header: OTRv4Header;
  flags: number; // 1 byte
  ratchetKey: Uint8Array; // 57 bytes (Ed448)
  identifier: Uint8Array; // 8 bytes (SSID-based/Session ID)
  nonce: Uint8Array; // 12 bytes (ChaCha20 nonce; validated only for length)
  ciphertext: Uint8Array;
  mac: Uint8Array; // 64 bytes (SHAKE-256 HMAC)
}

/**
 * TLV (Type-Length-Value) Records
 *
 * The length is derived from `value.byteLength` during serialization.
 */
export interface TLVRecord {
  type: number; // 2 bytes
  value: Uint8Array;
}
