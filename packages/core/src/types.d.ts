/**
 * OTRv4 Protocol Type Definitions (packages/core/src/types.ts)
 *
 * Based on the OTRv4 Protocol Specification:
 * https://github.com/otrv4/otrv4/blob/master/otrv4.md
 */
/** All OTRv4 messages start with the protocol version (4). */
export declare const PROTOCOL_VERSION = 4;
/**
 * Common Header for all OTRv4 messages.
 */
export interface OTRv4Header {
  protocolVersion: number;
  messageType: number;
  instanceTag: Uint8Array;
}
/**
 * OTRv4 Message Types (as specified in binary layout).
 */
export declare enum OTRv4MessageType {
  CLIENT_PROFILE = 1,
  QUERY = 2,
  DAKE_IDENTITY = 3,
  DAKE_AUTH_R = 4,
  DAKE_AUTH_I = 5,
  DATA = 6,
  FORGING_EDDSA_PUBLIC_KEY = 7,
}
/**
 * Client Profile (packages/core/src/otr/client-profile.ts)
 */
export interface ClientProfile {
  instanceTag: Uint8Array;
  publicKey: Uint8Array;
  forgingKey: Uint8Array;
  expiration: bigint;
  signature: Uint8Array;
}
/**
 * DAKE Identity Message
 */
export interface IdentityMessage {
  header: OTRv4Header;
  clientProfile: ClientProfile;
  Y: Uint8Array;
  B: Uint8Array;
}
/**
 * DAKE Auth-R Message
 */
export interface AuthRMessage {
  header: OTRv4Header;
  sigma: Uint8Array;
}
/**
 * DAKE Auth-I Message
 */
export interface AuthIMessage {
  header: OTRv4Header;
  sigma: Uint8Array;
}
/**
 * Data Message
 */
export interface DataMessage {
  header: OTRv4Header;
  flags: number;
  ratchetKey: Uint8Array;
  identifier: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
}
/**
 * TLV (Type-Length-Value) Records
 */
export interface TLVRecord {
  type: number;
  length: number;
  value: Uint8Array;
}
