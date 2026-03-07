/**
 * OTRv4 Interactive DAKE (DAKEZ) implementation.
 *
 * Based on OTRv4 Protocol Specification:
 * https://github.com/otrv4/otrv4/blob/master/otrv4.md#interactive-dake
 */
import { type ClientProfile, type IdentityMessage, type AuthRMessage, type AuthIMessage } from '../types.js';
export declare enum DAKEStateStatus {
  START = 'START',
  WAITING_AUTH_R = 'WAITING_AUTH_R',
  WAITING_AUTH_I = 'WAITING_AUTH_I',
  ENCRYPTED_MESSAGES = 'ENCRYPTED_MESSAGES',
  ERROR = 'ERROR',
}
export interface DAKEState {
  status: DAKEStateStatus;
  instanceTag: Uint8Array;
  remoteInstanceTag?: Uint8Array;
  ourProfile: ClientProfile;
  theirProfile?: ClientProfile;
  ourY_secret?: Uint8Array;
  ourY_public?: Uint8Array;
  ourB_secret?: bigint;
  ourB_public?: bigint;
  theirY_public?: Uint8Array;
  theirB_public?: bigint;
  ssid?: Uint8Array;
  k?: Uint8Array;
  createdAt: number;
}
/**
 * Clean up expired DAKE states (timeout recovery § 3.16.1).
 * Only removes states that are still in a handshake phase (WAITING_AUTH_R or
 * WAITING_AUTH_I). Active sessions (ENCRYPTED_MESSAGES) are never cleaned up
 * here since their `createdAt` is set at handshake start, not session start.
 */
export declare function cleanupExpiredDAKEStates(states: Map<string, DAKEState>, timeoutMs?: number): number;
/**
 * Serialize DAKEState for storage in chrome.storage.session (MV3 recovery).
 * Includes a version tag so stale/incompatible states can be discarded on load.
 */
export declare function serializeDAKEState(state: DAKEState): string;
/**
 * Deserialize and validate DAKEState from storage.
 * Rejects any state with a version mismatch or malformed fields so that an
 * outdated persisted state cannot silently produce incorrect behaviour.
 */
export declare function deserializeDAKEState(json: string): DAKEState;
/**
 * Initiate a new DAKE invitation (send Identity Message).
 */
export declare function initiateDAKE(
  instanceTag: Uint8Array,
  ourProfile: ClientProfile,
): Promise<{
  message: IdentityMessage;
  dakeState: DAKEState;
}>;
/**
 * Handle an incoming Identity Message and respond with Auth-R.
 */
export declare function handleIdentity(
  instanceTag: Uint8Array,
  ourProfile: ClientProfile,
  ourIdentitySecretH: Uint8Array,
  identityMsg: IdentityMessage,
): Promise<{
  message: AuthRMessage;
  dakeState: DAKEState;
}>;
/**
 * Handle an incoming Auth-R message and respond with Auth-I.
 */
export declare function handleAuthR(
  dakeState: DAKEState,
  ourIdentitySecretH: Uint8Array,
  authRMsg: AuthRMessage,
): Promise<{
  message: AuthIMessage;
  dakeState: DAKEState;
}>;
/**
 * Handle an incoming Auth-I message and finalize the DAKE.
 */
export declare function handleAuthI(
  dakeState: DAKEState,
  _ourIdentitySecretH: Uint8Array,
  authIMsg: AuthIMessage,
): Promise<{
  dakeState: DAKEState;
}>;
