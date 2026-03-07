/**
 * OTRv4 Interactive DAKE (DAKEZ) implementation.
 *
 * Based on OTRv4 Protocol Specification:
 * https://github.com/otrv4/otrv4/blob/master/otrv4.md#interactive-dake
 */

import {
  deserializePublicKey as decodeDH3072,
  computeSharedSecret as dh3072,
  serializePublicKey as encodeDH3072,
  generateKeypair as generateDH3072,
} from '$core/crypto/dh3072.js';
import { diffieHellman as ecdhEd448, generateKeypair as generateEd448 } from '$core/crypto/ed448.js';
import { kdf } from '$core/crypto/kdf.js';
import { rsig, rvrf } from '$core/crypto/ring-sig.js';
import {
  OTRv4MessageType,
  PROTOCOL_VERSION,
  type AuthIMessage,
  type AuthRMessage,
  type ClientProfile,
  type IdentityMessage,
} from '../types.js';
import { validateClientProfile } from './client-profile.js';

// ---------------------------------------------------------------------------
// DAKE State Types
// ---------------------------------------------------------------------------

export enum DAKEStateStatus {
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

  // Ephemeral keys (Identity Message / Auth-R)
  ourY_secret?: Uint8Array;
  ourY_public?: Uint8Array;
  ourB_secret?: bigint;
  ourB_public?: bigint;

  theirY_public?: Uint8Array;
  theirB_public?: bigint;

  // Shared secrets
  ssid?: Uint8Array;
  k?: Uint8Array;

  // Expiry for timeout recovery
  createdAt: number;
}

// ---------------------------------------------------------------------------
// DAKE Flow Constants
// ---------------------------------------------------------------------------

const DAKE_TIMEOUT_MS = 30 * 1000; // 30 seconds

// usage_shared_secret (§ "Ring signatures" / "DAKEZ")
const USAGE_SHARED_SECRET = 0x21;
// usage_SSID (§ "Handshake SSID")
const USAGE_SSID = 0x19;

/**
 * Clean up expired DAKE states (timeout recovery § 3.16.1).
 */
export function cleanupExpiredDAKEStates(states: Map<string, DAKEState>, timeoutMs: number = DAKE_TIMEOUT_MS): number {
  const now = Date.now();
  let cleanedCount = 0;
  for (const [key, state] of states.entries()) {
    if (now - state.createdAt > timeoutMs) {
      states.delete(key);
      cleanedCount++;
    }
  }
  return cleanedCount;
}

/**
 * Serialize DAKEState for storage in chrome.storage.session (MV3 recovery).
 * Handles BigInt conversions to numbers/strings.
 */
export function serializeDAKEState(state: DAKEState): string {
  return JSON.stringify(state, (_key, value) => {
    if (typeof value === 'bigint') return value.toString();
    if (value instanceof Uint8Array) return Array.from(value);
    return value;
  });
}

/**
 * Deserialize DAKEState from storage.
 */
export function deserializeDAKEState(json: string): DAKEState {
  const parsed = JSON.parse(json);
  if (parsed.ourB_secret) parsed.ourB_secret = BigInt(parsed.ourB_secret);
  if (parsed.ourB_public) parsed.ourB_public = BigInt(parsed.ourB_public);
  if (parsed.theirB_public) parsed.theirB_public = BigInt(parsed.theirB_public);

  const toUint8 = (val: any) => (val ? new Uint8Array(val) : val);
  parsed.instanceTag = toUint8(parsed.instanceTag);
  parsed.remoteInstanceTag = toUint8(parsed.remoteInstanceTag);
  parsed.ourY_secret = toUint8(parsed.ourY_secret);
  parsed.ourY_public = toUint8(parsed.ourY_public);
  parsed.theirY_public = toUint8(parsed.theirY_public);
  parsed.ssid = toUint8(parsed.ssid);
  parsed.k = toUint8(parsed.k);

  if (parsed.ourProfile) {
    parsed.ourProfile.publicKey = toUint8(parsed.ourProfile.publicKey);
    parsed.ourProfile.forgingKey = toUint8(parsed.ourProfile.forgingKey);
    parsed.ourProfile.instanceTag = toUint8(parsed.ourProfile.instanceTag);
    parsed.ourProfile.signature = toUint8(parsed.ourProfile.signature);
    parsed.ourProfile.expiration = BigInt(parsed.ourProfile.expiration);
  }
  if (parsed.theirProfile) {
    parsed.theirProfile.publicKey = toUint8(parsed.theirProfile.publicKey);
    parsed.theirProfile.forgingKey = toUint8(parsed.theirProfile.forgingKey);
    parsed.theirProfile.instanceTag = toUint8(parsed.theirProfile.instanceTag);
    parsed.theirProfile.signature = toUint8(parsed.theirProfile.signature);
    parsed.theirProfile.expiration = BigInt(parsed.theirProfile.expiration);
  }

  return parsed;
}

// ---------------------------------------------------------------------------
// DAKEZ Implementation
// ---------------------------------------------------------------------------

/**
 * Initiate a new DAKE invitation (send Identity Message).
 */
export async function initiateDAKE(
  instanceTag: Uint8Array,
  ourProfile: ClientProfile,
): Promise<{ message: IdentityMessage; dakeState: DAKEState }> {
  const ourY = generateEd448();
  const ourB = generateDH3072();

  const message: IdentityMessage = {
    header: {
      protocolVersion: PROTOCOL_VERSION,
      messageType: OTRv4MessageType.DAKE_IDENTITY,
      instanceTag,
    },
    clientProfile: ourProfile,
    Y: ourY.publicKey,
    B: encodeDH3072(ourB.publicKey),
  };

  const dakeState: DAKEState = {
    status: DAKEStateStatus.WAITING_AUTH_R,
    instanceTag,
    ourProfile,
    ourY_secret: ourY.privateKey,
    ourY_public: ourY.publicKey,
    ourB_secret: ourB.privateKey,
    ourB_public: ourB.publicKey,
    createdAt: Date.now(),
  };

  return { message, dakeState };
}

/**
 * Handle an incoming Identity Message and respond with Auth-R.
 */
export async function handleIdentity(
  instanceTag: Uint8Array,
  ourProfile: ClientProfile,
  ourIdentitySecretH: Uint8Array,
  identityMsg: IdentityMessage,
): Promise<{ message: AuthRMessage; dakeState: DAKEState }> {
  if (!validateClientProfile(identityMsg.clientProfile)) {
    throw new Error('Invalid remote Client Profile');
  }

  const ourY = generateEd448();
  const ourB = generateDH3072();

  const theirY = identityMsg.Y;
  const theirB = decodeDH3072(identityMsg.B);

  // Derive Shared Secret K and SSID
  const { k, ssid } = deriveDAKESecrets({
    ourY_secret: ourY.privateKey,
    ourB_secret: ourB.privateKey,
    theirY_public: theirY,
    theirB_public: theirB,
    profileAlice: identityMsg.clientProfile, // Identity sender is Alice
    profileBob: ourProfile, // Responder is Bob
  });

  // Ring: {H_A, H_B, Forging_A} where A is sender of Identity, B is responder (us)
  const ring: [Uint8Array, Uint8Array, Uint8Array] = [
    identityMsg.clientProfile.publicKey, // H_A
    ourProfile.publicKey, // H_B
    identityMsg.clientProfile.forgingKey, // Forging_A
  ];

  // Auth-R signature (signed by Bob using H_B)
  const sigma = rsig(ourIdentitySecretH, ring, k);

  const message: AuthRMessage = {
    header: {
      protocolVersion: PROTOCOL_VERSION,
      messageType: OTRv4MessageType.DAKE_AUTH_R,
      instanceTag,
    },
    clientProfile: ourProfile,
    Y: ourY.publicKey,
    B: encodeDH3072(ourB.publicKey),
    sigma,
  };

  const dakeState: DAKEState = {
    status: DAKEStateStatus.WAITING_AUTH_I,
    theirProfile: identityMsg.clientProfile, // Set the sender as theirProfile
    instanceTag,
    remoteInstanceTag: identityMsg.header.instanceTag,
    ourProfile,
    ourY_secret: ourY.privateKey,
    ourY_public: ourY.publicKey,
    ourB_secret: ourB.privateKey,
    ourB_public: ourB.publicKey,
    theirY_public: theirY,
    theirB_public: theirB,
    k,
    ssid,
    createdAt: Date.now(),
  };

  return { message, dakeState };
}

/**
 * Handle an incoming Auth-R message and respond with Auth-I.
 */
export async function handleAuthR(
  dakeState: DAKEState,
  ourIdentitySecretH: Uint8Array,
  authRMsg: AuthRMessage,
): Promise<{ message: AuthIMessage; dakeState: DAKEState }> {
  // 1. Verify RingSig sigma (Auth-R) uses Bob's ephemeral keys (Y, B) and profile from the message
  const theirY = authRMsg.Y;
  const theirB = decodeDH3072(authRMsg.B);
  const theirProfile = authRMsg.clientProfile;

  if (!validateClientProfile(theirProfile)) {
    throw new Error('Invalid remote Client Profile in Auth-R');
  }

  // Alice (Identity sender) derives K and SSID using Bob's newcomers
  const { k, ssid } = deriveDAKESecrets({
    ourY_secret: dakeState.ourY_secret!,
    ourB_secret: dakeState.ourB_secret!,
    theirY_public: theirY,
    theirB_public: theirB,
    profileAlice: dakeState.ourProfile, // Alice (us)
    profileBob: theirProfile, // Bob
  });

  const ring: [Uint8Array, Uint8Array, Uint8Array] = [
    dakeState.ourProfile.publicKey, // H_A (us)
    theirProfile.publicKey, // H_B (them)
    dakeState.ourProfile.forgingKey, // Forging_A (us)
  ];

  if (!rvrf(ring, authRMsg.sigma, k)) {
    throw new Error('Auth-R Ring Signature verification failed');
  }

  // 2. Respond with Auth-I RingSig
  const sigma = rsig(ourIdentitySecretH, ring, k);

  const message: AuthIMessage = {
    header: {
      protocolVersion: PROTOCOL_VERSION,
      messageType: OTRv4MessageType.DAKE_AUTH_I,
      instanceTag: dakeState.instanceTag,
    },
    sigma,
  };

  // After verifying the RingSig, Alice (Identity sender) must update her state with Bob's ephemeral keys and profile
  const nextState: DAKEState = {
    ...dakeState,
    theirY_public: theirY,
    theirB_public: theirB,
    theirProfile,
    k,
    ssid,
    status: DAKEStateStatus.ENCRYPTED_MESSAGES,
  };

  return { message, dakeState: nextState };
}

/**
 * Handle an incoming Auth-I message and finalize the DAKE.
 */
export async function handleAuthI(
  dakeState: DAKEState,
  _ourIdentitySecretH: Uint8Array,
  authIMsg: AuthIMessage,
): Promise<{ dakeState: DAKEState }> {
  if (!dakeState.k || !dakeState.theirProfile) {
    throw new Error('Invalid DAKE state: missing keys or profile');
  }

  // 1. Verify RingSig sigma (Auth-I)
  const ring: [Uint8Array, Uint8Array, Uint8Array] = [
    dakeState.theirProfile.publicKey, // H_A (them)
    dakeState.ourProfile.publicKey, // H_B (us)
    dakeState.theirProfile.forgingKey, // Forging_A (them)
  ];

  if (!rvrf(ring, authIMsg.sigma, dakeState.k)) {
    throw new Error('Auth-I Ring Signature verification failed');
  }

  const nextState: DAKEState = {
    ...dakeState,
    status: DAKEStateStatus.ENCRYPTED_MESSAGES,
  };

  return { dakeState: nextState };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

function deriveDAKESecrets(params: {
  ourY_secret: Uint8Array;
  ourB_secret: bigint;
  theirY_public: Uint8Array;
  theirB_public: bigint;
  profileAlice: ClientProfile;
  profileBob: ClientProfile;
}) {
  const ecdh = ecdhEd448(params.ourY_secret, params.theirY_public);
  const dh = dh3072(params.ourB_secret, params.theirB_public);
  const dhBytes = serializeDHSecret(dh);

  // K = SHAKE-256(usage_shared_secret || ECDH(ourY, theirY) || DH(ourB, theirB) || Profile_A || Profile_B, 64)
  const k = kdf(
    USAGE_SHARED_SECRET,
    [ecdh, dhBytes, serializeProfile(params.profileAlice), serializeProfile(params.profileBob)],
    64,
  );

  // SSID = SHAKE-256(usage_SSID || K, 8)
  const ssid = kdf(USAGE_SSID, [k], 8);

  return { k, ssid };
}

function serializeDHSecret(dh: bigint): Uint8Array {
  const bytes = new Uint8Array(384);
  let val = dh;
  for (let i = 383; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

function serializeProfile(p: ClientProfile): Uint8Array {
  // OTRv4 Client Profile binary layout for hashing: H || ForgingKey || InstanceTag || Expiration
  const bytes = new Uint8Array(57 + 57 + 4 + 8);
  bytes.set(p.publicKey, 0);
  bytes.set(p.forgingKey, 57);
  bytes.set(p.instanceTag, 114);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(118, p.expiration, false);
  return bytes;
}

export const DAKEState = DAKEStateStatus;
