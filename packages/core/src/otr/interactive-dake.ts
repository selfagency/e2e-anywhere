/**
 * OTRv4 Interactive DAKE (DAKEZ) implementation.
 *
 * Based on OTRv4 Protocol Specification:
 * https://github.com/otrv4/otrv4/blob/master/otrv4.md#interactive-dake
 */

import {
  generateKeypair as generateEd448,
  diffieHellman as ecdhEd448,
  validatePoint as validateEd448Point,
} from '$core/crypto/ed448.js';
import {
  generateKeypair as generateDH3072,
  computeSharedSecret as dh3072,
  serializePublicKey as encodeDH3072,
  deserializePublicKey as decodeDH3072,
} from '$core/crypto/dh3072.js';
import { rsig, rvrf } from '$core/crypto/ring-sig.js';
import { kdf } from '$core/crypto/kdf.js';
import {
  PROTOCOL_VERSION,
  OTRv4MessageType,
  type ClientProfile,
  type IdentityMessage,
  type AuthRMessage,
  type AuthIMessage,
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

  // Ephemeral keys (Identity Message / Auth-R) — cleared post-handshake
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

/** Serialization format version — increment when DAKEState shape changes. */
const DAKE_STATE_VERSION = 1;

// usage_shared_secret (§ "Ring signatures" / "DAKEZ")
const USAGE_SHARED_SECRET = 0x21;
// usage_SSID (§ "Handshake SSID")
const USAGE_SSID = 0x19;

// ---------------------------------------------------------------------------
// Internal byte helpers
// ---------------------------------------------------------------------------

/** Constant-time byte-array equality check. */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/**
 * Clean up expired DAKE states (timeout recovery § 3.16.1).
 * Only removes states that are still in a handshake phase (WAITING_AUTH_R or
 * WAITING_AUTH_I). Active sessions (ENCRYPTED_MESSAGES) are never cleaned up
 * here since their `createdAt` is set at handshake start, not session start.
 */
export function cleanupExpiredDAKEStates(states: Map<string, DAKEState>, timeoutMs: number = DAKE_TIMEOUT_MS): number {
  const now = Date.now();
  let cleanedCount = 0;
  for (const [key, state] of states.entries()) {
    // Only expire incomplete handshakes, not active sessions.
    if (state.status !== DAKEStateStatus.WAITING_AUTH_R && state.status !== DAKEStateStatus.WAITING_AUTH_I) {
      continue;
    }
    if (now - state.createdAt > timeoutMs) {
      // Best-effort zeroization of sensitive byte arrays before dropping state.
      state.instanceTag.fill(0);
      state.remoteInstanceTag?.fill(0);
      state.ourY_secret?.fill(0);
      state.ourY_public?.fill(0);
      state.theirY_public?.fill(0);
      state.ssid?.fill(0);
      state.k?.fill(0);
      states.delete(key);
      cleanedCount++;
    }
  }
  return cleanedCount;
}

/**
 * Serialize DAKEState for storage in chrome.storage.session (MV3 recovery).
 * Includes a version tag so stale/incompatible states can be discarded on load.
 */
export function serializeDAKEState(state: DAKEState): string {
  return JSON.stringify({ version: DAKE_STATE_VERSION, ...state }, (_key, value) => {
    if (typeof value === 'bigint') return value.toString();
    if (value instanceof Uint8Array) return Array.from(value);
    return value;
  });
}

// ---------------------------------------------------------------------------
// deserializeDAKEState — fully validated, typed deserialization
// ---------------------------------------------------------------------------

function isByteArray(value: unknown): value is number[] {
  return Array.isArray(value) && value.every(v => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 255);
}

function toUint8ArrayOptional(value: unknown, fieldName: string): Uint8Array | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isByteArray(value)) throw new Error(`Invalid byte array for field "${fieldName}"`);
  return new Uint8Array(value);
}

function toUint8ArrayRequired(value: unknown, fieldName: string): Uint8Array {
  const result = toUint8ArrayOptional(value, fieldName);
  if (!result) throw new Error(`Missing required byte array field "${fieldName}"`);
  return result;
}

function toBigIntOptional(value: unknown, fieldName: string): bigint | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' && typeof value !== 'number') {
    throw new Error(`Invalid BigInt-serialised value for field "${fieldName}"`);
  }
  return BigInt(String(value));
}

function toBigIntRequired(value: unknown, fieldName: string): bigint {
  const result = toBigIntOptional(value, fieldName);
  if (result === undefined) throw new Error(`Missing required BigInt field "${fieldName}"`);
  return result;
}

/**
 * Deserialize and validate DAKEState from storage.
 * Rejects any state with a version mismatch or malformed fields so that an
 * outdated persisted state cannot silently produce incorrect behaviour.
 */
export function deserializeDAKEState(json: string): DAKEState {
  const parsed: unknown = JSON.parse(json);

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Invalid DAKE state: not an object');
  }

  const record = parsed as Record<string, unknown>;

  if (record.version !== DAKE_STATE_VERSION) {
    throw new Error(`Invalid DAKE state: unsupported version ${String(record.version)}`);
  }

  const statusValue = record.status;
  if (typeof statusValue !== 'string' || !Object.values(DAKEStateStatus).includes(statusValue as DAKEStateStatus)) {
    throw new Error('Invalid DAKE state: invalid or missing "status"');
  }

  const createdAt = record.createdAt;
  if (typeof createdAt !== 'number' || !Number.isFinite(createdAt)) {
    throw new Error('Invalid DAKE state: invalid or missing "createdAt"');
  }

  const instanceTag = toUint8ArrayRequired(record.instanceTag, 'instanceTag');
  const remoteInstanceTag = toUint8ArrayOptional(record.remoteInstanceTag, 'remoteInstanceTag');

  const ourProfileRaw = record.ourProfile;
  if (typeof ourProfileRaw !== 'object' || ourProfileRaw === null) {
    throw new Error('Invalid DAKE state: invalid or missing "ourProfile"');
  }
  const ourProfileRecord = ourProfileRaw as Record<string, unknown>;
  const ourProfile: ClientProfile = {
    ...(ourProfileRecord as unknown as ClientProfile),
    publicKey: toUint8ArrayRequired(ourProfileRecord.publicKey, 'ourProfile.publicKey'),
    forgingKey: toUint8ArrayRequired(ourProfileRecord.forgingKey, 'ourProfile.forgingKey'),
    instanceTag: toUint8ArrayRequired(ourProfileRecord.instanceTag, 'ourProfile.instanceTag'),
    signature: toUint8ArrayRequired(ourProfileRecord.signature, 'ourProfile.signature'),
    expiration: toBigIntRequired(ourProfileRecord.expiration, 'ourProfile.expiration'),
  };

  let theirProfile: ClientProfile | undefined;
  if (record.theirProfile !== undefined && record.theirProfile !== null) {
    if (typeof record.theirProfile !== 'object') {
      throw new Error('Invalid DAKE state: "theirProfile" must be an object when present');
    }
    const theirProfileRecord = record.theirProfile as Record<string, unknown>;
    theirProfile = {
      ...(theirProfileRecord as unknown as ClientProfile),
      publicKey: toUint8ArrayRequired(theirProfileRecord.publicKey, 'theirProfile.publicKey'),
      forgingKey: toUint8ArrayRequired(theirProfileRecord.forgingKey, 'theirProfile.forgingKey'),
      instanceTag: toUint8ArrayRequired(theirProfileRecord.instanceTag, 'theirProfile.instanceTag'),
      signature: toUint8ArrayRequired(theirProfileRecord.signature, 'theirProfile.signature'),
      expiration: toBigIntRequired(theirProfileRecord.expiration, 'theirProfile.expiration'),
    };
  }

  const ourY_secret = toUint8ArrayOptional(record.ourY_secret, 'ourY_secret');
  const ourY_public = toUint8ArrayOptional(record.ourY_public, 'ourY_public');
  const theirY_public = toUint8ArrayOptional(record.theirY_public, 'theirY_public');
  const ssid = toUint8ArrayOptional(record.ssid, 'ssid');
  const k = toUint8ArrayOptional(record.k, 'k');

  const ourB_secret = toBigIntOptional(record.ourB_secret, 'ourB_secret');
  const ourB_public = toBigIntOptional(record.ourB_public, 'ourB_public');
  const theirB_public = toBigIntOptional(record.theirB_public, 'theirB_public');

  const state: DAKEState = {
    status: statusValue as DAKEStateStatus,
    instanceTag,
    ourProfile,
    createdAt,
  };
  if (remoteInstanceTag !== undefined) state.remoteInstanceTag = remoteInstanceTag;
  if (theirProfile !== undefined) state.theirProfile = theirProfile;
  if (ourY_secret !== undefined) state.ourY_secret = ourY_secret;
  if (ourY_public !== undefined) state.ourY_public = ourY_public;
  if (ourB_secret !== undefined) state.ourB_secret = ourB_secret;
  if (ourB_public !== undefined) state.ourB_public = ourB_public;
  if (theirY_public !== undefined) state.theirY_public = theirY_public;
  if (theirB_public !== undefined) state.theirB_public = theirB_public;
  if (ssid !== undefined) state.ssid = ssid;
  if (k !== undefined) state.k = k;
  return state;
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
  // Validate header before using any message fields.
  if (identityMsg.header.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error('Invalid Identity message: unsupported protocol version');
  }
  if (identityMsg.header.messageType !== OTRv4MessageType.DAKE_IDENTITY) {
    throw new Error('Invalid Identity message: incorrect message type');
  }
  if (!identityMsg.header.instanceTag || identityMsg.header.instanceTag.byteLength !== 4) {
    throw new Error('Invalid Identity message: malformed instance tag');
  }

  if (!validateClientProfile(identityMsg.clientProfile)) {
    throw new Error('Invalid remote Client Profile');
  }

  // Validate remote ephemeral Ed448 point before performing ECDH.
  if (!validateEd448Point(identityMsg.Y)) {
    throw new Error('Invalid Identity message: Y is not a valid Ed448 point');
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
  // Verify we are in the correct state with all required ephemeral secrets.
  if (dakeState.status !== DAKEStateStatus.WAITING_AUTH_R) {
    throw new Error(`Invalid DAKE state for Auth-R: expected WAITING_AUTH_R, got ${dakeState.status}`);
  }
  if (dakeState.ourY_secret === undefined || dakeState.ourB_secret === undefined) {
    throw new Error('Invalid DAKE state: missing required ephemeral secrets');
  }

  const theirProfile = authRMsg.clientProfile;

  if (!validateClientProfile(theirProfile)) {
    throw new Error('Invalid remote Client Profile in Auth-R');
  }

  // Validate remote ephemeral Ed448 point before performing ECDH.
  if (!validateEd448Point(authRMsg.Y)) {
    throw new Error('Invalid Auth-R message: Y is not a valid Ed448 point');
  }

  const theirY = authRMsg.Y;
  const theirB = decodeDH3072(authRMsg.B);

  // Alice (Identity sender) derives K and SSID using Bob's ephemeral keys.
  const { k, ssid } = deriveDAKESecrets({
    ourY_secret: dakeState.ourY_secret,
    ourB_secret: dakeState.ourB_secret,
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

  // Respond with Auth-I RingSig.
  const sigma = rsig(ourIdentitySecretH, ring, k);

  const message: AuthIMessage = {
    header: {
      protocolVersion: PROTOCOL_VERSION,
      messageType: OTRv4MessageType.DAKE_AUTH_I,
      instanceTag: dakeState.instanceTag,
    },
    sigma,
  };

  // Zeroize ephemeral private keys — no longer needed after handshake completes.
  dakeState.ourY_secret.fill(0);

  // Drop ephemeral secrets from post-handshake state by destructuring them out.
  // _ys/_yp/_bs/_bp reference the already-zeroed buffers above; they are discarded here.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { ourY_secret: _ys, ourY_public: _yp, ourB_secret: _bs, ourB_public: _bp, ...handshakeRest } = dakeState;
  const nextState: DAKEState = {
    ...handshakeRest,
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
  // Validate Auth-I header before verifying sigma or transitioning state.
  if (!authIMsg.header) {
    throw new Error('Invalid Auth-I message: missing header');
  }
  if (authIMsg.header.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error('Invalid Auth-I message: unsupported protocol version');
  }
  if (authIMsg.header.messageType !== OTRv4MessageType.DAKE_AUTH_I) {
    throw new Error('Invalid Auth-I message: incorrect message type');
  }
  // The Auth-I sender's instance tag must match what we recorded from the Identity message.
  if (
    dakeState.remoteInstanceTag === undefined ||
    !equalBytes(authIMsg.header.instanceTag, dakeState.remoteInstanceTag)
  ) {
    throw new Error('Invalid Auth-I message: instance tag mismatch');
  }

  if (dakeState.status !== DAKEStateStatus.WAITING_AUTH_I) {
    throw new Error(`Invalid DAKE state for Auth-I: expected WAITING_AUTH_I, got ${dakeState.status}`);
  }
  if (!dakeState.k || !dakeState.theirProfile) {
    throw new Error('Invalid DAKE state: missing keys or profile');
  }

  // Verify RingSig sigma (Auth-I).
  const ring: [Uint8Array, Uint8Array, Uint8Array] = [
    dakeState.theirProfile.publicKey, // H_A (them)
    dakeState.ourProfile.publicKey, // H_B (us)
    dakeState.theirProfile.forgingKey, // Forging_A (them)
  ];

  if (!rvrf(ring, authIMsg.sigma, dakeState.k)) {
    throw new Error('Auth-I Ring Signature verification failed');
  }

  // Zeroize ephemeral private key — no longer needed after handshake completes.
  dakeState.ourY_secret?.fill(0);

  // Drop ephemeral secrets from post-handshake state by destructuring them out.
  // _ys/_yp/_bs/_bp reference the already-zeroed (or absent) buffers above; they are discarded here.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { ourY_secret: _ys, ourY_public: _yp, ourB_secret: _bs, ourB_public: _bp, ...authIRest } = dakeState;
  const nextState: DAKEState = {
    ...authIRest,
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
