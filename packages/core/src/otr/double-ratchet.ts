/**
 * OTRv4 Double Ratchet Engine (Section 3.17)
 *
 * Implements the asymmetric (Diffie-Hellman) and symmetric (KDF chain)
 * ratchets for end-to-end encrypted messaging.
 */

import { diffieHellman } from '$core/crypto/ed448.js';
import { kdf } from '$core/crypto/kdf.js';

/** Ratchet usage IDs from OTRv4 spec (Section 3.17.1) */
export enum RatchetUsage {
  ROOT = 0x11,
  CHAIN = 0x12,
  MESSAGE = 0x13,
}

export interface RatchetState {
  /** Root key (RK) — updated via Diffie-Hellman ratchet. */
  rootKey: Uint8Array;
  /** Send chain key (CKs) — updated via symmetric ratchet. */
  sendChainKey: Uint8Array | null;
  /** Receive chain key (CKr) — updated via symmetric ratchet. */
  recvChainKey: Uint8Array | null;
  /** Our current ephemeral DH keypair. */
  ourDH: { privateKey: Uint8Array; publicKey: Uint8Array };
  /** Their current ephemeral DH public key. */
  theirDH: Uint8Array | null;
  /** Message counter for our send chain. */
  nSend: number;
  /** Message counter for their send chain (our receive chain). */
  nRecv: number;
  /** Previous number of messages in the send chain. */
  pSend: number;
  /** Dictionary of skipped message keys, indexed by (DH_pub, counter). */
  skippedMessageKeys: Map<string, Uint8Array>;
}

/**
 * Section 3.17.1: Double Ratchet KDF functions
 * These use SHAKE-256 with specific usage IDs.
 */

/**
 * KDF_Root(RK, DH_out) -> (RK', CKs)
 */
export function kdfRoot(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  // Usage ID 0x11
  const out = kdf(RatchetUsage.ROOT, [rk, dhOut], 128);
  return [out.slice(0, 64), out.slice(64, 128)];
}

/**
 * KDF_Chain(CK) -> (CK', MK)
 */
export function kdfChain(ck: Uint8Array): [Uint8Array, Uint8Array] {
  // Usage ID 0x12
  const out = kdf(RatchetUsage.CHAIN, [ck], 128);
  return [out.slice(0, 64), out.slice(64, 128)];
}

/**
 * KDF_Message(MK) -> (C, M, AD)
 * OTRv4 uses this to derive encryption key, MAC key, and authenticated data.
 */
export function deriveMessageSecrets(mk: Uint8Array): {
  encKey: Uint8Array;
  macKey: Uint8Array;
} {
  // Usage ID 0x13
  const out = kdf(RatchetUsage.MESSAGE, [mk], 128);
  return {
    encKey: out.slice(0, 32),
    macKey: out.slice(32, 96), // 64-byte MAC key
  };
}

/**
 * Initialize the Double Ratchet state after a successful DAKE.
 */
export function initializeRatchet(
  sharedSecret: Uint8Array,
  ourDH: { privateKey: Uint8Array; publicKey: Uint8Array },
  theirDH: Uint8Array | null = null,
): RatchetState {
  // Initiator (Alice) starts with sharedSecret as RK and Bob's DH key.
  // Responder (Bob) starts with sharedSecret as RK and DH ratchet is triggered by Alice's message.

  return {
    rootKey: sharedSecret,
    sendChainKey: null,
    recvChainKey: null,
    ourDH,
    theirDH,
    nSend: 0,
    nRecv: 0,
    pSend: 0,
    skippedMessageKeys: new Map(),
  };
}

/**
 * Perform an asymmetric (Diffie-Hellman) ratchet step.
 * Updates the root key and generates a new send chain key.
 */
export function dhRatchet(state: RatchetState, theirNewDH: Uint8Array): void {
  state.pSend = state.nSend;
  state.nSend = 0;
  state.nRecv = 0;
  state.theirDH = theirNewDH;

  // RK', CKr = KDF_Root(RK, DH(ourDH, theirDH))
  const dh = diffieHellman(state.ourDH.privateKey, state.theirDH);
  const [newRK, ckr] = kdfRoot(state.rootKey, dh);
  state.rootKey = newRK;
  state.recvChainKey = ckr;
}

/**
 * Perform a symmetric ratchet step on a chain key.
 *
 * (CK', MK) = KDF_Chain(CK)
 *
 * @returns { messageKey: MK }
 */
export function symmetricRatchet(chainKey: Uint8Array): {
  newChainKey: Uint8Array;
  messageKey: Uint8Array;
} {
  const [newChainKey, messageKey] = kdfChain(chainKey);
  return { newChainKey, messageKey };
}

/**
 * Skip message keys for missed messages.
 * OTRv4 stores these to allow out-of-order decryption.
 */
export function skipMessageKeys(state: RatchetState, until: number): void {
  if (!state.recvChainKey) return;

  while (state.nRecv < until) {
    const { newChainKey, messageKey } = symmetricRatchet(state.recvChainKey);
    state.recvChainKey = newChainKey;

    // Index by (DH_pub, counter) as per spec
    if (state.theirDH) {
      const key = `${Buffer.from(state.theirDH).toString('hex')}:${state.nRecv}`;
      state.skippedMessageKeys.set(key, messageKey);
    }
    state.nRecv++;
  }
}
