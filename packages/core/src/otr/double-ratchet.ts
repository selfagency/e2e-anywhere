/**
 * OTRv4 Double Ratchet Engine (Section 3.17)
 *
 * Implements the asymmetric (Diffie-Hellman) and symmetric (KDF chain)
 * ratchets for end-to-end encrypted messaging.
 */

import { diffieHellman, generateKeypair } from '$core/crypto/ed448.js';
import { kdf, hmac } from '$core/crypto/kdf.js';
import { encrypt as nobleEncrypt, decrypt as nobleDecrypt } from '$core/crypto/chacha20.js';
import { OTRv4MessageType, type DataMessage } from '$core/types.js';

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
  /** Session identifier established during DAKE. */
  identifier: Uint8Array;
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
 * Section 3.17: Message Header (Authenticated Data)
 */
export interface MessageHeader {
  /** Current ephemeral public key. */
  dh: Uint8Array;
  /** Previous chain length. */
  pn: number;
  /** Message counter in current chain. */
  n: number;
}

/**
 * Serialize the Associated Data (AD) for a message.
 * AD = header || ratchetKey || identifier
 *
 * (Note: Spec uses 'identifier' for (pn, n) and other session info)
 */
export function serializeAD(header: Uint8Array, dh: Uint8Array, pn: number, n: number): Uint8Array {
  // pn and n are 4-byte big-endian integers as per standard OTRv4 serialization
  const ad = new Uint8Array(header.length + dh.length + 8);
  ad.set(header, 0);
  ad.set(dh, header.length);

  const view = new DataView(ad.buffer, ad.byteOffset, ad.byteLength);
  view.setUint32(header.length + dh.length, pn, false);
  view.setUint32(header.length + dh.length + 4, n, false);

  return ad;
}

/**
 * Encrypt a message using the current ratchet state.
 */
export function encryptMessage(
  state: RatchetState,
  plaintext: Uint8Array,
  ad: Uint8Array,
): { ciphertext: Uint8Array; n: number; pn: number; dh: Uint8Array; macKey: Uint8Array } {
  if (!state.sendChainKey) {
    throw new Error('Ratchet not initialized for sending');
  }

  const { newChainKey, messageKey } = symmetricRatchet(state.sendChainKey);
  state.sendChainKey = newChainKey;

  const { encKey, macKey } = deriveMessageSecrets(messageKey);
  // console.log('encryptMessage derived encKey (hex):', Buffer.from(encKey).toString('hex'));
  const n = state.nSend;
  state.nSend++;

  // OTRv4 uses randomized 12-byte nonces for each message
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // The 'identifier' in AEAD is often just (pn, n) serialized as AD.
  const ciphertext = nobleEncrypt({
    key: encKey,
    nonce,
    plaintext,
    ad,
  });

  // OTRv4 concatenates [nonce || ciphertext] for the wire format.
  // The 'ciphertext' returned by our chacha20 wrapper already includes the 16-byte Poly1305 tag.
  const result = new Uint8Array(nonce.length + ciphertext.length);
  result.set(nonce, 0);
  result.set(ciphertext, nonce.length);

  return {
    ciphertext: result,
    n,
    pn: state.pSend,
    dh: state.ourDH.publicKey,
    macKey,
  };
}

/**
 * Decrypt a message using the current ratchet state or skipped keys.
 */
export function decryptMessage(
  state: RatchetState,
  header: MessageHeader,
  ciphertextWithNonce: Uint8Array,
  ad: Uint8Array,
): { plaintext: Uint8Array; macKey: Uint8Array } {
  const nonce = ciphertextWithNonce.slice(0, 12);
  const ciphertext = ciphertextWithNonce.slice(12);

  // 1. Check skipped message keys
  const dhHex = Buffer.from(header.dh).toString('hex');
  const skipKey = `${dhHex}:${header.n}`;
  const skippedMk = state.skippedMessageKeys.get(skipKey);

  if (skippedMk) {
    const { encKey, macKey } = deriveMessageSecrets(skippedMk);
    state.skippedMessageKeys.delete(skipKey);
    const plaintext = nobleDecrypt({ key: encKey, nonce, ciphertext, ad });
    return { plaintext, macKey };
  }

  // 2. Perform DH ratchet if message is for a new ephemeral key
  if (!state.theirDH || Buffer.from(header.dh).compare(Buffer.from(state.theirDH)) !== 0) {
    if (state.theirDH) {
      skipMessageKeys(state, header.pn);
    }
    dhRatchet(state, header.dh);

    // After performing a receive DH ratchet, we must generate a new local
    // ephemeral key and derive a new send chain key.
    dhRatchetSend(state);
  }

  // 3. Skip any missed messages in the current chain
  skipMessageKeys(state, header.n);

  // 4. Symmetric ratchet to current message
  if (!state.recvChainKey) {
    throw new Error('Ratchet not initialized for receiving');
  }

  const { newChainKey, messageKey } = symmetricRatchet(state.recvChainKey);
  state.recvChainKey = newChainKey;

  const { encKey, macKey } = deriveMessageSecrets(messageKey);
  // console.log('decryptMessage derived encKey (hex):', Buffer.from(encKey).toString('hex'));
  const plaintext = nobleDecrypt({ key: encKey, nonce, ciphertext, ad });

  state.nRecv++;

  return { plaintext, macKey };
}

/**
 * High-level Double Ratchet instance.
 * Encapsulates the state and provides a simpler interface for encrypting and decrypting messages.
 */
export class OTRv4DoubleRatchet {
  constructor(private state: RatchetState) {}

  /**
   * Encrypt a message payload into a DataMessage (Section 3.18).
   */
  public encrypt(plaintext: Uint8Array): DataMessage {
    // Before encrypting, if we don't have a sendChainKey, we must perform a DH ratchet
    // with our current DH and their current DH to establish the first chain.
    if (!this.state.sendChainKey && this.state.theirDH) {
      const dh = diffieHellman(this.state.ourDH.privateKey, this.state.theirDH);
      const [newRK, cks] = kdfRoot(this.state.rootKey, dh);
      this.state.rootKey = newRK;
      this.state.sendChainKey = cks;
    }

    // OTRv4 section 3.18: AD = protocol_version || message_type || flags || ratchet_key || identifier
    // message_type = 0x06 (DATA)
    const ad = new Uint8Array(1 + 1 + 1 + 57 + 8);
    ad[0] = 4; // protocol_version
    ad[1] = 0x06; // message_type
    ad[2] = 0; // flags
    ad.set(this.state.ourDH.publicKey, 3);
    ad.set(this.state.identifier, 3 + 57);

    // console.log('Encrypt AD:', Buffer.from(ad).toString('hex'));

    const { ciphertext, dh, n, pn, macKey } = encryptMessage(this.state, plaintext, ad);

    // console.log('Class Encrypt Header DH (hex):', Buffer.from(dh).toString('hex'));
    // console.log('Class Encrypt Ciphertext (last 16):', Buffer.from(ciphertext.slice(-16)).toString('hex'));

    // OTRv4 DataMessages use a specific nonce/ciphertext structure.
    // The 'ciphertext' from encryptMessage already includes the 12-byte nonce at the start.
    const nonce = ciphertext.slice(0, 12);
    const ct = ciphertext.slice(12);

    const message: DataMessage = {
      header: {
        protocolVersion: 4,
        messageType: OTRv4MessageType.DATA,
        instanceTag: new Uint8Array(4), // Placeholder, should be passed in or stored in state
      },
      flags: 0,
      n,
      pn,
      ratchetKey: dh,
      identifier: this.state.identifier,
      nonce,
      ciphertext: ct,
      mac: new Uint8Array(64), // Placeholder (Section 3.18.3)
      oldMacKeys: [],
    };

    // TODO: Calculate HMAC-SHA-512 (Section 3.18.3)
    // hmac(macKey, ad || message_header || message_payload)

    return message;
  }

  /**
   * Decrypt and authenticate an incoming DataMessage.
   */
  public decrypt(message: DataMessage): Uint8Array {
    const header: MessageHeader = {
      dh: message.ratchetKey,
      n: message.n,
      pn: message.pn,
    };

    // Reconstruct the AD as used in encrypt()
    const ad = new Uint8Array(1 + 1 + 1 + 57 + 8);
    ad[0] = 4;
    ad[1] = 0x06;
    ad[2] = message.flags;
    ad.set(message.ratchetKey, 3);
    ad.set(message.identifier, 3 + 57);

    // console.log('Decrypt AD:', Buffer.from(ad).toString('hex'));

    // Reconstruct the nonce || ciphertext for our decryptMessage helper
    const ciphertextWithNonce = new Uint8Array(message.nonce.length + message.ciphertext.length);
    ciphertextWithNonce.set(message.nonce, 0);
    ciphertextWithNonce.set(message.ciphertext, message.nonce.length);

    // console.log('Class Decrypt Header DH (hex):', Buffer.from(header.dh).toString('hex'));
    // console.log('Class Decrypt Ciphertext (last 16):', Buffer.from(message.ciphertext.slice(-16)).toString('hex'));

    const { plaintext, macKey } = decryptMessage(this.state, header, ciphertextWithNonce, ad);

    // TODO: Verify HMAC-SHA-512 (Section 3.18.3)
    // hmac(macKey, ad || message_header || message_payload)

    return plaintext;
  }

  /** Export state for serialization (Section 3.16.1 pattern) */
  public getState(): RatchetState {
    return this.state;
  }
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
  identifier: Uint8Array,
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
    identifier,
    nSend: 0,
    nRecv: 0,
    pSend: 0,
    skippedMessageKeys: new Map(),
  };
}

/**
 * Perform an asymmetric (Diffie-Hellman) ratchet step for the receive chain.
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
 * Perform an asymmetric (Diffie-Hellman) ratchet step for the send chain.
 */
export function dhRatchetSend(state: RatchetState): void {
  if (!state.theirDH) return;

  // Generate new ephemeral keypair
  state.ourDH = generateKeypair();

  // RK', CKs = KDF_Root(RK, DH(ourDH, theirDH))
  const dh = diffieHellman(state.ourDH.privateKey, state.theirDH);
  const [newRK, cks] = kdfRoot(state.rootKey, dh);
  state.rootKey = newRK;
  state.sendChainKey = cks;
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
