import { describe, it, expect } from 'vitest';
import {
  initializeRatchet,
  kdfRoot,
  kdfChain,
  deriveMessageSecrets,
  dhRatchet,
  symmetricRatchet,
  skipMessageKeys,
} from '$core/otr/double-ratchet.js';
import { generateKeypair } from '$core/crypto/ed448.js';

describe('Double Ratchet (Section 3.17)', () => {
  const sharedSecret = new Uint8Array(64).fill(0x42);
  const aliceDH = generateKeypair();
  const bobDH = generateKeypair();

  it('should initialize ratchet state correctly', () => {
    const state = initializeRatchet(sharedSecret, aliceDH, bobDH.publicKey);
    expect(state.rootKey).toEqual(sharedSecret);
    expect(state.ourDH).toEqual(aliceDH);
    expect(state.theirDH).toEqual(bobDH.publicKey);
    expect(state.nSend).toBe(0);
    expect(state.nRecv).toBe(0);
  });

  it('should derive consistent root keys in DH ratchet', () => {
    const aliceState = initializeRatchet(sharedSecret, aliceDH);
    const bobState = initializeRatchet(sharedSecret, bobDH);

    // Alice performs DH ratchet with Bob's public key
    dhRatchet(aliceState, bobDH.publicKey);

    // Bob receives Alice's public key (assuming he didn't have it initialized)
    dhRatchet(bobState, aliceDH.publicKey);

    expect(aliceState.rootKey).toEqual(bobState.rootKey);
    expect(aliceState.recvChainKey).toEqual(bobState.recvChainKey);
    expect(aliceState.rootKey).not.toEqual(sharedSecret);
  });

  it('should derive consistent message keys in symmetric ratchet', () => {
    const ck = new Uint8Array(64).fill(0x11);
    const { newChainKey: ck1, messageKey: mk1 } = symmetricRatchet(ck);
    const { newChainKey: ck2, messageKey: mk2 } = symmetricRatchet(ck1);

    expect(ck1).not.toEqual(ck);
    expect(ck2).not.toEqual(ck1);
    expect(mk1).not.toEqual(mk2);
  });

  it('should skip message keys correctly', () => {
    const state = initializeRatchet(sharedSecret, aliceDH, bobDH.publicKey);
    // Setup a receive chain
    const [, ckr] = kdfRoot(sharedSecret, new Uint8Array(57).fill(0x99));
    state.recvChainKey = ckr;

    skipMessageKeys(state, 3);

    expect(state.nRecv).toBe(3);
    expect(state.skippedMessageKeys.size).toBe(3);

    const dhHex = Buffer.from(bobDH.publicKey).toString('hex');
    expect(state.skippedMessageKeys.has(`${dhHex}:0`)).toBe(true);
    expect(state.skippedMessageKeys.has(`${dhHex}:1`)).toBe(true);
    expect(state.skippedMessageKeys.has(`${dhHex}:2`)).toBe(true);
  });

  it('should derive encryption and MAC keys from message key', () => {
    const mk = new Uint8Array(64).fill(0x33);
    const { encKey, macKey } = deriveMessageSecrets(mk);

    expect(encKey.length).toBe(32);
    expect(macKey.length).toBe(64);
  });
});
