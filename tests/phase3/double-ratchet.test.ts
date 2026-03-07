import { generateKeypair } from '$core/crypto/ed448.js';
import {
  deriveMessageSecrets,
  dhRatchet,
  initializeRatchet,
  kdfRoot,
  OTRv4DoubleRatchet,
  serializeAD,
  skipMessageKeys,
  symmetricRatchet,
} from '$core/otr/double-ratchet.js';
import { describe, expect, it } from 'vitest';

describe('Double Ratchet (Section 3.17)', () => {
  const sharedSecret = new Uint8Array(64).fill(0x42);
  const identifier = new Uint8Array(8).fill(0x55);
  const aliceDH = generateKeypair();
  const bobDH = generateKeypair();

  it('should initialize ratchet state correctly', () => {
    const state = initializeRatchet(sharedSecret, aliceDH, identifier, bobDH.publicKey);
    expect(state.rootKey).toEqual(sharedSecret);
    expect(state.ourDH).toEqual(aliceDH);
    expect(state.theirDH).toEqual(bobDH.publicKey);
    expect(state.identifier).toEqual(identifier);
    expect(state.nSend).toBe(0);
    expect(state.nRecv).toBe(0);
  });

  it('should derive consistent root keys in DH ratchet', () => {
    const aliceState = initializeRatchet(sharedSecret, aliceDH, identifier);
    const bobState = initializeRatchet(sharedSecret, bobDH, identifier);

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
    const state = initializeRatchet(sharedSecret, aliceDH, identifier, bobDH.publicKey);
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

  it('should serialize and authenticate AD correctly', () => {
    const header = new Uint8Array([0x01, 0x02, 0x03]);
    const dh = aliceDH.publicKey;
    const ad = serializeAD(header, dh, 10, 20);

    expect(ad.length).toBe(header.length + dh.length + 8);
    const view = new DataView(ad.buffer, ad.byteOffset, ad.byteLength);
    expect(view.getUint32(header.length + dh.length, false)).toBe(10);
    expect(view.getUint32(header.length + dh.length + 4, false)).toBe(20);
  });

  describe('OTRv4DoubleRatchet Integration', () => {
    it('should complete a multi-step exchange between Alice and Bob', () => {
      const aliceDR = new OTRv4DoubleRatchet(initializeRatchet(sharedSecret, aliceDH, identifier, bobDH.publicKey));
      const bobDR = new OTRv4DoubleRatchet(initializeRatchet(sharedSecret, bobDH, identifier));

      const plaintext = new TextEncoder().encode('Hello Bob!');

      // Alice sends to Bob
      const msg1 = aliceDR.encrypt(plaintext);
      const dec1 = bobDR.decrypt(msg1);
      expect(new TextDecoder().decode(dec1)).toBe('Hello Bob!');

      // Bob replies to Alice
      const replyText = new TextEncoder().encode('Hey Alice!');
      const msg2 = bobDR.encrypt(replyText);
      const dec2 = aliceDR.decrypt(msg2);
      expect(new TextDecoder().decode(dec2)).toBe('Hey Alice!');

      // Alice sends another message (same chain)
      const msg3 = aliceDR.encrypt(new TextEncoder().encode('Chain test'));
      const dec3 = bobDR.decrypt(msg3);
      expect(new TextDecoder().decode(dec3)).toBe('Chain test');

      expect(msg1.nonce.length).toBe(12);
      expect(msg3.ciphertext.length).toBeGreaterThan(0);
    });

    it('should handle out-of-order messages using skipped keys', () => {
      const aliceDR = new OTRv4DoubleRatchet(initializeRatchet(sharedSecret, aliceDH, identifier, bobDH.publicKey));
      const bobDR = new OTRv4DoubleRatchet(initializeRatchet(sharedSecret, bobDH, identifier));

      const msg1 = aliceDR.encrypt(new TextEncoder().encode('Msg 1'));
      const msg2 = aliceDR.encrypt(new TextEncoder().encode('Msg 2'));
      const msg3 = aliceDR.encrypt(new TextEncoder().encode('Msg 3'));

      // Decrypt Msg 3 first (skips 1 and 2)
      const dec3 = bobDR.decrypt(msg3);
      expect(new TextDecoder().decode(dec3)).toBe('Msg 3');

      // Decrypt Msg 1
      const dec1 = bobDR.decrypt(msg1);
      expect(new TextDecoder().decode(dec1)).toBe('Msg 1');

      // Decrypt Msg 2
      const dec2 = bobDR.decrypt(msg2);
      expect(new TextDecoder().decode(dec2)).toBe('Msg 2');
    });
  });
});
