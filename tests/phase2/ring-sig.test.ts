import { describe, expect, it } from 'vitest';
import { generateKeypair } from '$core/crypto/ed448.js';
import { rsig, rvrf } from '$core/crypto/ring-sig.js';

// Thin adapter so test code stays concise
function makeKeypair(): { sk: Uint8Array; pk: Uint8Array } {
  const { privateKey: sk, publicKey: pk } = generateKeypair();
  return { sk, pk };
}

describe('rsig / rvrf (OTRv4 ring signature)', () => {
  describe('rsig', () => {
    it('produces a 342-byte sigma when signer is index 0', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('test message');
      const sigma = rsig(kp1.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      expect(sigma).toBeInstanceOf(Uint8Array);
      expect(sigma.byteLength).toBe(342);
    });

    it('produces a 342-byte sigma when signer is index 1', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('test message');
      const sigma = rsig(kp2.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      expect(sigma).toBeInstanceOf(Uint8Array);
      expect(sigma.byteLength).toBe(342);
    });

    it('produces a 342-byte sigma when signer is index 2', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('test message');
      const sigma = rsig(kp3.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      expect(sigma).toBeInstanceOf(Uint8Array);
      expect(sigma.byteLength).toBe(342);
    });
  });

  describe('rvrf', () => {
    it('verifies a valid sigma produced by signer at index 0', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('hello ring');
      const sigma = rsig(kp1.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], sigma, m)).toBe(true);
    });

    it('verifies a valid sigma produced by signer at index 1', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('hello ring');
      const sigma = rsig(kp2.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], sigma, m)).toBe(true);
    });

    it('verifies a valid sigma produced by signer at index 2', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('hello ring');
      const sigma = rsig(kp3.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], sigma, m)).toBe(true);
    });

    it('rejects a sigma with a flipped bit in c1', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('hello ring');
      const sigma = rsig(kp1.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      const tampered = new Uint8Array(sigma);
      tampered[0]! ^= 0x01;
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], tampered, m)).toBe(false);
    });

    it('rejects a sigma with a flipped bit in r2', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('test');
      const sigma = rsig(kp1.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      const tampered = new Uint8Array(sigma);
      tampered[171]! ^= 0x01;
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], tampered, m)).toBe(false);
    });

    it('rejects when the message is different', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('original message');
      const sigma = rsig(kp1.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      const m2 = new TextEncoder().encode('different message');
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], sigma, m2)).toBe(false);
    });

    it('rejects when the ring is mismatched (different A2)', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const kp4 = makeKeypair();
      const m = new TextEncoder().encode('ring mismatch');
      const sigma = rsig(kp1.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      expect(rvrf([kp1.pk, kp4.pk, kp3.pk], sigma, m)).toBe(false);
    });

    it('rejects a sigma of wrong length', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('test');
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], new Uint8Array(341), m)).toBe(false);
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], new Uint8Array(343), m)).toBe(false);
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], new Uint8Array(0), m)).toBe(false);
    });

    it('rejects a sigma of all zeros', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('test');
      expect(rvrf([kp1.pk, kp2.pk, kp3.pk], new Uint8Array(342), m)).toBe(false);
    });

    it('produces distinct sigmas on repeated calls (randomness)', () => {
      const kp1 = makeKeypair();
      const kp2 = makeKeypair();
      const kp3 = makeKeypair();
      const m = new TextEncoder().encode('same message');
      const s1 = rsig(kp1.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      const s2 = rsig(kp1.sk, [kp1.pk, kp2.pk, kp3.pk], m);
      expect(Buffer.from(s1).equals(Buffer.from(s2))).toBe(false);
    });
  });
});
