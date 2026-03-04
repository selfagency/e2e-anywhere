import {
  DH_P,
  DH_PUBLIC_KEY_BYTES,
  computeSharedSecret,
  deserializePublicKey,
  generateKeypair,
  serializePublicKey,
  validateDHGroupMembership,
  validatePublicKey,
} from '$core/crypto/dh3072.js';
import { describe, expect, it } from 'vitest';

describe('phase 2.8 dh3072 primitives', () => {
  it('generates a keypair with correct structure', () => {
    const { publicKey, privateKey } = generateKeypair();
    expect(typeof publicKey).toBe('bigint');
    expect(typeof privateKey).toBe('bigint');
    expect(publicKey).toBeGreaterThan(1n);
    expect(privateKey).toBeGreaterThan(1n);
  });

  it('public key validates as a member of the group', () => {
    const { publicKey } = generateKeypair();
    expect(() => validatePublicKey(publicKey)).not.toThrow();
  });

  it('computes matching shared secrets from both sides (DH symmetry)', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const sharedAlice = computeSharedSecret(alice.privateKey, bob.publicKey);
    const sharedBob = computeSharedSecret(bob.privateKey, alice.publicKey);
    expect(sharedAlice).toBe(sharedBob);
  });

  it('throws when given a public key of 1 (trivial key)', () => {
    const { privateKey } = generateKeypair();
    expect(() => computeSharedSecret(privateKey, 1n)).toThrow('public key out of valid range');
  });

  it('throws when given a public key of 0', () => {
    const { privateKey } = generateKeypair();
    expect(() => computeSharedSecret(privateKey, 0n)).toThrow('public key out of valid range');
  });

  it('serializes pubkey to exactly 384 bytes (big-endian)', () => {
    const { publicKey } = generateKeypair();
    const serialized = serializePublicKey(publicKey);
    expect(serialized).toBeInstanceOf(Uint8Array);
    expect(serialized.byteLength).toBe(384);
  });

  it('round-trips publicKey through serialize/deserialize', () => {
    const { publicKey } = generateKeypair();
    const serialized = serializePublicKey(publicKey);
    const deserialized = deserializePublicKey(serialized);
    expect(deserialized).toBe(publicKey);
  });

  describe('deserializePublicKey input validation', () => {
    it('throws on a buffer shorter than 384 bytes', () => {
      const short = new Uint8Array(383);
      expect(() => deserializePublicKey(short)).toThrow(RangeError);
      expect(() => deserializePublicKey(short)).toThrow('384 bytes');
    });

    it('throws on a buffer longer than 384 bytes', () => {
      const long = new Uint8Array(385);
      expect(() => deserializePublicKey(long)).toThrow(RangeError);
      expect(() => deserializePublicKey(long)).toThrow('384 bytes');
    });

    it('throws on a zero-filled 384-byte buffer (out-of-range value 0)', () => {
      const zeroes = new Uint8Array(DH_PUBLIC_KEY_BYTES);
      expect(() => deserializePublicKey(zeroes)).toThrow('public key out of valid range');
    });

    it('throws on a 384-byte buffer encoding p − 1 (out-of-range)', () => {
      // p − 1 is outside [2, p − 2]
      const bytes = serializePublicKey(DH_P - 1n);
      expect(() => deserializePublicKey(bytes)).toThrow('public key out of valid range');
    });
  });

  describe('validateDHGroupMembership', () => {
    it('accepts a freshly generated public key', () => {
      const { publicKey } = generateKeypair();
      expect(validateDHGroupMembership(publicKey)).toBe(true);
    });

    it('rejects 0', () => {
      expect(validateDHGroupMembership(0n)).toBe(false);
    });

    it('rejects 1', () => {
      expect(validateDHGroupMembership(1n)).toBe(false);
    });

    it('rejects p − 1 (upper boundary exclusive)', () => {
      expect(validateDHGroupMembership(DH_P - 1n)).toBe(false);
    });

    it('rejects p (equals modulus)', () => {
      expect(validateDHGroupMembership(DH_P)).toBe(false);
    });

    it('rejects p − 2 (non-QR: not in prime-order subgroup)', () => {
      // p − 2 ≡ −2 (mod p); Legendre(−2) = Legendre(−1)·Legendre(2) = −1 for this prime,
      // so p − 2 is not a quadratic residue and must be rejected.
      expect(validateDHGroupMembership(DH_P - 2n)).toBe(false);
    });

    it('accepts 2 (valid lower boundary; QR for this prime)', () => {
      // g = 2 satisfies 2^((p−1)/2) ≡ 1 (mod p) for p ≡ 7 (mod 8).
      expect(validateDHGroupMembership(2n)).toBe(true);
    });
  });
});
