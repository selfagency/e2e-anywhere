import {
  computeSharedSecret,
  deserializePublicKey,
  generateKeypair,
  serializePublicKey,
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
});
