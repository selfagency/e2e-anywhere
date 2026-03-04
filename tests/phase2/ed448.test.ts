import { generateKeypair, sign, validatePoint, verify } from '$core/crypto/ed448.js';
import { describe, expect, it } from 'vitest';

describe('phase 2.7 ed448 primitives', () => {
  it('generates a keypair with correct byte lengths', () => {
    const { publicKey, privateKey } = generateKeypair();
    // Ed448-Goldilocks: 57-byte keys
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.byteLength).toBe(57);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.byteLength).toBe(57);
  });

  it('signs a message and produces a 114-byte signature', () => {
    const { privateKey } = generateKeypair();
    const message = new TextEncoder().encode('hello otrv4');
    const signature = sign(message, privateKey);
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.byteLength).toBe(114);
  });

  it('verifies a valid signature', () => {
    const { publicKey, privateKey } = generateKeypair();
    const message = new TextEncoder().encode('verify me');
    const signature = sign(message, privateKey);
    expect(verify(signature, message, publicKey)).toBe(true);
  });

  it('rejects a tampered message', () => {
    const { publicKey, privateKey } = generateKeypair();
    const message = new TextEncoder().encode('original');
    const signature = sign(message, privateKey);
    const tampered = new TextEncoder().encode('tampered');
    expect(verify(signature, tampered, publicKey)).toBe(false);
  });

  it('rejects a tampered signature', () => {
    const { publicKey, privateKey } = generateKeypair();
    const message = new TextEncoder().encode('original');
    const signature = sign(message, privateKey);
    const badSig = new Uint8Array(signature);
    badSig[0] ^= 0xff;
    expect(verify(badSig, message, publicKey)).toBe(false);
  });

  it('rejects cross-key verification', () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const message = new TextEncoder().encode('cross key');
    const signature = sign(message, kp1.privateKey);
    expect(verify(signature, message, kp2.publicKey)).toBe(false);
  });

  it('sign+verify roundtrip with empty message', () => {
    const { publicKey, privateKey } = generateKeypair();
    const message = new Uint8Array(0);
    const signature = sign(message, privateKey);
    expect(verify(signature, message, publicKey)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Phase 2.14 (prlx) — validatePoint: point validation hardening
// ---------------------------------------------------------------------------

describe('phase 2.14 validatePoint — Ed448 point validation hardening', () => {
  it('returns true for a freshly generated (valid) public key', () => {
    const { publicKey } = generateKeypair();
    expect(validatePoint(publicKey)).toBe(true);
  });

  it('returns false for a 57-byte all-zeros buffer (encodes identity / low-order point)', () => {
    expect(validatePoint(new Uint8Array(57))).toBe(false);
  });

  it('returns false for a buffer shorter than 57 bytes', () => {
    expect(validatePoint(new Uint8Array(0))).toBe(false);
    expect(validatePoint(new Uint8Array(56))).toBe(false);
  });

  it('returns false for a buffer longer than 57 bytes', () => {
    expect(validatePoint(new Uint8Array(58))).toBe(false);
    expect(validatePoint(new Uint8Array(114))).toBe(false);
  });

  it('returns false for a buffer of all 0xFF (structurally invalid point encoding)', () => {
    expect(validatePoint(new Uint8Array(57).fill(0xff))).toBe(false);
  });

  it('returns true for multiple independently generated keypairs', () => {
    for (let i = 0; i < 5; i++) {
      const { publicKey } = generateKeypair();
      expect(validatePoint(publicKey)).toBe(true);
    }
  });
});
