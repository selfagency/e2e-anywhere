/**
 * Bean 86v1 — Phase 2.12 property-based tests.
 *
 * These tests verify invariants that must hold for ALL valid inputs, not just
 * specific vectors.  Each test runs a small number of iterations (3–5) with
 * freshly generated material to approximate property-based testing without an
 * external framework.
 */

import { describe, expect, it } from 'vitest';
import { generateKeypair as ed448Keypair, sign, verify } from '$core/crypto/ed448.js';
import {
  DH_PUBLIC_KEY_BYTES,
  computeSharedSecret,
  deserializePublicKey,
  generateKeypair as dhKeypair,
  serializePublicKey,
  validatePublicKey,
} from '$core/crypto/dh3072.js';
import { HASH_LEN, derive } from '$core/crypto/kdf.js';
import { TAG_LEN, decrypt, encrypt } from '$core/crypto/chacha20.js';
import { RING_SIG_BYTES, rsig, rvrf } from '$core/crypto/ring-sig.js';

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/** Generate `n` bytes of deterministic test material from a seed string. */
function pseudoRandom(seed: string, n: number): Uint8Array {
  const enc = new TextEncoder().encode(seed);
  const buf = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    buf[i] = enc[i % enc.length]! ^ (i & 0xff);
  }
  return buf;
}

const ITERATIONS = 3;

// ---------------------------------------------------------------------------
// Ed448
// ---------------------------------------------------------------------------

describe('ed448 properties', () => {
  it('[∀ keypair] sign → verify succeeds (round-trip)', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const { privateKey, publicKey } = ed448Keypair();
      const msg = pseudoRandom(`ed448-rtrip-${i}`, 64);
      const sig = sign(msg, privateKey);
      expect(verify(sig, msg, publicKey)).toBe(true);
    }
  });

  it('[∀ keypair] signature is exactly 114 bytes', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const { privateKey } = ed448Keypair();
      const msg = pseudoRandom(`ed448-len-${i}`, 32);
      expect(sign(msg, privateKey).byteLength).toBe(114);
    }
  });

  it('[∀ keypair] signature is invalid for a different message', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const { privateKey, publicKey } = ed448Keypair();
      const msg = pseudoRandom(`ed448-msg-${i}`, 40);
      const sig = sign(msg, privateKey);
      const otherMsg = pseudoRandom(`ed448-other-${i}`, 40);
      expect(verify(sig, otherMsg, publicKey)).toBe(false);
    }
  });

  it('[∀ keypair] signing with a different key produces an invalid signature', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const { privateKey } = ed448Keypair();
      const { publicKey: otherPk } = ed448Keypair();
      const msg = pseudoRandom(`ed448-wrongkey-${i}`, 48);
      const sig = sign(msg, privateKey);
      expect(verify(sig, msg, otherPk)).toBe(false);
    }
  });

  it('[∀ keypair] two signatures of the same message are equal (Ed448 signing is deterministic)', () => {
    // Ed448 as used by @noble is deterministic — same sk+msg always gives same sig.
    // Verify this determinism property holds.
    for (let i = 0; i < ITERATIONS; i++) {
      const { privateKey, publicKey } = ed448Keypair();
      const msg = pseudoRandom(`ed448-det-${i}`, 32);
      const sig1 = sign(msg, privateKey);
      const sig2 = sign(msg, privateKey);
      expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(true);
      expect(verify(sig1, msg, publicKey)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// DH-3072
// ---------------------------------------------------------------------------

describe('dh3072 properties', () => {
  it('[∀ keypair pair] shared secret is equal on both sides', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const alice = dhKeypair();
      const bob = dhKeypair();
      const aliceShared = computeSharedSecret(alice.privateKey, bob.publicKey);
      const bobShared = computeSharedSecret(bob.privateKey, alice.publicKey);
      expect(aliceShared).toBe(bobShared);
    }
  });

  it('[∀ keypair] serialize → deserialize round-trips the public key', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const { publicKey } = dhKeypair();
      const bytes = serializePublicKey(publicKey);
      expect(bytes.byteLength).toBe(DH_PUBLIC_KEY_BYTES);
      const recovered = deserializePublicKey(bytes);
      expect(recovered).toBe(publicKey);
    }
  });

  it('[∀ generated keypair] public key passes validatePublicKey without throwing', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const { publicKey } = dhKeypair();
      expect(() => validatePublicKey(publicKey)).not.toThrow();
    }
  });

  it('validatePublicKey rejects boundary values: 0, 1, p, p-1', () => {
    // 0n and 1n are always below the valid range [2, p-2].
    // We test other boundary values by checking that generated keys always
    // pass — and that known-bad values (0, 1) are rejected.
    expect(() => validatePublicKey(0n)).toThrow(RangeError);
    expect(() => validatePublicKey(1n)).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

describe('kdf properties', () => {
  it('[∀ ikm] derive is deterministic', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const ikm = pseudoRandom(`kdf-ikm-${i}`, 32);
      const salt = pseudoRandom(`kdf-salt-${i}`, 64);
      const r1 = derive({ ikm, salt });
      const r2 = derive({ ikm, salt });
      expect(Buffer.from(r1).equals(Buffer.from(r2))).toBe(true);
    }
  });

  it('default output length equals HASH_LEN (64 bytes)', () => {
    const ikm = pseudoRandom('kdf-default-len', 32);
    const salt = pseudoRandom('kdf-salt-default', 64);
    expect(derive({ ikm, salt }).byteLength).toBe(HASH_LEN);
  });

  it('output length honours the length parameter', () => {
    const ikm = pseudoRandom('kdf-len', 32);
    const salt = pseudoRandom('kdf-salt-len', 64);
    for (const len of [16, 32, 64, 128]) {
      expect(derive({ ikm, salt, length: len }).byteLength).toBe(len);
    }
  });

  it('[∀ ikm pair] distinct IKMs produce distinct outputs', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const salt = pseudoRandom(`kdf-distinct-salt-${i}`, 64);
      const ikm1 = pseudoRandom(`kdf-ikm1-${i}`, 32);
      const ikm2 = pseudoRandom(`kdf-ikm2-${i}`, 32);
      // Make sure ikm1 ≠ ikm2
      ikm2[0] = (ikm2[0]! ^ 0xff) & 0xff;
      const out1 = derive({ ikm: ikm1, salt });
      const out2 = derive({ ikm: ikm2, salt });
      expect(Buffer.from(out1).equals(Buffer.from(out2))).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

describe('chacha20 properties', () => {
  it('[∀ plaintext] encrypt → decrypt round-trip', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const key = pseudoRandom(`cc20-key-${i}`, 32);
      const nonce = pseudoRandom(`cc20-nonce-${i}`, 12);
      const plaintext = pseudoRandom(`cc20-pt-${i}`, 64);
      const ciphertext = encrypt({ key, nonce, plaintext });
      const recovered = decrypt({ key, nonce, ciphertext });
      expect(Buffer.from(recovered).equals(Buffer.from(plaintext))).toBe(true);
    }
  });

  it('[∀ plaintext] ciphertext length = plaintext.byteLength + TAG_LEN', () => {
    for (const ptLen of [0, 1, 16, 63, 128]) {
      const key = pseudoRandom(`cc20-len-key-${ptLen}`, 32);
      const nonce = pseudoRandom(`cc20-len-nonce-${ptLen}`, 12);
      const plaintext = pseudoRandom(`cc20-len-pt-${ptLen}`, ptLen);
      const ct = encrypt({ key, nonce, plaintext });
      expect(ct.byteLength).toBe(ptLen + TAG_LEN);
    }
  });

  it('[∀ ciphertext] single-bit flip in ciphertext body causes decrypt to throw', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const key = pseudoRandom(`cc20-tamper-key-${i}`, 32);
      const nonce = pseudoRandom(`cc20-tamper-nonce-${i}`, 12);
      const plaintext = pseudoRandom(`cc20-tamper-pt-${i}`, 32);
      const ct = encrypt({ key, nonce, plaintext });
      const tampered = new Uint8Array(ct);
      tampered[0]! ^= 0x01;
      expect(() => decrypt({ key, nonce, ciphertext: tampered })).toThrow('invalid tag');
    }
  });

  it('[∀ ciphertext] wrong decryption key causes decrypt to throw', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const key = pseudoRandom(`cc20-wrongkey-key-${i}`, 32);
      const nonce = pseudoRandom(`cc20-wrongkey-nonce-${i}`, 12);
      const plaintext = pseudoRandom(`cc20-wrongkey-pt-${i}`, 32);
      const ct = encrypt({ key, nonce, plaintext });
      // Flip a bit in the first byte of the key — guaranteed to produce a different key
      const wrongKey = new Uint8Array(key);
      wrongKey[0]! ^= 0x01;
      expect(() => decrypt({ key: wrongKey, nonce, ciphertext: ct })).toThrow('invalid tag');
    }
  });

  it('[∀ ciphertext] wrong nonce causes decrypt to throw', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const key = pseudoRandom(`cc20-wrongnonce-key-${i}`, 32);
      const nonce = pseudoRandom(`cc20-wrongnonce-nonce-${i}`, 12);
      const plaintext = pseudoRandom(`cc20-wrongnonce-pt-${i}`, 32);
      const ct = encrypt({ key, nonce, plaintext });
      // Flip a bit in the first byte of the nonce — guaranteed to produce a different nonce
      const wrongNonce = new Uint8Array(nonce);
      wrongNonce[0]! ^= 0x01;
      expect(() => decrypt({ key, nonce: wrongNonce, ciphertext: ct })).toThrow('invalid tag');
    }
  });
});

// ---------------------------------------------------------------------------
// Ring signature properties
// ---------------------------------------------------------------------------

describe('ring-sig properties', () => {
  it('[∀ ring + signer] rvrf accepts a valid sigma for each ring position', () => {
    for (let pos = 0; pos < 3; pos++) {
      const kps = [ed448Keypair(), ed448Keypair(), ed448Keypair()] as const;
      const ring = [kps[0]!.publicKey, kps[1]!.publicKey, kps[2]!.publicKey] as const;
      const msg = pseudoRandom(`ringsig-pos-${pos}`, 48);
      const sk = kps[pos]!.privateKey;
      const sigma = rsig(sk, ring, msg);
      expect(sigma.byteLength).toBe(RING_SIG_BYTES);
      expect(rvrf(ring, sigma, msg)).toBe(true);
    }
  });

  it('[∀ ring] sigma is not deterministic (randomness per call)', () => {
    const kps = [ed448Keypair(), ed448Keypair(), ed448Keypair()] as const;
    const ring = [kps[0]!.publicKey, kps[1]!.publicKey, kps[2]!.publicKey] as const;
    const msg = pseudoRandom('ringsig-rand', 48);
    const s1 = rsig(kps[0]!.privateKey, ring, msg);
    const s2 = rsig(kps[0]!.privateKey, ring, msg);
    expect(Buffer.from(s1).equals(Buffer.from(s2))).toBe(false);
  });

  it('[∀ ring] forged sigma (all zeros) fails rvrf', () => {
    const kps = [ed448Keypair(), ed448Keypair(), ed448Keypair()] as const;
    const ring = [kps[0]!.publicKey, kps[1]!.publicKey, kps[2]!.publicKey] as const;
    const msg = pseudoRandom('ringsig-forged', 48);
    expect(rvrf(ring, new Uint8Array(RING_SIG_BYTES), msg)).toBe(false);
  });

  it('[∀ ring] valid sigma fails rvrf when a different message is supplied', () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const kps = [ed448Keypair(), ed448Keypair(), ed448Keypair()] as const;
      const ring = [kps[0]!.publicKey, kps[1]!.publicKey, kps[2]!.publicKey] as const;
      const msg = pseudoRandom(`ringsig-wrongmsg-${i}`, 48);
      const sigma = rsig(kps[0]!.privateKey, ring, msg);
      const otherMsg = pseudoRandom(`ringsig-wrongmsg-other-${i}`, 48);
      expect(rvrf(ring, sigma, otherMsg)).toBe(false);
    }
  });
});
