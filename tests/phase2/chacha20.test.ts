import { describe, expect, it } from 'vitest';
import { decrypt, encrypt, NONCE_LEN, TAG_LEN } from '$core/crypto/chacha20.js';

describe('phase 2.10 chacha20-poly1305', () => {
  const key = new Uint8Array(32).fill(0x42);
  const nonce = new Uint8Array(12).fill(0x07);
  const plaintext = new TextEncoder().encode('hello otrv4 chacha20');

  it('encrypts and produces ciphertext longer than plaintext by TAG_LEN bytes', () => {
    const ct = encrypt({ key, nonce, plaintext });
    expect(ct).toBeInstanceOf(Uint8Array);
    expect(ct.byteLength).toBe(plaintext.byteLength + TAG_LEN);
  });

  it('decrypts ciphertext back to original plaintext', () => {
    const ct = encrypt({ key, nonce, plaintext });
    const pt = decrypt({ key, nonce, ciphertext: ct });
    expect(pt).toEqual(plaintext);
  });

  it('NONCE_LEN is 12', () => {
    expect(NONCE_LEN).toBe(12);
  });

  it('TAG_LEN is 16', () => {
    expect(TAG_LEN).toBe(16);
  });

  it('is deterministic — same key/nonce/plaintext produces same ciphertext', () => {
    const a = encrypt({ key, nonce, plaintext });
    const b = encrypt({ key, nonce, plaintext });
    expect(a).toEqual(b);
  });

  it('different nonces produce different ciphertext', () => {
    const nonce2 = new Uint8Array(12).fill(0x08);
    const a = encrypt({ key, nonce, plaintext });
    const b = encrypt({ key, nonce: nonce2, plaintext });
    expect(a).not.toEqual(b);
  });

  it('tampered ciphertext fails to decrypt', () => {
    const ct = encrypt({ key, nonce, plaintext });
    const bad = new Uint8Array(ct);
    const badByte = bad[0];
    if (badByte !== undefined) bad[0] = badByte ^ 0xff;
    expect(() => decrypt({ key, nonce, ciphertext: bad })).toThrow('invalid tag');
  });

  it('encrypts empty plaintext', () => {
    const empty = new Uint8Array(0);
    const ct = encrypt({ key, nonce, plaintext: empty });
    expect(ct.byteLength).toBe(TAG_LEN);
    const pt = decrypt({ key, nonce, ciphertext: ct });
    expect(pt).toEqual(empty);
  });
});
