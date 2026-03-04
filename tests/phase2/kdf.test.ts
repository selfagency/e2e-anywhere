import { describe, expect, it } from 'vitest';
import { derive, HASH_LEN } from '$core/crypto/kdf.js';

describe('phase 2.9 kdf (HKDF-SHA-512)', () => {
  const ikm = new Uint8Array(32).fill(0xab);
  const salt = new Uint8Array(32).fill(0xcd);

  it('derives output of requested length', () => {
    const out = derive({ ikm, salt, info: new TextEncoder().encode('test'), length: 64 });
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.byteLength).toBe(64);
  });

  it('default length equals HASH_LEN (64 bytes for SHA-512)', () => {
    const out = derive({ ikm, salt });
    expect(out.byteLength).toBe(HASH_LEN);
  });

  it('is deterministic — same inputs produce same output', () => {
    const info = new TextEncoder().encode('otrv4');
    const a = derive({ ikm, salt, info, length: 32 });
    const b = derive({ ikm, salt, info, length: 32 });
    expect(a).toEqual(b);
  });

  it('different info produces different output', () => {
    const a = derive({ ikm, salt, info: new TextEncoder().encode('key-a'), length: 32 });
    const b = derive({ ikm, salt, info: new TextEncoder().encode('key-b'), length: 32 });
    expect(a).not.toEqual(b);
  });

  it('different salt produces different output', () => {
    const info = new TextEncoder().encode('otrv4');
    const a = derive({ ikm, salt: new Uint8Array(32).fill(0x01), info, length: 32 });
    const b = derive({ ikm, salt: new Uint8Array(32).fill(0x02), info, length: 32 });
    expect(a).not.toEqual(b);
  });

  it('different ikm produces different output', () => {
    const info = new TextEncoder().encode('otrv4');
    const a = derive({ ikm: new Uint8Array(32).fill(0x01), salt, info, length: 32 });
    const b = derive({ ikm: new Uint8Array(32).fill(0x02), salt, info, length: 32 });
    expect(a).not.toEqual(b);
  });

  it('returns independent buffers on repeated calls (no reference aliasing)', () => {
    const info = new TextEncoder().encode('otrv4');
    const a = derive({ ikm, salt, info, length: 32 });
    const b = derive({ ikm, salt, info, length: 32 });
    // Same inputs produce equal values
    expect(a).toEqual(b);
    // Mutating one buffer must not affect the other
    a.fill(0);
    expect(b.every((v: number) => v === 0)).toBe(false);
  });
});
