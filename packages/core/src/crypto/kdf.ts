/**
 * Key Derivation Function — HKDF-SHA-512 and HMAC-SHA-512 wrappers for OTRv4.
 *
 * Usage:
 *   const key = deriveKey({ ikm, salt, info: encode('MyContext'), length: 32 });
 *   const mac  = hmac({ key, message });
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';

/** Native output length of SHA-512 in bytes. */
export const HASH_LEN = 64;

/** OTRv4 protocol prefix for all hash inputs. */
const OTR_PREFIX = new TextEncoder().encode('OTRv4');

/**
 * SHAKE-256("OTRv4" || usageID || ...values, size)
 */
export function kdf(usage: number, values: Uint8Array[], length: number = 64): Uint8Array {
  const h = shake256.create({ dkLen: length });
  // console.log('KDF Usage:', usage.toString(16), 'Values:', values.map(v => Buffer.from(v).toString('hex')));
  h.update(OTR_PREFIX);
  h.update(Uint8Array.of(usage));
  for (const v of values) {
    h.update(v);
  }
  const out = h.digest();
  // console.log('KDF Output:', Buffer.from(out).toString('hex'));
  return out;
}

export interface DeriveParams {
  /** Input key material. */
  ikm: Uint8Array;
  /** Salt (should be uniformly random, same length as hash output). */
  salt: Uint8Array;
  /** Context info string — differentiates derived keys for different purposes. */
  info?: Uint8Array;
  /** Desired output length in bytes. Defaults to HASH_LEN (64). */
  length?: number;
}

export interface HmacParams {
  /** Secret key. */
  key: Uint8Array;
  /** Message to authenticate. */
  message: Uint8Array;
}

/**
 * Derive key material using HKDF-SHA-512.
 *
 * @returns Derived key of `length` bytes. The same inputs always produce
 *          the same output (deterministic).
 */
export function deriveKey({ ikm, salt, info, length = HASH_LEN }: DeriveParams): Uint8Array {
  return hkdf(sha512, ikm, salt, info, length);
}

/** Alias for {@link deriveKey}. */
export const derive = deriveKey;

/**
 * Compute HMAC-SHA-512 over `message` authenticated with `key`.
 *
 * @returns 64-byte authentication tag.
 */
export function hmac({ key, message }: HmacParams): Uint8Array {
  return nobleHmac(sha512, key, message);
}
