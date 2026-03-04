/**
 * Key Derivation Function — HKDF-SHA-512 wrapper for OTRv4.
 *
 * Usage:
 *   const key = derive({ ikm, salt, info: encode('MyContext'), length: 32 });
 */
/** Native output length of SHA-512 in bytes. */
export declare const HASH_LEN = 64;
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
/**
 * Derive key material using HKDF-SHA-512.
 *
 * @returns Derived key of `length` bytes. The same inputs always produce
 *          the same output (deterministic).
 */
export declare function derive({ ikm, salt, info, length }: DeriveParams): Uint8Array;
