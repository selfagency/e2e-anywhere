/**
 * Key Derivation Function — HKDF-SHA-512 and HMAC-SHA-512 wrappers for OTRv4.
 *
 * Usage:
 *   const key = deriveKey({ ikm, salt, info: encode('MyContext'), length: 32 });
 *   const mac  = hmac({ key, message });
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
export declare function deriveKey({ ikm, salt, info, length }: DeriveParams): Uint8Array;
/** Alias for {@link deriveKey}. */
export declare const derive: typeof deriveKey;
/**
 * Compute HMAC-SHA-512 over `message` authenticated with `key`.
 *
 * @returns 64-byte authentication tag.
 */
export declare function hmac({ key, message }: HmacParams): Uint8Array;
