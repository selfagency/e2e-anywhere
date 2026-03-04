/**
 * Argon2id password-hashing / key-derivation wrapper for OTRv4.
 *
 * Delegates to `hash-wasm` which ships a WASM-compiled Argon2 implementation.
 * Baseline parameters are defined in docs/security/security-invariants.md.
 *
 * Baseline KDF parameters (v1):
 *   m = 65536  (64 MiB memory cost)
 *   t = 3      (3 iterations)
 *   p = 1      (single lane, single-threaded)
 *   hashLen = 32 (256-bit derived key)
 */

import { argon2id as _argon2id } from 'hash-wasm';

/** Baseline Argon2id parameters (v1). */
export const ARGON2ID_PARAMS = {
  iterations: 3,
  parallelism: 1,
  memorySize: 65536,
  hashLength: 32,
} as const;

export interface Argon2idParams {
  /** Password / input key material. */
  password: Uint8Array;
  /** Random salt — must be at least 8 bytes; 16 bytes recommended. */
  salt: Uint8Array;
  /** Argon2id iteration count (t). Defaults to ARGON2ID_PARAMS.iterations. */
  iterations?: number;
  /** Degree of parallelism (p). Defaults to ARGON2ID_PARAMS.parallelism. */
  parallelism?: number;
  /** Memory usage in KiB (m). Defaults to ARGON2ID_PARAMS.memorySize. */
  memorySize?: number;
  /** Output length in bytes. Defaults to ARGON2ID_PARAMS.hashLength. */
  hashLength?: number;
}

/**
 * Derive key material using Argon2id.
 *
 * @returns Derived key as a `Uint8Array` of `hashLength` bytes.
 */
export async function argon2id({
  password,
  salt,
  iterations = ARGON2ID_PARAMS.iterations,
  parallelism = ARGON2ID_PARAMS.parallelism,
  memorySize = ARGON2ID_PARAMS.memorySize,
  hashLength = ARGON2ID_PARAMS.hashLength,
}: Argon2idParams): Promise<Uint8Array> {
  return _argon2id({ password, salt, iterations, parallelism, memorySize, hashLength, outputType: 'binary' });
}
