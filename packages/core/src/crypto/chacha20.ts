/**
 * ChaCha20-Poly1305 AEAD wrapper for OTRv4.
 *
 * Key:   32 bytes
 * Nonce: 12 bytes
 * Tag:   16 bytes (appended to ciphertext by encrypt, consumed by decrypt)
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

/** Required nonce length in bytes. */
export const NONCE_LEN = 12;

/** Authentication tag length in bytes. */
export const TAG_LEN = 16;

export interface EncryptParams {
  /** 32-byte encryption key. */
  key: Uint8Array;
  /** 12-byte nonce. Must not be reused with the same key. */
  nonce: Uint8Array;
  /** Plaintext to encrypt. */
  plaintext: Uint8Array;
}

export interface DecryptParams {
  /** 32-byte encryption key. */
  key: Uint8Array;
  /** 12-byte nonce used during encryption. */
  nonce: Uint8Array;
  /** Ciphertext with appended 16-byte Poly1305 authentication tag. */
  ciphertext: Uint8Array;
}

/**
 * Encrypt plaintext with ChaCha20-Poly1305.
 *
 * @returns `ciphertext || tag` — byteLength is `plaintext.byteLength + TAG_LEN`.
 */
export function encrypt({ key, nonce, plaintext }: EncryptParams): Uint8Array {
  return chacha20poly1305(key, nonce).encrypt(plaintext);
}

/**
 * Decrypt and authenticate a ChaCha20-Poly1305 ciphertext.
 *
 * @throws Error('invalid tag') if authentication fails.
 * @returns Decrypted plaintext.
 */
export function decrypt({ key, nonce, ciphertext }: DecryptParams): Uint8Array {
  return chacha20poly1305(key, nonce).decrypt(ciphertext);
}
