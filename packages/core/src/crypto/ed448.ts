import { ed448 } from '@noble/curves/ed448.js';

export interface Ed448Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Generate a fresh Ed448-Goldilocks keypair (57-byte keys). */
export function generateKeypair(): Ed448Keypair {
  const privateKey = ed448.utils.randomSecretKey();
  const publicKey = ed448.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Sign a message — returns a 114-byte signature. */
export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed448.sign(message, privateKey);
}

/**
 * Verify an Ed448 signature.
 * Returns false for malformed inputs rather than throwing.
 */
export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed448.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
