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
 * Perform Ed448 Diffie-Hellman (X448).
 * Note: OTRv4 uses Ed448 points for DAKE ephemeral keys.
 */
export function diffieHellman(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const sk = ed448.utils.getExtendedPublicKey(privateKey).scalar;
  const pk = ed448.Point.fromBytes(publicKey);
  const shared = pk.multiply(sk).toBytes();
  return shared;
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

/**
 * Validate that a byte array is a structurally sound, non-degenerate Ed448
 * public key.
 *
 * A point is accepted if and only if:
 *   1. It is exactly 57 bytes (the canonical compressed encoding for Ed448).
 *   2. It decodes to a valid curve point (on the curve, canonical encoding).
 *   3. It is torsion-free (i.e. in the prime-order subgroup).
 *   4. It is NOT a small-order point (rejects identity and cofactor-order points).
 *
 * Returns false rather than throwing for malformed inputs.
 *
 * Protects against:
 *   - Identity point injection (all-zeros public key)
 *   - Small-subgroup attacks via low-order / small-order points
 *   - Structurally invalid / non-canonical point encodings
 */
export function validatePoint(bytes: Uint8Array): boolean {
  if (bytes.byteLength !== 57) return false;
  try {
    const point = ed448.Point.fromBytes(bytes);
    // Reject identity and small-order points (cofactor attacks)
    if (point.isSmallOrder()) return false;
    // Confirm the point is in the prime-order subgroup
    if (!point.isTorsionFree()) return false;
    return true;
  } catch {
    return false;
  }
}
