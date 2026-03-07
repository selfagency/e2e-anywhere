export interface Ed448Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}
/** Generate a fresh Ed448-Goldilocks keypair (57-byte keys). */
export declare function generateKeypair(): Ed448Keypair;
/** Sign a message — returns a 114-byte signature. */
export declare function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
/**
 * Perform Ed448 Diffie-Hellman (X448).
 * Note: OTRv4 uses Ed448 points for DAKE ephemeral keys.
 */
export declare function diffieHellman(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
/**
 * Verify an Ed448 signature.
 * Returns false for malformed inputs rather than throwing.
 */
export declare function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
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
export declare function validatePoint(bytes: Uint8Array): boolean;
