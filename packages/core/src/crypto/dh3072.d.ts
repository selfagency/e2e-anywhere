/**
 * DH-3072 (RFC 3526 MODP Group 15) primitives for OTRv4.
 *
 * All arithmetic uses native BigInt. Public keys are represented as bigint;
 * wire format is 384 bytes big-endian.
 */
export declare const DH_P: bigint;
/** Serialized public key length in bytes (384 = 3072 bits / 8). */
export declare const DH_PUBLIC_KEY_BYTES = 384;
export interface DHKeypair {
  privateKey: bigint;
  publicKey: bigint;
}
/**
 * Generate a fresh DH-3072 keypair.
 * Returns bigint values; publicKey = g^privateKey mod p.
 */
export declare function generateKeypair(): DHKeypair;
/**
 * Validate that a public key is in the valid range [2, p − 2].
 * Throws RangeError on invalid input (prevents small-subgroup attacks).
 */
export declare function validatePublicKey(pubKey: bigint): void;
/**
 * Boolean-returning group-membership check.
 * Returns true iff pubKey is in the valid DH group range [2, p − 2].
 * Equivalent to validatePublicKey but does not throw.
 */
export declare function validateDHGroupMembership(pubKey: bigint): boolean;
/**
 * Compute DH shared secret.
 * Validates pubKey is in [2, p − 2] before computing.
 */
export declare function computeSharedSecret(privateKey: bigint, pubKey: bigint): bigint;
/**
 * Serialize a public key to 384 bytes (big-endian, zero-padded).
 */
export declare function serializePublicKey(pubKey: bigint): Uint8Array;
/**
 * Deserialize a 384-byte big-endian buffer to a public key bigint.
 */
export declare function deserializePublicKey(bytes: Uint8Array): bigint;
