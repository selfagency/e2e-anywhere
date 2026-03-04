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
 * Validate that a public key is in the valid range [2, p − 2] AND
 * in the prime-order subgroup (Legendre symbol check: pubKey^q mod p === 1).
 * Throws RangeError on invalid input (prevents small-subgroup/subgroup-confinement attacks).
 */
export declare function validatePublicKey(pubKey: bigint): void;
/**
 * Boolean-returning group-membership check.
 * Returns true iff pubKey is in [2, p − 2] AND in the prime-order subgroup
 * (i.e., pubKey^q ≡ 1 mod p).  Prevents subgroup-confinement attacks.
 */
export declare function validateDHGroupMembership(pubKey: bigint): boolean;
/**
 * Compute DH shared secret.
 * Validates pubKey is in [2, p − 2] and in the prime-order subgroup before computing.
 */
export declare function computeSharedSecret(privateKey: bigint, pubKey: bigint): bigint;
/**
 * Serialize a public key to 384 bytes (big-endian, zero-padded).
 */
export declare function serializePublicKey(pubKey: bigint): Uint8Array;
/**
 * Deserialize a 384-byte big-endian buffer to a public key bigint.
 * Throws RangeError if the buffer is not exactly DH_PUBLIC_KEY_BYTES long,
 * or if the resulting value is outside the valid group range [2, p − 2].
 */
export declare function deserializePublicKey(bytes: Uint8Array): bigint;
