/**
 * DH-3072 (RFC 3526 MODP Group 15) primitives for OTRv4.
 *
 * All arithmetic uses native BigInt. Public keys are represented as bigint;
 * wire format is 384 bytes big-endian.
 */

// RFC 3526 §2 — 3072-bit MODP Group 15 prime.
export const DH_P = BigInt(
  '0x' +
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',
);

const DH_G = 2n;

/** Serialized public key length in bytes (384 = 3072 bits / 8). */
export const DH_PUBLIC_KEY_BYTES = 384;

export interface DHKeypair {
  privateKey: bigint;
  publicKey: bigint;
}

/** Square-and-multiply modular exponentiation. */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/** Generate a 256-bit random private exponent from the operating environment. */
function randomPrivateExponent(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  // Clamp to valid range [2, DH_P − 2]; since DH_P ≫ 2^256 this is safe.
  if (result < 2n) result += 2n;
  return result;
}

/**
 * Generate a fresh DH-3072 keypair.
 * Returns bigint values; publicKey = g^privateKey mod p.
 */
export function generateKeypair(): DHKeypair {
  const privateKey = randomPrivateExponent();
  const publicKey = modPow(DH_G, privateKey, DH_P);
  return { privateKey, publicKey };
}

/**
 * Validate that a public key is in the valid range [2, p − 2].
 * Throws RangeError on invalid input (prevents small-subgroup attacks).
 */
export function validatePublicKey(pubKey: bigint): void {
  if (pubKey < 2n || pubKey > DH_P - 2n) {
    throw new RangeError('public key out of valid range');
  }
}

/**
 * Boolean-returning group-membership check.
 * Returns true iff pubKey is in the valid DH group range [2, p − 2].
 * Equivalent to validatePublicKey but does not throw.
 */
export function validateDHGroupMembership(pubKey: bigint): boolean {
  return pubKey >= 2n && pubKey <= DH_P - 2n;
}

/**
 * Compute DH shared secret.
 * Validates pubKey is in [2, p − 2] before computing.
 */
export function computeSharedSecret(privateKey: bigint, pubKey: bigint): bigint {
  validatePublicKey(pubKey);
  return modPow(pubKey, privateKey, DH_P);
}

/**
 * Serialize a public key to 384 bytes (big-endian, zero-padded).
 */
export function serializePublicKey(pubKey: bigint): Uint8Array {
  const bytes = new Uint8Array(DH_PUBLIC_KEY_BYTES);
  let val = pubKey;
  for (let i = DH_PUBLIC_KEY_BYTES - 1; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

/**
 * Deserialize a 384-byte big-endian buffer to a public key bigint.
 */
export function deserializePublicKey(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}
