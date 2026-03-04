/**
 * OTRv4 ring signature primitives: RSig and RVrf.
 *
 * Specification: https://github.com/otrv4/otrv4/blob/master/otrv4.md
 * § "Ring signatures" and "Appendix — HashToScalar"
 *
 * Wire format (RING-SIG): c1 || r1 || c2 || r2 || c3 || r3  (6 × 57 = 342 bytes)
 * All scalars are 57-byte little-endian (LE) values reduced mod q.
 *
 * Security properties:
 *   - Correctness : rvrf(ring, rsig(sk, ring, m), m) === true for any valid sk in ring
 *   - Unforgeability: cannot produce a valid sigma without knowing one ring member's secret key
 *   - Anonymity   : sigma is computationally indistinguishable regardless of which member signed
 *
 * Memory hygiene: intermediate scalars (nonce t_i) are represented as bigint
 * and cannot be reliably zeroized after use. JavaScript's runtime provides no
 * guaranteed mechanism for clearing bigint values from memory. This is an
 * accepted limitation of the current implementation; a future iteration may
 * represent scalars as zeroizable Uint8Array buffers if the threat model
 * requires stronger in-process memory hygiene guarantees.
 */

import { ed448 } from '@noble/curves/ed448.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** The curve group generator.  Alias to avoid repeated property lookups. */
const G = ed448.Point.BASE;

/** The curve order q (bigint). */
const q: bigint = ed448.Point.Fn.ORDER;

/** Size of a ring-sig scalar in bytes (LE-encoded). */
const SCALAR_BYTES = 57;

/** Wire size of the full RING-SIG structure. */
export const RING_SIG_BYTES = 6 * SCALAR_BYTES; // 342

/** OTRv4 protocol prefix for all hash inputs. */
const OTR_PREFIX: Uint8Array = new TextEncoder().encode('OTRv4');

/** usage_auth identifier (§ "Ring signatures"). */
const USAGE_AUTH = 0x1a;

// ---------------------------------------------------------------------------
// Internal: scalar arithmetic (all operations mod q)
// ---------------------------------------------------------------------------

/** (a - b) mod q, always in [0, q). */
function modSub(a: bigint, b: bigint): bigint {
  return (((a - b) % q) + q) % q;
}

/** (a * b) mod q. */
function modMul(a: bigint, b: bigint): bigint {
  return (a * b) % q;
}

/** (a + b + …) mod q, always in [0, q). */
function modAdd(...args: bigint[]): bigint {
  return args.reduce((acc, x) => (((acc + x) % q) + q) % q, 0n);
}

// ---------------------------------------------------------------------------
// Internal: scalar encoding / decoding (57-byte LE)
// ---------------------------------------------------------------------------

/**
 * Encode a scalar as 57-byte LE after reducing mod q.
 * Zero-pads naturally due to the fixed-size Uint8Array.
 */
function encodeScalar(n: bigint): Uint8Array {
  const v = ((n % q) + q) % q;
  const bytes = new Uint8Array(SCALAR_BYTES);
  let rem = v;
  for (let i = 0; i < SCALAR_BYTES; i++) {
    bytes[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  return bytes;
}

/**
 * Encode an arbitrary bigint as 57-byte LE WITHOUT modular reduction.
 * Used for encoding q itself in hash inputs (encodeScalar(q) === 0).
 */
function encodeBigInt57(n: bigint): Uint8Array {
  const bytes = new Uint8Array(SCALAR_BYTES);
  let rem = n;
  for (let i = 0; i < SCALAR_BYTES; i++) {
    bytes[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  return bytes;
}

/** Decode 57-byte LE → bigint mod q. */
function decodeScalar(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < SCALAR_BYTES; i++) {
    const byte = bytes[i];
    if (byte === undefined) throw new RangeError('decodeScalar: buffer too short');
    result |= BigInt(byte) << BigInt(8 * i);
  }
  return result % q;
}

// ---------------------------------------------------------------------------
// Internal: OTRv4 HashToScalar
// ---------------------------------------------------------------------------

/**
 * OTRv4 HashToScalar: SHAKE-256("OTRv4" || usageID || ...parts, 57) → bigint mod q.
 *
 * Per spec appendix:
 *   HashToScalar(usageID || d, 57) = HWC(usageID || d, 57)
 *   HWC(x, n) = SHAKE-256("OTRv4" || x, n)
 *   Interpret 57-byte output as LE integer, reduce mod q.
 */
function hashToScalar(usage: number, ...parts: Uint8Array[]): bigint {
  const h = shake256.create({ dkLen: SCALAR_BYTES });
  h.update(OTR_PREFIX);
  h.update(Uint8Array.of(usage));
  for (const p of parts) h.update(p);
  const raw = h.digest();
  return decodeScalar(raw);
}

// ---------------------------------------------------------------------------
// Internal: random scalar in Z_q via noble Ed448 key generation
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random scalar s ∈ Z_q via the Ed448
 * hash-and-prune procedure (same as used for signing keys).
 * This guarantees the scalar is in the correct subgroup.
 */
function randomScalar(): bigint {
  const sk = ed448.utils.randomSecretKey();
  const scalar = ed448.utils.getExtendedPublicKey(sk).scalar;
  // Zeroize the ephemeral secret key bytes
  sk.fill(0);
  return scalar;
}

// ---------------------------------------------------------------------------
// Internal: determine signer's ring index
// ---------------------------------------------------------------------------

/**
 * Find which ring entry matches the given public key.
 * Throws if the public key is not in the ring.
 *
 * Using bytesToHex comparison avoids timing-sensitive bigint comparison on
 * public data (the public key is not secret).
 */
function findSignerIndex(pk: Uint8Array, ring: readonly [Uint8Array, Uint8Array, Uint8Array]): 0 | 1 | 2 {
  const target = bytesToHex(pk);
  for (let i = 0 as 0 | 1 | 2; i < 3; i++) {
    if (bytesToHex(ring[i]!) === target) return i;
  }
  throw new RangeError('rsig: signer public key not found in ring');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Produce an OTRv4 ring signature for message `m`.
 *
 * @param sk   57-byte Ed448 secret key of the ring member signing this message.
 *             Must correspond to one of the keys in `ring`.
 * @param ring Ordered triple of 57-byte Ed448 public keys forming the ring.
 *             The order is preserved in the signature wire format.
 * @param m    Arbitrary-length message bytes.
 * @returns    342-byte RING-SIG structure: c1||r1||c2||r2||c3||r3.
 *
 * @throws {RangeError} if sk's public key is not present in ring.
 */
export function rsig(sk: Uint8Array, ring: readonly [Uint8Array, Uint8Array, Uint8Array], m: Uint8Array): Uint8Array {
  // Derive signer's public key and scalar a_i
  const { pointBytes: signerPk, scalar: a_i } = ed448.utils.getExtendedPublicKey(sk);

  // Find the signer's position in the ring
  const idx = findSignerIndex(signerPk, ring);

  // Decompress the other two ring members
  const A = [
    ed448.Point.fromBytes(ring[0]!),
    ed448.Point.fromBytes(ring[1]!),
    ed448.Point.fromBytes(ring[2]!),
  ] as const;

  // Sample randomness:
  //   - t_i: the real Schnorr nonce for the signer
  //   - c_j, r_j: simulated challenge/response for both non-signers j ≠ i
  const t_i = randomScalar();
  const c = [randomScalar(), randomScalar(), randomScalar()]; // we'll overwrite c[idx]
  const r = [randomScalar(), randomScalar(), randomScalar()]; // we'll overwrite r[idx]

  // Compute the commitment points T_j for each ring member:
  //   - Real: T_i = G * t_i
  //   - Simulated: T_j = G * r_j + A_j * c_j
  const T: [typeof G, typeof G, typeof G] = [
    G.multiply(r[0]!).add(A[0]!.multiply(c[0]!)), // simulated (will be replaced for idx==0)
    G.multiply(r[1]!).add(A[1]!.multiply(c[1]!)), // simulated (will be replaced for idx==1)
    G.multiply(r[2]!).add(A[2]!.multiply(c[2]!)), // simulated (will be replaced for idx==2)
  ];
  // Override the signer's T_i with the real Schnorr nonce point
  T[idx] = G.multiply(t_i);

  // Compute the ring challenge scalar:
  //   c = HashToScalar(usage_auth || G || q_bytes || A1 || A2 || A3 || T1 || T2 || T3 || m)
  const qBytes = encodeBigInt57(q);
  const cHash = hashToScalar(
    USAGE_AUTH,
    G.toBytes(),
    qBytes,
    ring[0]!,
    ring[1]!,
    ring[2]!,
    T[0]!.toBytes(),
    T[1]!.toBytes(),
    T[2]!.toBytes(),
    m,
  );

  // Complete the real signer's response:
  //   c_i = c - sum(c_j for j ≠ i)  mod q
  //   r_i = t_i - c_i * a_i          mod q
  const otherCs = ([0, 1, 2] as const).filter(j => j !== idx).map(j => c[j]!) as [bigint, bigint];
  c[idx] = modSub(cHash, modAdd(...otherCs));
  r[idx] = modSub(t_i, modMul(c[idx]!, a_i));

  // Assemble RING-SIG wire format: c1||r1||c2||r2||c3||r3
  const sigma = new Uint8Array(RING_SIG_BYTES);
  for (let i = 0; i < 3; i++) {
    sigma.set(encodeScalar(c[i]!), i * (2 * SCALAR_BYTES));
    sigma.set(encodeScalar(r[i]!), i * (2 * SCALAR_BYTES) + SCALAR_BYTES);
  }

  return sigma;
}

/**
 * Verify an OTRv4 ring signature.
 *
 * @param ring  Ordered triple of 57-byte Ed448 public keys — same order as was
 *              passed to `rsig`.
 * @param sigma 342-byte RING-SIG structure produced by `rsig`.
 * @param m     The signed message bytes.
 * @returns     true if the signature is valid; false otherwise.
 *              Never throws on malformed inputs.
 */
export function rvrf(ring: readonly [Uint8Array, Uint8Array, Uint8Array], sigma: Uint8Array, m: Uint8Array): boolean {
  if (sigma.byteLength !== RING_SIG_BYTES) return false;

  try {
    const A1 = ed448.Point.fromBytes(ring[0]!);
    const A2 = ed448.Point.fromBytes(ring[1]!);
    const A3 = ed448.Point.fromBytes(ring[2]!);

    const c1 = decodeScalar(sigma.subarray(0, 57));
    const r1 = decodeScalar(sigma.subarray(57, 114));
    const c2 = decodeScalar(sigma.subarray(114, 171));
    const r2 = decodeScalar(sigma.subarray(171, 228));
    const c3 = decodeScalar(sigma.subarray(228, 285));
    const r3 = decodeScalar(sigma.subarray(285, 342));

    // Recompute commitment points from scalars:
    //   T_j = G * r_j + A_j * c_j
    const T1 = G.multiply(r1).add(A1.multiply(c1));
    const T2 = G.multiply(r2).add(A2.multiply(c2));
    const T3 = G.multiply(r3).add(A3.multiply(c3));

    // Recompute the challenge hash:
    //   h = HashToScalar(usage_auth || G || q_bytes || A1 || A2 || A3 || T1 || T2 || T3 || m)
    const qBytes = encodeBigInt57(q);
    const h = hashToScalar(
      USAGE_AUTH,
      G.toBytes(),
      qBytes,
      ring[0]!,
      ring[1]!,
      ring[2]!,
      T1.toBytes(),
      T2.toBytes(),
      T3.toBytes(),
      m,
    );

    // Verify: h === c1 + c2 + c3 (mod q)
    return h === modAdd(c1, c2, c3);
  } catch {
    return false;
  }
}
