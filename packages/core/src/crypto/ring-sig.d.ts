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
 * Memory hygiene: the 57-byte LE encoding of the nonce scalar t_i is
 * explicitly zeroized (fill(0)) after its last use. The corresponding bigint
 * primitive cannot be zeroed — JavaScript provides no mechanism for clearing
 * bigint values from the GC-managed heap. The same fundamental limitation
 * applies to a_i, which is returned by @noble/curves as a bigint and cannot
 * be intercepted in byte form. These are accepted constraints of operating
 * within the noble/JS runtime.
 */
/** Wire size of the full RING-SIG structure. */
export declare const RING_SIG_BYTES: number;
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
 * @throws {RangeError} if any ring entry is not a valid 57-byte canonical Ed448 point.
 * @throws {RangeError} if sk's public key is not present in ring.
 */
export declare function rsig(
  sk: Uint8Array,
  ring: readonly [Uint8Array, Uint8Array, Uint8Array],
  m: Uint8Array,
): Uint8Array;
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
export declare function rvrf(
  ring: readonly [Uint8Array, Uint8Array, Uint8Array],
  sigma: Uint8Array,
  m: Uint8Array,
): boolean;
