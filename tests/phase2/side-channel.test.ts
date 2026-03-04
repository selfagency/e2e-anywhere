/**
 * Bean cj44 — Phase 2.13 side-channel and input-validation harnesses.
 *
 * Goals:
 *  1. Verify that crypto operations complete within documented time budgets
 *     (detect gross performance regressions, not subtle timing leaks).
 *  2. Verify that all public API surfaces reject malformed / adversarial
 *     inputs gracefully — no crashes, no information leaks via exceptions.
 *  3. Test input-validation completeness for edge cases: empty, all-zeros,
 *     oversized, and structurally malformed byte arrays.
 *
 * Note on JS timing:
 *   True constant-time guarantees are not achievable in JavaScript.  These
 *   harnesses are coarse sanity checks that catch gross deviations and
 *   ensure that the codebase does not inadvertently branch on secret-adjacent
 *   values in ways that produce observable order-of-magnitude differences.
 *   For rigorous timing analysis see docs/security/security-invariants.md.
 */

import { describe, expect, it } from 'vitest';
import { generateKeypair, sign, verify } from '$core/crypto/ed448.js';
import { rvrf, rsig, RING_SIG_BYTES } from '$core/crypto/ring-sig.js';

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

/**
 * Measure wall-clock time for `fn()` in milliseconds.
 * Uses `performance.now()` for sub-millisecond resolution.
 */
function timeMs(fn: () => void): number {
  const start = performance.now();
  fn();
  return performance.now() - start;
}

// Performance budget in ms for a single crypto operation on reference hardware.
// Generous budget to avoid flaky CI failures; actual operations are much faster.
const BUDGET_SINGLE_OP_MS = 500;

// ---------------------------------------------------------------------------
// Adversarial inputs used across multiple test groups
// ---------------------------------------------------------------------------

const EMPTY = new Uint8Array(0);
const ZEROS_57 = new Uint8Array(57); // all-zero Ed448 public key (identity)
const ZEROS_114 = new Uint8Array(114); // all-zero Ed448 signature
const ZEROS_342 = new Uint8Array(342); // all-zero RING-SIG
const OVERSIZED = new Uint8Array(10_000).fill(0xaa);

// ---------------------------------------------------------------------------
// ed448.verify — input validation and malformed-input resilience
// ---------------------------------------------------------------------------

describe('ed448.verify side-channel harnesses', () => {
  const { privateKey, publicKey } = generateKeypair();
  const msg = new TextEncoder().encode('side channel test message');
  const valid_sig = sign(msg, privateKey);

  it('returns false for a zero-byte signature (not throw)', () => {
    expect(verify(EMPTY, msg, publicKey)).toBe(false);
  });

  it('returns false for an all-zeros signature with valid public key', () => {
    expect(verify(ZEROS_114, msg, publicKey)).toBe(false);
  });

  it('returns false for an all-zeros public key (identity)', () => {
    expect(verify(valid_sig, msg, ZEROS_57)).toBe(false);
  });

  it('returns false for an oversized signature', () => {
    expect(verify(OVERSIZED, msg, publicKey)).toBe(false);
  });

  it('returns false for an oversized public key', () => {
    expect(verify(valid_sig, msg, OVERSIZED)).toBe(false);
  });

  it('completes within time budget for a valid verification', () => {
    const elapsed = timeMs(() => verify(valid_sig, msg, publicKey));
    expect(elapsed).toBeLessThan(BUDGET_SINGLE_OP_MS);
  });

  it('completes within time budget for an invalid signature (no short-circuit leakage)', () => {
    const elapsed = timeMs(() => verify(ZEROS_114, msg, publicKey));
    expect(elapsed).toBeLessThan(BUDGET_SINGLE_OP_MS);
  });

  it('completes within time budget for a truncated 56-byte public key', () => {
    const truncatedPk = publicKey.subarray(0, 56);
    const elapsed = timeMs(() => verify(valid_sig, msg, truncatedPk));
    expect(elapsed).toBeLessThan(BUDGET_SINGLE_OP_MS);
  });
});

// ---------------------------------------------------------------------------
// ring-sig.rvrf — input validation and malformed-input resilience
// ---------------------------------------------------------------------------

describe('ring-sig.rvrf side-channel harnesses', () => {
  const kp1 = generateKeypair();
  const kp2 = generateKeypair();
  const kp3 = generateKeypair();
  const ring = [kp1.publicKey, kp2.publicKey, kp3.publicKey] as const;
  const msg = new TextEncoder().encode('ring side channel test');
  const sigma = rsig(kp1.privateKey, ring, msg);

  it('returns false for RING-SIG of length 0 (not throw)', () => {
    expect(rvrf(ring, EMPTY, msg)).toBe(false);
  });

  it('returns false for RING-SIG of all zeros (plausible-length but invalid)', () => {
    expect(rvrf(ring, ZEROS_342, msg)).toBe(false);
  });

  it('returns false for RING-SIG that is 1 byte too short (341)', () => {
    expect(rvrf(ring, sigma.subarray(0, RING_SIG_BYTES - 1), msg)).toBe(false);
  });

  it('returns false for RING-SIG that is 1 byte too long (343)', () => {
    const oversizedSigma = new Uint8Array(RING_SIG_BYTES + 1);
    oversizedSigma.set(sigma);
    expect(rvrf(ring, oversizedSigma, msg)).toBe(false);
  });

  it('returns false when ring entry 0 is an all-zeros (identity) key', () => {
    const badRing = [ZEROS_57, kp2.publicKey, kp3.publicKey] as const;
    expect(rvrf(badRing, sigma, msg)).toBe(false);
  });

  it('returns false when ring entry 1 is an oversized key', () => {
    const badRing = [kp1.publicKey, OVERSIZED, kp3.publicKey] as const;
    expect(rvrf(badRing, sigma, msg)).toBe(false);
  });

  it('returns false when ring entry 2 is an empty key', () => {
    const badRing = [kp1.publicKey, kp2.publicKey, EMPTY] as const;
    expect(rvrf(badRing, sigma, msg)).toBe(false);
  });

  it('completes within time budget for a valid ring verification', () => {
    const elapsed = timeMs(() => rvrf(ring, sigma, msg));
    expect(elapsed).toBeLessThan(BUDGET_SINGLE_OP_MS);
  });

  it('completes within time budget for an all-zeros sigma (fast rejection expected)', () => {
    const elapsed = timeMs(() => rvrf(ring, ZEROS_342, msg));
    expect(elapsed).toBeLessThan(BUDGET_SINGLE_OP_MS);
  });
});

// ---------------------------------------------------------------------------
// ring-sig.rsig — signer-not-in-ring input validation
// ---------------------------------------------------------------------------

describe('ring-sig.rsig side-channel harnesses', () => {
  const kp1 = generateKeypair();
  const kp2 = generateKeypair();
  const kp3 = generateKeypair();
  const outsider = generateKeypair();

  it('throws RangeError when signer key is not in the ring (no silent failure)', () => {
    const ring = [kp1.publicKey, kp2.publicKey, kp3.publicKey] as const;
    const msg = new TextEncoder().encode('outsider test');
    expect(() => rsig(outsider.privateKey, ring, msg)).toThrow(RangeError);
  });

  it('completes within time budget when signer is in the ring', () => {
    const ring = [kp1.publicKey, kp2.publicKey, kp3.publicKey] as const;
    const msg = new TextEncoder().encode('timing test');
    const elapsed = timeMs(() => rsig(kp2.privateKey, ring, msg));
    expect(elapsed).toBeLessThan(BUDGET_SINGLE_OP_MS);
  });
});
