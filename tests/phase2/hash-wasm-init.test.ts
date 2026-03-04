import { describe, expect, it } from 'vitest';
import { argon2id } from '$core/crypto/argon2id.js';

/**
 * CI smoke test — verifies that the `hash-wasm` WASM module initialises
 * without error in the current execution environment.
 *
 * This test uses the minimum valid Argon2id parameters (memorySize=1024 KiB,
 * iterations=1) so that it completes quickly in CI while still exercising the
 * full WASM load path.  It does NOT validate performance — use
 * `pnpm --filter @e2e-anywhere/core bench:argon2id` for that.
 *
 * Invariant reference: docs/security/security-invariants.md § KDF (Argon2id)
 */
describe('phase 2 hash-wasm WASM initialisation smoke test', () => {
  const password = new Uint8Array(16).fill(0x01);
  const salt = new Uint8Array(16).fill(0x02);

  it('argon2id loads WASM and returns a binary digest without throwing', async () => {
    const result = await argon2id({
      password,
      salt,
      iterations: 1,
      memorySize: 1024,
      hashLength: 32,
    });

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.byteLength).toBe(32);
  });

  it('argon2id is deterministic — same inputs produce same output', async () => {
    const opts = { password, salt, iterations: 1, memorySize: 1024, hashLength: 32 };

    const a = await argon2id(opts);
    const b = await argon2id(opts);

    expect(a).toEqual(b);
  });

  it('argon2id produces different output for different passwords', async () => {
    const base = { salt, iterations: 1, memorySize: 1024, hashLength: 32 };

    const a = await argon2id({ ...base, password: new Uint8Array(16).fill(0x01) });
    const b = await argon2id({ ...base, password: new Uint8Array(16).fill(0x02) });

    expect(a).not.toEqual(b);
  });
});
