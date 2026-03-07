import { type ClientProfile } from '../types.js';
/**
 * Client Profile implementation for OTRv4 (packages/core/src/otr/client-profile.ts)
 *
 * Based on OTRv4 Protocol Specification:
 * https://github.com/otrv4/otrv4/blob/master/otrv4.md#client-profile
 */
export declare const CLIENT_PROFILE_EXPIRATION_MS: number;
/**
 * Create a new Client Profile with a fresh forging key.
 *
 * "The forging key is a one-time EdDSA public key. Its secret key SHOULD be
 * deleted immediately after the profile is signed."
 *
 * This helper only returns the public Client Profile. The ephemeral forging
 * secret key is never exposed to callers and is zeroized in this function
 * immediately after use.
 *
 * @param instanceTag - User's unique 4-byte instance tag.
 * @param identityKeyH - User's long-term Ed448 public key (H).
 * @param longTermSecretH - User's long-term Ed448 secret key for signing.
 * @param expiration - Optional custom expiration timestamp (seconds).
 *
 * @returns A new signed Client Profile bound to a fresh forging public key.
 */
export declare function createNewClientProfile(
  instanceTag: Uint8Array,
  identityKeyH: Uint8Array,
  longTermSecretH: Uint8Array,
  expiration?: bigint,
): ClientProfile;
/**
 * Create a Client Profile.
 *
 * @param instanceTag - User's unique 4-byte instance tag.
 * @param identityKeyH - User's long-term Ed448 public key (H). Must be a valid prime-order Ed448 point.
 * @param forgingKey - User's Ed448 forging public key. Must be a valid prime-order Ed448 point.
 * @param longTermSecretH - User's long-term Ed448 secret key for signing. Must be exactly 57 bytes.
 * @param expiration - Optional custom expiration timestamp (seconds). Must not exceed 7 days from now.
 *
 * Note: Default behavior is to discard the forging key secret immediately after profile signing.
 */
export declare function createClientProfile(
  instanceTag: Uint8Array,
  identityKeyH: Uint8Array,
  forgingKey: Uint8Array,
  longTermSecretH: Uint8Array,
  expiration?: bigint,
): ClientProfile;
/**
 * Validate a Client Profile.
 *
 * @param profile - The Client Profile to validate.
 * @returns true if the signature is valid and the profile is not expired.
 */
export declare function validateClientProfile(profile: ClientProfile): boolean;
