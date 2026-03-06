import { sign, verify, validatePoint, generateKeypair } from '$core/crypto/ed448.js';
import { type ClientProfile } from '../types.js';

/**
 * Client Profile implementation for OTRv4 (packages/core/src/otr/client-profile.ts)
 *
 * Based on OTRv4 Protocol Specification:
 * https://github.com/otrv4/otrv4/blob/master/otrv4.md#client-profile
 */

export const CLIENT_PROFILE_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000; // 1 week

/**
 * Create a new Client Profile with a fresh forging key.
 *
 * "The forging key is a one-time EdDSA public key. Its secret key SHOULD be
 * deleted immediately after the profile is signed."
 *
 * @param instanceTag - User's unique 4-byte instance tag.
 * @param identityKeyH - User's long-term Ed448 public key (H).
 * @param longTermSecretH - User's long-term Ed448 secret key for signing.
 * @param expiration - Optional custom expiration timestamp (seconds).
 *
 * @returns An object containing the new profile and the ephemeral forging keys.
 * IMPORTANT: The caller is responsible for zeroing the forging secret key.
 */
export function createNewClientProfile(
  instanceTag: Uint8Array,
  identityKeyH: Uint8Array,
  longTermSecretH: Uint8Array,
  expiration?: bigint,
): { profile: ClientProfile; forgingSecret: Uint8Array } {
  const forgingKeypair = generateKeypair();

  const profile = createClientProfile(instanceTag, identityKeyH, forgingKeypair.publicKey, longTermSecretH, expiration);

  return { profile, forgingSecret: forgingKeypair.privateKey };
}

/**
 * Create a Client Profile.
 *
 * @param instanceTag - User's unique 4-byte instance tag.
 * @param identityKeyH - User's long-term Ed448 public key (H).
 * @param forgingKey - User's Ed448 forging public key.
 * @param longTermSecretH - User's long-term Ed448 secret key for signing.
 * @param expiration - Optional custom expiration timestamp (seconds). Defaults to 1 week from now.
 *
 * Note: Default behavior is to discard the forging key secret immediately after profile signing.
 */
export function createClientProfile(
  instanceTag: Uint8Array,
  identityKeyH: Uint8Array,
  forgingKey: Uint8Array,
  longTermSecretH: Uint8Array,
  expiration?: bigint,
): ClientProfile {
  if (instanceTag.byteLength !== 4) throw new Error('Invalid instance tag length');
  if (identityKeyH.byteLength !== 57) throw new Error('Invalid identity key length');
  if (forgingKey.byteLength !== 57) throw new Error('Invalid forging key length');

  const exp = expiration ?? BigInt(Math.floor((Date.now() + CLIENT_PROFILE_EXPIRATION_MS) / 1000));

  // OTRv4 Client Profile signing: H || ForgingKey || InstanceTag || Expiration
  const dataToSign = new Uint8Array(57 + 57 + 4 + 8);
  dataToSign.set(identityKeyH, 0);
  dataToSign.set(forgingKey, 57);
  dataToSign.set(instanceTag, 114);
  const view = new DataView(dataToSign.buffer);
  view.setBigUint64(118, exp, false); // Big-Endian

  const signature = sign(dataToSign, longTermSecretH);

  return {
    instanceTag,
    publicKey: identityKeyH,
    forgingKey,
    expiration: exp,
    signature,
  };
}

/**
 * Validate a Client Profile.
 *
 * @param profile - The Client Profile to validate.
 * @returns true if the signature is valid and the profile is not expired.
 */
export function validateClientProfile(profile: ClientProfile): boolean {
  // 1. Basic length checks
  if (profile.instanceTag.byteLength !== 4) return false;
  if (profile.publicKey.byteLength !== 57) return false;
  if (profile.forgingKey.byteLength !== 57) return false;
  if (profile.signature.byteLength !== 114) return false;

  // 2. Validate curve point membership for both public keys
  if (!validatePoint(profile.publicKey)) return false;
  if (!validatePoint(profile.forgingKey)) return false;

  // 3. Expiration check
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (profile.expiration < now) return false;

  // 4. Signature verification
  const dataToVerify = new Uint8Array(57 + 57 + 4 + 8);
  dataToVerify.set(profile.publicKey, 0);
  dataToVerify.set(profile.forgingKey, 57);
  dataToVerify.set(profile.instanceTag, 114);
  const view = new DataView(dataToVerify.buffer);
  view.setBigUint64(118, profile.expiration, false); // Big-Endian

  return verify(profile.signature, dataToVerify, profile.publicKey);
}
