import { generateKeypair as generateEd448 } from '$core/crypto/ed448.js';
import { createNewClientProfile } from '$core/otr/client-profile.js';
import { DAKEState, handleAuthI, handleAuthR, handleIdentity, initiateDAKE } from '$core/otr/interactive-dake.js';
import { beforeEach, describe, expect, it } from 'vitest';

describe('Interactive DAKEZ Handshake', () => {
  const aliceInstance = new Uint8Array([1, 0, 0, 1]);
  const bobInstance = new Uint8Array([2, 0, 0, 2]);

  let aliceIdentity: ReturnType<typeof generateEd448>;
  let bobIdentity: ReturnType<typeof generateEd448>;

  beforeEach(() => {
    aliceIdentity = generateEd448();
    bobIdentity = generateEd448();
  });

  it('completes the full DAKEZ flow between Alice and Bob', async () => {
    // 1. Alice initiates
    const aliceProfile = createNewClientProfile(aliceInstance, aliceIdentity.publicKey, aliceIdentity.privateKey);
    const { message: identMsg, dakeState: aliceState1 } = await initiateDAKE(aliceInstance, aliceProfile);

    expect(aliceState1.status).toBe(DAKEState.WAITING_AUTH_R);

    // 2. Bob handles Identity and responds with Auth-R
    const bobProfile = createNewClientProfile(bobInstance, bobIdentity.publicKey, bobIdentity.privateKey);
    const { message: authRMsg, dakeState: bobState1 } = await handleIdentity(
      bobInstance,
      bobProfile,
      bobIdentity.privateKey,
      identMsg,
    );

    expect(bobState1.status).toBe(DAKEState.WAITING_AUTH_I);
    expect(bobState1.ssid).toBeDefined();

    // 3. Alice handles Auth-R and responds with Auth-I
    const { message: authIMsg, dakeState: aliceState2 } = await handleAuthR(
      aliceState1,
      aliceIdentity.privateKey,
      authRMsg,
    );

    expect(aliceState2.status).toBe(DAKEState.ENCRYPTED_MESSAGES);
    expect(aliceState2.ssid).toEqual(bobState1.ssid);

    // 4. Bob handles Auth-I and finalizes
    const { dakeState: bobState2 } = await handleAuthI(bobState1, bobIdentity.privateKey, authIMsg);

    expect(bobState2.status).toBe(DAKEState.ENCRYPTED_MESSAGES);
    expect(bobState2.ssid).toEqual(aliceState2.ssid);
  });
});
