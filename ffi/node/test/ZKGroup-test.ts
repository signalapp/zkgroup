import { assert } from 'chai';
import { toUUID, fromUUID } from '../zkgroup/internal/UUIDUtil';
import FFICompatArray, { FFICompatArrayType } from '../zkgroup/internal/FFICompatArray';

import AssertionError from '../zkgroup/errors/AssertionError';

import ServerSecretParams from '../zkgroup/ServerSecretParams';
import ServerZkAuthOperations from '../zkgroup/auth/ServerZkAuthOperations';
import GroupMasterKey from '../zkgroup/groups/GroupMasterKey';
import GroupSecretParams from '../zkgroup/groups/GroupSecretParams';
import ClientZkAuthOperations from '../zkgroup/auth/ClientZkAuthOperations';
import ClientZkGroupCipher from '../zkgroup/groups/ClientZkGroupCipher';
import ServerZkProfileOperations from '../zkgroup/profiles/ServerZkProfileOperations';
import ClientZkProfileOperations from '../zkgroup/profiles/ClientZkProfileOperations';
import ProfileKey from '../zkgroup/profiles/ProfileKey';
import ProfileKeyVersion from '../zkgroup/profiles/ProfileKeyVersion';

function hexToCompatArray(hex: string) {
  const buffer = Buffer.from(hex, 'hex');
  return new FFICompatArray(buffer);
}
function arrayToCompatArray(array: Array<number>) {
  const buffer = Buffer.from(array);
  return new FFICompatArray(buffer);
}
function assertByteArray(hex: string, actual: FFICompatArrayType) {
  const actualHex = actual.buffer.toString('hex');

  assert.strictEqual(hex, actualHex);
}
function assertArrayEquals(expected: FFICompatArrayType, actual: FFICompatArrayType) {
  const expectedHex = expected.buffer.toString('hex');
  const actualHex = actual.buffer.toString('hex');

  assert.strictEqual(expectedHex, actualHex);
}
function assertArrayNotEquals(expected: FFICompatArrayType, actual: FFICompatArrayType) {
  const expectedHex = expected.buffer.toString('hex');
  const actualHex = actual.buffer.toString('hex');

  assert.notEqual(expectedHex, actualHex);
}
function clone(data: FFICompatArrayType) {
  // Note: we can't relay on Buffer.slice, since it returns a reference to the same
    //   underlying memory
  const array = Uint8Array.prototype.slice.call(data.buffer);
  const buffer = Buffer.from(array);
  return new FFICompatArray(buffer);
}

describe('ZKGroup', () => {
  const TEST_ARRAY_16   = hexToCompatArray('000102030405060708090a0b0c0d0e0f');
  const TEST_ARRAY_32   = hexToCompatArray('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const TEST_ARRAY_32_1 = hexToCompatArray('6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283');
  const TEST_ARRAY_32_2 = hexToCompatArray('c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7');
  const TEST_ARRAY_32_3 = arrayToCompatArray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
  const TEST_ARRAY_32_4 = arrayToCompatArray([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]);
  const TEST_ARRAY_32_5 = hexToCompatArray('030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122');
  const authPresentationResult = hexToCompatArray(
'd8a9233bd5795b542d55213566b9275b57e89afa67604fa95909b24f79876f3ae8705445ef03f242fdcd2bb45d84f92837f218dc29a3b48ad62aee8eafd797409089234089da8012afc9a579947bff379fcfc6426e4138c6e40fa89daa81f920b65cf102ac7ec25d7d347378218027ddeb97226bf0f63a5e73604ccf771f5e03160f443f16d643a4d5314289372e9bcb627475ee7dd2e785df9c1a5cdc8b0b610249dafd7bfae8b991e67897644525ce9c241c9f1de8e3101d2d0a37d568e44be8bda33dd4d52c9e9ec690a23a9aecc3ed174530b5f48b359a600d4a025ae52c60736b29fca3b30bd380499f025a734fc590a83555046dd1bae9e88eff118a1e2001000000000000ea62dfd7314017cf3abbddca49967ae8e4ee6c265564afa449fe8932cf08360f9f0bae4f16b8a1baaa334380f31c67074098e1efd563ed0f7b9fef40fadc2007885515139ed1cd8c40731779216d130949c091301db2b7a1c824b8a80ecf3207e09b6b276eefa5823ba53ce408c6a00f153fd4367fb763b62a0da6dd5d46d50018a2e0c559b0866b32659dbce15ec2ec3074348c19c237d96e0e6f9737667c09783a82591025bbec56fecec86ae3b8a973efad7dc92b75b7a299ca037928620c3120eb228b2fb85873783b00d5cfbf49246adad4f7dca7e113f7ffae4804d30a5fd63dff8ee35df19a4bf6ab6bc28e0a0ed54c3b4bdd3d687e9ae2520cb9fc08c675d6cb06d4788b6b4604dd197c3ffc67a34fd082eb383bc77c3e1ed67dd70a86e9abaef924a325b4bf24fd59abebd9698d7302331d358e8cd9a91083f74f093410eccfc323f7e4ebf4372b31f5c35d668ba5f2a4052a56a0f680934862455340e20100');
  const profileKeyPresentationResult = hexToCompatArray(
'96a2113a6ca207c0267f7524ec9e462f782fe1b141dca11d9f1b1a6abb91c8064678698ad3606ffa805c84b74c36994c69d35e70a812bbc8a998f587eff32e6da811918d597098a23538166652c422d57729989373c5032e222011b91f3cf126aa8fc186f0fa3fe78d0b678b3338a7f274dbd472a134b380cc71c26e3d7a6d75f07bea48c6c4278dd0d3c2358020ee65445e33c7fd885eeccd9167a2de7b1005e41e968fab846625bb73771271054ea6111f59e903cfc86e2d777bb5bac4c470e0ded2506e8f88f0ad893518568b901530b024af6cf93da65bbb7ca2e41d7200268c6c473c6daa60f34ac1150d3145646930909190e854001e4767ee2a6810092cdca4ace21cfc5fa8a33a4d1dc55a1c4c58d8dd57b1c13f8c8e6a8bb3df05345a1673b9d5f7f6ae4413ee5d0b75e2c0b8c687b4ad4b829ea0aa871c0c0ee158e4c62881ad5e66f288af456d683fa195275b0a2663e9eb591e9bf10104efd04ec0010000000000005a85d52d959eee130f4373d7d6c713be18d46de59113976cce6be5b7d11bc60ed14dc880f704714753c0e90a47ea32ed8810348d6a6b4724ff4d8f597af94e034b4f71568bb5d656bce9c1b6ed609f8dd40eaf4690b4aad9cadc72d1f6513a0536d79151d5edba8e380ea0e7eeb9af648a33cc7d31b8d833d80a31c42dbe570434c107fa1ea74a1f198d78907bfd7013564f651c7238e088dc03a0db29c5f90fe5e3ccfa832cfb71dcb0ecd1231b97ce07e23ceb90e3764371e4f4ad6c25b303cd18c76066c863d2cff5e0eaead201080da97dfa62e4dcb8aa4ee0d1f921be0288e5d63dab0b2a6274296cb0b860a02ae3823fdf83a46a20030d1eb2ee043e0542f73cb291884fb8a7f88d761656762f2b2c25f1229ddd4b0e8508f7fc34c209dbad54763fe543a9626270c2de7427ac24dae85e6edec74329cb663bc1eae20ad6dd635ba1125a257f5be80230c4c314974f303ac3565c28d52385891bf10a035e7cb09e8378cfad94942cca29abcea0bfc06f0cd8c9c2f7b2a7ff9dc1f1c5076caf3b86fa003209fcee1436b508dc75376f98d2f389b0e36fddf02c88ceed02f1a5f324052194d12b1e37a049aaf4c91ff3042016c15205acefd1b8fbe8930a86e9abaef924a325b4bf24fd59abebd9698d7302331d358e8cd9a91083f74f093410eccfc323f7e4ebf4372b31f5c35d668ba5f2a4052a56a0f68093486245533abd327db84cf1093e6ece1390762a677de2a23f834e842a8f0b38c2d0ef635cb0b5bfbf515bb3e2688d38bc8b4f99b940d4663ece9a5fdbb4496ef1ec0a7661');

  it('testAuthIntegration', () => {
    const uuid           = toUUID(TEST_ARRAY_16);
    const redemptionTime = 123456;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams = ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkAuth       = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    const masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    const groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    const authCredentialResponse = serverZkAuth.issueAuthCredentialWithRandom(TEST_ARRAY_32_2, uuid, redemptionTime);

    // CLIENT
    // Receive credential
    const clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    const clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    const authCredential      = clientZkAuthCipher.receiveAuthCredential(uuid, redemptionTime, authCredentialResponse);

    // Create and decrypt user entry
    const uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    const      plaintext = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assert.strictEqual(uuid, plaintext);

    // Create presentation
    const presentation = clientZkAuthCipher.createAuthCredentialPresentationWithRandom(TEST_ARRAY_32_5, groupSecretParams, authCredential);

    // Verify presentation
    const uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());
    assert.strictEqual(presentation.getRedemptionTime(), redemptionTime);
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation);

    assertArrayEquals(presentation.serialize(), authPresentationResult);
  });

  it('testProfileKeyIntegration', () => {

    const uuid           = toUUID(TEST_ARRAY_16);
    const redemptionTime = 1234567;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams = ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkProfile    = new ServerZkProfileOperations(serverSecretParams);

    // CLIENT
    const masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    const groupPublicParams     = groupSecretParams.getPublicParams();
    const clientZkProfileCipher = new ClientZkProfileOperations(serverPublicParams);

    const profileKey             = new ProfileKey(TEST_ARRAY_32_1);
    const profileKeyCommitment = profileKey.getCommitment(uuid);

    // Create context and request
    const context = clientZkProfileCipher.createProfileKeyCredentialRequestContextWithRandom(TEST_ARRAY_32_3, uuid, profileKey);
    const request = context.getRequest();

    // SERVER
    const response = serverZkProfile.issueProfileKeyCredentialWithRandom(TEST_ARRAY_32_4, request, uuid, profileKeyCommitment);

    // CLIENT
    // Gets stored profile credential
    const clientZkGroupCipher  = new ClientZkGroupCipher(groupSecretParams);
    const profileKeyCredential = clientZkProfileCipher.receiveProfileKeyCredential(context, response);

    // Create encrypted UID and profile key
    const uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    const plaintext      = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assert.strictEqual(plaintext, uuid);

    const profileKeyCiphertext   = clientZkGroupCipher.encryptProfileKey(profileKey, uuid);
    const decryptedProfileKey    = clientZkGroupCipher.decryptProfileKey(profileKeyCiphertext, uuid);
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());

    const presentation = clientZkProfileCipher.createProfileKeyCredentialPresentationWithRandom(TEST_ARRAY_32_5, groupSecretParams, profileKeyCredential);

    assertArrayEquals(presentation.serialize(), profileKeyPresentationResult);

    // Verify presentation
    serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentation);
    const uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());

    const pkvB = profileKey.getProfileKeyVersion(uuid);
    const pkvC = new ProfileKeyVersion(pkvB.serialize());
    assertArrayEquals(pkvB.serialize(), pkvC.serialize());
  });

  it('testServerSignatures', () => {
    const serverSecretParams = ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();

    const message = TEST_ARRAY_32_1;

    const signature = serverSecretParams.signWithRandom(TEST_ARRAY_32_2, message);
    serverPublicParams.verifySignature(message, signature);

    assertByteArray('c145cbb391c7e3b470d3f2a702dfd4b8ed299e0dd948e733231ef29693db140fadce61b39c54a12345b7a71c492dbd714b04bf76763afe9e7ae7573c18e3c309', signature.serialize());

    const alteredMessage = clone(message);
    alteredMessage[0] ^= 1;

    assertArrayNotEquals(message, alteredMessage);

    try {
        serverPublicParams.verifySignature(alteredMessage, signature);
        throw new AssertionError('signature validation should have failed!');
    } catch (error) {
      // good
    }
  });

  it('testGroupIdentifier', () => {
    const groupSecretParams = GroupSecretParams.generateWithRandom(TEST_ARRAY_32);
    const groupPublicParams = groupSecretParams.getPublicParams();
    // assertByteArray('31f2c60f86f4c5996e9e2568355591d9', groupPublicParams.getGroupIdentifier().serialize());
  });

  it('testErrors', () => {
    const ckp = new FFICompatArray(GroupSecretParams.SIZE);
    ckp.buffer.fill(-127);

    try {
      const groupSecretParams = new GroupSecretParams(ckp);
    } catch (error) {
      // good
    }
  });

  it('testBlobEncryption', () => {
    const groupSecretParams   = GroupSecretParams.generate();
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    const plaintext = arrayToCompatArray([0,1,2,3,4]);
    const ciphertext = clientZkGroupCipher.encryptBlob(plaintext);
    const plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext);
    assertArrayEquals(plaintext, plaintext2);
  });

  it('testBlobEncryptionWithRandom', () => {
    const masterKey           = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams   = GroupSecretParams.deriveFromMasterKey(masterKey);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    const plaintext = hexToCompatArray('0102030405060708111213141516171819');
    const ciphertext = hexToCompatArray('3ee2a91944d8b4c64f4ac3b94d485294ea3a44480f5e2b9c51b65d511cb886a79712190c2216cbad76b690055a97d3eb59');

    const ciphertext2 = clientZkGroupCipher.encryptBlobWithRandom(TEST_ARRAY_32_2, plaintext);
    const plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext2);

    assertArrayEquals(plaintext, plaintext2);
    assertArrayEquals(ciphertext, ciphertext2);
  });
});
