//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

package org.signal.zkgroup.integrationtests;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.TimeUnit;
import org.junit.Test;
import org.signal.zkgroup.Hex;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.NotarySignature;
import org.signal.zkgroup.SecureRandomTest;
import org.signal.zkgroup.ServerPublicParams;
import org.signal.zkgroup.ServerSecretParams;
import org.signal.zkgroup.VerificationFailedException;
import org.signal.zkgroup.InvalidRedemptionTimeException;
import org.signal.zkgroup.auth.AuthCredential;
import org.signal.zkgroup.auth.AuthCredentialPresentation;
import org.signal.zkgroup.auth.AuthCredentialResponse;
import org.signal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.zkgroup.groups.ChangeSignature;
import org.signal.zkgroup.groups.ClientZkGroupCipher;
import org.signal.zkgroup.groups.GroupMasterKey;
import org.signal.zkgroup.groups.GroupPublicParams;
import org.signal.zkgroup.groups.GroupSecretParams;
import org.signal.zkgroup.groups.ProfileKeyCiphertext;
import org.signal.zkgroup.groups.UuidCiphertext;
import org.signal.zkgroup.profiles.ClientZkProfileOperations;
import org.signal.zkgroup.profiles.ProfileKey;
import org.signal.zkgroup.profiles.ProfileKeyCommitment;
import org.signal.zkgroup.profiles.ProfileKeyCredential;
import org.signal.zkgroup.profiles.ProfileKeyCredentialPresentation;
import org.signal.zkgroup.profiles.ProfileKeyCredentialRequest;
import org.signal.zkgroup.profiles.ProfileKeyCredentialRequestContext;
import org.signal.zkgroup.profiles.ProfileKeyCredentialResponse;
import org.signal.zkgroup.profiles.ProfileKeyVersion;
import org.signal.zkgroup.profiles.ServerZkProfileOperations;
import org.signal.zkgroup.util.UUIDUtil;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public final class ZkGroupTest extends SecureRandomTest {

  private static final byte[] TEST_ARRAY_16   = Hex.fromStringCondensedAssert("000102030405060708090a0b0c0d0e0f");

  private static final byte[] TEST_ARRAY_32   = Hex.fromStringCondensedAssert("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

  private static final byte[] TEST_ARRAY_32_1 = Hex.fromStringCondensedAssert("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283");

  private static final byte[] TEST_ARRAY_32_2 = Hex.fromStringCondensedAssert("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7");

  private static final byte[] TEST_ARRAY_32_3 = { 1, 2, 3, 4, 5, 6, 7, 8, 9,
      10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
      28, 29, 30, 31, 32 };

  private static final byte[] TEST_ARRAY_32_4 = { 
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33};


  private static final byte[] TEST_ARRAY_32_5 = Hex.fromStringCondensedAssert("030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122");

  private static final byte[] authPresentationResult = Hex.fromStringCondensedAssert(
"7081b1a0e0c5582ea7594c8ff4df3544e1e44da97bb85c603c03f771c9c3fd5c562988fcc6c0c0c6dda4ef19e2d70c7972173eb4fe8bb91c98769c303190a133246735075e3c1b881aae626d8430714b880d36b338349525c7a2f8a02f5579389cbc1e3df512e4937e0ce5b0b2a683d0a0b0e34ce4ec7dee93e57f38aaa46b2e36bc01bdb2d05ddcb7998783b50c614e129c6fa8a6b0b5c4b41257633e6995101068b48cdeb5501b6aaa8f7c2b10374172e73389be56a6215d61c7842e95ff7984130e95e29ade47334d6702692a52d8caa2fc78a984c1f15bedd37dbf512e74a60b1fc865fccb4fbee8f88cd7c44784dd319969a5e21094a58c2951d1a13b0a2001000000000000932141da5adbfa7d888a2119289be5729f8945dd3198632636869cab09bc87020d4e3e1933e86f956e1a2b778a5ea2e3203b73a3be0e519317708744d01bc60bae88996e8cd0dad3fd09093f0e8b1f1ee89402c49a8bc442602506f3421247068894b59efff212cf7427aea674346d9a116b960d0f35f32cfe3cde15bfe4a40dadbd8cc67ed79467abc2a64c98b4c2ba15f122217460d6b57ec43b40b8d1a50909c5a3c4e7b9cdfd70b77b40e40f98ad2dd1a0fca26768f5bae95b7975403901b082d2859d863d421127b9abdcb342be27d9bd309d21d96a310355c2d79963000ee9dee6507b98efcf84a650cf751103f4357d4257317408230d4b3eadf3a40e6b26547f9d0421b17c15d3de6e5642356e815b10300fcf9eddee8a2d57565e092047ffdb43a7b802030e20c50051edcf0fb92178e087fa5e5d1e045b38a01b3af44c192e9ea29581e9c3befd1a10aab20ccd19a6dec3ca0668d887e8f186851e40e20100"
          );

private static final byte[] profileKeyPresentationResult = Hex.fromStringCondensedAssert(

"f8a81bfd7d169872d41ed7456fa6d8b3ee3ce61f1b902e7817ad9c05881e414106e9c26592c8b2fffe8fcafa993272149ae6d8489cc0c558d7209ff48aa37a51246735075e3c1b881aae626d8430714b880d36b338349525c7a2f8a02f5579389cbc1e3df512e4937e0ce5b0b2a683d0a0b0e34ce4ec7dee93e57f38aaa46b2e36bc01bdb2d05ddcb7998783b50c614e129c6fa8a6b0b5c4b41257633e6995101068b48cdeb5501b6aaa8f7c2b10374172e73389be56a6215d61c7842e95ff794e1c1307b8c8a3d6cf3040a71d1a3ee9c21e8669931d210ecec3fb95e9212f4c58ef36e5a90059237fe22d6a5dc2d13287a72b1ce688fd91ee6cf78d2336081da60b1fc865fccb4fbee8f88cd7c44784dd319969a5e21094a58c2951d1a13b0a40010000000000005c2b1508a6acc3d4303340c0d6f6339816063c286627607200a93bebaee76c03f5c77b22c0b191ff821aab225280a84c98a3843b3338d83a6916ff820fce5308fe0ff1f75d7a3d38b3b908e2fe87bbdc54ec959a90ec85dd9107382897d05303486b972c420ef740398b8649d2013cb02e9c2a9d65813e4b34cc77b08ab4920572e3ec747eb96bf3e1ac5d16416dc6b9dc8b82bb4ecfdee0cd4bf2d985aed40ee07d57dd504fc6b1988a475efb5df74b55d7c54cf368037d10ed530d2ae3010d654c28c4baf605f7deaf5db68c9ccebd3d385b78b5f0e8226a1b96e71753fc05086e35f4702c20ef6d9f24690d16b940dbc4a3c98077ea28454cd8bbb08dc40c9b3988ffef2d5c833148f4377b17c7fdfbaaf1034f413a14eb2a8dbe13aba902afd208e40dd4d4faddd58dad881c894a8cf565da5e54d9796d7dfdc33529d80f2047ffdb43a7b802030e20c50051edcf0fb92178e087fa5e5d1e045b38a01b3af44c192e9ea29581e9c3befd1a10aab20ccd19a6dec3ca0668d887e8f186851e007efd1a1fbc7e15cd34b2b32b6d1e406b991baffcb0915ef502aa0bc655633d06b1927f3ad10cf25ed9a4cd7fa6949b0cd5842449b931a90def70dc85869e07101112131415161718191a1b1c1d1e1f"
);


  @Test
  public void testAuthIntegration() throws VerificationFailedException, InvalidInputException, InvalidRedemptionTimeException {

    UUID uuid           = UUIDUtil.deserialize(TEST_ARRAY_16);
    int  redemptionTime = 123456;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();
    ServerZkAuthOperations serverZkAuth       = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    AuthCredentialResponse authCredentialResponse = serverZkAuth.issueAuthCredential(createSecureRandom(TEST_ARRAY_32_2), uuid, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredential         authCredential      = clientZkAuthCipher.receiveAuthCredential(uuid, redemptionTime, authCredentialResponse);

    // Create and decrypt user entry
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    UUID           plaintext      = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assertEquals(uuid, plaintext);

    // Create presentation
    AuthCredentialPresentation presentation = clientZkAuthCipher.createAuthCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, authCredential);

    // Verify presentation, using times at the edge of the acceptable window
    UuidCiphertext uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());
    assertEquals(presentation.getRedemptionTime(), redemptionTime);

    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, TimeUnit.MILLISECONDS.convert(123455L, TimeUnit.DAYS));
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, TimeUnit.MILLISECONDS.convert(123458L, TimeUnit.DAYS));

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, TimeUnit.MILLISECONDS.convert(123455L, TimeUnit.DAYS) - 1L);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #1!");
    } catch(InvalidRedemptionTimeException e) {
      // good
    }

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, TimeUnit.MILLISECONDS.convert(123458L, TimeUnit.DAYS) + 1L);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #2!");
    } catch(InvalidRedemptionTimeException e) {
      // good
    }


    assertArrayEquals(presentation.serialize(), authPresentationResult);
  }


  @Test
  public void testAuthIntegrationCurrentTime() throws VerificationFailedException, InvalidInputException, InvalidRedemptionTimeException {

    // This test is mostly the same as testAuthIntegration() except instead of using a hardcoded
    // redemption date to compare against test vectors, it uses the current time

    UUID uuid           = UUIDUtil.deserialize(TEST_ARRAY_16);
    int  redemptionTime = (int)TimeUnit.DAYS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();
    ServerZkAuthOperations serverZkAuth       = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    AuthCredentialResponse authCredentialResponse = serverZkAuth.issueAuthCredential(createSecureRandom(TEST_ARRAY_32_2), uuid, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredential         authCredential      = clientZkAuthCipher.receiveAuthCredential(uuid, redemptionTime, authCredentialResponse);

    // Create and decrypt user entry
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    UUID           plaintext      = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assertEquals(uuid, plaintext);

    // Create presentation
    AuthCredentialPresentation presentation = clientZkAuthCipher.createAuthCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, authCredential);

    // Verify presentation, using times at the edge of the acceptable window
    UuidCiphertext uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());
    assertEquals(presentation.getRedemptionTime(), redemptionTime);

    // By default the library uses the current time
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation);

    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, TimeUnit.MILLISECONDS.convert(redemptionTime - 1L, TimeUnit.DAYS));
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, TimeUnit.MILLISECONDS.convert(redemptionTime + 2L, TimeUnit.DAYS));

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, TimeUnit.MILLISECONDS.convert(redemptionTime - 1L, TimeUnit.DAYS) - 1L);
        throw new AssertionError("verifyAuthCredentialPresentation (current time) should fail #1!");
    } catch(InvalidRedemptionTimeException e) {
      // good
    }

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, TimeUnit.MILLISECONDS.convert(redemptionTime + 2L, TimeUnit.DAYS) + 1L);
        throw new AssertionError("verifyAuthCredentialPresentation (current time) should fail #2!");
    } catch(InvalidRedemptionTimeException e) {
      // good
    }

  }


  @Test
  public void testProfileKeyIntegration() throws VerificationFailedException, InvalidInputException, UnsupportedEncodingException {

    UUID uuid           = UUIDUtil.deserialize(TEST_ARRAY_16);
    int  redemptionTime = 1234567;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();
    ServerZkProfileOperations serverZkProfile    = new ServerZkProfileOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams     groupPublicParams     = groupSecretParams.getPublicParams();
    ClientZkProfileOperations clientZkProfileCipher = new ClientZkProfileOperations(serverPublicParams);

    ProfileKey           profileKey             = new ProfileKey(TEST_ARRAY_32);
    ProfileKeyCommitment profileKeyCommitment = profileKey.getCommitment();

    // Create context and request
    ProfileKeyCredentialRequestContext context = clientZkProfileCipher.createProfileKeyCredentialRequestContext(createSecureRandom(TEST_ARRAY_32_3), uuid, profileKey);
    ProfileKeyCredentialRequest        request = context.getRequest();

    // SERVER 
    ProfileKeyCredentialResponse response = serverZkProfile.issueProfileKeyCredential(createSecureRandom(TEST_ARRAY_32_4), request, uuid, profileKeyCommitment);
   
    // CLIENT
    // Gets stored profile credential
    ClientZkGroupCipher  clientZkGroupCipher  = new ClientZkGroupCipher(groupSecretParams);
    ProfileKeyCredential profileKeyCredential = clientZkProfileCipher.receiveProfileKeyCredential(context, response);

    // Create encrypted UID and profile key
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    UUID           plaintext      = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assertEquals(plaintext, uuid);

    ProfileKeyCiphertext profileKeyCiphertext   = clientZkGroupCipher.encryptProfileKey(createSecureRandom(TEST_ARRAY_32_4), profileKey);
    ProfileKey           decryptedProfileKey    = clientZkGroupCipher.decryptProfileKey(profileKeyCiphertext);
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());

    ProfileKeyCredentialPresentation presentation = clientZkProfileCipher.createProfileKeyCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, profileKeyCredential);

    assertArrayEquals(presentation.serialize(), profileKeyPresentationResult);

    // Verify presentation
    serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentation);
    UuidCiphertext uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());

    ProfileKeyVersion pkvA = profileKeyCommitment.getProfileKeyVersion();
    ProfileKeyVersion pkvB = profileKey.getProfileKeyVersion();
    if (!pkvA.serialize().equals(pkvB.serialize()))
      throw new AssertionError();
    ProfileKeyVersion pkvC = new ProfileKeyVersion(pkvA.serialize());
    if (!pkvA.serialize().equals(pkvC.serialize()))
      throw new AssertionError();
  }

  @Test
  public void testGroupSignatures() throws VerificationFailedException {

    SecureRandom      groupSecretParamsSecureRandom = createSecureRandom(TEST_ARRAY_32);
    GroupSecretParams groupSecretParams             = GroupSecretParams.generate(groupSecretParamsSecureRandom);
    GroupMasterKey    masterKey                     = groupSecretParams.getMasterKey();
    GroupPublicParams groupPublicParams             = groupSecretParams.getPublicParams();

    byte[] message = TEST_ARRAY_32_1;

    ChangeSignature signature = groupSecretParams.sign(createSecureRandom(TEST_ARRAY_32_2), message);
    groupPublicParams.verifySignature(message, signature);

    //assertByteArray("ea39f1687426eadd144d8fcf0e33c43b1e278dbbe0a67c3e60d4ce531bcb5402" +
    //                "f16b2e587ca19189c8466fa1dcdb77ae12d1b8828781512cd292d0915a72b609", signature.serialize());

    byte[] alteredMessage = message.clone();
    alteredMessage[0] ^= 1;
  
    try {
        groupPublicParams.verifySignature(alteredMessage, signature);
        throw new AssertionError("verifySignature should fail!");
    } catch(VerificationFailedException e) {
      // good
    }
  }


  @Test
  public void testServerSignatures() throws VerificationFailedException {
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    byte[] message = TEST_ARRAY_32_1;

    NotarySignature signature = serverSecretParams.sign(createSecureRandom(TEST_ARRAY_32_2), message);
    serverPublicParams.verifySignature(message, signature);

    assertByteArray("819c59fcaca7023b13875ef63ef98df314de2a6a56d314f63cb98c234b55f506" +
                    "aff6475d295789c66a11cddec1602ef1c4a24414168fe9ba1036ba286b47ea07", signature.serialize());

    byte[] alteredMessage = message.clone();
    alteredMessage[0] ^= 1;
    try {
        serverPublicParams.verifySignature(alteredMessage, signature);
        throw new AssertionError("signature validation should have failed!");
    } catch (VerificationFailedException e) {
      // good
    }
  }

  @Test
  public void testGroupIdentifier() throws VerificationFailedException {
    GroupSecretParams   groupSecretParams   = GroupSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    //assertByteArray("31f2c60f86f4c5996e9e2568355591d9", groupPublicParams.getGroupIdentifier().serialize());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testErrors() throws RuntimeException {

    byte[] ckp = new byte[GroupSecretParams.SIZE];
    Arrays.fill(ckp, (byte) -127);

    GroupSecretParams groupSecretParams = new GroupSecretParams(ckp);
  }

  @Test
  public void testBlobEncryption() throws VerificationFailedException {
    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    ClientZkGroupCipher clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    byte[] plaintext = {0,1,2,3,4};
    byte[] ciphertext = clientZkGroupCipher.encryptBlob(plaintext);
    byte[] plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext);
    assertArrayEquals(plaintext, plaintext2);
  }

  private void assertByteArray(String expectedAsHex, byte[] actual) {
    byte[] expectedBytes = Hex.fromStringCondensedAssert(expectedAsHex);

    assertArrayEquals(expectedBytes, actual);
  }

}

