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
    "c051a9c14dd980bbc66f30980fb99574093830ba5265f7871f5723a687dc7535ca442d45f9f439c932764613955275d822bd3ab1f29104c0358da29f8315052d7c5f9f3195e5ed27fcaf25564eb3c419da5b0d7e2f4f4baa70c12dc12174e37d50c2a93b803d8c972f12af026ab60d91a4c4ba54842e73073c0b520f2513105a6e72350204c18d686645ca4991ac56a557f1e05f771697fb6aef6d1db72e6325e0d397fb7951fdfa1e3ae328244263d48b4a74de88e54fc8b8427bf56911f04bf28f0ac87f549b33c324b0063913191686b7bbc8724636d91b567cb7543c66394856a70ebc0f09db4892499ce625bdd3fe42e3d8d8012cc50fcf76f58ab5fc3920010000000000002405bffd51b8464339da562bb00efbe2fdf2a39faac890b7ccf2a8f78ee3920347574f11f0ce50370e854660943f28474eae61c089b24deda5d272b6615a7500753a3b54c7d147005b6bf8946e2a2426e6ff22d27f5e8d011b5a226dd8a43c0b94f91314fe0b29a1c885d920251bb4fb72ceb02a3198c20fdb7ce387df2f270ac77f816111da46a6df6db05eaaed026e73f80d5bf09360b857497fe2c25954058b546ca9766f39c5dafe92709a115097271b8dc166033b0d1dc435b62afc50007b6cc6c1dbe21013164e362c14f50921ca2c5b59a1fdf1ea722144a9b57ffc0980adf58c471afbb2f9ceee8b17110a39224001db909e1ae52b89f5b6911d3902fee77c0c13a60fb2265e3f0955a6ceb143f531a9bc75228db420bbd9535f990a2047ffdb43a7b802030e20c50051edcf0fb92178e087fa5e5d1e045b38a01b3af44c192e9ea29581e9c3befd1a10aab20ccd19a6dec3ca0668d887e8f186851e40e20100"
          );

private static final byte[] profileKeyPresentationResult = Hex.fromStringCondensedAssert(
"30c7b1e8509de165c17e485832a2bbdee52c5646e4380a9e09909343e4abcf5270ad9ba7194965fd629f473c8b56bf28d2cfc46c8a32c4d391b8b195fe8b6441a60435237e987f46d017832528d70b5d675a49ed170029b7d78addffe7d8733f90efce840c498f30e3d63db38cd3e9a63e7cfdfc9223ff9abd46ab490917f93586c5f334666b37e6a6cb970b12f8ff031350dbf53371099520e7a971a0843e110ababff79b279727b0b1024d858de25505011213013152cb2fc8faced94eed16eced97d0f93ad1cff266b1b1570a835d31e67fdaa6769ba2fe6266f3ab21d33b34e99043446a25a0b7c55d5fb6344b20dfde4f2957276bd73b0b5c0ee0d4a403ee9d2bfe7615017fd3a319bd8b93dd9249c1b0deab608d1b8b03584f1e1f493e5a17a32be08443c8915d6af3a2ccc61e95963db59a6dc085d7de371f1fd9b9610a3d90940d24596fc6a885d24c4fbaaba7b8a455349b5c3db649f5c8346a526cc001000000000000cf7682d575a1316e0dcf931a2f5b7d33e957d7c3dd21f0ae6a7ff449ec74cd04b8acddbf65534a93a683c268fbedec3391a89b9e54883dc500295ff07a738d0cf2acc1f47d29450531cad4504fc640c0686015f2ae69f91e70bb41610e9b9705c9b691a1868ed749dab9b1af009b31c05ba12133384647912622583e7720150d9cc7bedcd6a597b405363cb5b9bdba6707f8f61fcd7aa7802232c007d89b3102e8fb5b7fbdce05d5e339dfeee23867382ebab6fb4a1d185eaf6636801f1b440b43dddb9af62dcd39a2b20b42514e285a96bf4848697aec1c1f747d179156020d1605b253be3c715f0d52494de4b0c828167a58d809dbecf17d167b19fd361707c8ba1c33148ee7bcd43aad9dd106031b29f04c152a6cce255d1911a76f86d60ec2100dade16e463c53c244e5e39a50dd557510f7bec20b700cdae47fc7cabe0da5d53598cdd514ef70e2c06eefdcf4f665b753c2ae455918135c2b6609be62080dc44b1be5d5fd4f23e935217bc1be96119a0ef6223322a88e45f9621ca2490b3a31fce284d35c9d6b870aadc7e57fa381785d6bdbfb7cd951474b2f8923a10462f981600b971557ba0a7ddba9166a72d51251a7fefd62b2a214fe3b50c141032047ffdb43a7b802030e20c50051edcf0fb92178e087fa5e5d1e045b38a01b3af44c192e9ea29581e9c3befd1a10aab20ccd19a6dec3ca0668d887e8f186851e4a11e8c379e066bac4ac99e8c64b8b47d47579c9ebfc0f61a70dfa3feeb70a117cb6fc6f3b010b51d1eec5f4b93598265b81e91f65a21cbff539507ee9647d5e");

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

    ProfileKey           profileKey             = new ProfileKey(TEST_ARRAY_32_1);
    ProfileKeyCommitment profileKeyCommitment = profileKey.getCommitment(uuid);

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

    ProfileKeyCiphertext profileKeyCiphertext   = clientZkGroupCipher.encryptProfileKey(createSecureRandom(TEST_ARRAY_32_4), profileKey, uuid);
    ProfileKey           decryptedProfileKey    = clientZkGroupCipher.decryptProfileKey(profileKeyCiphertext, uuid);
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());

    ProfileKeyCredentialPresentation presentation = clientZkProfileCipher.createProfileKeyCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, profileKeyCredential);

    assertArrayEquals(presentation.serialize(), profileKeyPresentationResult);

    // Verify presentation
    serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentation);
    UuidCiphertext uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());

    ProfileKeyVersion pkvA = profileKeyCommitment.getProfileKeyVersion();
    ProfileKeyVersion pkvB = profileKey.getProfileKeyVersion(uuid);
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
  public void testBlobEncryption() throws InvalidInputException, VerificationFailedException {

      /*
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let randomness = zkgroup::TEST_ARRAY_32_2;

    let plaintext_vec = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19,
    ];

    let ciphertext_vec = vec![
        0xc0, 0x9c, 0x16, 0x75, 0x4b, 0x32, 0x86, 0x7f, 0xd5, 0x11, 0x9d, 0x18, 0x81, 0xd6, 0x2e,
        0x7c, 0x96, 0x7f, 0x6e, 0x3a, 0x8a, 0xf5, 0xf0, 0x9a, 0xc8, 0x4f, 0x7b, 0x74, 0xfc, 0xc6,
        0xd0, 0xe4, 0xd5, 0x9c, 0x9f, 0x4a, 0x17, 0x5e, 0x0f, 0x48, 0x9c, 0x47, 0xe4, 0x81, 0xf1,
    ];

    let calc_ciphertext_vec = group_secret_params
        .encrypt_blob(randomness, &plaintext_vec)
        .unwrap();
    let calc_plaintext_vec = group_secret_params
        .decrypt_blob(&calc_ciphertext_vec)
        .unwrap();
    assert!(calc_plaintext_vec == plaintext_vec);
    assert!(calc_ciphertext_vec == ciphertext_vec);
    */

    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);
    ClientZkGroupCipher clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    byte[] plaintext = Hex.fromStringCondensedAssert("0102030405060708111213141516171819");
    byte[] ciphertext = Hex.fromStringCondensedAssert("c09c16754b32867fd5119d1881d62e7c967f6e3a8af5f09ac84f7b74fcc6d0e4d59c9f4a175e0f489c47e481f1");

    byte[] ciphertext2 = clientZkGroupCipher.encryptBlob(createSecureRandom(TEST_ARRAY_32_2), plaintext);
    byte[] plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext);
    assertArrayEquals(plaintext, plaintext2);
    assertArrayEquals(ciphertext, ciphertext2);
  }

  private void assertByteArray(String expectedAsHex, byte[] actual) {
    byte[] expectedBytes = Hex.fromStringCondensedAssert(expectedAsHex);

    assertArrayEquals(expectedBytes, actual);
  }

}

