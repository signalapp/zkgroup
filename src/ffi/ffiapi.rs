//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use super::simpleapi;
use std::slice;

#[no_mangle]
pub extern "C" fn ClientKeyPair_generateDeterministic(
    randomness: *const u8,
    randomnessLen: u64,
    clientKeyPairOut: *mut u8,
    clientKeyPairLen: u64,
) -> bool {
    let randomness: &[u8] = unsafe { slice::from_raw_parts(randomness, randomnessLen as usize) };
    let client_key_pair: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(clientKeyPairOut, clientKeyPairLen as usize) };
    simpleapi::ClientKeyPair_generateDeterministic(randomness, client_key_pair)
}

#[no_mangle]
pub extern "C" fn ClientKeyPair_deriveFrom(
    masterKey: *const u8,
    masterKeyLen: u64,
    clientKeyPairOut: *mut u8,
    clientKeyPairLen: u64,
) -> bool {
    let master_key: &[u8] = unsafe { slice::from_raw_parts(masterKey, masterKeyLen as usize) };
    let client_key_pair: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(clientKeyPairOut, clientKeyPairLen as usize) };
    simpleapi::ClientKeyPair_deriveFrom(master_key, client_key_pair)
}

#[no_mangle]
pub extern "C" fn ClientKeyPair_signDeterministic(
    clientKeyPair: *const u8,
    clientKeyPairLen: u64,
    message: *const u8,
    messageLen: u64,
    randomness: *const u8,
    randomnessLen: u64,
    signatureOut: *mut u8,
    signatureLen: u64,
) -> bool {
    let client_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(clientKeyPair, clientKeyPairLen as usize) };
    let message: &[u8] = unsafe { slice::from_raw_parts(message, messageLen as usize) };
    let randomness: &[u8] = unsafe { slice::from_raw_parts(randomness, randomnessLen as usize) };
    let signature: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(signatureOut, signatureLen as usize) };

    simpleapi::ClientKeyPair_signDeterministic(client_key_pair, message, randomness, signature)
}

#[no_mangle]
pub extern "C" fn ClientKeyPair_getMasterKey(
    clientKeyPair: *const u8,
    clientKeyPairLen: u64,
    masterKeyOut: *mut u8,
    masterKeyLen: u64,
) -> bool {
    let client_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(clientKeyPair, clientKeyPairLen as usize) };
    let master_key: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(masterKeyOut, masterKeyLen as usize) };

    simpleapi::ClientKeyPair_getMasterKey(client_key_pair, master_key)
}

#[no_mangle]
pub extern "C" fn ClientKeyPair_getPublicKey(
    clientKeyPair: *const u8,
    clientKeyPairLen: u64,
    clientPublicKeyOut: *mut u8,
    clientPublicKeyLen: u64,
) -> bool {
    let client_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(clientKeyPair, clientKeyPairLen as usize) };
    let client_public_key: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(clientPublicKeyOut, clientPublicKeyLen as usize) };

    simpleapi::ClientKeyPair_getPublicKey(client_key_pair, client_public_key)
}

#[no_mangle]
pub extern "C" fn ServerKeyPair_generate(
    randomness: *const u8,
    randomnessLen: u64,
    serverKeyPairOut: *mut u8,
    serverKeyPairLen: u64,
) -> bool {
    let randomness: &[u8] = unsafe { slice::from_raw_parts(randomness, randomnessLen as usize) };
    let server_key_pair: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(serverKeyPairOut, serverKeyPairLen as usize) };
    simpleapi::ServerKeyPair_generateDeterministic(randomness, server_key_pair)
}

#[no_mangle]
pub extern "C" fn ServerKeyPair_getPublicKey(
    serverKeyPair: *const u8,
    serverKeyPairLen: u64,
    serverPublicKeyOut: *mut u8,
    serverPublicKeyLen: u64,
) -> bool {
    let server_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(serverKeyPair, serverKeyPairLen as usize) };
    let server_public_key: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(serverPublicKeyOut, serverPublicKeyLen as usize) };

    simpleapi::ServerKeyPair_getPublicKey(server_key_pair, server_public_key)
}

#[no_mangle]
pub extern "C" fn ServerKeyPair_signDeterministic(
    serverKeyPair: *const u8,
    serverKeyPairLen: u64,
    message: *const u8,
    messageLen: u64,
    randomness: *const u8,
    randomnessLen: u64,
    signatureOut: *mut u8,
    signatureLen: u64,
) -> bool {
    let server_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(serverKeyPair, serverKeyPairLen as usize) };
    let message: &[u8] = unsafe { slice::from_raw_parts(message, messageLen as usize) };
    let randomness: &[u8] = unsafe { slice::from_raw_parts(randomness, randomnessLen as usize) };
    let signature: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(signatureOut, signatureLen as usize) };

    simpleapi::ServerKeyPair_signDeterministic(server_key_pair, message, randomness, signature)
}

#[no_mangle]
pub extern "C" fn ClientPublicKey_getGroupIdentifier(
    clientPublicKey: *const u8,
    clientPublicKeyLen: u64,
    groupId: *mut u8,
    groupIdLen: u64,
) -> bool {
    let client_public_key: &[u8] =
        unsafe { slice::from_raw_parts(clientPublicKey, clientPublicKeyLen as usize) };
    let group_id: &mut [u8] = unsafe { slice::from_raw_parts_mut(groupId, groupIdLen as usize) };

    simpleapi::ClientPublicKey_getGroupIdentifier(client_public_key, group_id)
}

#[no_mangle]
pub extern "C" fn ClientPublicKey_verifySignature(
    clientPublicKey: *const u8,
    clientPublicKeyLen: u64,
    message: *const u8,
    messageLen: u64,
    signature: *const u8,
    signatureLen: u64,
) -> bool {
    let client_public_key: &[u8] =
        unsafe { slice::from_raw_parts(clientPublicKey, clientPublicKeyLen as usize) };
    let message: &[u8] = unsafe { slice::from_raw_parts(message, messageLen as usize) };
    let signature: &[u8] = unsafe { slice::from_raw_parts(signature, signatureLen as usize) };

    simpleapi::ClientPublicKey_verifySignature(client_public_key, message, signature)
}

#[no_mangle]
pub extern "C" fn ServerPublicKey_verifySignature(
    serverPublicKey: *const u8,
    serverPublicKeyLen: u64,
    message: *const u8,
    messageLen: u64,
    signature: *const u8,
    signatureLen: u64,
) -> bool {
    let server_public_key: &[u8] =
        unsafe { slice::from_raw_parts(serverPublicKey, serverPublicKeyLen as usize) };
    let message: &[u8] = unsafe { slice::from_raw_parts(message, messageLen as usize) };
    let signature: &[u8] = unsafe { slice::from_raw_parts(signature, signatureLen as usize) };

    simpleapi::ServerPublicKey_verifySignature(server_public_key, message, signature)
}

#[no_mangle]
pub extern "C" fn UserCiphertext_create(
    clientKeyPair: *const u8,
    clientKeyPairLen: u64,
    uid: *const u8,
    uidLen: u64,
    userCiphertextOut: *mut u8,
    userCiphertextLen: u64,
) -> bool {
    let client_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(clientKeyPair, clientKeyPairLen as usize) };
    let uid: &[u8] = unsafe { slice::from_raw_parts(uid, uidLen as usize) };
    let user_ciphertext: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(userCiphertextOut, userCiphertextLen as usize) };

    simpleapi::UserCiphertext_create(client_key_pair, uid, user_ciphertext)
}

#[no_mangle]
pub extern "C" fn UserCiphertext_decrypt(
    clientKeyPair: *const u8,
    clientKeyPairLen: u64,
    ciphertext: *const u8,
    ciphertextLen: u64,
    uidOut: *mut u8,
    uidLen: u64,
) -> bool {
    let client_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(clientKeyPair, clientKeyPairLen as usize) };
    let ciphertext: &[u8] = unsafe { slice::from_raw_parts(ciphertext, ciphertextLen as usize) };
    let uid: &mut [u8] = unsafe { slice::from_raw_parts_mut(uidOut, uidLen as usize) };

    simpleapi::UserCiphertext_decrypt(client_key_pair, ciphertext, uid)
}

#[no_mangle]
pub extern "C" fn IssuedCredential_createDeterministic(
    serverKeyPair: *const u8,
    serverKeyPairLen: u64,
    uid: *const u8,
    uidLen: u64,
    redemptionTime: u32,
    randomness: *const u8,
    randomnessLen: u64,
    issuedCredentialOut: *mut u8,
    issuedCredentialLen: u64,
) -> bool {
    let server_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(serverKeyPair, serverKeyPairLen as usize) };
    let uid: &[u8] = unsafe { slice::from_raw_parts(uid, uidLen as usize) };
    let redemption_time = redemptionTime;
    let randomness: &[u8] = unsafe { slice::from_raw_parts(randomness, randomnessLen as usize) };
    let issued_credential: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(issuedCredentialOut, issuedCredentialLen as usize) };

    simpleapi::IssuedCredential_createDeterministic(
        server_key_pair,
        uid,
        redemption_time,
        randomness,
        issued_credential,
    )
}

#[no_mangle]
pub extern "C" fn IssuedCredential_createStoredCredential(
    issuedCredential: *const u8,
    issuedCredentialLen: u64,
    serverPublicKey: *const u8,
    serverPublicKeyLen: u64,
    uid: *const u8,
    uidLen: u64,
    redemptionTime: u32,
    storedCredentialOut: *mut u8,
    storedCredentialLen: u64,
) -> bool {
    let issued_credential: &[u8] =
        unsafe { slice::from_raw_parts(issuedCredential, issuedCredentialLen as usize) };
    let server_public_key: &[u8] =
        unsafe { slice::from_raw_parts(serverPublicKey, serverPublicKeyLen as usize) };
    let uid: &[u8] = unsafe { slice::from_raw_parts(uid, uidLen as usize) };
    let redemption_time = redemptionTime;
    let stored_credential: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(storedCredentialOut, storedCredentialLen as usize) };

    simpleapi::IssuedCredential_createStoredCredential(
        issued_credential,
        server_public_key,
        uid,
        redemption_time,
        stored_credential,
    )
}

#[no_mangle]
pub extern "C" fn StoredCredential_createPresentationDeterministic(
    storedCredential: *const u8,
    storedCredentialLen: u64,
    clientKeyPair: *const u8,
    clientKeyPairLen: u64,
    randomness: *const u8,
    randomnessLen: u64,
    presentationOut: *mut u8,
    presentationLen: u64,
) -> bool {
    let client_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(clientKeyPair, clientKeyPairLen as usize) };
    let stored_credential: &[u8] =
        unsafe { slice::from_raw_parts(storedCredential, storedCredentialLen as usize) };
    let randomness: &[u8] = unsafe { slice::from_raw_parts(randomness, randomnessLen as usize) };
    let presentation: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(presentationOut, presentationLen as usize) };

    simpleapi::StoredCredential_createPresentationDeterministic(
        stored_credential,
        client_key_pair,
        randomness,
        presentation,
    )
}

#[no_mangle]
pub extern "C" fn Presentation_getRedemptionTime(
    presentation: *const u8,
    presentationLen: u64,
    redemptionTimeOut: *mut u8,
    redemptionTimeLen: u64,
) -> bool {
    let presentation: &[u8] =
        unsafe { slice::from_raw_parts(presentation, presentationLen as usize) };
    let redemption_time: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(redemptionTimeOut, redemptionTimeLen as usize) };

    simpleapi::Presentation_getRedemptionTime(presentation, redemption_time)
}

#[no_mangle]
pub extern "C" fn Presentation_verify(
    serverKeyPair: *const u8,
    serverKeyPairLen: u64,
    clientPublicKey: *const u8,
    clientPublicKeyLen: u64,
    presentation: *const u8,
    presentationLen: u64,
    storedUserEntry: *const u8,
    storedUserEntryLen: u64,
) -> bool {
    let server_key_pair: &[u8] =
        unsafe { slice::from_raw_parts(serverKeyPair, serverKeyPairLen as usize) };
    let client_public_key: &[u8] =
        unsafe { slice::from_raw_parts(clientPublicKey, clientPublicKeyLen as usize) };
    let presentation: &[u8] =
        unsafe { slice::from_raw_parts(presentation, presentationLen as usize) };
    let stored_user_entry: &[u8] =
        unsafe { slice::from_raw_parts(storedUserEntry, storedUserEntryLen as usize) };

    simpleapi::Presentation_verify(
        server_key_pair,
        client_public_key,
        presentation,
        stored_user_entry,
    )
}

#[no_mangle]
pub extern "C" fn zktestfunc(input: *const u8, inputLen: u64, output: *mut u8, outputLen: u64) {
    let input_slice: &[u8] = unsafe { slice::from_raw_parts(input, inputLen as usize) };
    let output_slice: &mut [u8] = unsafe { slice::from_raw_parts_mut(output, outputLen as usize) };

    for i in 0..input_slice.len() {
        output_slice[i] = input_slice[i] + 1;
    }
}
