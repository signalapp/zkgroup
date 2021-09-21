//
// Copyright (C) 2021 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use zkgroup::common::sho::Sho;
use zkgroup::crypto::credentials;
use zkgroup::crypto::proofs::{ReceiptCredentialIssuanceProof, ReceiptCredentialPresentationProof};
use zkgroup::crypto::receipt_credential_request;
use zkgroup::crypto::receipt_struct::ReceiptStruct;
use zkgroup::{ReceiptExpirationTime, ReceiptLevel, NUM_RECEIPT_CRED_ATTRIBUTES};

#[test]
fn test_request_response() {
    let mut sho = Sho::new(b"Test_Receipt_Credential_Request", b"");

    // client receives in response to initial request
    let receipt_expiration_time: ReceiptExpirationTime = 42;
    let receipt_level: ReceiptLevel = 3;

    // known to client and redemption server
    let receipt_serial_bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // client generated materials; issuance request
    let client_key_pair = receipt_credential_request::KeyPair::generate(&mut sho);
    let client_ciphertext = client_key_pair.encrypt(receipt_serial_bytes, &mut sho);
    let given_to_server_ciphertext = client_ciphertext.get_ciphertext();
    let given_to_server_public_key = client_key_pair.get_public_key();

    // server generated materials; issuance request -> issuance response
    let server_key_pair = credentials::KeyPair::generate(&mut sho, NUM_RECEIPT_CRED_ATTRIBUTES);
    let blinded_receipt_credential = server_key_pair.create_blinded_receipt_credential(
        given_to_server_public_key,
        given_to_server_ciphertext,
        receipt_expiration_time,
        receipt_level,
        &mut sho,
    );
    let given_to_client_blinded_receipt_credential =
        blinded_receipt_credential.get_blinded_receipt_credential();
    let given_to_client_receipt_credential_issuance_proof = ReceiptCredentialIssuanceProof::new(
        server_key_pair,
        given_to_server_public_key,
        given_to_server_ciphertext,
        blinded_receipt_credential,
        receipt_expiration_time,
        receipt_level,
        &mut sho,
    );

    // client generated materials; issuance response -> redemption request
    let receipt_struct =
        ReceiptStruct::new(receipt_serial_bytes, receipt_expiration_time, receipt_level);
    given_to_client_receipt_credential_issuance_proof
        .verify(
            server_key_pair.get_public_key(),
            given_to_server_public_key,
            given_to_server_ciphertext,
            given_to_client_blinded_receipt_credential,
            receipt_struct,
        )
        .expect("issuance proof validity check failed");
    let receipt_credential = client_key_pair
        .decrypt_blinded_receipt_credential(given_to_client_blinded_receipt_credential);
    let receipt_credential_presentation_proof = ReceiptCredentialPresentationProof::new(
        server_key_pair.get_public_key(),
        receipt_credential,
        &mut sho,
    );

    // server verification of the credential presentation
    receipt_credential_presentation_proof
        .verify(server_key_pair, receipt_struct)
        .expect("presentation proof validity check failed");
}
