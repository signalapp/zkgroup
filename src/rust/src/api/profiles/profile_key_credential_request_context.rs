//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::api;
use crate::common::simple_types::*;
use crate::crypto;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProfileKeyCredentialRequestContext {
    pub(crate) uid_bytes: UidBytes,
    pub(crate) P: RistrettoPoint,
    pub(crate) key_pair: crypto::profile_credential_request::KeyPair,
    pub(crate) ciphertext_with_secret_nonce:
        crypto::profile_credential_request::CiphertextWithSecretNonce,
    pub(crate) proof: crypto::proofs::ProfileCredentialRequestProof,
    pub(crate) plaintext_key_half: ProfileKeyHalfBytes,
}

impl ProfileKeyCredentialRequestContext {
    pub fn get_request(&self) -> api::profiles::ProfileKeyCredentialRequest {
        let ciphertext = self.ciphertext_with_secret_nonce.get_ciphertext();
        let public_key = self.key_pair.get_public_key();
        api::profiles::ProfileKeyCredentialRequest {
            public_key,
            ciphertext,
            proof: self.proof.clone(),
        }
    }
}
