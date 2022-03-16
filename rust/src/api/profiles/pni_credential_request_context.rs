//
// Copyright (C) 2021 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use crate::api;
use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PniCredentialRequestContext {
    pub(crate) reserved: ReservedBytes,
    pub(crate) aci_bytes: UidBytes,
    pub(crate) pni_bytes: UidBytes,
    pub(crate) profile_key_bytes: ProfileKeyBytes,
    pub(crate) key_pair: crypto::profile_key_credential_request::KeyPair,
    pub(crate) ciphertext_with_secret_nonce:
        crypto::profile_key_credential_request::CiphertextWithSecretNonce,
    pub(crate) proof: crypto::proofs::ProfileKeyCredentialRequestProof,
}

impl PniCredentialRequestContext {
    // This is correct: PniCredentialRequestContext and ProfileKeyCredentialRequestContext share a
    // request type.
    pub fn get_request(&self) -> api::profiles::ProfileKeyCredentialRequest {
        let ciphertext = self.ciphertext_with_secret_nonce.get_ciphertext();
        let public_key = self.key_pair.get_public_key();
        api::profiles::ProfileKeyCredentialRequest {
            reserved: Default::default(),
            public_key,
            ciphertext,
            proof: self.proof.clone(),
        }
    }
}
