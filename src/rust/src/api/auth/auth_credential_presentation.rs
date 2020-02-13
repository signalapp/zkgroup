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
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialPresentation {
    pub(crate) proof: crypto::proofs::AuthCredentialPresentationProof,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) redemption_time: RedemptionTime,
}

impl AuthCredentialPresentation {
    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            ciphertext: self.ciphertext,
        }
    }

    pub fn get_redemption_time(&self) -> RedemptionTime {
        self.redemption_time
    }
}
