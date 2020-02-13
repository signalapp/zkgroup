//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProfileKeyCredentialRequest {
    pub(crate) public_key: crypto::profile_credential_request::PublicKey,
    pub(crate) ciphertext: crypto::profile_credential_request::Ciphertext,
    pub(crate) proof: crypto::proofs::ProfileCredentialRequestProof,
}
