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
pub struct ProfileKeyCredentialResponse {
    pub(crate) blinded_credential: crypto::credentials::BlindedProfileCredential,
    pub(crate) proof: crypto::proofs::ProfileCredentialIssuanceProof,
}
