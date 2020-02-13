//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::simple_types::*;
use crate::crypto;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ProfileKeyCredential {
    pub(crate) credential: crypto::credentials::ProfileCredential,
    pub(crate) uid_bytes: UidBytes,
    pub(crate) P: RistrettoPoint,
    pub(crate) plaintext_key_half: ProfileKeyHalfBytes,
}
