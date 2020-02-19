//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileKeyCiphertext {
    pub(crate) ciphertext: crypto::profile_key_encryption::Ciphertext,
}
