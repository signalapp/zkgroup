//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::api;
use crate::common::constants::*;
use crate::common::simple_types::*;
use crate::crypto;
use poksho::ShoSha256;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ProfileKey {
    pub bytes: ProfileKeyBytes,
}

impl ProfileKey {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut bytes = [0u8; PROFILE_KEY_LEN];
        bytes.copy_from_slice(
            &ShoSha256::shohash(
                b"Signal_ZKGroup_ProfileKey_KeyGen",
                &randomness,
                PROFILE_KEY_LEN as u64,
            )[0..PROFILE_KEY_LEN],
        );
        Self { bytes }
    }

    pub fn create(bytes: ProfileKeyBytes) -> Self {
        Self { bytes }
    }

    pub fn get_bytes(&self) -> ProfileKeyBytes {
        self.bytes
    }

    pub fn get_commitment(&self, uid_bytes: UidBytes) -> api::profiles::ProfileKeyCommitment {
        let profile_key = crypto::profile_key_struct::ProfileKeyStruct::new(self.bytes, uid_bytes);
        let commitment = crypto::profile_key_commitment::Commitment::new(profile_key);
        api::profiles::ProfileKeyCommitment { commitment }
    }

    pub fn get_profile_key_version(&self, uid_bytes: UidBytes) -> api::profiles::ProfileKeyVersion {
        self.get_commitment(uid_bytes).get_profile_key_version()
    }
}
