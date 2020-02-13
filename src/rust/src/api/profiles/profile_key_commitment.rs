//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::crypto;
use crate::api;
use crate::common::constants::*;
use crate::common::simple_types::*;
use serde::{Deserialize, Serialize};
use poksho::ShoSha256;
use hex;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ProfileKeyCommitment {
    pub(crate) commitment: crypto::profile_key_commitment::Commitment,
}

impl ProfileKeyCommitment {

    pub fn get_profile_key_version(&self) -> api::profiles::ProfileKeyVersion {

        let commitment_bytes = bincode::serialize(&self.commitment).unwrap();

        let mut profile_key_version: ProfileKeyVersionBytes = [0u8; PROFILE_KEY_VERSION_LEN];
        profile_key_version.copy_from_slice(
            &ShoSha256::shohash(
                b"Signal_ZKGroup_ProfileKeyId",
                &commitment_bytes,
                PROFILE_KEY_VERSION_LEN as u64,
            ),
        );
        let pkv_hex_string = hex::encode(&profile_key_version[..]);
        let mut pkv_hex_array: [u8; PROFILE_KEY_VERSION_ENCODED_LEN] = [0u8; PROFILE_KEY_VERSION_ENCODED_LEN];
        pkv_hex_array.copy_from_slice(pkv_hex_string.as_bytes());
        api::profiles::ProfileKeyVersion{ bytes: pkv_hex_array }
    }
}
