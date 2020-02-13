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
use curve25519_dalek::ristretto::RistrettoPoint;
use poksho::ShoSha256;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ProfileKey {
    pub(crate) bytes: ProfileKeyBytes,
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

    pub fn get_commitment(&self) -> api::profiles::ProfileKeyCommitment {
        let mut bytes: ProfileKeyHalfBytes = Default::default();
        bytes.copy_from_slice(&self.bytes[0..16]);
        let P = RistrettoPoint::lizard_encode::<Sha256>(&bytes).unwrap();
        let commitment =
            crypto::profile_key_commitment::CommitmentWithSecretNonce::new(P).get_commitment();
        return api::profiles::ProfileKeyCommitment { commitment };
    }

    pub fn get_profile_key_version(&self) -> api::profiles::ProfileKeyVersion {
        self.get_commitment().get_profile_key_version()
    }
}
