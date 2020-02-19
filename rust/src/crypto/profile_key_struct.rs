//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::constants::*;
use crate::common::simple_types::*;
use crate::crypto::credentials;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

#[derive(Copy, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProfileKeyStruct {
    pub(crate) bytes: ProfileKeyBytes,
    pub(crate) M4: RistrettoPoint,
    pub(crate) M5: RistrettoPoint,
    pub(crate) m6: Scalar,
}

impl ProfileKeyStruct {
    pub fn new(profile_key_bytes: ProfileKeyBytes, uid_bytes: UidBytes) -> Self {
        let mut encoded_profile_key = profile_key_bytes;
        encoded_profile_key[0] &= 254;
        encoded_profile_key[31] &= 63;
        let M4 = RistrettoPoint::encode_253_bits(&encoded_profile_key).unwrap();
        let (M5, m6) = Self::calc_M5_m6(profile_key_bytes, uid_bytes);
        ProfileKeyStruct {
            bytes: profile_key_bytes,
            M4,
            M5,
            m6,
        }
    }

    pub fn calc_M5_m6(
        profile_key_bytes: ProfileKeyBytes,
        uid_bytes: UidBytes,
    ) -> (RistrettoPoint, Scalar) {
        let mut combined_array = [0u8; PROFILE_KEY_LEN + UUID_LEN];
        combined_array[..PROFILE_KEY_LEN].copy_from_slice(&profile_key_bytes);
        combined_array[PROFILE_KEY_LEN..].copy_from_slice(&uid_bytes);
        let M5 = RistrettoPoint::hash_from_bytes::<Sha512>(&combined_array);
        let m6 = calculate_scalar(b"Signal_ZKGroup_Enc_ProfileKey_m6", &combined_array);
        (M5, m6)
    }

    // Might return PointDecodeFailure
    pub fn from_M4(M4: RistrettoPoint, uid_bytes: UidBytes) -> (u8, [Self; 64]) {
        let mut ret: [ProfileKeyStruct; 64] = [Default::default(); 64];

        let (mask, candidates) = M4.decode_253_bits();

        let mut _n_found = 0;
        for i in 0..8 {
            let profile_key_bytes: ProfileKeyBytes = candidates[i];
            for j in 0..8 {
                let mut pk = profile_key_bytes;
                if ((j >> 2) & 1) == 1 {
                    pk[0] |= 0x01;
                }
                if ((j >> 1) & 1) == 1 {
                    pk[31] |= 0x80;
                }
                if (j & 1) == 1 {
                    pk[31] |= 0x40;
                }
                let (M5, m6) = Self::calc_M5_m6(pk, uid_bytes);
                ret[(i * 8) + j] = ProfileKeyStruct {
                    bytes: pk,
                    M4,
                    M5,
                    m6,
                };
            }
        }
        (mask, ret)
    }

    pub fn M6(&self) -> RistrettoPoint {
        let system = credentials::SystemParameters::get_hardcoded();
        self.m6 * system.G_m6
    }

    pub fn to_bytes(&self) -> ProfileKeyBytes {
        self.bytes
    }
}
