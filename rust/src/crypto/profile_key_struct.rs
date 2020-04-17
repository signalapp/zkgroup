//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::constants::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::credentials;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use curve25519_dalek::subtle::Choice;
use curve25519_dalek::subtle::ConditionallySelectable;

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
        let M5 = Self::calc_M5(profile_key_bytes, uid_bytes);
        let m6 = Self::calc_m6(M4);
        ProfileKeyStruct {
            bytes: profile_key_bytes,
            M4,
            M5,
            m6,
        }
    }

    pub fn calc_M5(profile_key_bytes: ProfileKeyBytes, uid_bytes: UidBytes) -> RistrettoPoint {
        let mut combined_array = [0u8; PROFILE_KEY_LEN + UUID_LEN];
        combined_array[..PROFILE_KEY_LEN].copy_from_slice(&profile_key_bytes);
        combined_array[PROFILE_KEY_LEN..].copy_from_slice(&uid_bytes);
        Sho::new(
            b"Signal_ZKGroup_20200416_ProfileKeyAndUid_ProfileKey_CalcM5",
            &combined_array,
        )
        .get_point_single_elligator()
    }

    pub fn calc_m6(M4: RistrettoPoint) -> Scalar {
        Sho::new(
            b"Signal_ZKGroup_20200416_M4_ProfileKey_Calcm6",
            M4.compress().as_bytes(),
        )
        .get_scalar()
    }

    pub fn M6(&self) -> RistrettoPoint {
        let system = credentials::SystemParams::get_hardcoded();
        self.m6 * system.G_m6
    }

    pub fn to_bytes(&self) -> ProfileKeyBytes {
        self.bytes
    }
}

impl ConditionallySelectable for ProfileKeyStruct {
    #[allow(clippy::needless_range_loop)]
    fn conditional_select(
        a: &ProfileKeyStruct,
        b: &ProfileKeyStruct,
        choice: Choice,
    ) -> ProfileKeyStruct {
        let mut bytes: ProfileKeyBytes = [0u8; PROFILE_KEY_LEN];
        for i in 0..PROFILE_KEY_LEN {
            bytes[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
        }

        ProfileKeyStruct {
            bytes,
            M4: RistrettoPoint::conditional_select(&a.M4, &b.M4, choice),
            M5: RistrettoPoint::conditional_select(&a.M5, &b.M5, choice),
            m6: Scalar::conditional_select(&a.m6, &b.m6, choice),
        }
    }
}
