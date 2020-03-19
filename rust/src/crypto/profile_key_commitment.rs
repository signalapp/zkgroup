//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::crypto::profile_key_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParameters {
    pub(crate) G_j1: RistrettoPoint,
    pub(crate) G_j2: RistrettoPoint,
    pub(crate) G_j3: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct Commitment {
    pub(crate) J1: RistrettoPoint,
    pub(crate) J2: RistrettoPoint,
    pub(crate) J3: RistrettoPoint,
}

impl SystemParameters {
    pub fn generate() -> Self {
        let G_j1 =
            RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_ProfileKey_Const_G_j1");
        let G_j2 =
            RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_ProfileKey_Const_G_j2");
        let G_j3 =
            RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_ProfileKey_Const_G_j3");
        SystemParameters { G_j1, G_j2, G_j3 }
    }

    pub fn get_hardcoded() -> SystemParameters {
        bincode::deserialize::<SystemParameters>(&SystemParameters::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0xc4, 0xc7, 0x7b, 0x23, 0x2b, 0x31, 0x7c, 0x84, 0xb1, 0xf, 0x5c, 0x95, 0x68, 0x8a, 0x5,
        0xa9, 0xc3, 0x13, 0x55, 0x23, 0xd7, 0x62, 0xe9, 0x80, 0xe7, 0xd6, 0x22, 0x9a, 0x1a, 0x39,
        0x88, 0x16, 0x3e, 0xcf, 0xf4, 0x9f, 0x49, 0x30, 0x1b, 0xef, 0xbb, 0x27, 0xd3, 0x65, 0xab,
        0x27, 0x33, 0x4, 0xfc, 0x5b, 0xbb, 0x5e, 0x54, 0xb7, 0xe, 0x6a, 0xc, 0xc3, 0x94, 0x3f, 0x2,
        0x7b, 0xa8, 0x4c, 0xb8, 0x3f, 0x7e, 0xe6, 0xd3, 0x1e, 0x7b, 0x6d, 0x9e, 0x0, 0xec, 0x87,
        0xd4, 0x80, 0x23, 0xb1, 0x7b, 0x26, 0xf7, 0xb8, 0x62, 0xe2, 0x84, 0x17, 0x96, 0xb4, 0x4f,
        0xce, 0xe2, 0x23, 0x82, 0x5f,
    ];
}

impl Commitment {
    pub fn new(profile_key: profile_key_struct::ProfileKeyStruct) -> Commitment {
        let commitment_system = SystemParameters::get_hardcoded();

        let profile_key_struct::ProfileKeyStruct { M4, M5, m6, .. } = profile_key;
        let J1 = (m6 * commitment_system.G_j1) + M4;
        let J2 = (m6 * commitment_system.G_j2) + M5;
        let J3 = m6 * commitment_system.G_j3;
        Commitment { J1, J2, J3 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;

    #[test]
    fn test_system() {
        // let params = SystemParameters::generate();
        // println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParameters::generate() == SystemParameters::get_hardcoded());
    }

    #[test]
    fn test_commitment() {
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
        let c1 = Commitment::new(profile_key);
        let c2 = Commitment::new(profile_key);
        assert!(c1 == c2);
    }
}
