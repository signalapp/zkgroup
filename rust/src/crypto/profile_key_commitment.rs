//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::sho::*;
use crate::crypto::profile_key_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParams {
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

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200416_Constant_ProfileKeyCommitment_SystemParams_Generate",
            b"",
        );
        let G_j1 = sho.get_point();
        let G_j2 = sho.get_point();
        let G_j3 = sho.get_point();
        SystemParams { G_j1, G_j2, G_j3 }
    }

    pub fn get_hardcoded() -> SystemParams {
        bincode::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0x78, 0xbc, 0x9, 0x56, 0x53, 0xc3, 0x95, 0x6d, 0x33, 0xde, 0xdc, 0xf3, 0x7f, 0xe4, 0xc8,
        0x4e, 0x68, 0xc8, 0xa7, 0x80, 0x19, 0x0, 0xd8, 0xc0, 0x8e, 0x46, 0xdc, 0x2f, 0x95, 0xa4,
        0x49, 0x79, 0x96, 0x9c, 0xd0, 0x9c, 0xa, 0x8a, 0x57, 0x46, 0x49, 0xbc, 0x3f, 0xd, 0xe1,
        0x5c, 0x6, 0xbc, 0x1e, 0xd3, 0x48, 0x2f, 0x2a, 0xb4, 0x32, 0x30, 0x33, 0x2e, 0x29, 0xbb,
        0x40, 0x78, 0x76, 0x27, 0x62, 0x51, 0x67, 0x61, 0xe0, 0x12, 0x3a, 0xa0, 0xd8, 0xdf, 0x75,
        0xa6, 0xa3, 0x4, 0x31, 0x20, 0x56, 0x7d, 0x6a, 0x61, 0x16, 0xf7, 0x5b, 0x7e, 0x83, 0x22,
        0x1f, 0xfa, 0xea, 0x5c, 0xac, 0x5e,
    ];
}

impl Commitment {
    pub fn new(profile_key: profile_key_struct::ProfileKeyStruct) -> Commitment {
        let commitment_system = SystemParams::get_hardcoded();

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
        //let params = SystemParams::generate();
        //println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_commitment() {
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
        let c1 = Commitment::new(profile_key);
        let c2 = Commitment::new(profile_key);
        assert!(c1 == c2);
    }
}
