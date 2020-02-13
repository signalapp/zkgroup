//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::simple_types::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParameters {
    pub(crate) G_j: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitmentWithSecretNonce {
    pub(crate) jprime: Scalar,
    pub(crate) E_J1: RistrettoPoint,
    pub(crate) E_J2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct Commitment {
    pub(crate) E_J1: RistrettoPoint,
    pub(crate) E_J2: RistrettoPoint,
}

impl SystemParameters {
    pub fn generate() -> Self {
        let G_j = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_ProfileKey_Const_G_j");
        SystemParameters { G_j }
    }

    pub fn get_hardcoded() -> SystemParameters {
        bincode::deserialize::<SystemParameters>(&SystemParameters::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 32] = [
        0x6e, 0x4e, 0x6e, 0x38, 0x97, 0x78, 0xc6, 0x84, 0x53, 0xa4, 0x2d, 0xa5, 0xb6, 0x5b, 0xae,
        0xc1, 0x1a, 0xae, 0xc1, 0xd5, 0x1e, 0x2e, 0x34, 0x5f, 0x17, 0x30, 0x83, 0xa2, 0xce, 0xd8,
        0x87, 0x6,
    ];
}

impl CommitmentWithSecretNonce {
    pub fn new(profile_key: RistrettoPoint) -> (CommitmentWithSecretNonce) {
        let system = SystemParameters::get_hardcoded();
        let jprime = calculate_scalar(
            b"Signal_ZKGroup_ProfileKey_Commit_jprime",
            profile_key.compress().as_bytes(),
        );
        let E_J1 = jprime * RISTRETTO_BASEPOINT_POINT;
        let E_J2 = (jprime * system.G_j) + profile_key;
        (CommitmentWithSecretNonce { jprime, E_J1, E_J2 })
    }

    pub fn get_commitment(&self) -> Commitment {
        Commitment {
            E_J1: self.E_J1,
            E_J2: self.E_J2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;

    #[test]
    fn test_system() {
        //let params = SystemParameters::generate();
        // println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParameters::generate() == SystemParameters::get_hardcoded());
    }

    #[test]
    fn test_commitment() {
        let profile_key = RistrettoPoint::hash_from_bytes::<Sha512>(&TEST_ARRAY_32);
        let c1 = CommitmentWithSecretNonce::new(profile_key);
        let c2 = CommitmentWithSecretNonce::new(profile_key);
        assert!(c1 == c2);
    }
}
