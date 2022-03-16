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
use crate::crypto::profile_key_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParams {
    pub(crate) G_j1: RistrettoPoint,
    pub(crate) G_j2: RistrettoPoint,
    pub(crate) G_j3: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitmentWithSecretNonce {
    pub(crate) J1: RistrettoPoint,
    pub(crate) J2: RistrettoPoint,
    pub(crate) J3: RistrettoPoint,
    pub(crate) j3: Scalar,
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
            b"Signal_ZKGroup_20200424_Constant_ProfileKeyCommitment_SystemParams_Generate",
            b"",
        );
        let G_j1 = sho.get_point();
        let G_j2 = sho.get_point();
        let G_j3 = sho.get_point();
        SystemParams { G_j1, G_j2, G_j3 }
    }

    pub fn get_hardcoded() -> SystemParams {
        let G_j1 = RistrettoPoint::from_uniform_bytes(&[
            134, 214, 189, 20, 105, 109, 71, 88, 227, 219, 43, 97, 86, 177, 67, 210, 199, 254, 19,
            79, 84, 122, 219, 173, 106, 18, 48, 36, 44, 247, 138, 90, 88, 22, 145, 123, 71, 140,
            178, 62, 85, 104, 78, 169, 5, 242, 233, 19, 157, 176, 2, 3, 136, 197, 38, 112, 126,
            226, 38, 85, 236, 79, 146, 61,
        ]);
        let G_j2 = RistrettoPoint::from_uniform_bytes(&[
            127, 159, 160, 191, 181, 50, 6, 252, 13, 64, 148, 133, 101, 163, 224, 135, 13, 34, 29,
            224, 20, 101, 154, 7, 169, 169, 243, 147, 189, 47, 227, 185, 62, 225, 76, 118, 214, 80,
            126, 243, 80, 31, 66, 44, 225, 116, 22, 230, 84, 230, 74, 235, 37, 220, 162, 123, 177,
            126, 100, 193, 57, 22, 72, 158,
        ]);
        let G_j3 = RistrettoPoint::from_uniform_bytes(&[
            154, 183, 149, 157, 112, 18, 114, 86, 206, 19, 115, 66, 14, 58, 51, 228, 202, 173, 31,
            142, 232, 131, 35, 93, 62, 233, 83, 155, 50, 244, 244, 106, 65, 150, 169, 148, 129, 32,
            165, 53, 1, 139, 57, 45, 99, 193, 168, 111, 138, 245, 212, 154, 252, 26, 169, 101, 186,
            49, 54, 63, 116, 253, 112, 111,
        ]);
        SystemParams { G_j1, G_j2, G_j3 }
    }
}

impl CommitmentWithSecretNonce {
    pub fn new(
        profile_key: profile_key_struct::ProfileKeyStruct,
        uid_bytes: UidBytes,
    ) -> CommitmentWithSecretNonce {
        let commitment_system = SystemParams::get_hardcoded();

        let profile_key_struct::ProfileKeyStruct { M3, M4, .. } = profile_key;
        let j3 = Self::calc_j3(profile_key.bytes, uid_bytes);
        let J1 = (j3 * commitment_system.G_j1) + M3;
        let J2 = (j3 * commitment_system.G_j2) + M4;
        let J3 = j3 * commitment_system.G_j3;
        CommitmentWithSecretNonce { J1, J2, J3, j3 }
    }

    pub fn get_profile_key_commitment(&self) -> Commitment {
        Commitment {
            J1: self.J1,
            J2: self.J2,
            J3: self.J3,
        }
    }

    pub fn calc_j3(profile_key_bytes: ProfileKeyBytes, uid_bytes: UidBytes) -> Scalar {
        let mut combined_array = [0u8; PROFILE_KEY_LEN + UUID_LEN];
        combined_array[..PROFILE_KEY_LEN].copy_from_slice(&profile_key_bytes);
        combined_array[PROFILE_KEY_LEN..].copy_from_slice(&uid_bytes);
        Sho::new(
            b"Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKeyCommitment_Calcj3",
            &combined_array,
        )
        .get_scalar()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system() {
        let params = SystemParams::generate();
        println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_commitment() {
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
        let c1 = CommitmentWithSecretNonce::new(profile_key, TEST_ARRAY_16);
        let c2 = CommitmentWithSecretNonce::new(profile_key, TEST_ARRAY_16);
        assert!(c1 == c2);
    }
}
