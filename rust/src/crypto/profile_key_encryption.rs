//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto::profile_key_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use ZkGroupError::*;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParameters {
    pub(crate) G_b: RistrettoPoint,
    pub(crate) G_b0: RistrettoPoint,
    pub(crate) G_b1: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPair {
    pub(crate) b: Scalar,
    pub(crate) b0: Scalar,
    pub(crate) b1: Scalar,
    pub(crate) B: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) B: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) E_B1: RistrettoPoint,
    pub(crate) E_B2: RistrettoPoint,
}

impl SystemParameters {
    pub fn generate() -> Self {
        let G_b = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_G_b");
        let G_b0 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_G_b0");
        let G_b1 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_G_b1");
        SystemParameters { G_b, G_b0, G_b1 }
    }

    pub fn get_hardcoded() -> SystemParameters {
        bincode::deserialize::<SystemParameters>(&SystemParameters::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0x6a, 0x28, 0x66, 0xf8, 0xd, 0xbf, 0xc9, 0xba, 0xec, 0xf4, 0xec, 0x86, 0x5c, 0xf1, 0x3a,
        0xda, 0xd1, 0x7d, 0x93, 0x32, 0x30, 0x5d, 0xfa, 0xfd, 0xd8, 0x1a, 0x47, 0x82, 0x50, 0x87,
        0x9b, 0x7d, 0x9a, 0x56, 0xd7, 0xcb, 0x9c, 0xed, 0x5d, 0xd2, 0x44, 0xa5, 0x6e, 0x89, 0x6c,
        0x14, 0x2c, 0xa6, 0x9c, 0xa6, 0xde, 0x99, 0x4c, 0x55, 0xaf, 0x35, 0x8e, 0xc6, 0x93, 0xa0,
        0x7b, 0x9, 0x37, 0x6d, 0x84, 0xd3, 0x1e, 0xb, 0x2f, 0x13, 0x1f, 0x7b, 0xc4, 0xf4, 0x31,
        0xe3, 0xb, 0x0, 0xa9, 0x9d, 0x37, 0x3d, 0x95, 0x88, 0x9f, 0xa2, 0x39, 0xee, 0x16, 0xa9,
        0x3f, 0x5e, 0x97, 0x75, 0x98, 0x4c,
    ];
}

impl KeyPair {
    pub fn derive_from(master_key: GroupMasterKeyBytes) -> Self {
        let system = SystemParameters::get_hardcoded();

        let b = calculate_scalar(b"Signal_ZKGroup_Enc_KeyDerive_b", &master_key);
        let b0 = calculate_scalar(b"Signal_ZKGroup_Enc_KeyDerive_b0", &master_key);
        let b1 = calculate_scalar(b"Signal_ZKGroup_Enc_KeyDerive_b1", &master_key);

        let B = b * system.G_b + b0 * system.G_b0 + b1 * system.G_b1;
        KeyPair { b, b0, b1, B }
    }

    pub fn encrypt(&self, profile_key: profile_key_struct::ProfileKeyStruct) -> Ciphertext {
        let E_B1 = self.calc_E_B1(profile_key);
        let E_B2 = (self.b * E_B1) + profile_key.M4;
        (Ciphertext { E_B1, E_B2 })
    }

    // Might return DecryptionFailure
    pub fn decrypt(
        &self,
        ciphertext: Ciphertext,
        uid_bytes: UidBytes,
    ) -> Result<profile_key_struct::ProfileKeyStruct, ZkGroupError> {
        let M4 = ciphertext.E_B2 - (self.b * ciphertext.E_B1);
        let (_mask, candidates) = profile_key_struct::ProfileKeyStruct::from_M4(M4, uid_bytes);
        for j in 0..64 {
            let candidate = candidates[j];
            if ciphertext.E_B1 == self.calc_E_B1(candidate) {
                return Ok(candidate);
            }
        }
        Err(DecryptionFailure)
    }

    fn calc_E_B1(&self, profile_key: profile_key_struct::ProfileKeyStruct) -> RistrettoPoint {
        (self.b0 + self.b1 * profile_key.m6) * profile_key.M5
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey { B: self.B }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;

    #[test]
    fn test_profile_key_encryption() {
        let master_key = TEST_ARRAY_32_1;
        //let system = SystemParameters::generate();
        //println!("PARAMS = {:#x?}", bincode::serialize(&system));
        assert!(SystemParameters::generate() == SystemParameters::get_hardcoded());

        let key_pair = KeyPair::derive_from(master_key);

        // Test serialize of key_pair
        let key_pair_bytes = bincode::serialize(&key_pair).unwrap();
        assert!(key_pair_bytes.len() == 128);
        match bincode::deserialize::<KeyPair>(&key_pair_bytes[0..key_pair_bytes.len() - 1]) {
            Err(_) => (),
            _ => assert!(false),
        };
        let key_pair2: KeyPair = bincode::deserialize(&key_pair_bytes).unwrap();
        assert!(key_pair == key_pair2);

        let mut profile_key_bytes = TEST_ARRAY_32_1;
        let uid_bytes = TEST_ARRAY_16_1;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(profile_key_bytes, uid_bytes);
        let ciphertext = key_pair.encrypt(profile_key);

        // Test serialize / deserialize of Ciphertext
        let ciphertext_bytes = bincode::serialize(&ciphertext).unwrap();
        assert!(ciphertext_bytes.len() == 64);
        let ciphertext2: Ciphertext = bincode::deserialize(&ciphertext_bytes).unwrap();
        assert!(ciphertext == ciphertext2);
        //println!("ciphertext_bytes = {:#x?}", ciphertext_bytes);
        /* TODOFIX
        assert!(
            ciphertext_bytes
                == vec![
                    0x38, 0xa9, 0xe2, 0xf1, 0x85, 0x8d, 0xc4, 0x4f, 0x82, 0x8d, 0xf5, 0xd4, 0x47,
                    0xe4, 0x5, 0x83, 0xf1, 0x8d, 0x7f, 0xe3, 0xa6, 0x3e, 0x31, 0x42, 0x78, 0x54,
                    0xf1, 0x11, 0xb2, 0x1c, 0xe9, 0x47, 0xf2, 0x6, 0x35, 0x54, 0xde, 0xf9, 0x2d,
                    0x18, 0xe7, 0x27, 0xeb, 0x3e, 0x26, 0x23, 0xf7, 0xba, 0xad, 0x95, 0x2c, 0x8d,
                    0x41, 0xe9, 0xd3, 0xd5, 0xbc, 0x70, 0xc3, 0xe5, 0xb2, 0xe8, 0x14, 0x2,
                ]
        );
        */

        let plaintext = key_pair.decrypt(ciphertext2, uid_bytes).unwrap();
        assert!(plaintext == profile_key);
    }
}
