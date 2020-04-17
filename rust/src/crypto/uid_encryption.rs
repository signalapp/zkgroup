//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::sho::*;
use crate::crypto::uid_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use ZkGroupError::*;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParams {
    pub(crate) G_a: RistrettoPoint,
    pub(crate) G_a0: RistrettoPoint,
    pub(crate) G_a1: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPair {
    pub(crate) a: Scalar,
    pub(crate) a0: Scalar,
    pub(crate) a1: Scalar,
    pub(crate) A: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) A: RistrettoPoint,
}

#[derive(Copy, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) E_A1: RistrettoPoint,
    pub(crate) E_A2: RistrettoPoint,
}

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200416_Constant_UidEncryption_SystemParams_Generate",
            b"",
        );
        let G_a = sho.get_point();
        let G_a0 = sho.get_point();
        let G_a1 = sho.get_point();
        SystemParams { G_a, G_a0, G_a1 }
    }

    pub fn get_hardcoded() -> SystemParams {
        bincode::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0x34, 0xa7, 0xd0, 0xdb, 0x2b, 0x73, 0x1a, 0xce, 0xd8, 0x16, 0xfa, 0x87, 0xda, 0xe7, 0x33,
        0x4a, 0x18, 0x2b, 0xd2, 0x3f, 0xde, 0xdf, 0x4c, 0xfa, 0xb3, 0x22, 0x79, 0xd8, 0xc8, 0xfb,
        0xfc, 0x60, 0x5e, 0x46, 0x2, 0x4f, 0xd7, 0x4a, 0x56, 0x6e, 0xba, 0xd2, 0x71, 0x23, 0xb5,
        0xf2, 0xec, 0x62, 0x68, 0x3, 0x90, 0x38, 0xbc, 0xee, 0xd0, 0x9d, 0xf4, 0xf0, 0x3e, 0x60,
        0x6e, 0x2a, 0xbc, 0x43, 0xea, 0x14, 0x7c, 0xf7, 0xab, 0x2a, 0x77, 0xd2, 0xc8, 0x70, 0x3d,
        0x4a, 0xf9, 0xf7, 0x2f, 0xee, 0x76, 0x20, 0x6b, 0xb, 0x1d, 0x2e, 0x97, 0x3b, 0x94, 0xf8,
        0x89, 0x85, 0x3d, 0x7, 0x89, 0x7a,
    ];
}

impl KeyPair {
    pub fn derive_from(sho: &mut Sho) -> Self {
        let system = SystemParams::get_hardcoded();

        let a = sho.get_scalar();
        let a0 = sho.get_scalar();
        let a1 = sho.get_scalar();

        let A = a * system.G_a + a0 * system.G_a0 + a1 * system.G_a1;
        KeyPair { a, a0, a1, A }
    }

    pub fn encrypt(&self, uid: uid_struct::UidStruct) -> Ciphertext {
        let E_A1 = self.calc_E_A1(uid);
        let E_A2 = (self.a * E_A1) + uid.M1;
        Ciphertext { E_A1, E_A2 }
    }

    // Might return DecryptionFailure
    pub fn decrypt(&self, ciphertext: Ciphertext) -> Result<uid_struct::UidStruct, ZkGroupError> {
        match uid_struct::UidStruct::from_M1(ciphertext.E_A2 - (self.a * ciphertext.E_A1)) {
            Err(_) => Err(DecryptionFailure),
            Ok(decrypted_uid) => {
                if ciphertext.E_A1 == self.calc_E_A1(decrypted_uid) {
                    Ok(decrypted_uid)
                } else {
                    Err(DecryptionFailure)
                }
            }
        }
    }

    fn calc_E_A1(&self, uid: uid_struct::UidStruct) -> RistrettoPoint {
        (self.a0 + self.a1 * uid.m3) * uid.M2
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey { A: self.A }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;

    #[test]
    fn test_uid_encryption() {
        let master_key = TEST_ARRAY_32;
        let mut sho = Sho::new(b"Test_Uid_Encryption", &master_key);

        //let system = SystemParams::generate();
        //println!("PARAMS = {:#x?}", bincode::serialize(&system));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());

        let key_pair = KeyPair::derive_from(&mut sho);

        // Test serialize of key_pair
        let key_pair_bytes = bincode::serialize(&key_pair).unwrap();
        assert!(key_pair_bytes.len() == 128);
        match bincode::deserialize::<KeyPair>(&key_pair_bytes[0..key_pair_bytes.len() - 1]) {
            Err(_) => (),
            _ => assert!(false),
        };
        let key_pair2: KeyPair = bincode::deserialize(&key_pair_bytes).unwrap();
        assert!(key_pair == key_pair2);

        let uid = uid_struct::UidStruct::new(TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(uid);

        // Test serialize / deserialize of Ciphertext
        let ciphertext_bytes = bincode::serialize(&ciphertext).unwrap();
        assert!(ciphertext_bytes.len() == 64);
        let ciphertext2: Ciphertext = bincode::deserialize(&ciphertext_bytes).unwrap();
        assert!(ciphertext == ciphertext2);
        //println!("ciphertext_bytes = {:#x?}", ciphertext_bytes);
        assert!(
            ciphertext_bytes
                == vec![
                    0x46, 0x77, 0x4b, 0x79, 0x7a, 0x69, 0xea, 0x62, 0x7e, 0x63, 0xa8, 0xf0, 0xbe,
                    0x9e, 0xb5, 0xbf, 0x9e, 0xf8, 0xc5, 0xea, 0xb9, 0x8d, 0x82, 0x95, 0x39, 0x98,
                    0xdc, 0x75, 0x40, 0xa6, 0xf1, 0x6d, 0xb6, 0x53, 0x5e, 0x79, 0xb3, 0xa8, 0x10,
                    0xa7, 0x6a, 0xa2, 0x10, 0x3d, 0x3, 0x7c, 0xd9, 0xd7, 0x8f, 0xc, 0x63, 0x9c,
                    0xa8, 0xb6, 0xa1, 0x36, 0x4e, 0x2, 0x1e, 0x29, 0xf3, 0x45, 0x8a, 0xa,
                ]
        );

        let plaintext = key_pair.decrypt(ciphertext2).unwrap();

        assert!(plaintext == uid);
    }
}
