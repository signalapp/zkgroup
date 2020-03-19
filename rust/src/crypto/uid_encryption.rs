//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto::uid_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use ZkGroupError::*;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParameters {
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

impl SystemParameters {
    pub fn generate() -> Self {
        let G_a = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_G_a");
        let G_a0 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_G_a0");
        let G_a1 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_G_a1");
        SystemParameters { G_a, G_a0, G_a1 }
    }

    pub fn get_hardcoded() -> SystemParameters {
        bincode::deserialize::<SystemParameters>(&SystemParameters::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0xfa, 0x86, 0x61, 0x21, 0xac, 0x3a, 0x5f, 0x96, 0xb5, 0xa8, 0x98, 0xd5, 0x4, 0x52, 0x8,
        0xf, 0x9a, 0xf9, 0xab, 0x4a, 0x0, 0x2d, 0x53, 0x20, 0xc5, 0x35, 0xd1, 0xd7, 0xb8, 0x38,
        0xde, 0x8, 0xb8, 0x42, 0x87, 0x13, 0xf1, 0xef, 0x1b, 0x68, 0xe1, 0x0, 0x5a, 0x7f, 0x59,
        0xfb, 0x6, 0x81, 0x4, 0xe9, 0x48, 0x66, 0x4d, 0x42, 0xdb, 0x41, 0xe8, 0x1b, 0xaf, 0x97,
        0xa2, 0x38, 0x9e, 0x1d, 0x5e, 0x1c, 0x53, 0xb0, 0xc5, 0x40, 0x50, 0xec, 0xee, 0x30, 0xcf,
        0xa, 0x98, 0x8e, 0x4, 0xdd, 0xb3, 0xb0, 0xde, 0xf4, 0xe7, 0x7c, 0xa, 0xc3, 0x95, 0xe, 0x9f,
        0x46, 0xba, 0xfb, 0xd0, 0x4b,
    ];
}

impl KeyPair {
    pub fn derive_from(master_key: GroupMasterKeyBytes) -> Self {
        let system = SystemParameters::get_hardcoded();

        let a = calculate_scalar(b"Signal_ZKGroup_Enc_KeyDerive_a", &master_key);
        let a0 = calculate_scalar(b"Signal_ZKGroup_Enc_KeyDerive_a0", &master_key);
        let a1 = calculate_scalar(b"Signal_ZKGroup_Enc_KeyDerive_a1", &master_key);

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
                    0x7a, 0x6c, 0x71, 0x6, 0xd5, 0xba, 0x1d, 0x83, 0x2e, 0xb1, 0xe1, 0x1d, 0xdb,
                    0x15, 0xb4, 0x4b, 0x5e, 0x3f, 0xe8, 0xd3, 0x71, 0x61, 0x31, 0xd6, 0x50, 0x3a,
                    0xb2, 0x9f, 0xef, 0xc5, 0x86, 0x56, 0xe2, 0xad, 0xd9, 0x71, 0x8, 0x4a, 0x3e,
                    0x5c, 0x6e, 0xe5, 0x30, 0x49, 0x4c, 0x53, 0xde, 0xa3, 0x55, 0xbd, 0xa2, 0x5a,
                    0x1b, 0x1, 0x85, 0x36, 0x96, 0x8f, 0x7, 0x61, 0x28, 0xdc, 0xcb, 0x44,
                ]
        );

        let plaintext = key_pair.decrypt(ciphertext2).unwrap();

        assert!(plaintext == uid);
    }
}
