//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::simple_types::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::Sha512;

use ZkGroupError::*;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct UidStruct {
    pub(crate) uid_bytes: UidBytes,
    pub(crate) M1: RistrettoPoint,
    pub(crate) M2: RistrettoPoint,
    pub(crate) m3: Scalar,
}

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

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) E_A1: RistrettoPoint,
    pub(crate) E_A2: RistrettoPoint,
}

impl UidStruct {
    pub fn new(uid_bytes: UidBytes) -> Self {
        let M1 = RistrettoPoint::lizard_encode::<Sha256>(&uid_bytes).unwrap(); // Swallow Lizard Encode errors; shouldn't happen
        let M2 = RistrettoPoint::hash_from_bytes::<Sha512>(&uid_bytes);
        let m3 = calculate_scalar(b"Signal_ZKGroup_Enc_Uid_m3", &uid_bytes);
        UidStruct {
            uid_bytes,
            M1,
            M2,
            m3,
        }
    }

    // Might return PointDecodeFailure
    pub fn from_M1(M1: RistrettoPoint) -> Result<Self, ZkGroupError> {
        match M1.lizard_decode::<Sha256>() {
            None => Err(PointDecodeFailure),
            Some(bytes) => Ok(Self::new(bytes)),
        }
    }

    pub fn to_bytes(&self) -> UidBytes {
        self.uid_bytes
    }
}

impl SystemParameters {
    pub fn generate() -> Self {
        let G_a = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_A");
        let G_a0 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_A0");
        let G_a1 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Enc_Const_A1");
        SystemParameters { G_a, G_a0, G_a1 }
    }

    pub fn get_hardcoded() -> SystemParameters {
        bincode::deserialize::<SystemParameters>(&SystemParameters::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0x88, 0x6e, 0xba, 0x59, 0xda, 0xb1, 0xe, 0x32, 0x18, 0xe9, 0x18, 0xc0, 0x7d, 0xe6, 0x8b,
        0x21, 0x5f, 0x14, 0x4c, 0xd6, 0x8d, 0x37, 0x14, 0xe1, 0x3, 0x20, 0x29, 0xe1, 0x7f, 0x7b,
        0xca, 0x26, 0x98, 0xee, 0x7a, 0x6b, 0xf7, 0xed, 0x2a, 0x45, 0xc0, 0x57, 0x62, 0x7, 0xf5,
        0xcf, 0xe4, 0x7a, 0x6c, 0xd4, 0x4d, 0x8e, 0x72, 0xe3, 0x2f, 0x63, 0x94, 0x19, 0x8b, 0x6e,
        0x95, 0xb8, 0x3a, 0x74, 0x22, 0x55, 0x64, 0xef, 0xa2, 0x75, 0xd8, 0xa1, 0x38, 0xfa, 0x21,
        0xb4, 0x65, 0xca, 0x9c, 0x18, 0xd6, 0xb4, 0xa, 0x78, 0xb5, 0x74, 0x46, 0x56, 0xfd, 0x36,
        0x9d, 0x1, 0xca, 0xc3, 0xcc, 0x60,
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

    pub fn encrypt(&self, uid_struct: UidStruct) -> Ciphertext {
        let E_A1 = self.calc_E_A1(uid_struct);
        let E_A2 = (self.a * E_A1) + uid_struct.M1;
        (Ciphertext { E_A1, E_A2 })
    }

    // Might return DecryptionFailure
    pub fn decrypt(&self, ciphertext: Ciphertext) -> Result<UidStruct, ZkGroupError> {
        match UidStruct::from_M1(ciphertext.E_A2 - (self.a * ciphertext.E_A1)) {
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

    fn calc_E_A1(&self, uid_struct: UidStruct) -> RistrettoPoint {
        (self.a0 + self.a1 * uid_struct.m3) * uid_struct.M2
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

        let uid_struct = UidStruct::new(TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(uid_struct);

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

        assert!(plaintext == uid_struct);
    }
}
