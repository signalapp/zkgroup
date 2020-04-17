//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::profile_key_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use curve25519_dalek::subtle::Choice;
use curve25519_dalek::subtle::ConditionallySelectable;
use curve25519_dalek::subtle::ConstantTimeEq;

use ZkGroupError::*;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParams {
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

#[derive(Copy, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) E_B1: RistrettoPoint,
    pub(crate) E_B2: RistrettoPoint,
}

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200416_Constant_ProfileKeyEncryption_SystemParams_Generate",
            b"",
        );
        let G_b = sho.get_point();
        let G_b0 = sho.get_point();
        let G_b1 = sho.get_point();
        SystemParams { G_b, G_b0, G_b1 }
    }

    pub fn get_hardcoded() -> SystemParams {
        bincode::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 96] = [
        0xd6, 0xcf, 0x95, 0x95, 0xd2, 0xe3, 0x20, 0x31, 0xa9, 0x78, 0x6a, 0x78, 0xc2, 0xa2, 0x8c,
        0xc6, 0x95, 0x60, 0xca, 0xa1, 0x30, 0xee, 0x5e, 0xfc, 0x1e, 0x94, 0xae, 0x2c, 0x73, 0x77,
        0x9b, 0x58, 0xc0, 0x19, 0x1c, 0x72, 0xf3, 0x34, 0xd4, 0xef, 0x31, 0x55, 0xba, 0x1f, 0x8d,
        0x39, 0x9f, 0x64, 0xcb, 0x83, 0x4c, 0xf5, 0x89, 0xf0, 0xd0, 0x8f, 0x4e, 0xe6, 0x81, 0x96,
        0x36, 0xa2, 0xd, 0x68, 0x2a, 0x18, 0x77, 0xa5, 0x4d, 0x24, 0x3f, 0x7e, 0x89, 0xd9, 0x8c,
        0xa4, 0xae, 0xde, 0xfa, 0x22, 0xe9, 0x1b, 0x49, 0x34, 0x1f, 0x60, 0x8d, 0x6, 0x78, 0xa3,
        0x44, 0x34, 0x5f, 0xd6, 0x26, 0x76,
    ];
}

impl KeyPair {
    pub fn derive_from(sho: &mut Sho) -> Self {
        let system = SystemParams::get_hardcoded();

        let b = sho.get_scalar();
        let b0 = sho.get_scalar();
        let b1 = sho.get_scalar();

        let B = b * system.G_b + b0 * system.G_b0 + b1 * system.G_b1;
        KeyPair { b, b0, b1, B }
    }

    pub fn encrypt(&self, profile_key: profile_key_struct::ProfileKeyStruct) -> Ciphertext {
        let E_B1 = self.calc_E_B1(profile_key);
        let E_B2 = (self.b * E_B1) + profile_key.M4;
        Ciphertext { E_B1, E_B2 }
    }

    // Might return DecryptionFailure
    #[allow(clippy::needless_range_loop)]
    pub fn decrypt(
        &self,
        ciphertext: Ciphertext,
        uid_bytes: UidBytes,
    ) -> Result<profile_key_struct::ProfileKeyStruct, ZkGroupError> {
        let M4 = ciphertext.E_B2 - (self.b * ciphertext.E_B1);
        let (mask, candidates) = M4.decode_253_bits();

        let m6 = profile_key_struct::ProfileKeyStruct::calc_m6(M4);
        let target_M5 = (self.b0 + self.b1 * m6).invert() * ciphertext.E_B1;

        let mut retval: profile_key_struct::ProfileKeyStruct = Default::default();
        let mut n_found = 0;
        for i in 0..8 {
            let is_valid_fe = Choice::from((mask >> i) & 1);
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
                let M5 = profile_key_struct::ProfileKeyStruct::calc_M5(pk, uid_bytes);
                let candidate_retval = profile_key_struct::ProfileKeyStruct {
                    bytes: pk,
                    M4,
                    M5,
                    m6,
                };
                let found = M5.ct_eq(&target_M5) & is_valid_fe;
                retval.conditional_assign(&candidate_retval, found);
                n_found += found.unwrap_u8();
            }
        }
        if n_found == 1 {
            Ok(retval)
        } else {
            Err(DecryptionFailure)
        }
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
        let mut sho = Sho::new(b"Test_Profile_Key_Encryption", &master_key);

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

        let profile_key_bytes = TEST_ARRAY_32_1;
        let uid_bytes = TEST_ARRAY_16_1;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(profile_key_bytes, uid_bytes);
        let ciphertext = key_pair.encrypt(profile_key);

        // Test serialize / deserialize of Ciphertext
        let ciphertext_bytes = bincode::serialize(&ciphertext).unwrap();
        assert!(ciphertext_bytes.len() == 64);
        let ciphertext2: Ciphertext = bincode::deserialize(&ciphertext_bytes).unwrap();
        assert!(ciphertext == ciphertext2);
        //println!("ciphertext_bytes = {:#x?}", ciphertext_bytes);
        assert!(
            ciphertext_bytes
                == vec![
                    0x6e, 0x62, 0x9e, 0xa, 0x43, 0x8e, 0x13, 0xfc, 0x2e, 0x43, 0xf9, 0x35, 0xd8,
                    0x58, 0xcf, 0xd8, 0xac, 0x11, 0x5, 0xe0, 0x4f, 0xb5, 0x95, 0xff, 0x62, 0xd2,
                    0x59, 0xe3, 0x7a, 0xb2, 0x76, 0x49, 0x58, 0xa5, 0x49, 0xd8, 0x6c, 0xbd, 0x2c,
                    0xc4, 0x9e, 0xcb, 0x2c, 0xa4, 0x8e, 0xc4, 0xa3, 0x4b, 0x6, 0xd3, 0x94, 0xd2,
                    0xaf, 0x49, 0x27, 0x93, 0x67, 0x18, 0x63, 0x9, 0xa8, 0x53, 0x7a, 0x6c,
                ]
        );

        let plaintext = key_pair.decrypt(ciphertext2, uid_bytes).unwrap();
        assert!(plaintext == profile_key);

        let mut sho = Sho::new(b"Test_Repeated_ProfileKeyEnc/Dec", b"seed");
        for _ in 0..100 {
            let mut uid_bytes: UidBytes = Default::default();
            let mut profile_key_bytes: ProfileKeyBytes = Default::default();

            uid_bytes.copy_from_slice(&sho.squeeze(UUID_LEN)[..]);
            profile_key_bytes.copy_from_slice(&sho.squeeze(PROFILE_KEY_LEN)[..]);

            let profile_key =
                profile_key_struct::ProfileKeyStruct::new(profile_key_bytes, uid_bytes);
            let ciphertext = key_pair.encrypt(profile_key);
            assert!(key_pair.decrypt(ciphertext, uid_bytes).unwrap() == profile_key);
        }

        let uid_bytes = TEST_ARRAY_16;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(profile_key);
        assert!(key_pair.decrypt(ciphertext, uid_bytes).unwrap() == profile_key);

        let uid_bytes = TEST_ARRAY_16;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32_2, TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(profile_key);
        assert!(key_pair.decrypt(ciphertext, uid_bytes).unwrap() == profile_key);

        let uid_bytes = TEST_ARRAY_16;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32_3, TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(profile_key);
        assert!(key_pair.decrypt(ciphertext, uid_bytes).unwrap() == profile_key);

        let uid_bytes = TEST_ARRAY_16;
        let profile_key = profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32_4, TEST_ARRAY_16);
        let ciphertext = key_pair.encrypt(profile_key);
        assert!(key_pair.decrypt(ciphertext, uid_bytes).unwrap() == profile_key);
    }
}
