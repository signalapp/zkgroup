//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::constants::SIGNATURE_LEN;
use crate::common::errors::*;
use crate::common::simple_types::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use ZkGroupError::*;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPair {
    pub(crate) signing_key: Scalar,
    pub(crate) public_key: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) public_key: RistrettoPoint,
}

impl KeyPair {
    pub fn derive_from(group_key: &[u8], label: &[u8]) -> Self {
        let signing_key = calculate_scalar(label, group_key);
        let public_key = signing_key * RISTRETTO_BASEPOINT_POINT;
        KeyPair {
            signing_key,
            public_key,
        }
    }

    // Could return SignatureVerificationFailure is public/private key are inconsistent
    pub fn sign(
        &self,
        message: &[u8],
        randomness: RandomnessBytes,
    ) -> Result<SignatureBytes, ZkGroupError> {
        match poksho::sign(self.signing_key, self.public_key, message, &randomness) {
            Ok(vec_bytes) => {
                let mut s: SignatureBytes = [0u8; SIGNATURE_LEN];
                s.copy_from_slice(&vec_bytes[..]);
                Ok(s)
            }
            Err(_) => Err(SignatureVerificationFailure),
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey {
            public_key: self.public_key,
        }
    }
}

impl PublicKey {
    // Might return SignatureVerificationFailure
    pub fn verify(&self, message: &[u8], signature: SignatureBytes) -> Result<(), ZkGroupError> {
        match poksho::verify_signature(&signature, self.public_key, message) {
            Err(_) => Err(SignatureVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;

    #[test]
    fn test_signature() {
        let group_key = TEST_ARRAY_32;
        let key_pair = KeyPair::derive_from(&group_key, b"Signal_ZKGroup_Sig_Client_KeyDerive");

        // Test serialize of key_pair
        let key_pair_bytes = bincode::serialize(&key_pair).unwrap();
        assert!(key_pair_bytes.len() == 64);
        let public_key_bytes = bincode::serialize(&key_pair.get_public_key()).unwrap();
        assert!(public_key_bytes.len() == 32);
        let key_pair2: KeyPair = bincode::deserialize(&key_pair_bytes).unwrap();
        assert!(key_pair == key_pair2);

        let mut message = TEST_ARRAY_32_1;
        let randomness = TEST_ARRAY_32_2;

        let signature = key_pair.sign(&message, randomness).unwrap();
        key_pair2
            .get_public_key()
            .verify(&message, signature)
            .unwrap();

        // test signature falure
        message[0] ^= 1;
        match key_pair2.get_public_key().verify(&message, signature) {
            Err(SignatureVerificationFailure) => (),
            _ => assert!(false),
        }

        let signature_result = [
            0xea, 0x39, 0xf1, 0x68, 0x74, 0x26, 0xea, 0xdd, 0x14, 0x4d, 0x8f, 0xcf, 0xe, 0x33,
            0xc4, 0x3b, 0x1e, 0x27, 0x8d, 0xbb, 0xe0, 0xa6, 0x7c, 0x3e, 0x60, 0xd4, 0xce, 0x53,
            0x1b, 0xcb, 0x54, 0x2, 0xf1, 0x6b, 0x2e, 0x58, 0x7c, 0xa1, 0x91, 0x89, 0xc8, 0x46,
            0x6f, 0xa1, 0xdc, 0xdb, 0x77, 0xae, 0x12, 0xd1, 0xb8, 0x82, 0x87, 0x81, 0x51, 0x2c,
            0xd2, 0x92, 0xd0, 0x91, 0x5a, 0x72, 0xb6, 0x9,
        ];

        assert!(&signature[..] == &signature_result[..]);
    }
}
