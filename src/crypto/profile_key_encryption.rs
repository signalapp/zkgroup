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

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPair {
    // private
    pub(crate) b: Scalar,

    // public
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

impl KeyPair {
    pub fn derive_from(master_key: GroupMasterKeyBytes) -> Self {
        let b = calculate_scalar(b"Signal_ZKGroup_PKEnc_KeyDerive_b", &master_key);
        let B = b * RISTRETTO_BASEPOINT_POINT;
        KeyPair { b, B }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey { B: self.B }
    }

    pub fn encrypt(&self, P: RistrettoPoint, randomness: RandomnessBytes) -> Ciphertext {
        let bprime = calculate_scalar(b"Signal_ZKGroup_ProfileKey_Encrypt_bprime", &randomness);
        let E_B1 = bprime * RISTRETTO_BASEPOINT_POINT;
        let E_B2 = bprime * self.B + P;
        Ciphertext { E_B1, E_B2 }
    }

    pub fn decrypt(&self, ciphertext: Ciphertext) -> RistrettoPoint {
        ciphertext.E_B2 - self.b * ciphertext.E_B1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;
    use sha2::Sha512;

    #[test]
    fn test_encryption() {
        let P = RistrettoPoint::hash_from_bytes::<Sha512>(&TEST_ARRAY_32);
        let master_key = TEST_ARRAY_32;
        let keypair = KeyPair::derive_from(master_key);
        let ciphertext = keypair.encrypt(P, TEST_ARRAY_32_2);
        let decrypted_P = keypair.decrypt(ciphertext);
        assert!(P == decrypted_P);
    }
}
