//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::simple_types::*;
use crate::crypto::credentials::{BlindedProfileCredential, ProfileCredential};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPair {
    // private
    pub(crate) d: Scalar,

    // public
    pub(crate) D: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) D: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct CiphertextWithSecretNonce {
    pub(crate) dprime: Scalar,
    pub(crate) E_D1: RistrettoPoint,
    pub(crate) E_D2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) E_D1: RistrettoPoint,
    pub(crate) E_D2: RistrettoPoint,
}

impl KeyPair {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let d = calculate_scalar(
            b"Signal_ZKGroup_ProfileKey_BlindIssue_KeyGen_q",
            &randomness,
        );
        let D = d * RISTRETTO_BASEPOINT_POINT;
        KeyPair { d, D }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey { D: self.D }
    }

    pub fn create_ciphertext(
        &self,
        profile_key: RistrettoPoint,
        randomness: RandomnessBytes,
    ) -> CiphertextWithSecretNonce {
        let dprime = calculate_scalar(
            b"Signal_ZKGroup_ProfileKey_BlindIssue_KeyGen_dprime",
            &randomness,
        );
        let D = self.D;
        let E_D1 = dprime * RISTRETTO_BASEPOINT_POINT;
        let E_D2 = dprime * D + profile_key;
        CiphertextWithSecretNonce { dprime, E_D1, E_D2 }
    }

    pub fn decrypt_blinded_profile_credential(
        &self,
        blinded_profile_credential: BlindedProfileCredential,
    ) -> ProfileCredential {
        let V = blinded_profile_credential.E_S2 - self.d * blinded_profile_credential.E_S1;
        ProfileCredential {
            t: blinded_profile_credential.t,
            U: blinded_profile_credential.U,
            V,
        }
    }
}

impl CiphertextWithSecretNonce {
    pub fn get_ciphertext(&self) -> Ciphertext {
        Ciphertext {
            E_D1: self.E_D1,
            E_D2: self.E_D2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;
    use crate::crypto::profile_key_commitment;
    use sha2::Sha512;

    #[test]
    fn test_request_response() {
        // client
        let profile_key = RistrettoPoint::hash_from_bytes::<Sha512>(&TEST_ARRAY_32);
        let blind_key_pair = KeyPair::generate(TEST_ARRAY_32_1);

        // server and client
        let _ = profile_key_commitment::CommitmentWithSecretNonce::new(profile_key);

        // client
        let _ = blind_key_pair.create_ciphertext(profile_key, TEST_ARRAY_32_1);

        // server
        /*TODO request_ciphertext.verify(c).unwrap();

        let credential_key_pair = credentials::KeyPair::generate(TEST_ARRAY_32_2);
        let uid_bytes = TEST_ARRAY_16;
        let redemption_time = 37;
        let randomness = TEST_ARRAY_32_3;
        let response =
            query.create_response(credential_key_pair, uid_bytes, redemption_time, randomness);

        response
            .verify(
                blind_key_pair,
                credential_key_pair.get_public_key(),
                query.E_D1,
                query.E_D2,
                uid_bytes,
                redemption_time,
            )
            .unwrap();

        let mac = response.get_mac(blind_key_pair);

        let master_key = GroupMasterKey::new(TEST_ARRAY_32_4);
        let uid_enc_key_pair = uid_encryption::KeyPair::derive_from(master_key);
        let profile_enc_key_pair = KeyPair::generate(TEST_ARRAY_32_4);
        let profile_ciphertext = profile_enc_key_pair
            .get_public_key()
            .encrypt(profile_key, TEST_ARRAY_32_4);

        let ppp = profile_presentation_proof::PresentationProof::new(
            mac,
            uid_enc_key_pair,
            credential_key_pair.get_public_key(),
            uid_bytes,
            profile_ciphertext.E_B1,
            profile_ciphertext.E_B2,
            profile_key,
            profile_enc_key_pair.B,
            profile_enc_key_pair.b,
            redemption_time,
            TEST_ARRAY_32_5,
        );

        let uid_struct = uid_encryption::UidStruct::new(uid_bytes);
        let uid_ciphertext = uid_enc_key_pair.encrypt(uid_struct);

        ppp.verify(
            uid_ciphertext,
            uid_enc_key_pair.get_public_key(),
            credential_key_pair,
            redemption_time,
            profile_ciphertext.E_B1,
            profile_ciphertext.E_B2,
            profile_enc_key_pair.B,
        ).unwrap();
        */
    }
}
