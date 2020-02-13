//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::api;
use crate::common::constants::*;
use crate::common::errors::ZkGroupError::*;
use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto;
use curve25519_dalek::ristretto::RistrettoPoint;
use poksho::ShoSha256;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Copy, Clone, Serialize, Deserialize, Default)]
pub struct GroupMasterKey {
    pub(crate) bytes: [u8; 32],
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct GroupSecretParams {
    pub(crate) uid_enc_key_pair: crypto::uid_encryption::KeyPair,
    pub(crate) profile_key_enc_key_pair: crypto::profile_key_encryption::KeyPair,
    sig_key_pair: crypto::signature::KeyPair,
    master_key: GroupMasterKey,
    group_id: GroupIdentifierBytes,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct GroupPublicParams {
    pub(crate) uid_enc_public_key: crypto::uid_encryption::PublicKey,
    pub(crate) profile_key_enc_public_key: crypto::profile_key_encryption::PublicKey,
    sig_public_key: crypto::signature::PublicKey,
    group_id: GroupIdentifierBytes,
}

impl GroupMasterKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        GroupMasterKey { bytes }
    }
}

impl GroupSecretParams {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut master_key: GroupMasterKey = Default::default();
        master_key.bytes.copy_from_slice(
            &ShoSha256::shohash(
                b"Signal_ZKGroup_Master_Random",
                &randomness,
                GROUP_MASTER_KEY_LEN as u64,
            )[0..GROUP_MASTER_KEY_LEN],
        );
        GroupSecretParams::derive_from_master_key(master_key)
    }

    pub fn derive_from_master_key(master_key: GroupMasterKey) -> Self {
        let uid_enc_key_pair = crypto::uid_encryption::KeyPair::derive_from(master_key.bytes);
        let profile_key_enc_key_pair =
            crypto::profile_key_encryption::KeyPair::derive_from(master_key.bytes);
        let sig_key_pair = crypto::signature::KeyPair::derive_from(
            &master_key.bytes,
            b"Signal_ZKGroup_Sig_Client_KeyDerive",
        );

        let mut group_id: GroupIdentifierBytes = Default::default();
        group_id.copy_from_slice(
            &ShoSha256::shohash(
                b"Signal_ZKGroup_GroupId",
                &master_key.bytes,
                GROUP_IDENTIFIER_LEN as u64,
            )[0..GROUP_IDENTIFIER_LEN],
        );

        Self {
            uid_enc_key_pair,
            profile_key_enc_key_pair,
            sig_key_pair,
            master_key,
            group_id,
        }
    }

    pub fn get_master_key(&self) -> GroupMasterKey {
        self.master_key
    }

    pub fn get_group_identifier(&self) -> GroupIdentifierBytes {
        self.group_id
    }

    pub fn get_public_params(&self) -> GroupPublicParams {
        GroupPublicParams {
            uid_enc_public_key: self.uid_enc_key_pair.get_public_key(),
            profile_key_enc_public_key: self.profile_key_enc_key_pair.get_public_key(),
            sig_public_key: self.sig_key_pair.get_public_key(),
            group_id: self.group_id,
        }
    }

    pub fn sign(
        &self,
        randomness: RandomnessBytes,
        message: &[u8],
    ) -> Result<ChangeSignatureBytes, ZkGroupError> {
        self.sig_key_pair.sign(message, randomness)
    }

    pub fn encrypt_uuid(&self, uid_bytes: UidBytes) -> api::groups::UuidCiphertext {
        let uid_struct = crypto::uid_encryption::UidStruct::new(uid_bytes);
        let ciphertext = self.uid_enc_key_pair.encrypt(uid_struct);
        api::groups::UuidCiphertext { ciphertext }
    }

    pub fn decrypt_uuid(
        &self,
        ciphertext: api::groups::UuidCiphertext,
    ) -> Result<UidBytes, ZkGroupError> {
        let uid_struct = self.uid_enc_key_pair.decrypt(ciphertext.ciphertext)?;
        Ok(uid_struct.to_bytes())
    }

    pub fn encrypt_profile_key(
        &self,
        randomness: RandomnessBytes,
        profile_key: api::profiles::ProfileKey,
    ) -> api::groups::ProfileKeyCiphertext {
        let mut bytes: ProfileKeyHalfBytes = Default::default();
        bytes.copy_from_slice(&profile_key.bytes[0..16]);
        let P = RistrettoPoint::lizard_encode::<Sha256>(&bytes).unwrap();
        let mut plaintext_key_half: ProfileKeyHalfBytes = Default::default();
        plaintext_key_half.copy_from_slice(&profile_key.bytes[16..32]);
        let ciphertext = self.profile_key_enc_key_pair.encrypt(P, randomness);
        api::groups::ProfileKeyCiphertext {
            ciphertext,
            plaintext_key_half,
        }
    }

    pub fn encrypt_profile_key_point(
        &self,
        randomness: RandomnessBytes,
        P: RistrettoPoint,
        plaintext_key_half: ProfileKeyHalfBytes,
    ) -> api::groups::ProfileKeyCiphertext {
        let ciphertext = self.profile_key_enc_key_pair.encrypt(P, randomness);
        api::groups::ProfileKeyCiphertext {
            ciphertext,
            plaintext_key_half,
        }
    }

    pub fn decrypt_profile_key(
        &self,
        ciphertext: api::groups::ProfileKeyCiphertext,
    ) -> Result<api::profiles::ProfileKey, ZkGroupError> {
        let P = self.profile_key_enc_key_pair.decrypt(ciphertext.ciphertext);
        match P.lizard_decode::<Sha256>() {
            None => Err(PointDecodeFailure),
            Some(profile_key_bytes) => {
                let mut bytes: ProfileKeyBytes = Default::default();
                bytes[0..16].copy_from_slice(&profile_key_bytes[..]);
                bytes[16..32].copy_from_slice(&ciphertext.plaintext_key_half[..]);
                Ok(api::profiles::ProfileKey { bytes })
            }
        }
    }

    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Vec<u8> {
        plaintext.to_vec()
    }

    pub fn decrypt_blob(self, ciphertext: &[u8]) -> Result<Vec<u8>, ZkGroupError> {
        Ok(ciphertext.to_vec())
    }
}

impl GroupPublicParams {
    pub fn get_group_identifier(&self) -> GroupIdentifierBytes {
        self.group_id
    }

    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: ChangeSignatureBytes,
    ) -> Result<(), ZkGroupError> {
        self.sig_public_key.verify(message, signature)
    }
}
