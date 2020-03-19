//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::api;
use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerSecretParams {
    pub(crate) auth_credentials_key_pair: crypto::credentials::KeyPair,
    pub(crate) profile_key_credentials_key_pair: crypto::credentials::KeyPair,
    sig_key_pair: crypto::signature::KeyPair,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerPublicParams {
    pub(crate) auth_credentials_public_key: crypto::credentials::PublicKey,
    pub(crate) profile_key_credentials_public_key: crypto::credentials::PublicKey,
    sig_public_key: crypto::signature::PublicKey,
}

impl ServerSecretParams {
    pub fn generate(randomness: [u8; 32]) -> Self {
        let auth_credentials_key_pair =
            crypto::credentials::KeyPair::generate(randomness, NUM_AUTH_CRED_ATTRIBUTES);
        let profile_key_credentials_key_pair =
            crypto::credentials::KeyPair::generate(randomness, NUM_PROFILE_KEY_CRED_ATTRIBUTES);
        let sig_key_pair = crypto::signature::KeyPair::derive_from(
            &randomness,
            b"Signal_ZKGroup_Sig_Server_KeyGen",
        );
        Self {
            auth_credentials_key_pair,
            profile_key_credentials_key_pair,
            sig_key_pair,
        }
    }

    pub fn get_public_params(&self) -> ServerPublicParams {
        ServerPublicParams {
            auth_credentials_public_key: self.auth_credentials_key_pair.get_public_key(),
            profile_key_credentials_public_key: self
                .profile_key_credentials_key_pair
                .get_public_key(),
            sig_public_key: self.sig_key_pair.get_public_key(),
        }
    }

    pub fn sign(
        &self,
        randomness: RandomnessBytes,
        message: &[u8],
    ) -> Result<NotarySignatureBytes, ZkGroupError> {
        self.sig_key_pair.sign(message, randomness)
    }

    pub fn issue_auth_credential(
        &self,
        randomness: RandomnessBytes,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
    ) -> api::auth::AuthCredentialResponse {
        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
        let credential =
            self.auth_credentials_key_pair
                .create_auth_credential(uid, redemption_time, randomness);
        let proof = crypto::proofs::AuthCredentialIssuanceProof::new(
            self.auth_credentials_key_pair,
            credential,
            uid,
            redemption_time,
            randomness,
        );
        api::auth::AuthCredentialResponse { credential, proof }
    }

    pub fn verify_auth_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AuthCredentialPresentation,
    ) -> Result<(), ZkGroupError> {
        presentation.proof.verify(
            self.auth_credentials_key_pair,
            group_public_params.uid_enc_public_key,
            presentation.ciphertext,
            presentation.redemption_time,
        )
    }

    pub fn verify_profile_key_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::profiles::ProfileKeyCredentialPresentation,
    ) -> Result<(), ZkGroupError> {
        let credentials_key_pair = self.profile_key_credentials_key_pair;
        let uid_enc_public_key = group_public_params.uid_enc_public_key;
        let profile_key_enc_public_key = group_public_params.profile_key_enc_public_key;

        presentation.proof.verify(
            credentials_key_pair,
            presentation.uid_enc_ciphertext,
            uid_enc_public_key,
            presentation.profile_key_enc_ciphertext,
            profile_key_enc_public_key,
        )
    }

    pub fn issue_profile_key_credential(
        &self,
        randomness: RandomnessBytes,
        request: &api::profiles::ProfileKeyCredentialRequest,
        uid_bytes: UidBytes,
        commitment: api::profiles::ProfileKeyCommitment,
    ) -> Result<api::profiles::ProfileKeyCredentialResponse, ZkGroupError> {
        request.proof.verify(
            request.public_key,
            request.ciphertext,
            commitment.commitment,
        )?;

        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
        let blinded_credential_with_secret_nonce = self
            .auth_credentials_key_pair
            .create_blinded_profile_key_credential(
                uid,
                request.public_key,
                request.ciphertext,
                randomness,
            );

        let proof = crypto::proofs::ProfileKeyCredentialIssuanceProof::new(
            self.profile_key_credentials_key_pair,
            request.public_key,
            request.ciphertext,
            blinded_credential_with_secret_nonce,
            uid,
            randomness,
        );

        Ok(api::profiles::ProfileKeyCredentialResponse {
            blinded_credential: blinded_credential_with_secret_nonce
                .get_blinded_profile_key_credential(),
            proof,
        })
    }
}

impl ServerPublicParams {
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: NotarySignatureBytes,
    ) -> Result<(), ZkGroupError> {
        self.sig_public_key.verify(message, signature)
    }

    pub fn receive_auth_credential(
        &self,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
        response: &api::auth::AuthCredentialResponse,
    ) -> Result<api::auth::AuthCredential, ZkGroupError> {
        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
        response.proof.verify(
            self.auth_credentials_public_key,
            response.credential,
            uid,
            redemption_time,
        )?;

        Ok(api::auth::AuthCredential {
            credential: response.credential,
            server_public_params: *self,
            uid,
            redemption_time,
        })
    }

    pub fn create_auth_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        auth_credential: api::auth::AuthCredential,
    ) -> api::auth::AuthCredentialPresentation {
        let uuid_ciphertext = group_secret_params.encrypt_uid_struct(auth_credential.uid);

        let proof = crypto::proofs::AuthCredentialPresentationProof::new(
            self.auth_credentials_public_key,
            group_secret_params.uid_enc_key_pair,
            auth_credential.credential,
            auth_credential.uid,
            uuid_ciphertext.ciphertext,
            auth_credential.redemption_time,
            randomness,
        );

        api::auth::AuthCredentialPresentation {
            proof,
            ciphertext: uuid_ciphertext.ciphertext,
            redemption_time: auth_credential.redemption_time,
        }
    }

    pub fn create_profile_key_credential_request_context(
        &self,
        randomness: RandomnessBytes,
        uid_bytes: UidBytes,
        profile_key: api::profiles::ProfileKey,
    ) -> api::profiles::ProfileKeyCredentialRequestContext {
        let profile_key_struct =
            crypto::profile_key_struct::ProfileKeyStruct::new(profile_key.bytes, uid_bytes);

        let commitment = crypto::profile_key_commitment::Commitment::new(profile_key_struct);

        let key_pair = crypto::profile_key_credential_request::KeyPair::generate(randomness);
        let ciphertext_with_secret_nonce = key_pair.encrypt(profile_key_struct, randomness);

        let proof = crypto::proofs::ProfileKeyCredentialRequestProof::new(
            key_pair,
            profile_key_struct,
            ciphertext_with_secret_nonce,
            commitment,
            randomness,
        );

        api::profiles::ProfileKeyCredentialRequestContext {
            uid_bytes,
            profile_key_bytes: profile_key_struct.bytes,
            key_pair,
            ciphertext_with_secret_nonce,
            proof,
        }
    }

    pub fn receive_profile_key_credential(
        &self,
        context: &api::profiles::ProfileKeyCredentialRequestContext,
        response: &api::profiles::ProfileKeyCredentialResponse,
    ) -> Result<api::profiles::ProfileKeyCredential, ZkGroupError> {
        response.proof.verify(
            self.profile_key_credentials_public_key,
            context.key_pair.get_public_key(),
            context.uid_bytes,
            context.ciphertext_with_secret_nonce.get_ciphertext(),
            response.blinded_credential,
        )?;

        let credential = context
            .key_pair
            .decrypt_blinded_profile_key_credential(response.blinded_credential);

        Ok(api::profiles::ProfileKeyCredential {
            credential,
            uid_bytes: context.uid_bytes,
            profile_key_bytes: context.profile_key_bytes,
        })
    }

    pub fn create_profile_key_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        profile_key_credential: api::profiles::ProfileKeyCredential,
    ) -> api::profiles::ProfileKeyCredentialPresentation {
        let uid_enc_key_pair = group_secret_params.uid_enc_key_pair;
        let profile_key_enc_key_pair = group_secret_params.profile_key_enc_key_pair;
        let credentials_public_key = self.profile_key_credentials_public_key;

        let uuid_ciphertext = group_secret_params.encrypt_uuid(profile_key_credential.uid_bytes);
        let profile_key_ciphertext = group_secret_params.encrypt_profile_key_bytes(
            randomness,
            profile_key_credential.profile_key_bytes,
            profile_key_credential.uid_bytes,
        );

        let proof = crypto::proofs::ProfileKeyCredentialPresentationProof::new(
            uid_enc_key_pair,
            profile_key_enc_key_pair,
            credentials_public_key,
            profile_key_credential.credential,
            uuid_ciphertext.ciphertext,
            profile_key_ciphertext.ciphertext,
            profile_key_credential.uid_bytes,
            profile_key_credential.profile_key_bytes,
            randomness,
        );

        api::profiles::ProfileKeyCredentialPresentation {
            proof,
            uid_enc_ciphertext: uuid_ciphertext.ciphertext,
            profile_key_enc_ciphertext: profile_key_ciphertext.ciphertext,
        }
    }
}
