//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]
use crate::common::errors::ZkGroupError::*;
use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto::credentials;
use crate::crypto::profile_credential_request;
use crate::crypto::profile_key_commitment;
use crate::crypto::profile_key_encryption;
use crate::crypto::uid_encryption;
use curve25519_dalek::ristretto::RistrettoPoint;
use poksho::ShoSha256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileCredentialRequestProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialPresentationProof {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_V: RistrettoPoint,
    C_y2prime: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileCredentialPresentationProof {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_y5: RistrettoPoint,
    C_V: RistrettoPoint,
    C_y2prime: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

impl AuthCredentialIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add(
            "C_WXYi",
            &[
                ("wprime", "G_wprime"),
                ("w", "G_w"),
                ("x0", "G_x0"),
                ("x1", "G_x1"),
                ("y1", "G_y1"),
                ("y2", "G_y2"),
                ("y3", "G_y3"),
                ("y4", "G_y4"),
            ],
        );
        st.add(
            "V",
            &[
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
                ("y2", "M2"),
                ("y3", "M3"),
                ("y4", "M4"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair,
        credential: credentials::AuthCredential,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
        randomness: RandomnessBytes,
    ) -> Self {
        let system = credentials::SystemParameters::get_hardcoded();

        let M = credentials::convert_to_points(uid_bytes, redemption_time);
        let C_WXYi = key_pair.C_W
            + key_pair.X
            + key_pair.Yi[0]
            + key_pair.Yi[1]
            + key_pair.Yi[2]
            + key_pair.Yi[3];

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("w", key_pair.w);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.yi[0]);
        scalar_args.add("y2", key_pair.yi[1]);
        scalar_args.add("y3", key_pair.yi[2]);
        scalar_args.add("y4", key_pair.yi[3]);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_WXYi", C_WXYi);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_w", system.G_w);
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);
        point_args.add("G_y1", system.G_yi[0]);
        point_args.add("G_y2", system.G_yi[1]);
        point_args.add("G_y3", system.G_yi[2]);
        point_args.add("G_y4", system.G_yi[3]);
        point_args.add("V", credential.V);
        point_args.add("U", credential.U);
        point_args.add("tU", credential.t * credential.U);
        point_args.add("M1", M[0]);
        point_args.add("M2", M[1]);
        point_args.add("M3", M[2]);
        point_args.add("M4", M[3]);

        let proof_randomness = ShoSha256::shohash(b"Signal_ZKGroup_Mac_Proof", &randomness, 32);
        let poksho_proof = Self::get_poksho_statement()
            .prove(&scalar_args, &point_args, &[], &proof_randomness[..])
            .unwrap();
        Self { poksho_proof }
    }

    pub fn verify(
        &self,
        public_key: credentials::PublicKey,
        credential: credentials::AuthCredential,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
    ) -> Result<(), ZkGroupError> {
        let system = credentials::SystemParameters::get_hardcoded();

        let M = credentials::convert_to_points(uid_bytes, redemption_time);
        let C_WXYi = public_key.C_W
            + public_key.X
            + public_key.Yi[0]
            + public_key.Yi[1]
            + public_key.Yi[2]
            + public_key.Yi[3];

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_WXYi", C_WXYi);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_w", system.G_w);
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);
        point_args.add("G_y1", system.G_yi[0]);
        point_args.add("G_y2", system.G_yi[1]);
        point_args.add("G_y3", system.G_yi[2]);
        point_args.add("G_y4", system.G_yi[3]);
        point_args.add("V", credential.V);
        point_args.add("U", credential.U);
        point_args.add("tU", credential.t * credential.U);
        point_args.add("M1", M[0]);
        point_args.add("M2", M[1]);
        point_args.add("M3", M[2]);
        point_args.add("M4", M[3]);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ProofVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ProfileCredentialRequestProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("D", &[("d", "G")]);
        st.add("E_D1", &[("dprime", "G")]);
        st.add("E_J1", &[("jprime", "G")]);
        st.add("E_D2-E_J2", &[("dprime", "D"), ("jprime", "-G_j")]);
        st
    }

    pub fn new(
        key_pair: profile_credential_request::KeyPair,
        ciphertext: profile_credential_request::CiphertextWithSecretNonce,
        commitment: profile_key_commitment::CommitmentWithSecretNonce,
        randomness: RandomnessBytes,
    ) -> ProfileCredentialRequestProof {
        let commitment_system = profile_key_commitment::SystemParameters::get_hardcoded();

        let mut point_args = poksho::PointArgs::new();
        point_args.add("D", key_pair.D);
        point_args.add("E_D1", ciphertext.E_D1);
        point_args.add("E_J1", commitment.E_J1);
        point_args.add("E_D2-E_J2", ciphertext.E_D2 - commitment.E_J2);
        point_args.add("-G_j", -commitment_system.G_j);

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("d", key_pair.d);
        scalar_args.add("dprime", ciphertext.dprime);
        scalar_args.add("jprime", commitment.jprime);

        let proof_randomness = ShoSha256::shohash(
            b"Signal_ZKGroup_ProfileKey_BlindIssue_Proof",
            &randomness,
            32,
        );
        let poksho_proof = Self::get_poksho_statement()
            .prove(&scalar_args, &point_args, &[], &proof_randomness[..])
            .unwrap();
        ProfileCredentialRequestProof { poksho_proof }
    }

    pub fn verify(
        &self,
        public_key: profile_credential_request::PublicKey,
        ciphertext: profile_credential_request::Ciphertext,
        commitment: profile_key_commitment::Commitment,
    ) -> Result<(), ZkGroupError> {
        let system = profile_key_commitment::SystemParameters::get_hardcoded();

        let mut point_args = poksho::PointArgs::new();
        point_args.add("D", public_key.D);
        point_args.add("E_D1", ciphertext.E_D1);
        point_args.add("E_J1", commitment.E_J1);
        point_args.add("E_D2-E_J2", ciphertext.E_D2 - commitment.E_J2);
        point_args.add("-G_j", -system.G_j);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ProofVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ProfileCredentialIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add(
            "C_WXYi",
            &[
                ("wprime", "G_wprime"),
                ("w", "G_w"),
                ("x0", "G_x0"),
                ("x1", "G_x1"),
                ("y1", "G_y1"),
                ("y2", "G_y2"),
                ("y3", "G_y3"),
                ("y4", "G_y4"),
                ("y5", "G_y5"),
            ],
        );
        st.add("E_S1", &[("y5", "E_D1"), ("rprime", "G")]);
        st.add(
            "E_S2",
            &[
                ("y5", "E_D2"),
                ("rprime", "D"),
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
                ("y2", "M2"),
                ("y3", "M3"),
                ("y4", "M4"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair,
        request_public_key: profile_credential_request::PublicKey,
        request: profile_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedProfileCredentialWithSecretNonce,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
        randomness: RandomnessBytes,
    ) -> ProfileCredentialIssuanceProof {
        let M = credentials::convert_to_points(uid_bytes, redemption_time);
        let C_WXYi = key_pair.C_W
            + key_pair.X
            + key_pair.Yi[0]
            + key_pair.Yi[1]
            + key_pair.Yi[2]
            + key_pair.Yi[3]
            + key_pair.Yi[4];
        let credentials_system = credentials::SystemParameters::get_hardcoded();

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("w", key_pair.w);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.yi[0]);
        scalar_args.add("y2", key_pair.yi[1]);
        scalar_args.add("y3", key_pair.yi[2]);
        scalar_args.add("y4", key_pair.yi[3]);
        scalar_args.add("y5", key_pair.yi[4]);
        scalar_args.add("rprime", blinded_credential.rprime);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_WXYi", C_WXYi);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_yi[0]);
        point_args.add("G_y2", credentials_system.G_yi[1]);
        point_args.add("G_y3", credentials_system.G_yi[2]);
        point_args.add("G_y4", credentials_system.G_yi[3]);
        point_args.add("G_y5", credentials_system.G_yi[4]);
        point_args.add("E_S1", blinded_credential.E_S1);
        point_args.add("E_D1", request.E_D1);
        point_args.add("E_S2", blinded_credential.E_S2);
        point_args.add("E_D2", request.E_D2);
        point_args.add("D", request_public_key.D);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", M[0]);
        point_args.add("M2", M[1]);
        point_args.add("M3", M[2]);
        point_args.add("M4", M[3]);

        let proof_randomness =
            ShoSha256::shohash(b"Signal_ZKGroup_BlindIssueMac_Proof", &randomness, 32);
        let poksho_proof = Self::get_poksho_statement()
            .prove(&scalar_args, &point_args, &[], &proof_randomness[..])
            .unwrap();
        ProfileCredentialIssuanceProof { poksho_proof }
    }

    pub fn verify(
        &self,
        credentials_public_key: credentials::PublicKey,
        request_public_key: profile_credential_request::PublicKey,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
        ciphertext: profile_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedProfileCredential,
    ) -> Result<(), ZkGroupError> {
        let credentials_system = credentials::SystemParameters::get_hardcoded();
        let M = credentials::convert_to_points(uid_bytes, redemption_time);

        let C_WXYi = credentials_public_key.C_W
            + credentials_public_key.X
            + credentials_public_key.Yi[0]
            + credentials_public_key.Yi[1]
            + credentials_public_key.Yi[2]
            + credentials_public_key.Yi[3]
            + credentials_public_key.Yi[4];

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_WXYi", C_WXYi);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_yi[0]);
        point_args.add("G_y2", credentials_system.G_yi[1]);
        point_args.add("G_y3", credentials_system.G_yi[2]);
        point_args.add("G_y4", credentials_system.G_yi[3]);
        point_args.add("G_y5", credentials_system.G_yi[4]);
        point_args.add("E_S1", blinded_credential.E_S1);
        point_args.add("E_D1", ciphertext.E_D1);
        point_args.add("E_S2", blinded_credential.E_S2);
        point_args.add("E_D2", ciphertext.E_D2);
        point_args.add("D", request_public_key.D);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", M[0]);
        point_args.add("M2", M[1]);
        point_args.add("M3", M[2]);
        point_args.add("M4", M[3]);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ProofVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl AuthCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("C_y1-E_A2", &[("z", "G_y1"), ("a", "-E_A1")]);
        st.add("C_y3", &[("z", "G_y3"), ("m3", "G_m3")]);
        st.add("C_y4", &[("z", "G_y4")]);
        st.add("C_y2prime", &[("a1", "C_y2")]);
        st.add(
            "E_A1",
            &[("a0", "C_y2"), ("m3", "C_y2prime"), ("z0", "G_y2")],
        );
        st.add("C_x1", &[("t", "C_x0"), ("z1", "G_x0"), ("z", "G_x1")]);
        st.add("A", &[("a", "G_a"), ("a0", "G_a0"), ("a1", "G_a1")]);
        st.add("Z", &[("z", "G_V-XY1Y2Y3Y4")]);
        st
    }

    pub fn new(
        credentials_public_key: credentials::PublicKey,
        uid_enc_key_pair: uid_encryption::KeyPair,
        credential: credentials::AuthCredential,
        uid_struct: uid_encryption::UidStruct,
        ciphertext: uid_encryption::Ciphertext,
        redemption_time: RedemptionTime,
        randomness: RandomnessBytes,
    ) -> Self {
        let uid_system = uid_encryption::SystemParameters::get_hardcoded();
        let credentials_system = credentials::SystemParameters::get_hardcoded();
        let M = credentials::convert_to_points(uid_struct.uid_bytes, redemption_time);

        let z = calculate_scalar(b"Signal_ZKGroup_Present_r", &randomness);

        let C_y1 = z * credentials_system.G_yi[0] + M[0];
        let C_y2 = z * credentials_system.G_yi[1] + M[1];
        let C_y3 = z * credentials_system.G_yi[2] + M[2];
        let C_y4 = z * credentials_system.G_yi[3];
        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;
        let C_y2prime = uid_enc_key_pair.a1 * C_y2;

        let z0 = -z * (uid_enc_key_pair.a0 + uid_enc_key_pair.a1 * uid_struct.m3);
        let z1 = -(credential.t * z);

        let credentials::PublicKey { C_W: _, X, Yi } = credentials_public_key;

        let G_VXY1Y2Y3Y4 = credentials_system.G_V - X - Yi[0] - Yi[1] - Yi[2] - Yi[3];

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("a", uid_enc_key_pair.a);
        scalar_args.add("m3", uid_struct.m3);
        scalar_args.add("a1", uid_enc_key_pair.a1);
        scalar_args.add("a0", uid_enc_key_pair.a0);
        scalar_args.add("z0", z0);
        scalar_args.add("t", credential.t);
        scalar_args.add("z1", z1);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_y1-E_A2", C_y1 - ciphertext.E_A2);
        point_args.add("G_y1", credentials_system.G_yi[0]);
        point_args.add("-E_A1", -ciphertext.E_A1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_yi[2]);
        point_args.add("G_m3", credentials_system.G_mi[2]);
        point_args.add("C_y4", C_y4);
        point_args.add("G_y4", credentials_system.G_yi[3]);
        point_args.add("C_y2prime", C_y2prime);
        point_args.add("C_y2", C_y2);
        point_args.add("E_A1", ciphertext.E_A1);
        point_args.add("G_y2", credentials_system.G_yi[1]);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_key_pair.A);
        point_args.add("G_a", uid_system.G_a);
        point_args.add("G_a0", uid_system.G_a0);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("Z", z * G_VXY1Y2Y3Y4);
        point_args.add("G_V-XY1Y2Y3Y4", G_VXY1Y2Y3Y4);

        let proof_randomness = ShoSha256::shohash(b"Signal_ZKGroup_Present_Proof", &randomness, 32);

        let poksho_proof = Self::get_poksho_statement()
            .prove(&scalar_args, &point_args, &[], &proof_randomness[..])
            .unwrap();

        Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_V,
            C_y2prime,
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credential_key_pair: credentials::KeyPair,
        uid_enc_public_key: uid_encryption::PublicKey,
        ciphertext: uid_encryption::Ciphertext,
        redemption_time: RedemptionTime,
    ) -> Result<(), ZkGroupError> {
        let uid_system = uid_encryption::SystemParameters::get_hardcoded();
        let credentials_system = credentials::SystemParameters::get_hardcoded();

        let m4 = encode_redemption_time(redemption_time);

        let AuthCredentialPresentationProof {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_V,
            C_y2prime,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_V, C_y2prime) =
            (*C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_y4, *C_V, *C_y2prime);

        let credentials::KeyPair {
            w: _,
            wprime: _,
            W,
            x0,
            x1,
            yi,
            C_W: _,
            X,
            Yi,
        } = credential_key_pair;
        let G4 = credentials_system.G_mi[3];

        let G_VXY1Y2Y3Y4 = credentials_system.G_V - X - Yi[0] - Yi[1] - Yi[2] - Yi[3];

        let Z = C_V
            - W
            - x0 * C_x0
            - x1 * C_x1
            - (yi[0] * C_y1)
            - (yi[1] * C_y2)
            - (yi[2] * C_y3)
            - (yi[3] * (m4 * G4 + C_y4));

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_y1-E_A2", C_y1 - ciphertext.E_A2);
        point_args.add("G_y1", credentials_system.G_yi[0]);
        point_args.add("-E_A1", -ciphertext.E_A1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_yi[2]);
        point_args.add("G_m3", credentials_system.G_mi[2]);
        point_args.add("C_y4", C_y4);
        point_args.add("G_y4", credentials_system.G_yi[3]);
        point_args.add("C_y2prime", C_y2prime);
        point_args.add("C_y2", C_y2);
        point_args.add("E_A1", ciphertext.E_A1);
        point_args.add("G_y2", credentials_system.G_yi[1]);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_public_key.A);
        point_args.add("G_a", uid_system.G_a);
        point_args.add("G_a0", uid_system.G_a0);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("Z", Z);
        point_args.add("G_V-XY1Y2Y3Y4", G_VXY1Y2Y3Y4);

        match Self::get_poksho_statement().verify_proof(&poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupError::ProofVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ProfileCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("C_y1-E_A2", &[("z", "G_y1"), ("a", "-E_A1")]);
        st.add("C_y3", &[("z", "G_y3"), ("m3", "G_m3")]);
        st.add("C_y4", &[("z", "G_y4")]);
        st.add("C_y2prime", &[("a1", "C_y2")]);
        st.add(
            "E_A1",
            &[("a0", "C_y2"), ("m3", "C_y2prime"), ("z0", "G_y2")],
        );
        st.add("C_x1", &[("t", "C_x0"), ("z1", "G_x0"), ("z", "G_x1")]);
        st.add("A", &[("a", "G_a"), ("a0", "G_a0"), ("a1", "G_a1")]);
        st.add("Z", &[("z", "G_V-XY1Y2Y3Y4Y5")]);
        st.add("B", &[("b", "G")]);
        st.add("C_y5-E_B2", &[("z", "G_y5"), ("b", "-E_B1")]);
        st
    }

    pub fn new(
        uid_enc_key_pair: uid_encryption::KeyPair,
        profile_key_enc_key_pair: profile_key_encryption::KeyPair,
        credentials_public_key: credentials::PublicKey,
        credential: credentials::ProfileCredential,
        uid_ciphertext: uid_encryption::Ciphertext,
        profile_key_ciphertext: profile_key_encryption::Ciphertext,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
        profile_key: RistrettoPoint,
        randomness: RandomnessBytes,
    ) -> Self {
        let credentials_system = credentials::SystemParameters::get_hardcoded();
        let uid_system = uid_encryption::SystemParameters::get_hardcoded();
        let uid_struct = uid_encryption::UidStruct::new(uid_bytes);
        let M = credentials::convert_to_points_uid_struct(uid_struct, redemption_time);

        let z = calculate_scalar(b"Signal_ZKGroup_Present_r", &randomness);

        let C_y1 = z * credentials_system.G_yi[0] + M[0];
        let C_y2 = z * credentials_system.G_yi[1] + M[1];
        let C_y3 = z * credentials_system.G_yi[2] + M[2];
        let C_y4 = z * credentials_system.G_yi[3];
        let C_y5 = z * credentials_system.G_yi[4] + profile_key;
        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;
        let C_y2prime = uid_enc_key_pair.a1 * C_y2;

        let z0 = -z * (uid_enc_key_pair.a0 + uid_enc_key_pair.a1 * uid_struct.m3);
        let z1 = -(credential.t * z);

        let credentials::PublicKey { C_W: _, X, Yi } = credentials_public_key;

        let G_VXY1Y2Y3Y4Y5 = credentials_system.G_V - X - Yi[0] - Yi[1] - Yi[2] - Yi[3] - Yi[4];

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("a", uid_enc_key_pair.a);
        scalar_args.add("m3", uid_struct.m3);
        scalar_args.add("a1", uid_enc_key_pair.a1);
        scalar_args.add("a0", uid_enc_key_pair.a0);
        scalar_args.add("z0", z0);
        scalar_args.add("t", credential.t);
        scalar_args.add("z1", z1);
        scalar_args.add("b", profile_key_enc_key_pair.b);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_y1-E_A2", C_y1 - uid_ciphertext.E_A2);
        point_args.add("G_y1", credentials_system.G_yi[0]);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_yi[2]);
        point_args.add("G_m3", credentials_system.G_mi[2]);
        point_args.add("C_y4", C_y4);
        point_args.add("G_y4", credentials_system.G_yi[3]);
        point_args.add("C_y2prime", C_y2prime);
        point_args.add("C_y2", C_y2);
        point_args.add("E_A1", uid_ciphertext.E_A1);
        point_args.add("G_y2", credentials_system.G_yi[1]);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_key_pair.A);
        point_args.add("G_a", uid_system.G_a);
        point_args.add("G_a0", uid_system.G_a0);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("Z", z * G_VXY1Y2Y3Y4Y5);
        point_args.add("G_V-XY1Y2Y3Y4Y5", G_VXY1Y2Y3Y4Y5);
        point_args.add("B", profile_key_enc_key_pair.B);
        point_args.add("C_y5-E_B2", C_y5 - profile_key_ciphertext.E_B2);
        point_args.add("G_y5", credentials_system.G_yi[4]);
        point_args.add("-E_B1", -profile_key_ciphertext.E_B1);

        let proof_randomness = ShoSha256::shohash(b"Signal_ZKGroup_Present_Proof", &randomness, 32);

        let poksho_proof = Self::get_poksho_statement()
            .prove(&scalar_args, &point_args, &[], &proof_randomness[..])
            .unwrap();

        ProfileCredentialPresentationProof {
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_y5,
            C_x0,
            C_V,
            C_x1,
            C_y2prime,
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credentials_key_pair: credentials::KeyPair,
        uid_ciphertext: uid_encryption::Ciphertext,
        uid_enc_public_key: uid_encryption::PublicKey,
        profile_key_ciphertext: profile_key_encryption::Ciphertext,
        profile_key_enc_public_key: profile_key_encryption::PublicKey,
        redemption_time: RedemptionTime,
    ) -> Result<(), ZkGroupError> {
        let m4 = encode_redemption_time(redemption_time);
        let enc_system = uid_encryption::SystemParameters::get_hardcoded();
        let mac_system = credentials::SystemParameters::get_hardcoded();

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_y5,
            C_V,
            C_y2prime,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_y5, C_V, C_y2prime) = (
            *C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_y4, *C_y5, *C_V, *C_y2prime,
        );

        let credentials::KeyPair {
            w: _,
            wprime: _,
            W,
            x0,
            x1,
            yi,
            C_W: _,
            X,
            Yi,
        } = credentials_key_pair;
        let G4 = mac_system.G_mi[3];

        let G_VXY1Y2Y3Y4Y5 = mac_system.G_V - X - Yi[0] - Yi[1] - Yi[2] - Yi[3] - Yi[4];

        let Z = C_V
            - W
            - x0 * C_x0
            - x1 * C_x1
            - (yi[0] * C_y1)
            - (yi[1] * C_y2)
            - (yi[2] * C_y3)
            - (yi[3] * (m4 * G4 + C_y4))
            - (yi[4] * C_y5);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_y1-E_A2", C_y1 - uid_ciphertext.E_A2);
        point_args.add("G_y1", mac_system.G_yi[0]);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", mac_system.G_yi[2]);
        point_args.add("G_m3", mac_system.G_mi[2]);
        point_args.add("C_y4", C_y4);
        point_args.add("G_y4", mac_system.G_yi[3]);
        point_args.add("C_y2prime", C_y2prime);
        point_args.add("C_y2", C_y2);
        point_args.add("E_A1", uid_ciphertext.E_A1);
        point_args.add("G_y2", mac_system.G_yi[1]);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", mac_system.G_x0);
        point_args.add("G_x1", mac_system.G_x1);
        point_args.add("A", uid_enc_public_key.A);
        point_args.add("G_a", enc_system.G_a);
        point_args.add("G_a0", enc_system.G_a0);
        point_args.add("G_a1", enc_system.G_a1);
        point_args.add("Z", Z);
        point_args.add("G_V-XY1Y2Y3Y4Y5", G_VXY1Y2Y3Y4Y5);
        point_args.add("B", profile_key_enc_public_key.B);
        point_args.add("C_y5-E_B2", C_y5 - profile_key_ciphertext.E_B2);
        point_args.add("G_y5", mac_system.G_yi[4]);
        point_args.add("-E_B1", -profile_key_ciphertext.E_B1);

        match Self::get_poksho_statement().verify_proof(&poksho_proof, &point_args, &[]) {
            Err(e) => {
                println!("{:?}", e);
                Err(ZkGroupError::ProofVerificationFailure)
            }
            Ok(_) => Ok(()),
        }
    }
}
