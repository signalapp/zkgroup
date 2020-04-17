//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]
use crate::common::constants::*;
use crate::common::errors::ZkGroupError::*;
use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::credentials;
use crate::crypto::profile_key_commitment;
use crate::crypto::profile_key_credential_request;
use crate::crypto::profile_key_encryption;
use crate::crypto::profile_key_struct;
use crate::crypto::uid_encryption;
use crate::crypto::uid_struct;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileKeyCredentialRequestProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileKeyCredentialIssuanceProof {
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
pub struct ProfileKeyCredentialPresentationProof {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_y5: RistrettoPoint,
    C_y6: RistrettoPoint,
    C_V: RistrettoPoint,
    C_y2prime: RistrettoPoint,
    C_y5prime: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

impl AuthCredentialIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("C_W", &[("w", "G_w"), ("wprime", "G_wprime")]);
        st.add(
            "G_V-I",
            &[
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
        uid: uid_struct::UidStruct,
        redemption_time: RedemptionTime,
        sho: &mut Sho,
    ) -> Self {
        let system = credentials::SystemParams::get_hardcoded();

        let M = credentials::convert_to_points_uid_struct(uid, redemption_time);

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y1);
        scalar_args.add("y2", key_pair.y2);
        scalar_args.add("y3", key_pair.y3);
        scalar_args.add("y4", key_pair.y4);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", key_pair.C_W);
        point_args.add("G_w", system.G_w);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_V-I", system.G_V - key_pair.I);
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);
        point_args.add("G_y1", system.G_y1);
        point_args.add("G_y2", system.G_y2);
        point_args.add("G_y3", system.G_y3);
        point_args.add("G_y4", system.G_y4);
        point_args.add("V", credential.V);
        point_args.add("U", credential.U);
        point_args.add("tU", credential.t * credential.U);
        point_args.add("M1", M[0]);
        point_args.add("M2", M[1]);
        point_args.add("M3", M[2]);
        point_args.add("M4", M[3]);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        Self { poksho_proof }
    }

    pub fn verify(
        &self,
        public_key: credentials::PublicKey,
        credential: credentials::AuthCredential,
        uid_struct: uid_struct::UidStruct,
        redemption_time: RedemptionTime,
    ) -> Result<(), ZkGroupError> {
        let system = credentials::SystemParams::get_hardcoded();

        let M = credentials::convert_to_points_uid_struct(uid_struct, redemption_time);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", public_key.C_W);
        point_args.add("G_w", system.G_w);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_V-I", system.G_V - public_key.I);
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);
        point_args.add("G_y1", system.G_y1);
        point_args.add("G_y2", system.G_y2);
        point_args.add("G_y3", system.G_y3);
        point_args.add("G_y4", system.G_y4);
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

impl ProfileKeyCredentialRequestProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("Y", &[("y", "G")]);
        st.add("D1", &[("r1", "G")]);
        st.add("E1", &[("r2", "G")]);
        st.add("F1", &[("r3", "G")]);
        st.add("J3", &[("m6", "G_j3")]);
        st.add("D2-J1", &[("r1", "Y"), ("m6", "-G_j1")]);
        st.add("E2-J2", &[("r2", "Y"), ("m6", "-G_j2")]);
        st.add("F2", &[("r3", "Y"), ("m6", "G_m6")]);
        st
    }

    pub fn new(
        key_pair: profile_key_credential_request::KeyPair,
        profile_key: profile_key_struct::ProfileKeyStruct,
        ciphertext: profile_key_credential_request::CiphertextWithSecretNonce,
        commitment: profile_key_commitment::Commitment,
        sho: &mut Sho,
    ) -> ProfileKeyCredentialRequestProof {
        let commitment_system = profile_key_commitment::SystemParams::get_hardcoded();
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("y", key_pair.y);
        scalar_args.add("r1", ciphertext.r1);
        scalar_args.add("r2", ciphertext.r2);
        scalar_args.add("r3", ciphertext.r3);
        scalar_args.add("m6", profile_key.m6);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", key_pair.Y);
        point_args.add("D1", ciphertext.D1);
        point_args.add("E1", ciphertext.E1);
        point_args.add("F1", ciphertext.F1);
        point_args.add("J3", commitment.J3);
        point_args.add("G_j3", commitment_system.G_j3);
        point_args.add("D2-J1", ciphertext.D2 - commitment.J1);
        point_args.add("-G_j1", -commitment_system.G_j1);
        point_args.add("E2-J2", ciphertext.E2 - commitment.J2);
        point_args.add("-G_j2", -commitment_system.G_j2);
        point_args.add("F2", ciphertext.F2);
        point_args.add("G_m6", credentials_system.G_m6);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        ProfileKeyCredentialRequestProof { poksho_proof }
    }

    pub fn verify(
        &self,
        public_key: profile_key_credential_request::PublicKey,
        ciphertext: profile_key_credential_request::Ciphertext,
        commitment: profile_key_commitment::Commitment,
    ) -> Result<(), ZkGroupError> {
        let commitment_system = profile_key_commitment::SystemParams::get_hardcoded();
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", public_key.Y);
        point_args.add("D1", ciphertext.D1);
        point_args.add("E1", ciphertext.E1);
        point_args.add("F1", ciphertext.F1);
        point_args.add("J3", commitment.J3);
        point_args.add("G_j3", commitment_system.G_j3);
        point_args.add("D2-J1", ciphertext.D2 - commitment.J1);
        point_args.add("-G_j1", -commitment_system.G_j1);
        point_args.add("E2-J2", ciphertext.E2 - commitment.J2);
        point_args.add("-G_j2", -commitment_system.G_j2);
        point_args.add("F2", ciphertext.F2);
        point_args.add("G_m6", credentials_system.G_m6);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ProofVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ProfileKeyCredentialIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("C_W", &[("w", "G_w"), ("wprime", "G_wprime")]);
        st.add(
            "G_V-I",
            &[
                ("x0", "G_x0"),
                ("x1", "G_x1"),
                ("y1", "G_y1"),
                ("y2", "G_y2"),
                ("y3", "G_y3"),
                ("y4", "G_y4"),
                ("y5", "G_y5"),
                ("y6", "G_y6"),
            ],
        );
        st.add(
            "S1",
            &[("y4", "D1"), ("y5", "E1"), ("y6", "F1"), ("rprime", "G")],
        );
        st.add(
            "S2",
            &[
                ("y4", "D2"),
                ("y5", "E2"),
                ("y6", "F2"),
                ("rprime", "Y"),
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
                ("y2", "M2"),
                ("y3", "M3"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair,
        request_public_key: profile_key_credential_request::PublicKey,
        request: profile_key_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedProfileKeyCredentialWithSecretNonce,
        uid: uid_struct::UidStruct,
        sho: &mut Sho,
    ) -> ProfileKeyCredentialIssuanceProof {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y1);
        scalar_args.add("y2", key_pair.y2);
        scalar_args.add("y3", key_pair.y3);
        scalar_args.add("y4", key_pair.y4);
        scalar_args.add("y5", key_pair.y5);
        scalar_args.add("y6", key_pair.y6);
        scalar_args.add("rprime", blinded_credential.rprime);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", key_pair.C_W);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_V-I", credentials_system.G_V - key_pair.I);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y1);
        point_args.add("G_y2", credentials_system.G_y2);
        point_args.add("G_y3", credentials_system.G_y3);
        point_args.add("G_y4", credentials_system.G_y4);
        point_args.add("G_y5", credentials_system.G_y5);
        point_args.add("G_y6", credentials_system.G_y6);
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("E1", request.E1);
        point_args.add("F1", request.F1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("E2", request.E2);
        point_args.add("F2", request.F2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", uid.M1);
        point_args.add("M2", uid.M2);
        point_args.add("M3", uid.M3);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        ProfileKeyCredentialIssuanceProof { poksho_proof }
    }

    pub fn verify(
        &self,
        credentials_public_key: credentials::PublicKey,
        request_public_key: profile_key_credential_request::PublicKey,
        uid_bytes: UidBytes,
        request: profile_key_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedProfileKeyCredential,
    ) -> Result<(), ZkGroupError> {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid = uid_struct::UidStruct::new(uid_bytes);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", credentials_public_key.C_W);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_V-I", credentials_system.G_V - credentials_public_key.I);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y1);
        point_args.add("G_y2", credentials_system.G_y2);
        point_args.add("G_y3", credentials_system.G_y3);
        point_args.add("G_y4", credentials_system.G_y4);
        point_args.add("G_y5", credentials_system.G_y5);
        point_args.add("G_y6", credentials_system.G_y6);
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("E1", request.E1);
        point_args.add("F1", request.F1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("E2", request.E2);
        point_args.add("F2", request.F2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", uid.M1);
        point_args.add("M2", uid.M2);
        point_args.add("M3", uid.M3);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ProofVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl AuthCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();

        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add("A", &[("a", "G_a"), ("a0", "G_a0"), ("a1", "G_a1")]);
        st.add("C_y1-E_A2", &[("z", "G_y1"), ("a", "-E_A1")]);
        st.add("C_y2prime", &[("a1", "C_y2")]);
        st.add(
            "E_A1",
            &[("a0", "C_y2"), ("m3", "C_y2prime"), ("z1", "G_y2")],
        );
        st.add("C_y3", &[("z", "G_y3"), ("m3", "G_m3")]);
        st.add("C_y4", &[("z", "G_y4")]);
        st
    }

    pub fn new(
        credentials_public_key: credentials::PublicKey,
        uid_enc_key_pair: uid_encryption::KeyPair,
        credential: credentials::AuthCredential,
        uid: uid_struct::UidStruct,
        uid_ciphertext: uid_encryption::Ciphertext,
        redemption_time: RedemptionTime,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid_system = uid_encryption::SystemParams::get_hardcoded();
        let M = credentials::convert_to_points_uid_struct(uid, redemption_time);

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y1 + M[0];
        let C_y2 = z * credentials_system.G_y2 + M[1];
        let C_y3 = z * credentials_system.G_y3 + M[2];
        let C_y4 = z * credentials_system.G_y4;

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;
        let C_y2prime = uid_enc_key_pair.a1 * C_y2;

        let z0 = -(credential.t * z);
        let z1 = -z * (uid_enc_key_pair.a0 + uid_enc_key_pair.a1 * uid.m3);

        let I = credentials_public_key.I;
        let Z = z * I;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        scalar_args.add("a", uid_enc_key_pair.a);
        scalar_args.add("a0", uid_enc_key_pair.a0);
        scalar_args.add("a1", uid_enc_key_pair.a1);
        scalar_args.add("m3", uid.m3);
        scalar_args.add("z1", z1);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_key_pair.A);
        point_args.add("G_a", uid_system.G_a);
        point_args.add("G_a0", uid_system.G_a0);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("C_y1-E_A2", C_y1 - uid_ciphertext.E_A2);
        point_args.add("G_y1", credentials_system.G_y1);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("C_y2prime", C_y2prime);
        point_args.add("C_y2", C_y2);
        point_args.add("E_A1", uid_ciphertext.E_A1);
        point_args.add("G_y2", credentials_system.G_y2);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y3);
        point_args.add("G_m3", credentials_system.G_m3);
        point_args.add("C_y4", C_y4);
        point_args.add("G_y4", credentials_system.G_y4);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
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
        credentials_key_pair: credentials::KeyPair,
        uid_enc_public_key: uid_encryption::PublicKey,
        uid_ciphertext: uid_encryption::Ciphertext,
        redemption_time: RedemptionTime,
    ) -> Result<(), ZkGroupError> {
        let enc_system = uid_encryption::SystemParams::get_hardcoded();
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let Self {
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
            W,
            x0,
            x1,
            y1,
            y2,
            y3,
            y4,
            I,
            ..
        } = credentials_key_pair;

        let m4 = encode_redemption_time(redemption_time);
        let M4 = m4 * credentials_system.G_m4;
        let Z =
            C_V - W - x0 * C_x0 - x1 * C_x1 - y1 * C_y1 - y2 * C_y2 - y3 * C_y3 - y4 * (C_y4 + M4);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_public_key.A);
        point_args.add("G_a", enc_system.G_a);
        point_args.add("G_a0", enc_system.G_a0);
        point_args.add("G_a1", enc_system.G_a1);
        point_args.add("C_y1-E_A2", C_y1 - uid_ciphertext.E_A2);
        point_args.add("G_y1", credentials_system.G_y1);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("C_y2prime", C_y2prime);
        point_args.add("C_y2", C_y2);
        point_args.add("E_A1", uid_ciphertext.E_A1);
        point_args.add("G_y2", credentials_system.G_y2);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y3);
        point_args.add("G_m3", credentials_system.G_m3);
        point_args.add("C_y4", C_y4);
        point_args.add("G_y4", credentials_system.G_y4);

        match Self::get_poksho_statement().verify_proof(&poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupError::ProofVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ProfileKeyCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add("A", &[("a", "G_a"), ("a0", "G_a0"), ("a1", "G_a1")]);
        st.add("B", &[("b", "G_b"), ("b0", "G_b0"), ("b1", "G_b1")]);
        st.add("C_y1-E_A2", &[("z", "G_y1"), ("a", "-E_A1")]);
        st.add("C_y2prime", &[("a1", "C_y2")]);
        st.add(
            "E_A1",
            &[("a0", "C_y2"), ("m3", "C_y2prime"), ("z1", "G_y2")],
        );
        st.add("C_y3", &[("z", "G_y3"), ("m3", "G_m3")]);
        st.add("C_y4-E_B2", &[("z", "G_y4"), ("b", "-E_B1")]);
        st.add("C_y5prime", &[("b1", "C_y5")]);
        st.add(
            "E_B1",
            &[("b0", "C_y5"), ("m6", "C_y5prime"), ("z2", "G_y5")],
        );
        st.add("C_y6", &[("z", "G_y6"), ("m6", "G_m6")]);
        st
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uid_enc_key_pair: uid_encryption::KeyPair,
        profile_key_enc_key_pair: profile_key_encryption::KeyPair,
        credentials_public_key: credentials::PublicKey,
        credential: credentials::ProfileKeyCredential,
        uid_ciphertext: uid_encryption::Ciphertext,
        profile_key_ciphertext: profile_key_encryption::Ciphertext,
        uid_bytes: UidBytes,
        profile_key_bytes: ProfileKeyBytes,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid_system = uid_encryption::SystemParams::get_hardcoded();
        let profile_key_system = profile_key_encryption::SystemParams::get_hardcoded();
        let uid = uid_struct::UidStruct::new(uid_bytes);
        let profile_key = profile_key_struct::ProfileKeyStruct::new(profile_key_bytes, uid_bytes);

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y1 + uid.M1;
        let C_y2 = z * credentials_system.G_y2 + uid.M2;
        let C_y3 = z * credentials_system.G_y3 + uid.M3;
        let C_y4 = z * credentials_system.G_y4 + profile_key.M4;
        let C_y5 = z * credentials_system.G_y5 + profile_key.M5;
        let C_y6 = z * credentials_system.G_y6 + profile_key.M6();

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;
        let C_y2prime = uid_enc_key_pair.a1 * C_y2;
        let C_y5prime = profile_key_enc_key_pair.b1 * C_y5;

        let z0 = -(credential.t * z);
        let z1 = -z * (uid_enc_key_pair.a0 + uid_enc_key_pair.a1 * uid.m3);
        let z2 = -z * (profile_key_enc_key_pair.b0 + profile_key_enc_key_pair.b1 * profile_key.m6);

        let I = credentials_public_key.I;
        let Z = z * I;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        scalar_args.add("a", uid_enc_key_pair.a);
        scalar_args.add("a0", uid_enc_key_pair.a0);
        scalar_args.add("a1", uid_enc_key_pair.a1);
        scalar_args.add("b", profile_key_enc_key_pair.b);
        scalar_args.add("b0", profile_key_enc_key_pair.b0);
        scalar_args.add("b1", profile_key_enc_key_pair.b1);
        scalar_args.add("m3", uid.m3);
        scalar_args.add("z1", z1);
        scalar_args.add("z2", z2);
        scalar_args.add("m6", profile_key.m6);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_key_pair.A);
        point_args.add("G_a", uid_system.G_a);
        point_args.add("G_a0", uid_system.G_a0);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("B", profile_key_enc_key_pair.B);
        point_args.add("G_b", profile_key_system.G_b);
        point_args.add("G_b0", profile_key_system.G_b0);
        point_args.add("G_b1", profile_key_system.G_b1);
        point_args.add("C_y1-E_A2", C_y1 - uid_ciphertext.E_A2);
        point_args.add("G_y1", credentials_system.G_y1);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("C_y2prime", C_y2prime);
        point_args.add("C_y2", C_y2);
        point_args.add("E_A1", uid_ciphertext.E_A1);
        point_args.add("G_y2", credentials_system.G_y2);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y3);
        point_args.add("G_m3", credentials_system.G_m3);
        point_args.add("C_y4-E_B2", C_y4 - profile_key_ciphertext.E_B2);
        point_args.add("G_y4", credentials_system.G_y4);
        point_args.add("-E_B1", -profile_key_ciphertext.E_B1);
        point_args.add("C_y5prime", C_y5prime);
        point_args.add("C_y5", C_y5);
        point_args.add("E_B1", profile_key_ciphertext.E_B1);
        point_args.add("G_y5", credentials_system.G_y5);
        point_args.add("C_y6", C_y6);
        point_args.add("G_y6", credentials_system.G_y6);
        point_args.add("G_m6", credentials_system.G_m6);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();

        ProfileKeyCredentialPresentationProof {
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_y5,
            C_y6,
            C_x0,
            C_x1,
            C_V,
            C_y2prime,
            C_y5prime,
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
    ) -> Result<(), ZkGroupError> {
        let uid_enc_system = uid_encryption::SystemParams::get_hardcoded();
        let profile_key_enc_system = profile_key_encryption::SystemParams::get_hardcoded();
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_y5,
            C_y6,
            C_V,
            C_y2prime,
            C_y5prime,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_y5, C_y6, C_V, C_y2prime, C_y5prime) = (
            *C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_y4, *C_y5, *C_y6, *C_V, *C_y2prime, *C_y5prime,
        );

        let credentials::KeyPair {
            W,
            x0,
            x1,
            y1,
            y2,
            y3,
            y4,
            y5,
            y6,
            I,
            ..
        } = credentials_key_pair;

        let Z = C_V
            - W
            - x0 * C_x0
            - x1 * C_x1
            - (y1 * C_y1)
            - (y2 * C_y2)
            - (y3 * C_y3)
            - (y4 * C_y4)
            - (y5 * C_y5)
            - (y6 * C_y6);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_public_key.A);
        point_args.add("G_a", uid_enc_system.G_a);
        point_args.add("G_a0", uid_enc_system.G_a0);
        point_args.add("G_a1", uid_enc_system.G_a1);
        point_args.add("B", profile_key_enc_public_key.B);
        point_args.add("G_b", profile_key_enc_system.G_b);
        point_args.add("G_b0", profile_key_enc_system.G_b0);
        point_args.add("G_b1", profile_key_enc_system.G_b1);
        point_args.add("C_y1-E_A2", C_y1 - uid_ciphertext.E_A2);
        point_args.add("G_y1", credentials_system.G_y1);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("C_y2prime", C_y2prime);
        point_args.add("C_y2", C_y2);
        point_args.add("E_A1", uid_ciphertext.E_A1);
        point_args.add("G_y2", credentials_system.G_y2);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y3);
        point_args.add("G_m3", credentials_system.G_m3);
        point_args.add("C_y4-E_B2", C_y4 - profile_key_ciphertext.E_B2);
        point_args.add("G_y4", credentials_system.G_y4);
        point_args.add("-E_B1", -profile_key_ciphertext.E_B1);
        point_args.add("C_y5prime", C_y5prime);
        point_args.add("C_y5", C_y5);
        point_args.add("E_B1", profile_key_ciphertext.E_B1);
        point_args.add("G_y5", credentials_system.G_y5);
        point_args.add("C_y6", C_y6);
        point_args.add("G_y6", credentials_system.G_y6);
        point_args.add("G_m6", credentials_system.G_m6);

        match Self::get_poksho_statement().verify_proof(&poksho_proof, &point_args, &[]) {
            Err(e) => {
                println!("{:?}", e);
                Err(ZkGroupError::ProofVerificationFailure)
            }
            Ok(_) => Ok(()),
        }
    }
}
