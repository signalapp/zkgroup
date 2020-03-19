//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::simple_types::*;
use crate::crypto::profile_key_credential_request;
use crate::crypto::uid_struct;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

#[derive(Copy, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemParameters {
    pub(crate) G_w: RistrettoPoint,
    pub(crate) G_wprime: RistrettoPoint,
    pub(crate) G_x0: RistrettoPoint,
    pub(crate) G_x1: RistrettoPoint,
    pub(crate) G_y1: RistrettoPoint,
    pub(crate) G_y2: RistrettoPoint,
    pub(crate) G_y3: RistrettoPoint,
    pub(crate) G_y4: RistrettoPoint,
    pub(crate) G_y5: RistrettoPoint,
    pub(crate) G_y6: RistrettoPoint,
    pub(crate) G_m1: RistrettoPoint,
    pub(crate) G_m2: RistrettoPoint,
    pub(crate) G_m3: RistrettoPoint,
    pub(crate) G_m4: RistrettoPoint,
    pub(crate) G_m5: RistrettoPoint,
    pub(crate) G_m6: RistrettoPoint,
    pub(crate) G_V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPair {
    // private
    pub(crate) w: Scalar,
    pub(crate) wprime: Scalar,
    pub(crate) W: RistrettoPoint,
    pub(crate) x0: Scalar,
    pub(crate) x1: Scalar,
    pub(crate) y1: Scalar,
    pub(crate) y2: Scalar,
    pub(crate) y3: Scalar,
    pub(crate) y4: Scalar,
    pub(crate) y5: Scalar,
    pub(crate) y6: Scalar,

    // public
    pub(crate) C_W: RistrettoPoint,
    pub(crate) I: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) C_W: RistrettoPoint,
    pub(crate) I: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileKeyCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedProfileKeyCredentialWithSecretNonce {
    pub(crate) rprime: Scalar,
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedProfileKeyCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

pub(crate) fn convert_to_points_uid_struct(
    uid: uid_struct::UidStruct,
    redemption_time: RedemptionTime,
) -> Vec<RistrettoPoint> {
    let system = SystemParameters::get_hardcoded();
    let redemption_time_scalar = encode_redemption_time(redemption_time);
    vec![uid.M1, uid.M2, uid.M3, redemption_time_scalar * system.G_m4]
}

impl SystemParameters {
    pub fn generate() -> Self {
        let G_w = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_w");
        let G_wprime =
            RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_wprime");

        let G_x0 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_x0");
        let G_x1 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_x1");

        let G_y1 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_y1");
        let G_y2 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_y2");
        let G_y3 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_y3");
        let G_y4 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_y4");
        let G_y5 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_y5");
        let G_y6 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_y6");

        let G_m1 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_m1");
        let G_m2 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_m2");
        let G_m3 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_m3");
        let G_m4 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_m4");
        let G_m5 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_m5");
        let G_m6 = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_m6");

        let G_V = RistrettoPoint::hash_from_bytes::<Sha512>(b"Signal_ZKGroup_Mac_Const_G_V");

        SystemParameters {
            G_w,
            G_wprime,
            G_x0,
            G_x1,
            G_y1,
            G_y2,
            G_y3,
            G_y4,
            G_y5,
            G_y6,
            G_m1,
            G_m2,
            G_m3,
            G_m4,
            G_m5,
            G_m6,
            G_V,
        }
    }

    pub fn get_hardcoded() -> SystemParameters {
        bincode::deserialize::<SystemParameters>(&SystemParameters::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 544] = [
        0x80, 0x99, 0x1b, 0x54, 0xfc, 0x18, 0x29, 0xe, 0x85, 0x1f, 0x37, 0x25, 0x86, 0x89, 0x72,
        0xd8, 0xf, 0x6d, 0x53, 0x57, 0xc0, 0xe, 0x78, 0x89, 0x93, 0xfb, 0x3b, 0x43, 0x2, 0x13,
        0x30, 0x22, 0xb0, 0x27, 0xe4, 0x17, 0xd5, 0xd, 0xb0, 0xbd, 0x12, 0xc5, 0x44, 0xd3, 0x8b,
        0x5a, 0xf9, 0x14, 0x8, 0x3c, 0xc6, 0x44, 0xdb, 0x98, 0xf4, 0xaa, 0xee, 0x8c, 0xeb, 0x2f,
        0x45, 0x6c, 0x69, 0x57, 0x28, 0xad, 0xc3, 0xf2, 0xf8, 0xd8, 0xb0, 0x83, 0xc, 0xa8, 0xc9,
        0x15, 0x86, 0x55, 0xe, 0xa4, 0x2c, 0x62, 0x7e, 0xa5, 0x28, 0x85, 0xbf, 0xa6, 0x72, 0x6,
        0x3a, 0x5, 0xfc, 0x1b, 0x92, 0x47, 0x5e, 0x9d, 0xf5, 0xe, 0xe9, 0x9, 0x21, 0xda, 0xf5,
        0x53, 0x65, 0xb1, 0xe0, 0x4c, 0xf8, 0xa, 0xf0, 0x7f, 0x5a, 0x21, 0x65, 0xd2, 0x1e, 0x87,
        0xb, 0x61, 0xaf, 0x81, 0x8b, 0xf, 0x4f, 0x35, 0x84, 0xfa, 0xc4, 0xf8, 0x65, 0xf5, 0x22,
        0xf3, 0x92, 0x5, 0x16, 0xe5, 0xa5, 0x77, 0xd7, 0xab, 0x1d, 0xfd, 0x2, 0xde, 0xa7, 0x2d,
        0xc2, 0x5, 0x90, 0x5c, 0xfa, 0xf1, 0x6, 0xd6, 0x55, 0x25, 0x86, 0x96, 0xcd, 0x72, 0xf0,
        0x9c, 0xef, 0xc, 0x22, 0xe1, 0x59, 0x4c, 0xe6, 0x44, 0xc9, 0xa, 0xce, 0x6e, 0x4b, 0x54,
        0xb0, 0x1, 0x36, 0xd4, 0xe0, 0x3a, 0x93, 0xf6, 0xc2, 0x37, 0x16, 0x46, 0x42, 0x3b, 0xbb,
        0x38, 0x61, 0x2f, 0xf9, 0xe, 0xb4, 0xd8, 0xab, 0x39, 0xb1, 0x24, 0xa0, 0xc3, 0x9d, 0x2d,
        0xa3, 0xfa, 0x4b, 0xc6, 0xf, 0x7d, 0xf6, 0x7d, 0x1f, 0x8f, 0xea, 0x94, 0x93, 0x26, 0x94,
        0xc4, 0x99, 0x97, 0xcd, 0x80, 0xe1, 0x12, 0xd7, 0xfd, 0x20, 0x56, 0x34, 0x80, 0x77, 0x4b,
        0x97, 0x9a, 0xfa, 0xc0, 0xa4, 0x49, 0xc4, 0xbd, 0x82, 0x9f, 0x8, 0xff, 0xff, 0xdf, 0x98,
        0x76, 0xce, 0x1a, 0x6, 0x32, 0xe9, 0xf4, 0xf1, 0xa9, 0x26, 0x73, 0x41, 0x4a, 0x3c, 0x47,
        0xef, 0x41, 0x33, 0xe8, 0xd1, 0xd5, 0x43, 0xbc, 0xd, 0x50, 0xd2, 0xf8, 0xb1, 0xf3, 0x36,
        0x88, 0x83, 0x1b, 0xf2, 0x52, 0x6d, 0x69, 0x6a, 0xd2, 0xd2, 0x99, 0xb1, 0xf4, 0xf5, 0xbc,
        0x33, 0xf0, 0x8b, 0xb0, 0xad, 0x5c, 0x63, 0xb, 0x49, 0xbd, 0x7c, 0xd3, 0x2, 0x56, 0x5f,
        0x20, 0x42, 0x88, 0x99, 0x64, 0xc8, 0x76, 0x3c, 0xd2, 0xa, 0x24, 0xdc, 0xe4, 0x49, 0xa3,
        0xc6, 0xc8, 0x18, 0xf9, 0xf3, 0xc8, 0x36, 0x2a, 0xbd, 0x67, 0x2d, 0xbf, 0x50, 0x30, 0xc7,
        0x5, 0x12, 0xb0, 0x3, 0xf8, 0x72, 0x7b, 0x72, 0x94, 0x3, 0xaf, 0x70, 0x27, 0x69, 0xde,
        0xd3, 0xca, 0xbe, 0x67, 0xc8, 0x5c, 0xc6, 0xec, 0x5e, 0xb8, 0x5d, 0x17, 0xb3, 0x97, 0xf4,
        0x53, 0x68, 0x14, 0xf1, 0x6b, 0xa6, 0x42, 0x53, 0x5f, 0x52, 0x6b, 0x82, 0x40, 0xd, 0xb3,
        0x16, 0x11, 0x99, 0x67, 0x6c, 0x34, 0x6c, 0x3f, 0xc5, 0x3, 0x9, 0x69, 0x56, 0x17, 0x8d,
        0x70, 0xd2, 0xc, 0x21, 0x1b, 0x59, 0xa, 0x7d, 0x74, 0x2, 0x58, 0x5e, 0xcb, 0xe8, 0xae,
        0x3e, 0x2, 0x79, 0x16, 0x91, 0xb1, 0x11, 0xb2, 0xa3, 0xe0, 0x5e, 0x13, 0xf2, 0x51, 0x1b,
        0x88, 0xf3, 0x2a, 0xae, 0xde, 0x25, 0x44, 0x71, 0x7b, 0xdc, 0x3f, 0x22, 0x2, 0xdc, 0x8d,
        0x94, 0xac, 0x8b, 0x1b, 0xd4, 0x96, 0xe4, 0x84, 0x68, 0x1a, 0xb9, 0xd0, 0xc, 0xd7, 0xb4,
        0x34, 0x88, 0xe9, 0x9c, 0x3a, 0xef, 0x1f, 0x97, 0x8f, 0x8, 0xa6, 0xf4, 0x68, 0xaa, 0x65,
        0x3c, 0x88, 0xa3, 0xd1, 0xc6, 0x25, 0x1d, 0x5b, 0xa4, 0x3b, 0x34, 0xc4, 0x7e, 0x5d, 0xad,
        0xfd, 0xf7, 0x33, 0x4e, 0x81, 0x3b, 0x74, 0x37, 0xf7, 0xb4, 0xf7, 0x1e, 0x4d, 0xcf, 0xa5,
        0x52, 0x2e, 0x90, 0x7b, 0xc5, 0xd8, 0x6b, 0x21, 0x91, 0x19, 0x4b, 0xf2, 0x6d, 0x40, 0x63,
        0x4e, 0xfe, 0x49, 0x30, 0xee, 0x2a, 0x61, 0xb5, 0x7, 0x4d, 0x2d, 0x77, 0x50, 0x72, 0x3f,
        0x7a, 0x2, 0x79, 0x1d,
    ];
}

impl KeyPair {
    pub fn generate(randomness: RandomnessBytes, num_attributes: usize) -> Self {
        if num_attributes > 6 || num_attributes < 4 {
            panic!();
        }

        let system = SystemParameters::get_hardcoded();
        let w = calculate_scalar(b"Signal_ZKGroup_Mac_KeyGen_w", &randomness);
        let W = w * system.G_w;
        let wprime = calculate_scalar(b"Signal_ZKGroup_Mac_KeyGen_wprime", &randomness);
        let x0 = calculate_scalar(b"Signal_ZKGroup_Mac_KeyGen_x0", &randomness);
        let x1 = calculate_scalar(b"Signal_ZKGroup_Mac_KeyGen_x1", &randomness);
        let y1 = calculate_scalar(b"Signal_ZKGroup_Mac_Keygen_y1", &randomness);
        let y2 = calculate_scalar(b"Signal_ZKGroup_Mac_Keygen_y2", &randomness);
        let y3 = calculate_scalar(b"Signal_ZKGroup_Mac_Keygen_y3", &randomness);
        let y4 = calculate_scalar(b"Signal_ZKGroup_Mac_Keygen_y4", &randomness);
        let y5 = calculate_scalar(b"Signal_ZKGroup_Mac_Keygen_y5", &randomness);
        let y6 = calculate_scalar(b"Signal_ZKGroup_Mac_Keygen_y6", &randomness);

        let C_W = (w * system.G_w) + (wprime * system.G_wprime);
        let mut I = system.G_V
            - (x0 * system.G_x0)
            - (x1 * system.G_x1)
            - (y1 * system.G_y1)
            - (y2 * system.G_y2)
            - (y3 * system.G_y3)
            - (y4 * system.G_y4);

        if num_attributes > 4 {
            I -= y5 * system.G_y5;
        }
        if num_attributes > 5 {
            I -= y6 * system.G_y6;
        }

        KeyPair {
            w,
            wprime,
            W,
            x0,
            x1,
            y1,
            y2,
            y3,
            y4,
            y5,
            y6,
            C_W,
            I,
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey {
            C_W: self.C_W,
            I: self.I,
        }
    }

    pub fn create_auth_credential(
        &self,
        uid: uid_struct::UidStruct,
        redemption_time: RedemptionTime,
        randomness: RandomnessBytes,
    ) -> AuthCredential {
        let M = convert_to_points_uid_struct(uid, redemption_time);
        let (t, U, V) = self.credential_core(M, randomness);
        AuthCredential { t, U, V }
    }

    fn credential_core(
        &self,
        M: Vec<RistrettoPoint>,
        randomness: RandomnessBytes,
    ) -> (Scalar, RistrettoPoint, RistrettoPoint) {
        if M.len() > 6 {
            panic!();
        }
        let t = calculate_scalar(b"Signal_ZKGroup_MAC_Random_t", &randomness);
        let U = calculate_scalar(b"Signal_ZKGroup_Mac_Random_U", &randomness)
            * RISTRETTO_BASEPOINT_POINT;

        let mut V = self.W + (self.x0 + self.x1 * t) * U;
        V += self.y1 * M[0];
        V += self.y2 * M[1];
        V += self.y3 * M[2];
        if M.len() > 3 {
            V += self.y4 * M[3];
        }
        if M.len() > 4 {
            V += self.y5 * M[4];
        }
        if M.len() > 5 {
            V += self.y6 * M[5];
        }
        (t, U, V)
    }

    pub fn create_blinded_profile_key_credential(
        &self,
        uid: uid_struct::UidStruct,
        public_key: profile_key_credential_request::PublicKey,
        ciphertext: profile_key_credential_request::Ciphertext,
        randomness: RandomnessBytes,
    ) -> BlindedProfileKeyCredentialWithSecretNonce {
        let M = vec![uid.M1, uid.M2, uid.M3];

        let (t, U, Vprime) = self.credential_core(M, randomness);
        let rprime = calculate_scalar(b"Signal_ZKGroup_BlindIssueMac_KeyGen_rprime", &randomness);
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime;
        let S1 =
            R1 + (self.y4 * ciphertext.D1) + (self.y5 * ciphertext.E1) + (self.y6 * ciphertext.F1);
        let S2 =
            R2 + (self.y4 * ciphertext.D2) + (self.y5 * ciphertext.E2) + (self.y6 * ciphertext.F2);
        BlindedProfileKeyCredentialWithSecretNonce {
            rprime,
            t,
            U,
            S1,
            S2,
        }
    }
}

impl BlindedProfileKeyCredentialWithSecretNonce {
    pub fn get_blinded_profile_key_credential(&self) -> BlindedProfileKeyCredential {
        BlindedProfileKeyCredential {
            t: self.t,
            U: self.U,
            S1: self.S1,
            S2: self.S2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;
    use crate::crypto::proofs;

    #[test]
    fn test_system() {
        //let params = SystemParameters::generate();
        //println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParameters::generate() == SystemParameters::get_hardcoded());
    }

    #[test]
    fn test_mac() {
        let keypair = KeyPair::generate(TEST_ARRAY_32, NUM_AUTH_CRED_ATTRIBUTES);

        let uid_bytes = TEST_ARRAY_16;
        let redemption_time = 37;
        let randomness = TEST_ARRAY_32;
        let uid = uid_struct::UidStruct::new(uid_bytes);
        let credential = keypair.create_auth_credential(uid, redemption_time, randomness);
        let proof = proofs::AuthCredentialIssuanceProof::new(
            keypair,
            credential,
            uid,
            redemption_time,
            randomness,
        );

        let public_key = keypair.get_public_key();
        proof
            .verify(public_key, credential, uid, redemption_time)
            .unwrap();

        let keypair_bytes = bincode::serialize(&keypair).unwrap();
        let keypair2 = bincode::deserialize(&keypair_bytes).unwrap();
        assert!(keypair == keypair2);

        let public_key_bytes = bincode::serialize(&public_key).unwrap();
        let public_key2 = bincode::deserialize(&public_key_bytes).unwrap();
        assert!(public_key == public_key2);

        let mac_bytes = bincode::serialize(&credential).unwrap();

        //println!("mac_bytes = {:#x?}", mac_bytes);
        assert!(
            mac_bytes
                == vec![
                    0x56, 0xac, 0x4e, 0x56, 0xb, 0x22, 0x1a, 0xd0, 0xa8, 0xa1, 0xfe, 0xdd, 0xed,
                    0xfb, 0x26, 0x3d, 0x9c, 0x54, 0x67, 0x4b, 0x18, 0x94, 0x52, 0x2, 0x2, 0x4c,
                    0xea, 0xcb, 0x9e, 0x6, 0x18, 0x6, 0xfc, 0xff, 0x19, 0xdf, 0x46, 0x4f, 0x21,
                    0x1e, 0xfb, 0x70, 0xd9, 0xe1, 0x5b, 0xd, 0x8d, 0x90, 0xcc, 0xce, 0x2f, 0x7c,
                    0x42, 0x23, 0x1e, 0x39, 0x3f, 0x90, 0x8a, 0xe8, 0x2d, 0xcb, 0x99, 0x2, 0x7e,
                    0xb9, 0x2, 0x48, 0x9c, 0x2f, 0xe1, 0xaa, 0x9d, 0xb3, 0xa5, 0x95, 0x6a, 0x27,
                    0xc6, 0x4f, 0x23, 0x39, 0x81, 0xbc, 0xfa, 0xeb, 0x10, 0xdc, 0x27, 0x7a, 0x18,
                    0x3a, 0x6d, 0x4a, 0x16, 0x67,
                ]
        );
    }
}
