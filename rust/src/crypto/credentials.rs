//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::profile_key_credential_request;
use crate::crypto::uid_struct;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemParams {
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
    let system = SystemParams::get_hardcoded();
    let redemption_time_scalar = encode_redemption_time(redemption_time);
    vec![uid.M1, uid.M2, uid.M3, redemption_time_scalar * system.G_m4]
}

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200416_Constant_Credentials_SystemParams_Generate",
            b"",
        );
        let G_w = sho.get_point();
        let G_wprime = sho.get_point();

        let G_x0 = sho.get_point();
        let G_x1 = sho.get_point();

        let G_y1 = sho.get_point();
        let G_y2 = sho.get_point();
        let G_y3 = sho.get_point();
        let G_y4 = sho.get_point();
        let G_y5 = sho.get_point();
        let G_y6 = sho.get_point();

        let G_m1 = sho.get_point();
        let G_m2 = sho.get_point();
        let G_m3 = sho.get_point();
        let G_m4 = sho.get_point();
        let G_m5 = sho.get_point();
        let G_m6 = sho.get_point();

        let G_V = sho.get_point();

        SystemParams {
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

    pub fn get_hardcoded() -> SystemParams {
        bincode::deserialize::<SystemParams>(&SystemParams::SYSTEM_HARDCODED).unwrap()
    }

    const SYSTEM_HARDCODED: [u8; 544] = [
        0x9e, 0xbf, 0x7e, 0x55, 0x42, 0xbe, 0x53, 0x14, 0x38, 0xc1, 0xfe, 0x53, 0xd9, 0x52, 0xdc,
        0xf5, 0xc6, 0x85, 0x21, 0x4c, 0x4e, 0xf7, 0x77, 0x24, 0x3d, 0x7e, 0x98, 0x87, 0xa6, 0xfc,
        0xf0, 0x4f, 0x76, 0xbb, 0x25, 0xe9, 0xc9, 0xd9, 0x3, 0xaa, 0x58, 0x2, 0x82, 0xfa, 0x36,
        0x8d, 0xba, 0x98, 0x65, 0x84, 0xa8, 0x31, 0x0, 0xd9, 0x2f, 0xa, 0x77, 0x7a, 0xb4, 0x67,
        0xb3, 0x38, 0xd0, 0x5b, 0xb0, 0x1c, 0x78, 0xc0, 0x66, 0xc1, 0x3b, 0xbd, 0xd7, 0xd3, 0x2b,
        0x64, 0xad, 0x47, 0x66, 0xb0, 0x3f, 0xfb, 0x8c, 0x7, 0x78, 0x88, 0xac, 0x91, 0x94, 0xb1,
        0xb9, 0xaa, 0xa3, 0xec, 0x42, 0x11, 0x92, 0x47, 0xe7, 0xb6, 0xe7, 0xa0, 0x3d, 0xb4, 0x8a,
        0x17, 0x8e, 0xfc, 0xeb, 0x57, 0x0, 0xc1, 0xa4, 0x40, 0xf7, 0x65, 0x5b, 0xc1, 0x48, 0xc4,
        0x48, 0x81, 0x91, 0x2, 0xc5, 0xd9, 0x32, 0x38, 0x4c, 0xfd, 0x2e, 0x1a, 0xb1, 0xa, 0xfc,
        0xca, 0x8b, 0x1e, 0x8f, 0xf6, 0xd5, 0x70, 0x90, 0xe9, 0xff, 0x6f, 0x6a, 0x77, 0x70, 0x3c,
        0x17, 0x6a, 0x2a, 0x81, 0x11, 0x57, 0x70, 0xec, 0xa6, 0x30, 0xd2, 0x26, 0x40, 0x9e, 0xc,
        0xc6, 0x82, 0x35, 0x2f, 0x3c, 0x41, 0x6, 0x66, 0xec, 0xbb, 0x44, 0x88, 0x1a, 0x36, 0xee,
        0x2, 0x26, 0x88, 0x1b, 0x7b, 0xd3, 0xe5, 0xf5, 0x41, 0x5b, 0x4a, 0x6d, 0xfe, 0x53, 0x9f,
        0x71, 0x68, 0x90, 0x25, 0xfc, 0xe3, 0xa3, 0x5e, 0x18, 0xd1, 0x60, 0xab, 0x8a, 0xf5, 0x4f,
        0x64, 0x8f, 0x93, 0xd9, 0xec, 0x40, 0xc2, 0x4, 0x99, 0x0, 0x13, 0x9b, 0x0, 0x4f, 0xba,
        0x27, 0x37, 0xef, 0xd8, 0x25, 0x86, 0x2c, 0xf6, 0x54, 0x9f, 0x5f, 0xe0, 0x5c, 0xce, 0x1f,
        0x29, 0x23, 0x66, 0xbc, 0xb5, 0xc2, 0xf6, 0x34, 0xc0, 0xc, 0x74, 0x46, 0xea, 0xc9, 0x8f,
        0x7, 0xb0, 0x67, 0x2e, 0x19, 0xb9, 0xc0, 0x79, 0x8a, 0x7e, 0x1a, 0x8c, 0x45, 0x40, 0xc7,
        0x31, 0x98, 0xd, 0x9d, 0xfe, 0xfe, 0xb5, 0x1c, 0x60, 0x52, 0x8f, 0x7, 0xe5, 0xad, 0xa3,
        0x33, 0x74, 0x50, 0xe2, 0xb1, 0x4b, 0x3d, 0x1d, 0x4e, 0x58, 0xcd, 0x14, 0x5b, 0x7a, 0xcd,
        0x6b, 0xac, 0xee, 0x75, 0x47, 0x57, 0x81, 0x83, 0x6d, 0x94, 0x10, 0x22, 0x76, 0x8f, 0x26,
        0xd5, 0x41, 0x20, 0x1d, 0x6b, 0x6, 0x65, 0xca, 0xe8, 0x98, 0xb4, 0xfa, 0x61, 0x77, 0x98,
        0xd8, 0x8a, 0xd5, 0x97, 0x3d, 0xb5, 0x6e, 0x47, 0xa7, 0xe6, 0xa, 0x42, 0xf7, 0x57, 0x9a,
        0x4d, 0x81, 0x7a, 0x8b, 0x39, 0xd4, 0x4d, 0x22, 0x81, 0x6b, 0xaa, 0xfd, 0x65, 0xae, 0x24,
        0x78, 0xcc, 0xf6, 0x78, 0x71, 0x42, 0x14, 0xad, 0xa6, 0x9a, 0x56, 0x1e, 0xe7, 0xc, 0x4b,
        0xf7, 0x55, 0xd0, 0xdb, 0x6e, 0x9a, 0xaf, 0xab, 0x2d, 0x76, 0x8, 0xb2, 0xa3, 0x4c, 0xb5,
        0x69, 0x89, 0xb0, 0x73, 0x0, 0x29, 0x18, 0x7f, 0xd8, 0x9d, 0x5, 0x8c, 0x10, 0xb3, 0x43,
        0xb8, 0x73, 0xb3, 0x83, 0x39, 0xb9, 0x6d, 0xef, 0xf5, 0x58, 0x6b, 0x80, 0xe8, 0xc, 0xc7,
        0xf4, 0x9e, 0xf2, 0xc2, 0xde, 0x4e, 0x30, 0x6b, 0x5b, 0x7d, 0xfb, 0xf4, 0xae, 0x56, 0xa3,
        0x64, 0x7a, 0xb1, 0x97, 0x65, 0xf9, 0x28, 0x17, 0x8d, 0x9, 0x3f, 0x37, 0x79, 0xcc, 0xd7,
        0x27, 0x3, 0x4e, 0x31, 0x90, 0x27, 0x60, 0x7b, 0x42, 0xc0, 0xda, 0x2c, 0xee, 0x2, 0x8a,
        0x63, 0xe9, 0x15, 0x5c, 0x6e, 0xf1, 0x2b, 0xb9, 0xc6, 0xbc, 0x38, 0x7e, 0xa5, 0x20, 0x26,
        0x90, 0xfa, 0x3, 0xe5, 0xd1, 0x73, 0x40, 0x74, 0xff, 0x27, 0x5e, 0x83, 0x73, 0xb8, 0xbe,
        0x9, 0xcf, 0x9d, 0xfb, 0x24, 0x54, 0x2a, 0x42, 0xf0, 0x2f, 0x66, 0x83, 0xea, 0xba, 0xa9,
        0x28, 0x16, 0x2, 0x34, 0x60, 0xcd, 0xf7, 0x94, 0xe6, 0xcb, 0x5d, 0x54, 0xe2, 0xd4, 0x7a,
        0x49, 0xe6, 0x5e, 0xe7, 0xd8, 0x63, 0xcc, 0xda, 0xb8, 0xa, 0xab, 0x83, 0xa2, 0x73, 0x6e,
        0xe7, 0x35, 0x82, 0x1a,
    ];
}

impl KeyPair {
    pub fn generate(sho: &mut Sho, num_attributes: usize) -> Self {
        if num_attributes > 6 || num_attributes < 4 {
            panic!();
        }

        let system = SystemParams::get_hardcoded();
        let w = sho.get_scalar();
        let W = w * system.G_w;
        let wprime = sho.get_scalar();
        let x0 = sho.get_scalar();
        let x1 = sho.get_scalar();
        let y1 = sho.get_scalar();
        let y2 = sho.get_scalar();
        let y3 = sho.get_scalar();
        let y4 = sho.get_scalar();
        let y5 = sho.get_scalar();
        let y6 = sho.get_scalar();

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
        sho: &mut Sho,
    ) -> AuthCredential {
        let M = convert_to_points_uid_struct(uid, redemption_time);
        let (t, U, V) = self.credential_core(M, sho);
        AuthCredential { t, U, V }
    }

    fn credential_core(
        &self,
        M: Vec<RistrettoPoint>,
        sho: &mut Sho,
    ) -> (Scalar, RistrettoPoint, RistrettoPoint) {
        if M.len() > 6 {
            panic!();
        }
        let t = sho.get_scalar();
        let U = sho.get_point();

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
        sho: &mut Sho,
    ) -> BlindedProfileKeyCredentialWithSecretNonce {
        let M = vec![uid.M1, uid.M2, uid.M3];

        let (t, U, Vprime) = self.credential_core(M, sho);
        let rprime = sho.get_scalar();
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
        //let params = SystemParams::generate();
        //println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_mac() {
        let mut sho = Sho::new(b"Test_Credentials", b"");
        let keypair = KeyPair::generate(&mut sho, NUM_AUTH_CRED_ATTRIBUTES);

        let uid_bytes = TEST_ARRAY_16;
        let redemption_time = 37;
        let uid = uid_struct::UidStruct::new(uid_bytes);
        let credential = keypair.create_auth_credential(uid, redemption_time, &mut sho);
        let proof = proofs::AuthCredentialIssuanceProof::new(
            keypair,
            credential,
            uid,
            redemption_time,
            &mut sho,
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
                    0x2e, 0xf3, 0x98, 0xf1, 0x86, 0x77, 0xc7, 0xf7, 0x24, 0x40, 0x51, 0xaf, 0xe3,
                    0x9, 0x9b, 0xc3, 0x6b, 0xda, 0xfc, 0x98, 0xe9, 0x33, 0xbc, 0xe4, 0x22, 0xb8,
                    0xf1, 0x68, 0xb8, 0x1a, 0x9b, 0xd, 0xac, 0xf0, 0xeb, 0xca, 0xeb, 0xa4, 0xf1,
                    0xe9, 0x67, 0x31, 0xbc, 0xa, 0xc1, 0x3b, 0xbd, 0xfa, 0x82, 0x25, 0x17, 0xb,
                    0x18, 0xb9, 0x14, 0xf8, 0xcd, 0x93, 0x26, 0xa3, 0x42, 0xb1, 0xd, 0x5a, 0xf0,
                    0x96, 0x4, 0x1e, 0x7c, 0x4b, 0x75, 0xe, 0x92, 0xbc, 0xe2, 0x53, 0x16, 0xcd,
                    0xfa, 0xee, 0x3d, 0x16, 0x1a, 0xd5, 0xe, 0x77, 0xab, 0x18, 0xc5, 0x93, 0x48,
                    0xed, 0x64, 0x42, 0xb7, 0x7f,
                ]
        );
    }
}
