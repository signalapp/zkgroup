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
    pub(crate) G_m1: RistrettoPoint,
    pub(crate) G_m2: RistrettoPoint,
    pub(crate) G_m3: RistrettoPoint,
    pub(crate) G_m4: RistrettoPoint,
    pub(crate) G_V: RistrettoPoint,
    pub(crate) G_z: RistrettoPoint,
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
    vec![uid.M1, uid.M2, redemption_time_scalar * system.G_m3]
}

impl SystemParams {
    pub fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Constant_Credentials_SystemParams_Generate",
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

        let G_m1 = sho.get_point();
        let G_m2 = sho.get_point();
        let G_m3 = sho.get_point();
        let G_m4 = sho.get_point();

        let G_V = sho.get_point();
        let G_z = sho.get_point();

        SystemParams {
            G_w,
            G_wprime,
            G_x0,
            G_x1,
            G_y1,
            G_y2,
            G_y3,
            G_y4,
            G_m1,
            G_m2,
            G_m3,
            G_m4,
            G_V,
            G_z,
        }
    }

    pub fn get_hardcoded() -> SystemParams {
       
        let G_w = RistrettoPoint::from_uniform_bytes(&[210, 132, 29, 12, 176, 96, 228, 141, 0, 105, 248, 221, 188, 215, 142, 5, 133, 128, 198, 233, 10, 242, 146, 191, 192, 101, 95, 40, 61, 222, 70, 146, 190, 154, 120, 79, 82, 138, 78, 146, 235, 130, 102, 95, 5, 65, 141, 138, 138, 67, 99, 43, 107, 109, 171, 223, 168, 114, 251, 221, 137, 113, 146, 246]);
        let G_wprime = RistrettoPoint::from_uniform_bytes(&[120, 132, 127, 163, 242, 160, 204, 11, 92, 127, 155, 19, 223, 148, 80, 91, 127, 3, 177, 35, 85, 138, 177, 80, 26, 168, 107, 113, 137, 246, 195, 106, 235, 181, 229, 219, 55, 123, 204, 132, 45, 113, 99, 55, 165, 60, 41, 27, 150, 247, 41, 141, 248, 64, 23, 154, 77, 212, 185, 208, 134, 50, 37, 133]);

        let G_x0 =RistrettoPoint::from_uniform_bytes(&[169, 16, 44, 87, 254, 49, 83, 89, 185, 129, 208, 45, 247, 211, 51, 160, 46, 101, 81, 214, 114, 111, 134, 235, 192, 210, 8, 211, 192, 111, 4, 49, 193, 247, 226, 104, 247, 72, 225, 121, 6, 204, 220, 0, 76, 31, 216, 229, 232, 31, 20, 97, 219, 101, 91, 122, 228, 149, 62, 175, 35, 155, 23, 105]);
        let G_x1 = RistrettoPoint::from_uniform_bytes(&[151, 91, 128, 205, 165, 184, 255, 187, 67, 109, 124, 93, 51, 16, 64, 163, 181, 180, 45, 201, 166, 40, 63, 1, 132, 111, 138, 65, 211, 55, 238, 251, 53, 90, 32, 98, 192, 251, 81, 171, 200, 58, 242, 110, 155, 174, 162, 201, 23, 159, 104, 44, 159, 96, 6, 96, 32, 186, 138, 225, 80, 238, 102, 214]);

        let G_y1 =RistrettoPoint::from_uniform_bytes(&[166, 139, 126, 149, 128, 61, 150, 138, 230, 43, 254, 97, 67, 25, 65, 79, 237, 188, 80, 180, 243, 70, 69, 121, 121, 39, 59, 29, 60, 84, 100, 30, 112, 231, 20, 239, 193, 167, 108, 180, 175, 51, 126, 163, 151, 7, 91, 165, 255, 79, 240, 71, 216, 191, 167, 97, 176, 65, 114, 83, 52, 203, 75, 121]);
        let G_y2 = RistrettoPoint::from_uniform_bytes(&[32, 98, 176, 147, 143, 237, 14, 208, 166, 76, 101, 48, 73, 52, 239, 225, 153, 34, 107, 116, 5, 138, 191, 130, 37, 50, 99, 101, 186, 76, 251, 219, 3, 90, 17, 208, 187, 25, 183, 135, 8, 110, 69, 92, 213, 233, 120, 168, 244, 65, 117, 124, 161, 163, 51, 57, 107, 168, 212, 43, 168, 228, 7, 218]);
        let G_y3 = RistrettoPoint::from_uniform_bytes(&[179, 35, 207, 46, 135, 58, 184, 186, 83, 65, 15, 100, 135, 27, 74, 41, 6, 112, 157, 152, 194, 207, 3, 229, 211, 134, 164, 183, 156, 177, 44, 255, 6, 40, 106, 166, 111, 219, 145, 126, 205, 145, 109, 175, 121, 77, 145, 33, 71, 96, 138, 238, 53, 186, 65, 63, 239, 82, 191, 88, 193, 67, 217, 114]);
        let G_y4 = RistrettoPoint::from_uniform_bytes(&[228, 114, 204, 236, 31, 252, 159, 239, 147, 163, 124, 114, 6, 159, 24, 124, 74, 23, 155, 187, 106, 207, 162, 70, 54, 34, 28, 8, 114, 128, 49, 219, 14, 173, 37, 239, 235, 219, 120, 153, 77, 172, 81, 101, 12, 31, 93, 168, 54, 166, 118, 243, 146, 46, 206, 214, 107, 219, 185, 39, 113, 236, 197, 207]);

        let G_m1 = RistrettoPoint::from_uniform_bytes(&[199, 83, 149, 223, 150, 180, 229, 55, 179, 254, 8, 236, 106, 205, 249, 41, 147, 81, 86, 119, 201, 233, 252, 197, 170, 226, 253, 52, 158, 148, 122, 19, 152, 190, 97, 128, 203, 234, 67, 97, 182, 161, 208, 77, 126, 221, 71, 231, 31, 250, 217, 213, 83, 211, 56, 77, 179, 205, 59, 217, 53, 103, 51, 195]);
        let G_m2 = RistrettoPoint::from_uniform_bytes(&[97, 241, 15, 62, 124, 64, 26, 39, 82, 155, 109, 79, 15, 94, 128, 93, 109, 78, 122, 220, 51, 179, 126, 6, 9, 236, 73, 159, 105, 53, 242, 144, 123, 118, 7, 161, 161, 149, 139, 23, 178, 2, 116, 159, 48, 44, 121, 19, 21, 102, 13, 28, 202, 140, 156, 172, 178, 211, 105, 179, 188, 43, 246, 116]);
        let G_m3 = RistrettoPoint::from_uniform_bytes(&[86, 9, 216, 233, 225, 13, 194, 29, 72, 43, 136, 82, 104, 174, 201, 187, 125, 153, 245, 143, 109, 99, 204, 19, 221, 10, 39, 181, 95, 186, 190, 124, 182, 125, 119, 103, 139, 172, 107, 218, 47, 222, 47, 139, 249, 117, 231, 122, 24, 24, 211, 47, 168, 208, 145, 249, 63, 56, 137, 198, 112, 242, 96, 230]);
        let G_m4 = RistrettoPoint::from_uniform_bytes(&[33, 13, 15, 192, 94, 119, 67, 143, 202, 107, 42, 198, 175, 69, 125, 220, 203, 156, 73, 40, 233, 57, 206, 253, 155, 91, 93, 147, 215, 69, 159, 18, 83, 216, 6, 138, 170, 236, 18, 32, 194, 15, 8, 80, 95, 164, 240, 116, 54, 112, 196, 20, 222, 6, 178, 168, 63, 71, 58, 227, 236, 100, 197, 161]);

        let G_V = RistrettoPoint::from_uniform_bytes(&[162, 150, 216, 191, 54, 170, 148, 210, 187, 191, 215, 255, 118, 195, 143, 11, 139, 230, 75, 190, 161, 44, 88, 82, 157, 170, 129, 56, 41, 174, 67, 132, 51, 206, 85, 149, 148, 41, 49, 61, 19, 82, 132, 135, 58, 109, 179, 99, 221, 198, 76, 246, 75, 18, 246, 221, 133, 2, 121, 168, 88, 183, 230, 222]);
        let G_z = RistrettoPoint::from_uniform_bytes(&[28, 108, 249, 16, 241, 209, 114, 87, 87, 153, 91, 94, 46, 8, 120, 113, 157, 139, 115, 244, 199, 79, 89, 2, 234, 126, 12, 46, 234, 188, 234, 190, 25, 10, 194, 180, 124, 43, 149, 215, 203, 21, 41, 56, 8, 207, 157, 210, 143, 207, 116, 67, 185, 50, 252, 254, 26, 78, 141, 122, 251, 242, 78, 58]);

        SystemParams {
            G_w,
            G_wprime,
            G_x0,
            G_x1,
            G_y1,
            G_y2,
            G_y3,
            G_y4,
            G_m1,
            G_m2,
            G_m3,
            G_m4,
            G_V,
            G_z,
        }
    }
}

impl KeyPair {
    pub fn generate(sho: &mut Sho, num_attributes: usize) -> Self {
        if num_attributes > 4 || num_attributes < 3 {
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

        let C_W = (w * system.G_w) + (wprime * system.G_wprime);
        let mut I = system.G_V
            - (x0 * system.G_x0)
            - (x1 * system.G_x1)
            - (y1 * system.G_y1)
            - (y2 * system.G_y2)
            - (y3 * system.G_y3);

        if num_attributes > 3 {
            I -= y4 * system.G_y4;
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
        if M.len() > 4 {
            panic!();
        }
        let t = sho.get_scalar();
        let U = sho.get_point();

        let mut V = self.W + (self.x0 + self.x1 * t) * U;
        V += self.y1 * M[0];
        V += self.y2 * M[1];
        if M.len() > 2 {
            V += self.y3 * M[2];
        }
        if M.len() > 3 {
            V += self.y4 * M[3];
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
        let M = vec![uid.M1, uid.M2];

        let (t, U, Vprime) = self.credential_core(M, sho);
        let rprime = sho.get_scalar();
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime;
        let S1 = R1 + (self.y3 * ciphertext.D1) + (self.y4 * ciphertext.E1);
        let S2 = R2 + (self.y3 * ciphertext.D2) + (self.y4 * ciphertext.E2);
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
        let params = SystemParams::generate();
        println!("PARAMS = {:#x?}", bincode::serialize(&params));
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

        println!("mac_bytes = {:#x?}", mac_bytes);
        assert!(
            mac_bytes
                == vec![
                    0xe0, 0xce, 0x21, 0xfe, 0xb7, 0xc3, 0xb8, 0x62, 0x3a, 0xe6, 0x20, 0xab, 0x3e,
                    0xe6, 0x5d, 0x94, 0xa3, 0xf3, 0x40, 0x53, 0x31, 0x63, 0xd2, 0x4c, 0x5d, 0x41,
                    0xa0, 0xd6, 0x7a, 0x40, 0xb3, 0x2, 0x8e, 0x50, 0xa2, 0x7b, 0xd4, 0xda, 0xe9,
                    0x9d, 0x60, 0x0, 0xdb, 0x97, 0x3d, 0xbc, 0xc5, 0xad, 0xe1, 0x32, 0xbc, 0x56,
                    0xb0, 0xe1, 0xac, 0x16, 0x7b, 0xb, 0x2c, 0x9, 0xe2, 0xb6, 0xc8, 0x5b, 0x68,
                    0xc8, 0x8e, 0x7d, 0xfd, 0x58, 0x97, 0x51, 0xe9, 0x8, 0x1f, 0x81, 0xb0, 0x24,
                    0xea, 0xa0, 0xaf, 0x29, 0x6, 0xed, 0xb3, 0x9, 0x32, 0xed, 0x65, 0x28, 0x2f,
                    0xa1, 0x79, 0x9e, 0x1, 0x24,
                ]
        );
    }
}
