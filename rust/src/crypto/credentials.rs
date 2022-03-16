//
// Copyright (C) 2020-2021 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::common::array_utils::{ArrayLike, OneBased};
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::receipt_struct::ReceiptStruct;
use crate::crypto::uid_struct;
use crate::crypto::{profile_key_credential_request, receipt_credential_request, receipt_struct};
use crate::{
    NUM_AUTH_CRED_ATTRIBUTES, NUM_PROFILE_KEY_CRED_ATTRIBUTES, NUM_RECEIPT_CRED_ATTRIBUTES,
};

const NUM_SUPPORTED_ATTRS: usize = 6;
#[derive(Copy, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemParams {
    pub(crate) G_w: RistrettoPoint,
    pub(crate) G_wprime: RistrettoPoint,
    pub(crate) G_x0: RistrettoPoint,
    pub(crate) G_x1: RistrettoPoint,
    pub(crate) G_y: OneBased<[RistrettoPoint; NUM_SUPPORTED_ATTRS]>,
    pub(crate) G_m1: RistrettoPoint,
    pub(crate) G_m2: RistrettoPoint,
    pub(crate) G_m3: RistrettoPoint,
    pub(crate) G_m4: RistrettoPoint,
    pub(crate) G_V: RistrettoPoint,
    pub(crate) G_z: RistrettoPoint,
}

/// Used to specialize a [`KeyPair<S>`] to support a certain number of attributes.
///
/// The only required member is `Storage`, which should be a fixed-size array of [`Scalar`], one for
/// each attribute. However, for backwards compatibility some systems support fewer attributes than
/// are actually stored, and in this case the `NUM_ATTRS` member can be set to a custom value. Note
/// that `NUM_ATTRS` must always be less than or equal to the number of elements in `Storage`.
pub trait AttrScalars {
    /// The storage (should be a fixed-size array of Scalar).
    type Storage: ArrayLike<Scalar> + Copy + Eq + Serialize + for<'a> Deserialize<'a>;

    /// The number of attributes supported in this system.
    ///
    /// Defaults to the full set stored in `Self::Storage`.
    const NUM_ATTRS: usize = Self::Storage::LEN;
}

impl AttrScalars for AuthCredential {
    // Store four scalars for backwards compatibility.
    type Storage = [Scalar; 4];
    const NUM_ATTRS: usize = NUM_AUTH_CRED_ATTRIBUTES;
}
impl AttrScalars for ProfileKeyCredential {
    // Store four scalars for backwards compatibility.
    type Storage = [Scalar; 4];
    const NUM_ATTRS: usize = NUM_PROFILE_KEY_CRED_ATTRIBUTES;
}
impl AttrScalars for ReceiptCredential {
    // Store four scalars for backwards compatibility.
    type Storage = [Scalar; 4];
    const NUM_ATTRS: usize = NUM_RECEIPT_CRED_ATTRIBUTES;
}
impl AttrScalars for PniCredential {
    type Storage = [Scalar; 6];
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair<S: AttrScalars> {
    // private
    pub(crate) w: Scalar,
    pub(crate) wprime: Scalar,
    pub(crate) W: RistrettoPoint,
    pub(crate) x0: Scalar,
    pub(crate) x1: Scalar,
    pub(crate) y: OneBased<S::Storage>,

    // public
    pub(crate) C_W: RistrettoPoint,
    pub(crate) I: RistrettoPoint,
}

impl<S: AttrScalars> Clone for KeyPair<S> {
    fn clone(&self) -> Self {
        // Rely on Copy
        *self
    }
}

impl<S: AttrScalars> Copy for KeyPair<S> {}

impl<S: AttrScalars> PartialEq for KeyPair<S> {
    fn eq(&self, other: &Self) -> bool {
        self.w == other.w
            && self.wprime == other.wprime
            && self.W == other.W
            && self.x0 == other.x0
            && self.x1 == other.x1
            && self.y == other.y
            && self.C_W == other.C_W
            && self.I == other.I
    }
}
impl<S: AttrScalars> Eq for KeyPair<S> {}

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

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct PniCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}
#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedPniCredentialWithSecretNonce {
    pub(crate) rprime: Scalar,
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedPniCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedReceiptCredentialWithSecretNonce {
    pub(crate) rprime: Scalar,
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedReceiptCredential {
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

pub(crate) fn convert_to_points_receipt_struct(
    receipt: receipt_struct::ReceiptStruct,
) -> Vec<RistrettoPoint> {
    let system = SystemParams::get_hardcoded();
    let m1 = receipt.calc_m1();
    let receipt_serial_scalar = encode_receipt_serial_bytes(receipt.receipt_serial_bytes);
    vec![m1 * system.G_m1, receipt_serial_scalar * system.G_m2]
}

pub(crate) fn convert_to_point_M2_receipt_serial_bytes(
    receipt_serial_bytes: ReceiptSerialBytes,
) -> RistrettoPoint {
    let system = SystemParams::get_hardcoded();
    let receipt_serial_scalar = encode_receipt_serial_bytes(receipt_serial_bytes);
    receipt_serial_scalar * system.G_m2
}

impl SystemParams {
    #[cfg(test)]
    fn generate() -> Self {
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

        // We don't ever want to use existing generator points in new ways,
        // so new points have to be added at the end.
        let G_y5 = sho.get_point();
        let G_y6 = sho.get_point();

        SystemParams {
            G_w,
            G_wprime,
            G_x0,
            G_x1,
            G_y: OneBased([G_y1, G_y2, G_y3, G_y4, G_y5, G_y6]),
            G_m1,
            G_m2,
            G_m3,
            G_m4,
            G_V,
            G_z,
        }
    }

    pub fn get_hardcoded() -> SystemParams {
        let G_w = RistrettoPoint::from_uniform_bytes(&[
            0xd2, 0x84, 0x1d, 0xc, 0xb0, 0x60, 0xe4, 0x8d, 0x0, 0x69, 0xf8, 0xdd, 0xbc, 0xd7, 0x8e,
            0x5, 0x85, 0x80, 0xc6, 0xe9, 0xa, 0xf2, 0x92, 0xbf, 0xc0, 0x65, 0x5f, 0x28, 0x3d, 0xde,
            0x46, 0x92, 0xbe, 0x9a, 0x78, 0x4f, 0x52, 0x8a, 0x4e, 0x92, 0xeb, 0x82, 0x66, 0x5f,
            0x5, 0x41, 0x8d, 0x8a, 0x8a, 0x43, 0x63, 0x2b, 0x6b, 0x6d, 0xab, 0xdf, 0xa8, 0x72,
            0xfb, 0xdd, 0x89, 0x71, 0x92, 0xf6,
        ]);

        let G_wprime = RistrettoPoint::from_uniform_bytes(&[
            0x78, 0x84, 0x7f, 0xa3, 0xf2, 0xa0, 0xcc, 0xb, 0x5c, 0x7f, 0x9b, 0x13, 0xdf, 0x94,
            0x50, 0x5b, 0x7f, 0x3, 0xb1, 0x23, 0x55, 0x8a, 0xb1, 0x50, 0x1a, 0xa8, 0x6b, 0x71,
            0x89, 0xf6, 0xc3, 0x6a, 0xeb, 0xb5, 0xe5, 0xdb, 0x37, 0x7b, 0xcc, 0x84, 0x2d, 0x71,
            0x63, 0x37, 0xa5, 0x3c, 0x29, 0x1b, 0x96, 0xf7, 0x29, 0x8d, 0xf8, 0x40, 0x17, 0x9a,
            0x4d, 0xd4, 0xb9, 0xd0, 0x86, 0x32, 0x25, 0x85,
        ]);

        let G_x0 = RistrettoPoint::from_uniform_bytes(&[
            0xa9, 0x10, 0x2c, 0x57, 0xfe, 0x31, 0x53, 0x59, 0xb9, 0x81, 0xd0, 0x2d, 0xf7, 0xd3,
            0x33, 0xa0, 0x2e, 0x65, 0x51, 0xd6, 0x72, 0x6f, 0x86, 0xeb, 0xc0, 0xd2, 0x8, 0xd3,
            0xc0, 0x6f, 0x4, 0x31, 0xc1, 0xf7, 0xe2, 0x68, 0xf7, 0x48, 0xe1, 0x79, 0x6, 0xcc, 0xdc,
            0x0, 0x4c, 0x1f, 0xd8, 0xe5, 0xe8, 0x1f, 0x14, 0x61, 0xdb, 0x65, 0x5b, 0x7a, 0xe4,
            0x95, 0x3e, 0xaf, 0x23, 0x9b, 0x17, 0x69,
        ]);
        let G_x1 = RistrettoPoint::from_uniform_bytes(&[
            0x97, 0x5b, 0x80, 0xcd, 0xa5, 0xb8, 0xff, 0xbb, 0x43, 0x6d, 0x7c, 0x5d, 0x33, 0x10,
            0x40, 0xa3, 0xb5, 0xb4, 0x2d, 0xc9, 0xa6, 0x28, 0x3f, 0x1, 0x84, 0x6f, 0x8a, 0x41,
            0xd3, 0x37, 0xee, 0xfb, 0x35, 0x5a, 0x20, 0x62, 0xc0, 0xfb, 0x51, 0xab, 0xc8, 0x3a,
            0xf2, 0x6e, 0x9b, 0xae, 0xa2, 0xc9, 0x17, 0x9f, 0x68, 0x2c, 0x9f, 0x60, 0x6, 0x60,
            0x20, 0xba, 0x8a, 0xe1, 0x50, 0xee, 0x66, 0xd6,
        ]);
        let G_y1 = RistrettoPoint::from_uniform_bytes(&[
            0xa6, 0x8b, 0x7e, 0x95, 0x80, 0x3d, 0x96, 0x8a, 0xe6, 0x2b, 0xfe, 0x61, 0x43, 0x19,
            0x41, 0x4f, 0xed, 0xbc, 0x50, 0xb4, 0xf3, 0x46, 0x45, 0x79, 0x79, 0x27, 0x3b, 0x1d,
            0x3c, 0x54, 0x64, 0x1e, 0x70, 0xe7, 0x14, 0xef, 0xc1, 0xa7, 0x6c, 0xb4, 0xaf, 0x33,
            0x7e, 0xa3, 0x97, 0x7, 0x5b, 0xa5, 0xff, 0x4f, 0xf0, 0x47, 0xd8, 0xbf, 0xa7, 0x61,
            0xb0, 0x41, 0x72, 0x53, 0x34, 0xcb, 0x4b, 0x79,
        ]);
        let G_y2 = RistrettoPoint::from_uniform_bytes(&[
            0x20, 0x62, 0xb0, 0x93, 0x8f, 0xed, 0xe, 0xd0, 0xa6, 0x4c, 0x65, 0x30, 0x49, 0x34,
            0xef, 0xe1, 0x99, 0x22, 0x6b, 0x74, 0x5, 0x8a, 0xbf, 0x82, 0x25, 0x32, 0x63, 0x65,
            0xba, 0x4c, 0xfb, 0xdb, 0x3, 0x5a, 0x11, 0xd0, 0xbb, 0x19, 0xb7, 0x87, 0x8, 0x6e, 0x45,
            0x5c, 0xd5, 0xe9, 0x78, 0xa8, 0xf4, 0x41, 0x75, 0x7c, 0xa1, 0xa3, 0x33, 0x39, 0x6b,
            0xa8, 0xd4, 0x2b, 0xa8, 0xe4, 0x7, 0xda,
        ]);
        let G_y3 = RistrettoPoint::from_uniform_bytes(&[
            0xb3, 0x23, 0xcf, 0x2e, 0x87, 0x3a, 0xb8, 0xba, 0x53, 0x41, 0xf, 0x64, 0x87, 0x1b,
            0x4a, 0x29, 0x6, 0x70, 0x9d, 0x98, 0xc2, 0xcf, 0x3, 0xe5, 0xd3, 0x86, 0xa4, 0xb7, 0x9c,
            0xb1, 0x2c, 0xff, 0x6, 0x28, 0x6a, 0xa6, 0x6f, 0xdb, 0x91, 0x7e, 0xcd, 0x91, 0x6d,
            0xaf, 0x79, 0x4d, 0x91, 0x21, 0x47, 0x60, 0x8a, 0xee, 0x35, 0xba, 0x41, 0x3f, 0xef,
            0x52, 0xbf, 0x58, 0xc1, 0x43, 0xd9, 0x72,
        ]);
        let G_y4 = RistrettoPoint::from_uniform_bytes(&[
            0xe4, 0x72, 0xcc, 0xec, 0x1f, 0xfc, 0x9f, 0xef, 0x93, 0xa3, 0x7c, 0x72, 0x6, 0x9f,
            0x18, 0x7c, 0x4a, 0x17, 0x9b, 0xbb, 0x6a, 0xcf, 0xa2, 0x46, 0x36, 0x22, 0x1c, 0x8,
            0x72, 0x80, 0x31, 0xdb, 0xe, 0xad, 0x25, 0xef, 0xeb, 0xdb, 0x78, 0x99, 0x4d, 0xac,
            0x51, 0x65, 0xc, 0x1f, 0x5d, 0xa8, 0x36, 0xa6, 0x76, 0xf3, 0x92, 0x2e, 0xce, 0xd6,
            0x6b, 0xdb, 0xb9, 0x27, 0x71, 0xec, 0xc5, 0xcf,
        ]);
        let G_m1 = RistrettoPoint::from_uniform_bytes(&[
            0xc7, 0x53, 0x95, 0xdf, 0x96, 0xb4, 0xe5, 0x37, 0xb3, 0xfe, 0x8, 0xec, 0x6a, 0xcd,
            0xf9, 0x29, 0x93, 0x51, 0x56, 0x77, 0xc9, 0xe9, 0xfc, 0xc5, 0xaa, 0xe2, 0xfd, 0x34,
            0x9e, 0x94, 0x7a, 0x13, 0x98, 0xbe, 0x61, 0x80, 0xcb, 0xea, 0x43, 0x61, 0xb6, 0xa1,
            0xd0, 0x4d, 0x7e, 0xdd, 0x47, 0xe7, 0x1f, 0xfa, 0xd9, 0xd5, 0x53, 0xd3, 0x38, 0x4d,
            0xb3, 0xcd, 0x3b, 0xd9, 0x35, 0x67, 0x33, 0xc3,
        ]);
        let G_m2 = RistrettoPoint::from_uniform_bytes(&[
            0x61, 0xf1, 0xf, 0x3e, 0x7c, 0x40, 0x1a, 0x27, 0x52, 0x9b, 0x6d, 0x4f, 0xf, 0x5e, 0x80,
            0x5d, 0x6d, 0x4e, 0x7a, 0xdc, 0x33, 0xb3, 0x7e, 0x6, 0x9, 0xec, 0x49, 0x9f, 0x69, 0x35,
            0xf2, 0x90, 0x7b, 0x76, 0x7, 0xa1, 0xa1, 0x95, 0x8b, 0x17, 0xb2, 0x2, 0x74, 0x9f, 0x30,
            0x2c, 0x79, 0x13, 0x15, 0x66, 0xd, 0x1c, 0xca, 0x8c, 0x9c, 0xac, 0xb2, 0xd3, 0x69,
            0xb3, 0xbc, 0x2b, 0xf6, 0x74,
        ]);
        let G_m3 = RistrettoPoint::from_uniform_bytes(&[
            0x56, 0x9, 0xd8, 0xe9, 0xe1, 0xd, 0xc2, 0x1d, 0x48, 0x2b, 0x88, 0x52, 0x68, 0xae, 0xc9,
            0xbb, 0x7d, 0x99, 0xf5, 0x8f, 0x6d, 0x63, 0xcc, 0x13, 0xdd, 0xa, 0x27, 0xb5, 0x5f,
            0xba, 0xbe, 0x7c, 0xb6, 0x7d, 0x77, 0x67, 0x8b, 0xac, 0x6b, 0xda, 0x2f, 0xde, 0x2f,
            0x8b, 0xf9, 0x75, 0xe7, 0x7a, 0x18, 0x18, 0xd3, 0x2f, 0xa8, 0xd0, 0x91, 0xf9, 0x3f,
            0x38, 0x89, 0xc6, 0x70, 0xf2, 0x60, 0xe6,
        ]);
        let G_m4 = RistrettoPoint::from_uniform_bytes(&[
            0x21, 0xd, 0xf, 0xc0, 0x5e, 0x77, 0x43, 0x8f, 0xca, 0x6b, 0x2a, 0xc6, 0xaf, 0x45, 0x7d,
            0xdc, 0xcb, 0x9c, 0x49, 0x28, 0xe9, 0x39, 0xce, 0xfd, 0x9b, 0x5b, 0x5d, 0x93, 0xd7,
            0x45, 0x9f, 0x12, 0x53, 0xd8, 0x6, 0x8a, 0xaa, 0xec, 0x12, 0x20, 0xc2, 0xf, 0x8, 0x50,
            0x5f, 0xa4, 0xf0, 0x74, 0x36, 0x70, 0xc4, 0x14, 0xde, 0x6, 0xb2, 0xa8, 0x3f, 0x47,
            0x3a, 0xe3, 0xec, 0x64, 0xc5, 0xa1,
        ]);
        let G_V = RistrettoPoint::from_uniform_bytes(&[
            0xa2, 0x96, 0xd8, 0xbf, 0x36, 0xaa, 0x94, 0xd2, 0xbb, 0xbf, 0xd7, 0xff, 0x76, 0xc3,
            0x8f, 0xb, 0x8b, 0xe6, 0x4b, 0xbe, 0xa1, 0x2c, 0x58, 0x52, 0x9d, 0xaa, 0x81, 0x38,
            0x29, 0xae, 0x43, 0x84, 0x33, 0xce, 0x55, 0x95, 0x94, 0x29, 0x31, 0x3d, 0x13, 0x52,
            0x84, 0x87, 0x3a, 0x6d, 0xb3, 0x63, 0xdd, 0xc6, 0x4c, 0xf6, 0x4b, 0x12, 0xf6, 0xdd,
            0x85, 0x2, 0x79, 0xa8, 0x58, 0xb7, 0xe6, 0xde,
        ]);
        let G_z = RistrettoPoint::from_uniform_bytes(&[
            0x1c, 0x6c, 0xf9, 0x10, 0xf1, 0xd1, 0x72, 0x57, 0x57, 0x99, 0x5b, 0x5e, 0x2e, 0x8,
            0x78, 0x71, 0x9d, 0x8b, 0x73, 0xf4, 0xc7, 0x4f, 0x59, 0x2, 0xea, 0x7e, 0xc, 0x2e, 0xea,
            0xbc, 0xea, 0xbe, 0x19, 0xa, 0xc2, 0xb4, 0x7c, 0x2b, 0x95, 0xd7, 0xcb, 0x15, 0x29,
            0x38, 0x8, 0xcf, 0x9d, 0xd2, 0x8f, 0xcf, 0x74, 0x43, 0xb9, 0x32, 0xfc, 0xfe, 0x1a,
            0x4e, 0x8d, 0x7a, 0xfb, 0xf2, 0x4e, 0x3a,
        ]);

        // We don't ever want to use existing generator points in new ways,
        // so new points have to be added at the end.
        let G_y5 = RistrettoPoint::from_uniform_bytes(&[
            0xe7, 0xce, 0xe0, 0x19, 0xd6, 0xca, 0x39, 0x51, 0x86, 0x5a, 0xf6, 0xca, 0x41, 0x36,
            0xe4, 0x27, 0x28, 0xc5, 0xd1, 0x91, 0xe5, 0xd2, 0x94, 0x9a, 0x8a, 0x47, 0x6f, 0xe9,
            0x49, 0xbc, 0x40, 0x4e, 0xa6, 0xe6, 0x8, 0x7, 0x58, 0xb4, 0x1f, 0xa6, 0x4e, 0xab, 0xef,
            0x35, 0x0, 0x8a, 0x51, 0xc1, 0x71, 0x7, 0x76, 0x72, 0xae, 0x2b, 0xcf, 0xcc, 0x44, 0x54,
            0xdb, 0xa4, 0x3d, 0x84, 0xa1, 0x66,
        ]);
        let G_y6 = RistrettoPoint::from_uniform_bytes(&[
            0x5e, 0x2c, 0xbe, 0xdd, 0xdd, 0x8c, 0xd9, 0x46, 0xf7, 0x13, 0x3, 0x28, 0x11, 0xfe,
            0x94, 0x1d, 0x1c, 0x3, 0x87, 0xc1, 0x89, 0x54, 0xa0, 0xe0, 0xe0, 0xa9, 0x25, 0xe3,
            0x8d, 0x8f, 0x55, 0x32, 0x86, 0xa, 0x69, 0x3e, 0x9, 0xc1, 0x51, 0x6a, 0xd2, 0x6e, 0x99,
            0xc6, 0x5, 0x76, 0xd8, 0xdb, 0x75, 0xa7, 0xdc, 0x30, 0x2d, 0x73, 0x28, 0x7a, 0x7, 0x11,
            0xe8, 0xf3, 0xea, 0xff, 0x14, 0x2c,
        ]);

        SystemParams {
            G_w,
            G_wprime,
            G_x0,
            G_x1,
            G_y: OneBased([G_y1, G_y2, G_y3, G_y4, G_y5, G_y6]),
            G_m1,
            G_m2,
            G_m3,
            G_m4,
            G_V,
            G_z,
        }
    }
}

impl<S: AttrScalars> KeyPair<S> {
    pub fn generate(sho: &mut Sho) -> Self {
        assert!(S::NUM_ATTRS >= 1, "at least one attribute required");
        assert!(
            S::NUM_ATTRS <= NUM_SUPPORTED_ATTRS,
            "more than {} attributes not supported",
            NUM_SUPPORTED_ATTRS
        );
        assert!(
            S::NUM_ATTRS <= S::Storage::LEN,
            "more attributes than storage",
        );

        let system = SystemParams::get_hardcoded();
        let w = sho.get_scalar();
        let W = w * system.G_w;
        let wprime = sho.get_scalar();
        let x0 = sho.get_scalar();
        let x1 = sho.get_scalar();

        let y = OneBased::<S::Storage>::create(|| sho.get_scalar());

        let C_W = (w * system.G_w) + (wprime * system.G_wprime);
        let mut I = system.G_V - (x0 * system.G_x0) - (x1 * system.G_x1);

        for (yn, G_yn) in y.iter().zip(system.G_y.iter()).take(S::NUM_ATTRS) {
            I -= yn * G_yn;
        }

        KeyPair {
            w,
            wprime,
            W,
            x0,
            x1,
            y,
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

    fn credential_core(
        &self,
        M: &[RistrettoPoint],
        sho: &mut Sho,
    ) -> (Scalar, RistrettoPoint, RistrettoPoint) {
        assert!(
            M.len() <= S::NUM_ATTRS,
            "more than {} attributes not supported",
            S::NUM_ATTRS
        );
        let t = sho.get_scalar();
        let U = sho.get_point();

        let mut V = self.W + (self.x0 + self.x1 * t) * U;
        for (yn, Mn) in self.y.iter().zip(M) {
            V += yn * Mn;
        }
        (t, U, V)
    }
}

impl KeyPair<AuthCredential> {
    pub fn create_auth_credential(
        &self,
        uid: uid_struct::UidStruct,
        redemption_time: RedemptionTime,
        sho: &mut Sho,
    ) -> AuthCredential {
        let M = convert_to_points_uid_struct(uid, redemption_time);
        let (t, U, V) = self.credential_core(&M, sho);
        AuthCredential { t, U, V }
    }
}

impl KeyPair<ProfileKeyCredential> {
    pub fn create_blinded_profile_key_credential(
        &self,
        uid: uid_struct::UidStruct,
        public_key: profile_key_credential_request::PublicKey,
        ciphertext: profile_key_credential_request::Ciphertext,
        sho: &mut Sho,
    ) -> BlindedProfileKeyCredentialWithSecretNonce {
        let M = [uid.M1, uid.M2];

        let (t, U, Vprime) = self.credential_core(&M, sho);
        let rprime = sho.get_scalar();
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime;
        let S1 = R1 + (self.y[3] * ciphertext.D1) + (self.y[4] * ciphertext.E1);
        let S2 = R2 + (self.y[3] * ciphertext.D2) + (self.y[4] * ciphertext.E2);
        BlindedProfileKeyCredentialWithSecretNonce {
            rprime,
            t,
            U,
            S1,
            S2,
        }
    }
}

impl KeyPair<PniCredential> {
    pub fn create_blinded_pni_credential(
        &self,
        uid: uid_struct::UidStruct,
        pni: uid_struct::UidStruct,
        public_key: profile_key_credential_request::PublicKey,
        ciphertext: profile_key_credential_request::Ciphertext,
        sho: &mut Sho,
    ) -> BlindedPniCredentialWithSecretNonce {
        let M = [uid.M1, uid.M2];

        let (t, U, Vprime) = self.credential_core(&M, sho);
        let Vprime_with_pni = Vprime + (self.y[5] * pni.M1) + (self.y[6] * pni.M2);
        let rprime = sho.get_scalar();
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime_with_pni;
        let S1 = R1 + (self.y[3] * ciphertext.D1) + (self.y[4] * ciphertext.E1);
        let S2 = R2 + (self.y[3] * ciphertext.D2) + (self.y[4] * ciphertext.E2);
        BlindedPniCredentialWithSecretNonce {
            rprime,
            t,
            U,
            S1,
            S2,
        }
    }
}

impl KeyPair<ReceiptCredential> {
    pub fn create_blinded_receipt_credential(
        &self,
        public_key: receipt_credential_request::PublicKey,
        ciphertext: receipt_credential_request::Ciphertext,
        receipt_expiration_time: ReceiptExpirationTime,
        receipt_level: ReceiptLevel,
        sho: &mut Sho,
    ) -> BlindedReceiptCredentialWithSecretNonce {
        let params = SystemParams::get_hardcoded();
        let m1 = ReceiptStruct::calc_m1_from(receipt_expiration_time, receipt_level);
        let M = [m1 * params.G_m1];

        let (t, U, Vprime) = self.credential_core(&M, sho);
        let rprime = sho.get_scalar();
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime;
        let S1 = self.y[2] * ciphertext.D1 + R1;
        let S2 = self.y[2] * ciphertext.D2 + R2;
        BlindedReceiptCredentialWithSecretNonce {
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

impl BlindedPniCredentialWithSecretNonce {
    pub fn get_blinded_pni_credential(&self) -> BlindedPniCredential {
        BlindedPniCredential {
            t: self.t,
            U: self.U,
            S1: self.S1,
            S2: self.S2,
        }
    }
}

impl BlindedReceiptCredentialWithSecretNonce {
    pub fn get_blinded_receipt_credential(&self) -> BlindedReceiptCredential {
        BlindedReceiptCredential {
            t: self.t,
            U: self.U,
            S1: self.S1,
            S2: self.S2,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::constants::*;
    use crate::crypto::proofs;

    use super::*;

    #[test]
    fn test_system() {
        let params = SystemParams::generate();
        println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_mac() {
        let mut sho = Sho::new(b"Test_Credentials", b"");
        let keypair = KeyPair::<AuthCredential>::generate(&mut sho);

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
