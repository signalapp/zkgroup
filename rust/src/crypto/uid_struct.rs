//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto::credentials;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::Sha512;

use ZkGroupError::*;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct UidStruct {
    pub(crate) bytes: UidBytes,
    pub(crate) M1: RistrettoPoint,
    pub(crate) M2: RistrettoPoint,
    pub(crate) M3: RistrettoPoint,
    pub(crate) m3: Scalar,
}

impl UidStruct {
    pub fn new(uid_bytes: UidBytes) -> Self {
        let system = credentials::SystemParameters::get_hardcoded();
        let M1 = RistrettoPoint::lizard_encode::<Sha256>(&uid_bytes);
        let M2 = RistrettoPoint::hash_from_bytes::<Sha512>(&uid_bytes);
        let m3 = calculate_scalar(b"Signal_ZKGroup_Enc_Uid_m3", &uid_bytes);
        let M3 = m3 * system.G_m3;
        UidStruct {
            bytes: uid_bytes,
            M1,
            M2,
            M3,
            m3,
        }
    }

    // Might return PointDecodeFailure
    pub fn from_M1(M1: RistrettoPoint) -> Result<Self, ZkGroupError> {
        match M1.lizard_decode::<Sha256>() {
            None => Err(PointDecodeFailure),
            Some(bytes) => Ok(Self::new(bytes)),
        }
    }

    pub fn to_bytes(&self) -> UidBytes {
        self.bytes
    }
}
