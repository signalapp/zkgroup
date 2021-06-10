//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use crate::common::constants::*;
use curve25519_dalek::scalar::Scalar;

pub type AesKeyBytes = [u8; AES_KEY_LEN];
pub type GroupMasterKeyBytes = [u8; GROUP_MASTER_KEY_LEN];
pub type UidBytes = [u8; UUID_LEN];
pub type ProfileKeyBytes = [u8; PROFILE_KEY_LEN];
pub type RandomnessBytes = [u8; RANDOMNESS_LEN];
pub type ReservedBytes = [u8; RESERVED_LEN];
pub type SignatureBytes = [u8; SIGNATURE_LEN];
pub type NotarySignatureBytes = [u8; SIGNATURE_LEN];
pub type GroupIdentifierBytes = [u8; GROUP_IDENTIFIER_LEN];
pub type ProfileKeyVersionBytes = [u8; PROFILE_KEY_VERSION_LEN];
pub type ProfileKeyVersionEncodedBytes = [u8; PROFILE_KEY_VERSION_ENCODED_LEN];
pub type RedemptionTime = u32;

pub fn encode_redemption_time(redemption_time: u32) -> Scalar {
    let mut scalar_bytes: [u8; 32] = Default::default();
    scalar_bytes[0..4].copy_from_slice(&redemption_time.to_be_bytes());
    Scalar::from_bytes_mod_order(scalar_bytes)
}

#[test]
fn test_encode_scalar() {
    let s_bytes = [0xFF; 32];
    match bincode::deserialize::<Scalar>(&s_bytes) {
        Err(_) => (),
        Ok(_) => unreachable!(),
    }
}
