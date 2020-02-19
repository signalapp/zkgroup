//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use crate::common::constants::*;
use curve25519_dalek::scalar::Scalar;
use poksho::ShoSha256;

pub type GroupMasterKeyBytes = [u8; GROUP_MASTER_KEY_LEN];
pub type UidBytes = [u8; UUID_LEN];
pub type ProfileKeyBytes = [u8; PROFILE_KEY_LEN];
pub type RandomnessBytes = [u8; RANDOMNESS_LEN];
pub type SignatureBytes = [u8; SIGNATURE_LEN];
pub type ChangeSignatureBytes = [u8; SIGNATURE_LEN];
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

pub fn calculate_scalar(label: &[u8], data: &[u8]) -> Scalar {
    let mut scalar_bytes = [0u8; 64];
    scalar_bytes.copy_from_slice(&ShoSha256::shohash(label, data, 64)[0..64]);
    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}

#[test]
fn test_encode_scalar() {
    let s_bytes = [0xFF; 32];
    match bincode::deserialize::<Scalar>(&s_bytes) {
        Err(_) => (),
        Ok(_) => assert!(false),
    }
}
