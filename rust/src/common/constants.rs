//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

pub const NUM_AUTH_CRED_ATTRIBUTES: usize = 3;
pub const NUM_PROFILE_KEY_CRED_ATTRIBUTES: usize = 4;
pub const NUM_RECEIPT_CRED_ATTRIBUTES: usize = 2;

// NOTE: When any of these values change, codegen.py must also be updated.
pub const AES_KEY_LEN: usize = 32;
pub const AESGCM_NONCE_LEN: usize = 12;
pub const AESGCM_TAG_LEN: usize = 16;
pub const GROUP_MASTER_KEY_LEN: usize = 32;
pub const GROUP_SECRET_PARAMS_LEN: usize = 289;
pub const GROUP_PUBLIC_PARAMS_LEN: usize = 97;
pub const GROUP_IDENTIFIER_LEN: usize = 32;
pub const AUTH_CREDENTIAL_LEN: usize = 181;
pub const AUTH_CREDENTIAL_PRESENTATION_LEN: usize = 493;
pub const AUTH_CREDENTIAL_RESPONSE_LEN: usize = 361;
pub const PROFILE_KEY_LEN: usize = 32;
pub const PROFILE_KEY_CIPHERTEXT_LEN: usize = 65;
pub const PROFILE_KEY_COMMITMENT_LEN: usize = 97;
pub const PROFILE_KEY_CREDENTIAL_LEN: usize = 145;
pub const PROFILE_KEY_CREDENTIAL_PRESENTATION_LEN: usize = 713;
pub const PROFILE_KEY_CREDENTIAL_REQUEST_LEN: usize = 329;
pub const PROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN: usize = 473;
pub const PROFILE_KEY_CREDENTIAL_RESPONSE_LEN: usize = 457;
pub const PROFILE_KEY_VERSION_LEN: usize = 32;
pub const PROFILE_KEY_VERSION_ENCODED_LEN: usize = 64;
pub const RECEIPT_CREDENTIAL_LEN: usize = 129;
pub const RECEIPT_CREDENTIAL_PRESENTATION_LEN: usize = 329;
pub const RECEIPT_CREDENTIAL_REQUEST_LEN: usize = 97;
pub const RECEIPT_CREDENTIAL_REQUEST_CONTEXT_LEN: usize = 177;
pub const RECEIPT_CREDENTIAL_RESPONSE_LEN: usize = 409;
pub const RECEIPT_SERIAL_LEN: usize = 16;
pub const RESERVED_LEN: usize = 1;
pub const SERVER_SECRET_PARAMS_LEN: usize = 1121;
pub const SERVER_PUBLIC_PARAMS_LEN: usize = 225;
pub const UUID_CIPHERTEXT_LEN: usize = 65;
pub const RANDOMNESS_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const UUID_LEN: usize = 16;

pub const TEST_ARRAY_16: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

pub const TEST_ARRAY_16_1: [u8; 16] = [
    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
];

pub const TEST_ARRAY_32: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

pub const TEST_ARRAY_32_1: [u8; 32] = [
    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
    119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
];

pub const TEST_ARRAY_32_2: [u8; 32] = [
    200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218,
    219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
];

pub const TEST_ARRAY_32_3: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];

pub const TEST_ARRAY_32_4: [u8; 32] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33,
];

pub const TEST_ARRAY_32_5: [u8; 32] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34,
];
