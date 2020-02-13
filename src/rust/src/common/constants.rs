//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

pub const MAX_CRED_ATTRIBUTES: usize = 5;

pub const GROUP_MASTER_KEY_LEN: usize = 32;
pub const GROUP_SECRET_PARAMS_LEN: usize = 320;
pub const GROUP_PUBLIC_PARAMS_LEN: usize = 128;
pub const GROUP_IDENTIFIER_LEN: usize = 32;
pub const AUTH_CREDENTIAL_LEN: usize = 372;
pub const AUTH_CREDENTIAL_PRESENTATION_LEN: usize = 620;
pub const AUTH_CREDENTIAL_RESPONSE_LEN: usize = 392;
pub const CLIENT_CREDENTIAL_MANAGER_LEN: usize = 256;
pub const PROFILE_KEY_HALF_LEN: usize = 16;
pub const PROFILE_KEY_LEN: usize = 32;
pub const PROFILE_KEY_CIPHERTEXT_LEN: usize = 64;
pub const PROFILE_KEY_COMMITMENT_LEN: usize = 64;
pub const PROFILE_KEY_CREDENTIAL_LEN: usize = 160;
pub const PROFILE_KEY_CREDENTIAL_PRESENTATION_LEN: usize = 760;
pub const PROFILE_KEY_CREDENTIAL_REQUEST_LEN: usize = 232;
pub const PROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN: usize = 360;
pub const PROFILE_KEY_CREDENTIAL_RESPONSE_LEN: usize = 488;
pub const PROFILE_KEY_VERSION_LEN: usize = 32;
pub const PROFILE_KEY_VERSION_ENCODED_LEN: usize = 64;
pub const SERVER_SECRET_PARAMS_LEN: usize = 608;
pub const SERVER_PUBLIC_PARAMS_LEN: usize = 256;
pub const UUID_CIPHERTEXT_LEN: usize = 64;
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
