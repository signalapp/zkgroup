//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::api;
use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct AuthCredential {
    pub(crate) credential: crypto::credentials::AuthCredential,
    pub(crate) server_public_params: api::ServerPublicParams,
    pub(crate) uid_bytes: UidBytes,
    pub(crate) redemption_time: RedemptionTime,
}
