// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use aptos_crypto::{
    hash::{CryptoHash, CryptoHasher},
    HashValue,
};
use aptos_crypto_derive::CryptoHasher;
use move_core_types::account_address::AccountAddress;
use serde::{Deserialize, Serialize};

const ACCOUNT_ADDRESS_KEY_PREFIX: &str = "acc_blb_|";

#[derive(
    Clone, Debug, CryptoHasher, Eq, PartialEq, Serialize, Deserialize, Ord, PartialOrd, Hash,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
pub enum StateStoreKey {
    AccountAddressKey(AccountAddress),
}

struct RawStateStoreKey {
    bytes: Vec<u8>,
}

impl From<&StateStoreKey> for RawStateStoreKey {
    fn from(key: &StateStoreKey) -> Self {
        match key {
            StateStoreKey::AccountAddressKey(account_address) => {
                let mut account_address_prefix = ACCOUNT_ADDRESS_KEY_PREFIX.as_bytes().to_vec();
                account_address_prefix.extend(account_address.to_vec());
                RawStateStoreKey {
                    bytes: account_address_prefix,
                }
            }
        }
    }
}

impl CryptoHash for StateStoreKey {
    type Hasher = StateStoreKeyHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.update(RawStateStoreKey::from(self).bytes.as_ref());
        state.finish()
    }
}
