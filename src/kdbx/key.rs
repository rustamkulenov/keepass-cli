/*
   Copyright 2021 Rustam Kulenov

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

use core::panic;

use cipher::generic_array::{typenum::U32, typenum::U64, GenericArray};
use hmac_sha256::*;
use sha2::{Digest, Sha256, Sha512};

use super::crypt::kdf::{AesKdf, Kdf};

pub trait Key {
    // A HMAC Key for a header
    fn header_hmac_key(&self) -> GenericArray<u8, U64>;

    // A HMAC Key for a payload
    fn payload_hmac_key(&self) -> GenericArray<u8, U64>;

    // A key used for symmetric encryption/decryption
    fn master_key(&self) -> GenericArray<u8, U32>;
}

pub trait KeyItem {
    fn raw_key(&self) -> Vec<u8>;
}

pub struct PasswordKey {
    // SHA256 of a password
    passw_hash: [u8; 32],
}

pub struct CompositeKey<T: KeyItem> {
    items: Vec<T>,
    transformed: GenericArray<u8, U32>,
    is_transformed: bool,
    rounds: u64,
    master_seed: Vec<u8>,
    seed: Vec<u8>,
}

impl PasswordKey {
    pub fn new(passw: &str) -> PasswordKey {
        PasswordKey {
            passw_hash: Hash::hash(passw.as_bytes()),
        }
    }
}

impl KeyItem for PasswordKey {
    // Simply returns SHA256 of password string as bytes array (32 bytes).
    fn raw_key(&self) -> Vec<u8> {
        self.passw_hash.to_vec()
    }
}

impl<T: KeyItem> CompositeKey<T> {
    pub fn new(master_seed: Vec<u8>, seed: Vec<u8>, rounds: u64) -> CompositeKey<T> {
        CompositeKey {
            items: vec![],
            transformed: GenericArray::default(),
            is_transformed: false,
            rounds,
            seed,
            master_seed,
        }
    }

    // Adds an item into composite key if it is not transformed yet.
    pub fn add(&mut self, item: T) {
        if self.is_transformed {
            panic!("Can not add items to transformed composite key");
        }
        self.items.push(item);
    }

    // Returns SHA256 of all concatenated keys (32 bytes).
    fn raw_key(&self) -> GenericArray<u8, U32> {
        let mut sha = Sha256::new();
        for item in &self.items {
            sha.update(item.raw_key());
        }

        sha.finalize()
    }

    // SHA512 of [UINT64_MAX | hmac_key_keepass2]
    // UINT64_MAX is 16 0xFF
    fn hmac_key(&self) -> GenericArray<u8, U64> {
        self.hmac_key_for_index(u64::MAX)
    }

    // Transforms the composite key using KDF
    pub fn transform(&mut self) {
        if self.is_transformed {
            return;
        }

        let kdf = AesKdf {
            seed: &self.seed,
            rounds: self.rounds,
        };

        *(&mut self.transformed) = kdf.transform_key(&self.raw_key()).unwrap();
        self.is_transformed = true;
    }

    // SHA512 of [index | hmac_key_keepass2]
    fn hmac_key_for_index(&self, block_index: u64) -> GenericArray<u8, U64> {
        Sha512::new()
            .chain(&block_index.to_le_bytes()[..])
            .chain(&self.hmac_key_keepass2())
            .finalize()
    }

    // Calculates SHA512 of [master_Seed | composite_key | 0x01] used for Keepass2
    fn hmac_key_keepass2(&self) -> GenericArray<u8, U64> {
        if !self.is_transformed {
            panic!("Transform the key first");
        }

        Sha512::new()
            .chain(&self.master_seed)
            .chain(&self.transformed)
            .chain(1u8.to_le_bytes())
            .finalize()
    }
}

impl<T: KeyItem> Key for CompositeKey<T> {
    fn header_hmac_key(&self) -> GenericArray<u8, U64> {
        self.hmac_key()
    }

    fn payload_hmac_key(&self) -> GenericArray<u8, U64> {
        self.hmac_key_keepass2()
    }

    fn master_key(&self) -> GenericArray<u8, U32> {
        if !self.is_transformed {
            panic!("Transform the key first");
        }

        Sha256::new()
            .chain(&self.master_seed)
            .chain(&self.transformed)
            .finalize()
    }
}
