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

use aes::Aes256;
use block_modes::{block_padding::ZeroPadding, BlockMode, Ecb};
use sha2::{Digest, Sha256};
use std::io;

pub trait Kdf {
    fn transform_key(&self, composite_key: &[u8]) -> io::Result<[u8; 32]>;
}

pub struct AesKdf<'a> {
    pub seed: &'a [u8],
    pub rounds: u64,
}

impl Kdf for AesKdf<'_> {
    fn transform_key(&self, composite_key: &[u8]) -> io::Result<[u8; 32]> {
        type Aes256Ecb = Ecb<Aes256, ZeroPadding>;

        let mut key: Vec<u8> = composite_key.to_vec();

        // encrypt the key repeatedly
        for _ in 0..self.rounds {
            let cipher = Aes256Ecb::new_from_slices(&self.seed, Default::default())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let key_len = key.len();
            let new_key = cipher
                .encrypt(&mut key, key_len)
                .map(Vec::from)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            key = new_key;
        }

        let hash = Sha256::new().chain(key).finalize();

        let mut res: [u8; 32] = [0u8; 32];
        res.copy_from_slice(&hash);

        Ok(res)
    }
}
