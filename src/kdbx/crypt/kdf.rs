/*
Based on:
https://github.com/sseemayer/keepass-rs/blob/master/src/crypt/kdf.rs
*/

use crate::kdbx::result::{CryptoError, DatabaseIntegrityError, Error, Result};
use aes::Aes256;
use cipher::generic_array::{typenum::U32, GenericArray};
use cipher::{BlockEncrypt, NewBlockCipher};
use sha2::{Digest, Sha256};

pub(crate) trait Kdf {
    fn transform_key(&self, composite_key: &GenericArray<u8, U32>)
        -> Result<GenericArray<u8, U32>>;
}

pub struct AesKdf<'a> {
    pub seed: &'a [u8],
    pub rounds: u64,
}

impl Kdf for AesKdf<'_> {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>> {
        let cipher = Aes256::new(&GenericArray::clone_from_slice(&self.seed));
        let mut block1 = GenericArray::clone_from_slice(&composite_key[..16]);
        let mut block2 = GenericArray::clone_from_slice(&composite_key[16..]);
        for _ in 0..self.rounds {
            cipher.encrypt_block(&mut block1);
            cipher.encrypt_block(&mut block2);
        }

        let mut digest = Sha256::new();

        digest.update(block1);
        digest.update(block2);

        Ok(digest.finalize())
    }
}
