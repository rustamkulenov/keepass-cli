/*
Based on:
https://github.com/sseemayer/keepass-rs/blob/master/src/crypt/kdf.rs
*/

use aes::Aes256;
use cipher::generic_array::{GenericArray};
use cipher::{BlockEncrypt, NewBlockCipher};
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

        let hash = digest.finalize();

        let mut res: [u8; 32] = [0u8; 32];
        res.copy_from_slice(&hash);

        Ok(res)
    }
}
