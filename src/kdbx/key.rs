use sha2::{Sha256, Sha512, Digest};
use hmac_sha256::*;

pub trait Key {

    // Creates 32 bytes hash from a key to be used as key for HMAC SHA512 calculation.
    fn hmac_key(&self, master_seed: &[u8]) -> [u8; 64];

    // Returns raw key as array of bytes.
    fn raw_key(&self) -> &[u8];
}

pub struct PasswordKey<'a> {
    passw: &'a str
}

impl PasswordKey<'_> {

    pub fn new(passw: &str) -> PasswordKey {
        PasswordKey {
            passw
        }
    }

}

impl Key for PasswordKey<'_> {

    fn raw_key(&self) -> &[u8] {
        self.passw.as_bytes()
    }

    fn hmac_key(&self, master_seed: &[u8]) -> [u8; 64]{
        let data = [master_seed, self.raw_key(), &[1u8]].concat();

        let mut hasher = Sha512::new();
        hasher.update(&data[..]);
        let h = hasher.finalize();
        let mut res : [u8; 64] = [0u8; 64];
        res.copy_from_slice(h.as_slice());
        
        res
    }

}