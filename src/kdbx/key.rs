use hmac_sha256::*;
use sha2::{Digest, Sha256, Sha512};

use super::crypt::kdf::{AesKdf, Kdf};

pub trait Key {
    // SHA512 of [UINT64_MAX | hmac_key_keepass2]
    // UINT64_MAX is 16 0xFF
    fn hmac_key(&self, master_seed: &[u8]) -> [u8; 64] {
        self.hmac_key_for_index(master_seed, u64::MAX)
    }

    // SHA512 of [index | hmac_key_keepass2]
    fn hmac_key_for_index(&self, master_seed: &[u8], block_index: u64) -> [u8; 64] {
        let hash = Sha512::new()
            .chain(&block_index.to_le_bytes()[..])
            .chain(&self.hmac_key_keepass2(master_seed))
            .finalize();
        let mut res: [u8; 64] = [0u8; 64];
        res.copy_from_slice(&hash);

        res
    }

    // Calculates SHA512 of [master_Seed | composite_key | 0x01] used for Keepass2
    fn hmac_key_keepass2(&self, master_seed: &[u8]) -> [u8; 64] {
        let hash = Sha512::new()
            .chain(master_seed)
            .chain(&self.transformed(master_seed))
            .chain(1u8.to_le_bytes())
            .finalize();
        let mut res: [u8; 64] = [0u8; 64];
        res.copy_from_slice(&hash);

        res
    }

    fn transformed(&self, master_seed: &[u8]) -> [u8; 32] {
        let kdf = AesKdf {
            seed: master_seed,
            rounds: 1,  // TODO: Provide real value
        };

        kdf.transform_key(self.raw_key().as_slice()).unwrap()
    }

    // A key used for symmetric encryption/decryption
    fn final_key(&self, master_seed: &[u8]) -> [u8; 32] {
        let hash = Sha256::new()
            .chain(master_seed)
            .chain(&self.raw_key())
            .finalize();
        let mut res: [u8; 32] = [0u8; 32];
        res.copy_from_slice(&hash);

        res
    }

    // Returns raw key as array of bytes.
    fn raw_key(&self) -> Vec<u8>;
}

pub struct PasswordKey {
    // SHA256 of a password
    passw_hash: [u8; 32],
}

pub struct CompositeKey<T: Key> {
    items: Vec<T>,
}

impl PasswordKey {
    pub fn new(passw: &str) -> PasswordKey {
        PasswordKey {
            passw_hash: Hash::hash(passw.as_bytes()),
        }
    }
}

impl<T: Key> CompositeKey<T> {
    pub fn new() -> CompositeKey<T> {
        CompositeKey { items: vec![] }
    }

    pub fn add(&mut self, item: T) {
        self.items.push(item);
    }
}

impl Key for PasswordKey {
    // Simply returns SHA256 of password string as bytes array (32 bytes).
    fn raw_key(&self) -> Vec<u8> {
        self.passw_hash.to_vec()
    }
}

impl<T: Key> Key for CompositeKey<T> {
    // Returns SHA256 of all concatenated keys (32 bytes).
    fn raw_key(&self) -> Vec<u8> {
        let all_keys: Vec<u8> = self.items.iter().flat_map(|k| k.raw_key()).collect();
        Hash::hash(&all_keys[..]).to_vec()
    }
}
