use std::io::Write;

use byteorder::{ByteOrder, LittleEndian};
use hmac_sha256::{Hash, HMAC};
use rand::Rng;

use super::consts::*;
use super::crypt::ciphers::Cipher;
use super::decompress::Decompress;
use super::key::{CompositeKey, Key, PasswordKey};
use super::result::Result;
use super::variant_dictionary::{VariantDictionary, VariantDictionaryValue};

const ROUNDS: u64 = 100;
const SEED_LEN: usize = 32;

pub(crate) struct KdbxWriter {}

impl KdbxWriter {
    pub(crate) fn write<S: Write, C: Cipher, D: Decompress>(
        stream: &mut S,
        password: &str,
        payload: minidom::Element,
        cipher: &C,
        compression: &D,
    ) -> Result<()> {
        let mut buf = [0u8; 1024];
        let mut idx: usize = 0;

        // Write header
        Self::write_header_with_crc(&mut buf, idx, password);
        // Flush buffer to output stream
        stream.write_all(&mut buf)?;

        // Write payload
        //TODO

        Ok(())
    }

    #[inline]
    fn write_base_signature(buf: &mut [u8], idx: &mut usize) {
        LittleEndian::write_u32(&mut buf[*idx..*idx + 4], KDBX_PREFIX);
        *idx += 4;
    }

    fn write_version_signature(buf: &mut [u8], idx: &mut usize) {
        LittleEndian::write_u32(&mut buf[*idx..*idx + 4], VER_SIGNATURE_2XPOST);
        *idx += 4;
    }

    fn write_file_version(buf: &mut [u8], idx: &mut usize) {
        LittleEndian::write_u32(&mut buf[*idx..*idx + 4], FILE_FORMAT_4);
        *idx += 4;
    }

    fn write_SHA_HMAC(buf: &mut [u8], idx: &mut usize, key: &impl Key) {
        let sha256 = Hash::hash(&buf[..*idx]);
        let hmac_sha256 = HMAC::mac(&buf[..*idx], &key.header_hmac_key());

        buf[*idx..*idx + 32].copy_from_slice(&sha256);
        *idx += 32;
        buf[*idx..*idx + 32].copy_from_slice(&hmac_sha256);
        *idx += 32;
    }

    fn write_header_field_prefix(
        buf: &mut [u8],
        idx: &mut usize,
        header_id: HeaderFieldId,
        size: u32,
    ) {
        buf[*idx] = header_id as u8;
        *idx += 1;
        LittleEndian::write_u32(&mut buf[*idx..*idx + 4], size);
        *idx += 4;
    }

    fn write_header_with_crc(buf: &mut [u8; 1024], mut idx: usize, password: &str) {
        // Write header's signature and versions
        KdbxWriter::write_base_signature(buf, &mut idx);
        KdbxWriter::write_version_signature(buf, &mut idx);
        KdbxWriter::write_file_version(buf, &mut idx);

        // Write Master Seed
        KdbxWriter::write_header_field_prefix(buf, &mut idx, HeaderFieldId::MasterSeed, 32);
        let mut master_seed = [0u8; 32];
        rand::thread_rng().fill(&mut master_seed);
        buf[idx..idx + 32].copy_from_slice(&master_seed);
        idx += 32;

        // Write KDF header
        KdbxWriter::write_header_field_prefix(buf, &mut idx, HeaderFieldId::KdfParameters, 0);
        // will update 0 to actual value below
        let pre_kdf_idx = idx;

        let mut kdf: VariantDictionary = VariantDictionary::empty();
        kdf.add(KDF_ROUNDS_KEY, VariantDictionaryValue::UInt64(ROUNDS));
        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed);
        kdf.add(
            KDF_SEED_KEY,
            VariantDictionaryValue::ByteArray(seed.to_vec()),
        );
        let mut uid = [0u8; 16];
        kdf.add("$UUID", VariantDictionaryValue::ByteArray(uid.to_vec()));

        kdf.write(buf, &mut idx);
        LittleEndian::write_u32(
            &mut buf[pre_kdf_idx - 4..pre_kdf_idx],
            (idx - pre_kdf_idx) as u32,
        );

        // End of header [0xD 0xA 0xD 0xA]
        KdbxWriter::write_header_field_prefix(buf, &mut idx, HeaderFieldId::EndOfHeader, 4);
        buf[idx..idx + 4].copy_from_slice(&[0xd, 0xa, 0xd, 0xa]);
        idx += 4;

        // Write Hash and HMAC of header
        let key = PasswordKey::new(password);
        let mut composite_key = CompositeKey::new(master_seed.to_vec(), seed.to_vec(), ROUNDS);
        composite_key.add(key);
        composite_key.transform();

        KdbxWriter::write_SHA_HMAC(buf, &mut idx, &composite_key);
    }
}

#[cfg(test)]
mod tests {
    use crate::kdbx::{
        consts::{FILE_FORMAT_4, VER_SIGNATURE_2XPOST},
        kdbx_header::KdbxHeader,
        kdbx_reader::KdbxReader, kdbx_writer::ROUNDS,
    };

    use super::KdbxWriter;

    /// Checks writing and reading of base signature.
    #[test]
    fn base_signature_write_read_test() {
        let mut idx = 0;
        let mut buf = [0u8; 16];
        KdbxWriter::write_base_signature(&mut buf, &mut idx);
        idx = 0;
        KdbxReader::read_base_signature(&buf, &mut idx).unwrap(); // Result value ignore. Expect no error.
    }

    /// Checks writing and reading of supported version fields.
    #[test]
    fn version_write_read_test() {
        // Write
        let mut idx = 0;
        let mut buf = [0u8; 16];
        KdbxWriter::write_version_signature(&mut buf, &mut idx);
        KdbxWriter::write_file_version(&mut buf, &mut idx);
        // Read
        idx = 0;
        let mut header = KdbxHeader {
            version_format: 0,
            version_major: 0,
            version_minor: 0,
            compressed: false,
            master_seed: Vec::with_capacity(32),
            iv: Vec::with_capacity(32),
        };
        KdbxReader::read_version_signature(&buf, &mut idx, &mut header).unwrap();
        KdbxReader::read_file_version(&buf, &mut idx, &mut header).unwrap();

        // Assertions. Writer writes hardcoded values as below:
        assert_eq!(header.version_format, VER_SIGNATURE_2XPOST);
        assert_eq!(header.version_format, VER_SIGNATURE_2XPOST);
        assert_eq!(
            (header.version_major as u32) << 16 + (header.version_minor),
            FILE_FORMAT_4
        );
    }

    /// Writes whole header with HMAC Hash and checks that is able to read it correctly with HMAC Hash check.
    #[test]
    fn write_and_read_header_with_crc() {
        // Write
        let mut buf = [0u8; 1024];
        let mut idx: usize = 0;
        let password = "CrypticPassw00rt!";
        KdbxWriter::write_header_with_crc(&mut buf, idx, password);
        // Read
        idx = 0;
        let mut header = KdbxHeader {
            version_format: 0,
            version_major: 0,
            version_minor: 0,
            compressed: false,
            master_seed: Vec::with_capacity(32),
            iv: Vec::with_capacity(32),
        };
        let composite_key = KdbxReader::read_and_check_header(&Vec::from(buf), &mut idx, &mut header, password).unwrap();
        println!("{:?}", composite_key);
        assert_eq!(composite_key.rounds, ROUNDS); // Hardcoded value in Writer
        // Assert: no errors when reading header
    }
}
