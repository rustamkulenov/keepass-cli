use std::io::Write;

use byteorder::{ByteOrder, LittleEndian};
use rand::Rng;

use super::consts::*;
use super::crypt::ciphers::Cipher;
use super::decompress::Decompress;
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

        KdbxWriter::write_base_signature(&mut buf, &mut idx);
        KdbxWriter::write_version_signature(&mut buf, &mut idx);
        KdbxWriter::write_file_version(&mut buf, &mut idx);

        // KDF header
        KdbxWriter::write_header_field_prefix(&mut buf, &mut idx, HeaderFieldId::KdfParameters, 0); // will update 0 to actual value below
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

        kdf.write(&mut buf, &mut idx);
        LittleEndian::write_u32(
            &mut buf[pre_kdf_idx - 4..pre_kdf_idx],
            (idx - pre_kdf_idx) as u32,
        );

        // End of header
        KdbxWriter::write_header_field_prefix(&mut buf, &mut idx, HeaderFieldId::EndOfHeader, 4);
        buf[idx..idx + 4].copy_from_slice(&[0xd, 0xa, 0xd, 0xa]);
        idx += 4;

        stream.write_all(&mut buf)?;

        Ok(())
    }

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
}
