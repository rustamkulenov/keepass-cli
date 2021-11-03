use std::io::Write;

use byteorder::{ByteOrder, LittleEndian};

use super::consts::*;
use super::crypt::ciphers::Cipher;
use super::decompress::Decompress;
use super::result::Result;

pub(crate) struct KdbxWriter {}

impl KdbxWriter {
    pub(crate) fn write<S: Write, C: Cipher, D: Decompress>(
        stream: &mut S,
        password: &str,
        payload: minidom::Element,
        cipher: &C,
        compression: &D,
    ) -> Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024 * 1024);
        let mut idx: usize = 0;

        KdbxWriter::write_base_signature(&mut buf, &mut idx);
        KdbxWriter::write_version_signature(&mut buf, &mut idx);
        KdbxWriter::write_file_version(&mut buf, &mut idx);

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
}
