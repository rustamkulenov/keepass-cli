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

use std::collections::HashMap;
use std::convert::Into;
use std::io;
use std::io::prelude::*;
use std::io::ErrorKind;
use byteorder::{ByteOrder, LittleEndian};
use hmac_sha256::*;

use super::consts::*;
use super::key::*;
use super::result::Result;
use super::variant_dictionary::{VariantDictionary, VariantDictionaryValue, FromVariantDictionaryValue};

pub struct KdbxReader {}

pub struct KdbxHeader {
    //pub kdf: VariantDictionary,
    pub version_format: u32,
    pub version_minor: u16,
    pub version_major: u16,
    pub master_seed: Vec<u8>,
}

impl KdbxReader {
    pub fn new<T: Read>(stream: &mut T) -> Result<KdbxHeader> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        stream.read_to_end(&mut buf)?;
        let mut idx: usize = 0;

        // KDBX v4 File format:
        //  | 12b    | n      [1b      |2b  |size]  | 32b              | 32b                   |
        //  | Header | Fields:[field_id|size|data]* | SHA256 of header | HMAC SHA256 of header | Database
        let _ = KdbxReader::read_base_signature(&buf, idx)?;
        idx += 4;
        let version_format = KdbxReader::read_version_signature(&buf, idx)?;
        idx += 4;
        let (version_major, version_minor) = KdbxReader::read_file_version(&buf, idx)?;
        idx += 4;

        let mut fields: HashMap<HeaderFieldId, VariantDictionaryValue> = HashMap::new();
        let mut kdf: VariantDictionary = VariantDictionary::empty();
        KdbxReader::read_fields(&buf, &mut idx, &mut fields, &mut kdf)?;

        let master_seed = &<Vec<u8>>::from_variant_dictionary_value(fields.get(&HeaderFieldId::MasterSeed).unwrap()).unwrap();
        let rounds: u64 = kdf.get("R")?;
        let seed: Vec<u8> = kdf.get("S")?;

        let key = PasswordKey::new("Q12345");
        let mut composite_key = CompositeKey::new(master_seed.to_vec(), seed,  rounds);
        composite_key.add(key);

        KdbxReader::check_hmac256hash(&buf, idx, &composite_key)?;

        Ok(KdbxHeader {
            version_format,
            version_major,
            version_minor,
            master_seed: Vec::with_capacity(32),
        })
    }

    fn read_fields(
        buf: &[u8],
        idx: &mut usize,
        fields: &mut HashMap<HeaderFieldId, VariantDictionaryValue>,
        kdf: &mut VariantDictionary
    ) -> io::Result<()> {
        const FIELD_HEADER_SIZE: usize = 5;

        loop {
            match KdbxReader::read_header_field(&buf, *idx) {
                Ok((field_id, data_len)) => {
                    *idx = *idx + FIELD_HEADER_SIZE;

                    match field_id {
                        HeaderFieldId::EndOfHeader => {
                            *idx = *idx + data_len as usize;
                            break;
                        }
                        HeaderFieldId::MasterSeed => {
                            let master_seed = buf[*idx..*idx + data_len as usize].to_vec();
                            fields.insert(
                                HeaderFieldId::MasterSeed,
                                VariantDictionaryValue::ByteArray(master_seed),
                            );
                        }
                        HeaderFieldId::KdfParameters => {
                            let buf = &buf[*idx..*idx + data_len as usize];
                            *kdf = VariantDictionary::parse(buf).unwrap();
                        }

                        _ => (),
                    }

                    *idx = *idx + data_len as usize;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    // Bytes 0-3: Primary identifier, common across all kdbx versions
    fn read_base_signature(buf: &[u8], idx: usize) -> io::Result<u32> {
        let prefix: u32 = LittleEndian::read_u32(&buf[idx..idx + 4]);
        println!("Prefix: {:X}", prefix);

        if prefix != KDBX_PREFIX {
            Err(io::Error::new(ErrorKind::Other, "Unexpected prefix"))
        } else {
            Ok(prefix)
        }
    }

    // Bytes 4-7: Secondary identifier. Byte 4 can be used to identify the file version
    // (0x67 is latest, 0x66 is the KeePass 2 pre-release format and 0x55 is KeePass 1)
    fn read_version_signature(buf: &[u8], idx: usize) -> io::Result<u32> {
        let version_format = LittleEndian::read_u32(&buf[idx..idx + 4]);
        println!("Version: {:X}", version_format);

        match version_format {
            VER_SIGNATURE_1X => Err(io::Error::new(ErrorKind::Other, "v1 is not supported")),
            VER_SIGNATURE_2XPRE | VER_SIGNATURE_2XPOST => Ok(version_format),
            _ => Err(io::Error::new(
                ErrorKind::Other,
                "Not expected version signature",
            )),
        }
    }

    // Bytes 8-9: LE WORD, file version (minor)
    // Bytes 10-11: LE WORD, file version (major)
    fn read_file_version(buf: &[u8], idx: usize) -> io::Result<(u16, u16)> {
        let version_minor = LittleEndian::read_u16(&buf[idx..idx + 2]);
        let version_major = LittleEndian::read_u16(&buf[idx + 2..idx + 4]);
        println!("File version: {}.{}", version_major, version_minor);

        if FILE_FORMAT_4 != (version_major as u32) << 16 + (version_minor) {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Not expected file version",
            ));
        }

        Ok((version_major, version_minor))
    }

    // 64 bytes. 32 for SHA-256 hash and 32 for HMAC
    fn check_hmac256hash(
        buf: &[u8],
        idx: usize,
        key: &impl Key
    ) -> io::Result<()> {
        let data = &buf[..idx];

        let expected_sha256 = &buf[idx..idx + 32];
        let expected_hmac_sha256 = &buf[idx + 32..idx + 64];

        let actual_sha256 = Hash::hash(data);
        let actual_hmac_sha256 = HMAC::mac(data, &key.hmac_key());

        print!("Hash Diff:          ");
        for i in 0..32 {
            print!(
                "{}",
                if expected_sha256[i] != actual_sha256[i] {
                    "X"
                } else {
                    "∙"
                }
            );
        }
        println!();

        print!("HMAC Diff:          ");
        for i in 0..32 {
            print!(
                "{}",
                if expected_hmac_sha256[i] != actual_hmac_sha256[i] {
                    "X"
                } else {
                    "∙"
                }
            );
        }
        println!();

        Ok(())
    }

    // Each field consists of Field_d (1 byte), Data_Size(4 bytes) and data.
    fn read_header_field(buf: &[u8], idx: usize) -> io::Result<(HeaderFieldId, u32)> {
        let field_id = buf[idx];
        let data_len = LittleEndian::read_u32(&buf[idx + 1..idx + 5]);

        println!("Field: {:?} ({}B)", HeaderFieldId::from(field_id), data_len);
        println!(
            "Value: {:x?}",
            buf[idx + 5..idx + 5 + data_len as usize].to_ascii_lowercase()
        );

        Ok((field_id.into(), data_len))
    }
}
