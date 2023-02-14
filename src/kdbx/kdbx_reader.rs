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

use byteorder::{ByteOrder, LittleEndian};
use flate2::read::GzDecoder;
use hmac_sha256::*;
use std::collections::HashMap;
use std::convert::Into;
use std::io;
use std::io::prelude::*;
use std::io::ErrorKind;

use super::consts::*;
use super::crypt::ciphers::AES256Cipher;
use super::crypt::ciphers::Cipher;
use super::crypt::*;
use super::decompress::{GZipCompression, NoCompression};
use super::kdbx_header::KdbxHeader;
use super::key::*;
use super::result::Result;
use super::variant_dictionary::{VariantDictionary, VariantDictionaryValue};

pub(crate) struct KdbxReader {}

impl KdbxReader {
    pub fn read_from<T: Read>(stream: &mut T, password: &str) -> Result<minidom::Element> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024 * 1024);
        stream.read_to_end(&mut buf)?;
        let mut idx: usize = 0;

        // KDBX v4 File format:
        //  | 12b    | n      [1b      |4b  |size]  | 32b              | 32b                   |
        //  | Header | Fields:[field_id|size|data]* | SHA256 of header | HMAC SHA256 of header | Database
        let mut header = KdbxHeader {
            version_format: 0,
            version_major: 0,
            version_minor: 0,
            compressed: false,
            master_seed: Vec::with_capacity(32),
            iv: Vec::with_capacity(32),
        };

        let composite_key = Self::read_and_check_header(&buf, &mut idx, &mut header, password)?;

        println!("reading hmac payload...");

        // read encrypted payload from hmac-verified block stream
        let payload_encrypted = hmac_block_stream::read_hmac_block_stream(
            &buf[idx..],
            &composite_key.payload_hmac_key(),
        )?;

        println!("read: {}B", &payload_encrypted.len());

        let mut cipher = AES256Cipher::new(&composite_key.master_key(), &header.iv)?;
        let payload_compressed = cipher.decrypt(&payload_encrypted)?;

        let mut payload: Vec<u8> = Vec::new();
        if header.compressed {
            let mut zip = GzDecoder::new(&payload_compressed[..]);
            zip.read_to_end(&mut payload)?;
        } else {
            payload = payload_compressed;
        }

        idx = 0; // indexing from payload beginning
        println!("Reading inner header");
        let mut fields = HashMap::new();
        KdbxReader::read_inner_fields(&payload, &mut idx, &mut fields)?;

        const NS: &str = "ns";

        let mut xml_payload = String::from_utf8(payload[idx..].to_vec()).unwrap();
        xml_payload = xml_payload // Add required namespace and remove spaces
            .replace("<KeePassFile>", r#"<KeePassFile xmlns="ns">"#)
            .replace("\n", "")
            .replace("\t", "");

        println!("{:?}", xml_payload);

        let xml_doc: minidom::Element = xml_payload.parse().unwrap();

        Ok(xml_doc)
    }

    pub fn read_header_fields(
        buf: &[u8],
        idx: &mut usize,
        header: &mut KdbxHeader,
        kdf: &mut VariantDictionary,
    ) -> io::Result<()> {
        const FIELD_HEADER_SIZE: usize = 5;

        loop {
            match KdbxReader::read_header_field(&buf, *idx) {
                Ok((field_id, data_len)) => {
                    *idx = *idx + FIELD_HEADER_SIZE;
                    let field_data = &buf[*idx..*idx + data_len as usize];

                    match field_id {
                        HeaderFieldId::EndOfHeader => {
                            *idx = *idx + data_len as usize;
                            break;
                        }
                        HeaderFieldId::MasterSeed => header.master_seed = field_data.to_vec(),
                        HeaderFieldId::EncryptionIV => header.iv = field_data.to_vec(),
                        HeaderFieldId::CompressionFlags => {
                            let flag: u32 = LittleEndian::read_u32(field_data);
                            header.compressed = flag == 1;
                        }
                        HeaderFieldId::CipherID => {
                            if CIPHERSUITE_AES256 != field_data {
                                panic!("Only AES256 is supported for payload encryption")
                            }
                        }
                        HeaderFieldId::KdfParameters => {
                            *kdf = VariantDictionary::parse(field_data).unwrap();
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

    pub fn read_inner_fields(
        buf: &[u8],
        idx: &mut usize,
        _fields: &mut HashMap<HeaderFieldId, VariantDictionaryValue>,
    ) -> io::Result<()> {
        const FIELD_HEADER_SIZE: usize = 5;

        loop {
            match KdbxReader::read_header_field(&buf, *idx) {
                Ok((field_id, data_len)) => {
                    *idx = *idx + FIELD_HEADER_SIZE;
                    let _field_data = &buf[*idx..*idx + data_len as usize];

                    match field_id {
                        HeaderFieldId::EndOfHeader => {
                            *idx = *idx + data_len as usize;
                            break;
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
    pub fn read_base_signature(buf: &[u8], idx: &mut usize) -> io::Result<()> {
        let prefix: u32 = LittleEndian::read_u32(&buf[*idx..*idx + 4]);
        *idx += 4;
        println!("Prefix: {:X}", prefix);

        if prefix != KDBX_PREFIX {
            Err(io::Error::new(ErrorKind::Other, "Unexpected prefix"))
        } else {
            Ok(())
        }
    }

    // Bytes 4-7: Secondary identifier. Byte 4 can be used to identify the file version
    // (0x67 is latest, 0x66 is the KeePass 2 pre-release format and 0x55 is KeePass 1)
    pub fn read_version_signature(
        buf: &[u8],
        idx: &mut usize,
        header: &mut KdbxHeader,
    ) -> io::Result<()> {
        let version_format = LittleEndian::read_u32(&buf[*idx..*idx + 4]);
        *idx += 4;
        println!("Version: {:X}", version_format);

        header.version_format = version_format;

        match version_format {
            VER_SIGNATURE_1X => Err(io::Error::new(ErrorKind::Other, "v1 is not supported")),
            VER_SIGNATURE_2XPRE | VER_SIGNATURE_2XPOST => Ok(()),
            _ => Err(io::Error::new(
                ErrorKind::Other,
                "Not expected version signature",
            )),
        }
    }

    // Bytes 8-9: LE WORD, file version (minor)
    // Bytes 10-11: LE WORD, file version (major)
    pub fn read_file_version(buf: &[u8], idx: &mut usize, header: &mut KdbxHeader) -> io::Result<()> {
        let version_minor = LittleEndian::read_u16(&buf[*idx..*idx + 2]);
        let version_major = LittleEndian::read_u16(&buf[*idx + 2..*idx + 4]);
        *idx += 4;

        println!("File version: {}.{}", version_major, version_minor);

        header.version_major = version_major;
        header.version_minor = version_minor;

        if FILE_FORMAT_4 != (version_major as u32) << 16 + (version_minor) {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Not expected file version",
            ));
        }

        Ok(())
    }

    // 64 bytes. 32 for SHA-256 hash and 32 for HMAC
    pub fn check_hmac256hash(buf: &[u8], idx: &mut usize, key: &impl Key) -> io::Result<()> {
        let data = &buf[..*idx];

        let expected_sha256 = &buf[*idx..*idx + 32];
        let expected_hmac_sha256 = &buf[*idx + 32..*idx + 64];
        *idx += 64;

        let actual_sha256 = Hash::hash(data);
        let actual_hmac_sha256 = HMAC::mac(data, &key.header_hmac_key());

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
    pub fn read_header_field(buf: &[u8], idx: usize) -> io::Result<(HeaderFieldId, u32)> {
        let field_id = buf[idx];
        let data_len = LittleEndian::read_u32(&buf[idx + 1..idx + 5]);

        println!("Field: {:?} ({}B)", HeaderFieldId::from(field_id), data_len);
        println!(
            "Value: {:x?}",
            buf[idx + 5..idx + 5 + data_len as usize].to_ascii_lowercase()
        );

        Ok((field_id.into(), data_len))
    }

    pub fn read_and_check_header(buf: &Vec<u8>, idx: &mut usize, header: &mut KdbxHeader, password: &str) -> io::Result<CompositeKey<PasswordKey>> {
        KdbxReader::read_base_signature(buf, idx)?;
        KdbxReader::read_version_signature(buf, idx, header)?;
        KdbxReader::read_file_version(buf, idx, header)?;
        let mut kdf: VariantDictionary = VariantDictionary::empty();
        KdbxReader::read_header_fields(buf, idx, header, &mut kdf)?;
        let rounds: u64 = kdf.get(KDF_ROUNDS_KEY).unwrap();
        let seed: Vec<u8> = kdf.get(KDF_SEED_KEY).unwrap();
        let key = PasswordKey::new(password);
        let master_seed = header.master_seed.clone();
        let mut composite_key = CompositeKey::new(master_seed, seed, rounds);
        composite_key.add(key);
        composite_key.transform();
        KdbxReader::check_hmac256hash(buf, idx, &composite_key)?;
        Ok(composite_key)
    }
    
}
