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

use std::io;
use std::convert::Into;
use std::io::prelude::*;
use std::io::ErrorKind;

use hmac_sha256::*;

use super::consts::*;
use super::utils::*;

pub struct KdbxReader {
    pub buf: Vec<u8>,

    pub version_format: u32,
    pub version_minor: u16,
    pub version_major: u16,
    pub master_seed: Vec<u8>
}

impl KdbxReader {

    pub fn new<T: Read>(stream: &mut T) -> io::Result<KdbxReader> {
        let mut k = KdbxReader {
            buf: Vec::with_capacity(10 * 1024),
            version_format: 0,
            version_minor: 0,
            version_major: 0,
            master_seed: Vec::with_capacity(64),
        };

        stream.read_to_end(&mut k.buf)?;
        let mut idx: usize = 0;

        k.read_header(&mut idx)?;
        k.read_fields(&mut idx)?;

        let key = "Q12345".as_bytes();
        k.check_hmac256hash(idx, &key)?;

        Ok(k)
    }

    fn read_header(&mut self, idx: &mut usize) -> io::Result<()> {
        self.read_base_signature(*idx)?;
        *idx += 4;
        self.read_version_signature(*idx)?;
        *idx += 4;
        self.read_file_version(*idx)?;
        *idx += 4;

        Ok(())
    }

    fn read_fields(&mut self, idx: &mut usize) -> io::Result<()> {
        const FIELD_HEADER_SIZE: usize = 5;

        loop {
            match self.read_header_field(*idx) {
                Ok((field_id, data_len)) => {
                    *idx = *idx + FIELD_HEADER_SIZE;

                    match field_id {
                        HeaderFieldId::EndOfHeader => {
                            *idx = *idx + data_len as usize;
                            break;
                        },
                        HeaderFieldId::MasterSeed => {
                            self.master_seed = vec![0; data_len as usize];
                            self.master_seed.clone_from_slice(&self.buf[*idx..*idx+data_len as usize]);
                        }

                        _ => ()
                    }

                    *idx = *idx + data_len as usize;

                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
    
    // Bytes 0-3: Primary identifier, common across all kdbx versions
    fn read_base_signature(&self, idx: usize) -> io::Result<()> {
        let prefix: u32 = as_u32_le(&self.buf[idx..idx+4]);
        println!("Prefix: {:X}", prefix);

        if prefix != KDBX_PREFIX {
            Err(io::Error::new(ErrorKind::Other, "Unexpected prefix"))
        } else {
            Ok(())
        }
    }

    // Bytes 4-7: Secondary identifier. Byte 4 can be used to identify the file version
    // (0x67 is latest, 0x66 is the KeePass 2 pre-release format and 0x55 is KeePass 1)
    fn read_version_signature(&mut self, idx: usize) -> io::Result<()> {
        self.version_format = as_u32_le(&self.buf[idx..idx+4]);
        println!("Version: {:X}", self.version_format);

        match self.version_format {
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
    fn read_file_version(&mut self, idx: usize) -> io::Result<()> {
        self.version_minor = as_u16_le(&self.buf[idx..idx+2]);
        self.version_major = as_u16_le(&self.buf[idx+2..idx+4]);
        println!(
            "File version: {}.{}",
            self.version_minor, self.version_major
        );

        Ok(())
    }

    // 64 bytes. 32 for SHA-256 hash and 32 for HMAC
    fn check_hmac256hash(&self, idx: usize, key: &[u8]) -> io::Result<()> {
        let data = &self.buf[..idx];
        let expected_sha256 = &self.buf[idx..idx+32];
        let expected_hmac_sha256 = &self.buf[idx+32..idx+64];
        let actual_sha256 = Hash::hash(data);
        let actual_hmac_sha256 = HMAC::mac(data, key);

        print!("Hash Diff:          ");
        for i in 0..32 {
            print!("{}", if expected_sha256[i] != actual_sha256[i] {"X"} else {"∙"});
        }
        println!();

        print!("HMAC Diff:          ");
        for i in 0..32 {
            print!("{}", if expected_hmac_sha256[i] != actual_hmac_sha256[i] {"X"} else {"∙"});
        }
        println!();

        Ok(())
    }

    // Each field consists of Field_d (1 byte), Data_Size(4 bytes) and data.
    fn read_header_field(&self, idx: usize) -> io::Result<(HeaderFieldId, u32)> {
        let field_id = self.buf[idx];
        let data_len = as_u32_le(&self.buf[idx + 1..idx + 5]);

        println!("Field: {} {}", field_id, data_len);
        println!(
            "Value: {:?}",
            self.buf[idx + 5..idx + 5 + data_len as usize].to_ascii_lowercase()
        );

        Ok((field_id.into(), data_len))
    }

}
