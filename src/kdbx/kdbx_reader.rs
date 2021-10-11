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
use std::io::prelude::*;
use std::io::ErrorKind;

use hmac_sha256::*;

use super::consts::*;
use super::utils::*;

const BUF_SIZE: usize = 1024;

pub struct KdbxReader {
    pub version_format: u32,
    pub version_minor: u16,
    pub version_major: u16,
}

impl KdbxReader {
    // Bytes 0-3: Primary identifier, common across all kdbx versions
    fn read_base_signature<T: Read>(&mut self, f: &mut T, buf: &mut [u8]) -> io::Result<()> {
        f.read(&mut buf[0..4])?;
        let prefix: u32 = as_u32_le(&buf);
        println!("Prefix: {:X}", prefix);

        if prefix != KDBX_PREFIX {
            Err(io::Error::new(ErrorKind::Other, "Unexpected prefix"))
        } else {
            Ok(())
        }
    }

    // Bytes 4-7: Secondary identifier. Byte 4 can be used to identify the file version
    // (0x67 is latest, 0x66 is the KeePass 2 pre-release format and 0x55 is KeePass 1)
    fn read_version_signature<T: Read>(&mut self, f: &mut T, buf: &mut [u8]) -> io::Result<()> {
        f.read(&mut buf[0..4])?;
        self.version_format = as_u32_le(&buf);
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
    fn read_file_version<T: Read>(&mut self, f: &mut T, buf: &mut [u8]) -> io::Result<()> {
        f.read(&mut buf[0..4])?;
        self.version_minor = as_u16_le(&buf[0..2]);
        self.version_major = as_u16_le(&buf[2..4]);
        println!(
            "File version: {}.{}",
            self.version_minor, self.version_major
        );

        Ok(())
    }

    fn check_hmac256hash<T: Read>(&mut self, f: &mut T, data: &mut [u8], key: &[u8]) -> io::Result<()> {
        let mut expected = [0u8; 64]; // sha256 and hmac_sha256
        f.read(&mut expected)?;
        let actual_sha256 = Hash::hash(data);
        let actual_hmac_sha256 = HMAC::mac(data, key);

        print!("Hash Diff:          ");
        for i in 0..32 {
            print!("{}", if expected[i] != actual_sha256[i] {"X"} else {"∙"});
        }
        println!();

        print!("HMAC Diff:          ");
        for i in 0..32 {
            print!("{}", if expected[32+i] != actual_hmac_sha256[i] {"X"} else {"∙"});
        }
        println!();

        Ok(())
    }

    // Each field consists of Field_d (1 byte), Data_Size(4 bytes) and data.
    fn read_header_field<T: Read>(
        &mut self,
        f: &mut T,
        buf: &mut [u8],
        idx: usize,
    ) -> io::Result<(u8, u32)> {
        f.read(&mut buf[idx..idx + 5])?;
        let field_id = buf[idx];
        let data_len = as_u32_le(&buf[idx + 1..idx + 5]);

        println!("Field: {} {}", field_id, data_len);

        f.read(&mut buf[idx + 5..idx + 5 + data_len as usize])?;

        println!(
            "Value: {:?}",
            buf[idx..idx + data_len as usize].to_ascii_lowercase()
        );

        Ok((field_id, data_len))
    }

    pub fn new<T: Read>(stream: &mut T) -> io::Result<Self> {
        let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];

        let mut k = KdbxReader {
            version_format: 0,
            version_minor: 0,
            version_major: 0,
        };

        let mut idx: usize = 0;

        k.read_base_signature(stream, &mut buf[idx..idx + 4])?;
        idx += 4;
        k.read_version_signature(stream, &mut buf[idx..idx + 4])?;
        idx += 4;
        k.read_file_version(stream, &mut buf[idx..idx + 4])?;
        idx += 4;

        const FIELD_HEADER_SIZE: usize = 5;

        loop {
            match k.read_header_field(stream, &mut buf, idx) {
                Ok((field_id, data_len)) => {
                    idx = idx + FIELD_HEADER_SIZE + data_len as usize;
                    if field_id == HeaderFieldId::EndOfHeader as u8 {
                        break;
                    };
                }
                Err(e) => return Err(e),
            }
        }

        let key = "Q12345".as_bytes();
        k.check_hmac256hash(stream, &mut buf[..idx], &key)?;

        Ok(k)
    }
}
