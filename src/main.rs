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
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::ErrorKind;

const FILE_PATH: &str = "example-AES-256-KDF-Q12345.kdbx";
const KDBX_PREFIX: u32 = 0x9AA2D903;
const VER_SIGNATURE_1X: u32 = 0xB54BFB65;
const VER_SIGNATURE_2XPRE: u32 = 0xB54BFB66;
const VER_SIGNATURE_2XPOST: u32 = 0xB54BFB67;

const BUF_SIZE: usize = 1024;

fn main() -> io::Result<()> {
    let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];

    let f = File::open(FILE_PATH);

    let mut file = match f {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open file: {}", e);
            panic!();
        }
    };

    read_base_signature(&mut file, &mut buf)?;
    read_version_signature(&mut file, &mut buf)?;
    read_file_version(&mut file, &mut buf)?;

    read_header_field(&mut file, &mut buf)?;
    read_header_field(&mut file, &mut buf)?;
    read_header_field(&mut file, &mut buf)?;
    read_header_field(&mut file, &mut buf)?;

    println!("Hello, world!");

    Ok(())
}

fn as_u32_be(array: &[u8]) -> u32 {
    ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + ((array[3] as u32) << 0)
}

fn as_u32_le(array: &[u8]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

fn as_u16_le(array: &[u8]) -> u16 {
    ((array[0] as u16) << 0)
        + ((array[1] as u16) << 8)
}

// Bytes 0-3: Primary identifier, common across all kdbx versions
fn read_base_signature<T: Read>(f: &mut T, buf: &mut [u8]) -> io::Result<()> {
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
fn read_version_signature<T: Read>(f: &mut T, buf: &mut [u8]) -> io::Result<()> {
    f.read(&mut buf[0..4])?;
    let v: u32 = as_u32_le(&buf);
    println!("Version: {:X}", v);

    match v {
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
fn read_file_version<T: Read>(f: &mut T, buf: &mut [u8]) -> io::Result<()> {
    f.read(&mut buf[0..4])?;
    let v1: u16 = as_u16_le(&buf[0..2]);
    let v2: u16 = as_u16_le(&buf[2..4]);
    println!("File version: {}.{}", v1, v2);

    Ok(())
}

// Each field consists of Field_d (1 byte), Data_Size(4 bytes) and data.
fn read_header_field<T: Read>(f: &mut T, buf: &mut [u8]) -> io::Result<()> {
    f.read(&mut buf[0..5])?; // 5 bytes
    let field_id = buf[0];
    let data_len = as_u32_le(&buf[1..5]);

    println!("Field: {} {}", field_id, data_len);

    f.read(&mut buf[0..data_len as usize])?;

    println!(
        "Value: {:x?}{:x?}{:x?}{:x?}",
        as_u32_be(&buf[0..4]),
        as_u32_be(&buf[4..8]),
        as_u32_be(&buf[8..12]),
        as_u32_be(&buf[12..16])
    );

    Ok(())
}
