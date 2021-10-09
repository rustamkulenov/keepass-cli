use std::io;
use std::io::prelude::*;
use std::io::ErrorKind;

use super::consts::*;
use super::utils::*;

const BUF_SIZE: usize = 1024;

pub struct KdbxReader {}

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
    fn read_file_version<T: Read>(&mut self, f: &mut T, buf: &mut [u8]) -> io::Result<()> {
        f.read(&mut buf[0..4])?;
        let v1: u16 = as_u16_le(&buf[0..2]);
        let v2: u16 = as_u16_le(&buf[2..4]);
        println!("File version: {}.{}", v1, v2);

        Ok(())
    }

    // Each field consists of Field_d (1 byte), Data_Size(4 bytes) and data.
    fn read_header_field<T: Read>(&mut self, f: &mut T, buf: &mut [u8]) -> io::Result<()> {
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

    pub fn new<T: Read>(stream: &mut T) -> io::Result<Self> {
        let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];

        let mut k = KdbxReader {};

        k.read_base_signature(stream, &mut buf)?;
        k.read_version_signature(stream, &mut buf)?;
        k.read_file_version(stream, &mut buf)?;
    
        k.read_header_field(stream, &mut buf)?;
        k.read_header_field(stream, &mut buf)?;
        k.read_header_field(stream, &mut buf)?;
        k.read_header_field(stream, &mut buf)?;
    
        Ok(k)
    }

}
