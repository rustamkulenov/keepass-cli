/*
   Based on:
   https://github.com/sseemayer/keepass-rs/blob/master/src/variant_dictionary.rs
*/
use super::result::{DatabaseIntegrityError, Error, Result};
use byteorder::{ByteOrder, LittleEndian};

use std::collections::HashMap;

const VARDICT_VERSION: u16 = 0x100;

#[derive(Debug)]
pub(crate) struct VariantDictionary {
    data: HashMap<String, VariantDictionaryValue>,
}

impl VariantDictionary {
    pub(crate) fn empty() -> VariantDictionary {
        VariantDictionary {
            data: HashMap::new(),
        }
    }

    pub(crate) fn parse(buffer: &[u8]) -> Result<VariantDictionary> {
        let version = LittleEndian::read_u16(&buffer[0..2]);

        if version != VARDICT_VERSION {
            return Err(DatabaseIntegrityError::InvalidVariantDictionaryVersion { version }.into());
        }

        let mut pos = 2;
        let mut data = HashMap::new();

        while pos < buffer.len() {
            let value_type = buffer[pos];
            pos += 1;

            if value_type == 0 {
                // Null terminator
                break;
            };

            let key_length = LittleEndian::read_u32(&buffer[pos..(pos + 4)]) as usize;
            pos += 4;

            let key = std::str::from_utf8(&buffer[pos..(pos + key_length)])
                .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
                .to_owned();
            pos += key_length;

            let value_length = LittleEndian::read_u32(&buffer[pos..(pos + 4)]) as usize;
            pos += 4;

            println!("  - {0} ({1}B)", &key, value_length);

            let value_buffer = &buffer[pos..(pos + value_length)];
            pos += value_length;

            let value = match value_type {
                0x04 => VariantDictionaryValue::UInt32(LittleEndian::read_u32(value_buffer)),
                0x05 => VariantDictionaryValue::UInt64(LittleEndian::read_u64(value_buffer)),
                0x08 => VariantDictionaryValue::Bool(value_buffer != [0]),
                0x0c => VariantDictionaryValue::Int32(LittleEndian::read_i32(value_buffer)),
                0x0d => VariantDictionaryValue::Int64(LittleEndian::read_i64(value_buffer)),
                0x18 => VariantDictionaryValue::String(
                    std::str::from_utf8(value_buffer)
                        .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
                        .into(),
                ),
                0x42 => VariantDictionaryValue::ByteArray(value_buffer.to_vec()),
                _ => {
                    return Err(DatabaseIntegrityError::InvalidVariantDictionaryValueType {
                        value_type,
                    }
                    .into());
                }
            };

            data.insert(key, value);
        }

        Ok(VariantDictionary { data })
    }

    pub(crate) fn write(&self, buffer: &mut [u8], idx: &mut usize) {
        LittleEndian::write_u16(&mut buffer[*idx..*idx + 2], VARDICT_VERSION);
        *idx += 2;

        self.data.iter().for_each(|(k, v)| {
            let keybuf = k.as_bytes();
            let keysize = keybuf.len() as u32;
            match v {
                &VariantDictionaryValue::UInt32(v) => {
                    buffer[*idx] = 0x04; // type
                    *idx += 1;
                    LittleEndian::write_u32(&mut buffer[*idx..*idx + 4], keysize); // key + key length
                    *idx += 4;
                    buffer[*idx..*idx + keysize as usize].copy_from_slice(keybuf);
                    *idx += keysize as usize;
                    LittleEndian::write_u32(&mut buffer[*idx..*idx + 4], 4); // value length
                    *idx += 4;
                    LittleEndian::write_u32(&mut buffer[*idx..*idx + 4], v); // value
                    *idx += 4;
                }
                &VariantDictionaryValue::UInt64(v) => {
                    buffer[*idx] = 0x05; // type
                    *idx += 1;
                    LittleEndian::write_u32(&mut buffer[*idx..*idx + 4], keysize); // key + key length
                    *idx += 4;
                    buffer[*idx..*idx + keysize as usize].copy_from_slice(keybuf);
                    *idx += keysize as usize;
                    LittleEndian::write_u32(&mut buffer[*idx..*idx + 4], 8); // value length
                    *idx += 4;
                    LittleEndian::write_u64(&mut buffer[*idx..*idx + 8], v); // value
                    *idx += 8;
                }
                VariantDictionaryValue::ByteArray(v) => {
                    buffer[*idx] = 0x42; // type
                    *idx += 1;
                    LittleEndian::write_u32(&mut buffer[*idx..*idx + 4], keysize); // key + key length
                    *idx += 4;
                    buffer[*idx..*idx + keysize as usize].copy_from_slice(keybuf);
                    *idx += keysize as usize;
                    let vsize = v.len();
                    LittleEndian::write_u32(&mut buffer[*idx..*idx + 4], vsize as u32); // value length
                    *idx += 4;
                    buffer[*idx..*idx + vsize].copy_from_slice(v); // value
                    *idx += vsize;
                }
                _ => {} // skip
            }
        });

        buffer[*idx] = 0; // Null terminator byte
        *idx += 1;
    }

    pub(crate) fn add(&mut self, key: &str, value: VariantDictionaryValue) {
        self.data.insert(key.to_string(), value);
    }

    pub(crate) fn get<T>(&self, key: &str) -> Result<T>
    where
        T: FromVariantDictionaryValue<T>,
    {
        let vdv = if let Some(v) = self.data.get(key) {
            v
        } else {
            return Err(Error::from(DatabaseIntegrityError::MissingKDFParams {
                key: key.to_owned(),
            }));
        };

        T::from_variant_dictionary_value(vdv).ok_or_else(|| {
            DatabaseIntegrityError::MistypedKDFParam {
                key: key.to_owned(),
            }
            .into()
        })
    }
}

pub(crate) trait FromVariantDictionaryValue<T> {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<T>;
}

impl FromVariantDictionaryValue<u32> for u32 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<u32> {
        if let VariantDictionaryValue::UInt32(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<u64> for u64 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<u64> {
        if let VariantDictionaryValue::UInt64(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<bool> for bool {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<bool> {
        if let VariantDictionaryValue::Bool(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<i32> for i32 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<i32> {
        if let VariantDictionaryValue::Int32(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<i64> for i64 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<i64> {
        if let VariantDictionaryValue::Int64(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<String> for String {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<String> {
        if let VariantDictionaryValue::String(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<Vec<u8>> for Vec<u8> {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<Vec<u8>> {
        if let VariantDictionaryValue::ByteArray(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub(crate) enum VariantDictionaryValue {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(Vec<u8>),
}

mod test {
    use byteorder::{ByteOrder, LittleEndian};
    use rand::Rng;

    use crate::kdbx::consts::{KDF_ROUNDS_KEY, KDF_SEED_KEY};

    use super::{VariantDictionary, VariantDictionaryValue};

    #[test]
    fn variant_dictionary_write_read_u64_field_test() {
        const ROUNDS: u64 = 0xFFFFFFFFFFFFFFFF;

        let mut buf = [0u8; 1024];
        let mut idx: usize = 0;

        // Write

        let mut kdf: VariantDictionary = VariantDictionary::empty();
        kdf.add(KDF_ROUNDS_KEY, VariantDictionaryValue::UInt64(ROUNDS));
        kdf.write(&mut buf, &mut idx);

        println!("{0}B written: {1:?}", idx, &buf[..idx]);
        // Read

        let kdf: VariantDictionary = VariantDictionary::parse(&buf[..idx]).unwrap();

        // Expectations

        assert!(idx == 2 + 1 + 4 + 1 + 4 + 8 + 1, "Unexpected written data size");
        assert!(kdf.data.contains_key("R"), "Expected R key not found");
    }

    #[test]
    fn variant_dictionary_write_read_test() {
        const ROUNDS: u64 = 7;

        let mut buf = [0u8; 1024];
        let mut idx: usize = 0;

        // Write

        let mut kdf: VariantDictionary = VariantDictionary::empty();
        let seed = [255u8; 32];
        kdf.add(
            KDF_SEED_KEY,
            VariantDictionaryValue::ByteArray(seed.to_vec()),
        );
        kdf.add(KDF_ROUNDS_KEY, VariantDictionaryValue::UInt64(ROUNDS));
        let uid = [10u8; 16];
        kdf.add("$UUID", VariantDictionaryValue::ByteArray(uid.to_vec()));

        kdf.write(&mut buf, &mut idx);

        println!("{0}B written: {1:?}", idx, &buf[..idx]);
        // Read

        let kdf: VariantDictionary = VariantDictionary::parse(&buf[..idx]).unwrap();

        // Expectations

        assert!(kdf.data.contains_key("S"));
        assert!(kdf.data.contains_key("R"));
        assert!(kdf.data.contains_key("$UUID"));
    }
}
