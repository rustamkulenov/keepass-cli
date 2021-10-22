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

use hex_literal::hex;

pub const KDBX_PREFIX: u32 = 0x9AA2D903;
pub const VER_SIGNATURE_1X: u32 = 0xB54BFB65;
pub const VER_SIGNATURE_2XPRE: u32 = 0xB54BFB66;
pub const VER_SIGNATURE_2XPOST: u32 = 0xB54BFB67;
pub const FILE_FORMAT_4: u32 = 0x00040000;

pub const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
pub const CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
pub const CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

const KDF_AES_KDBX4: [u8; 16] = hex!("7c02bb8279a74ac0927d114a00648238");
const KDF_ARGON2: [u8; 16] = hex!("ef636ddf8c29444b91f7a9a403e30a0c");

#[repr(u8)]
#[derive(PartialEq, PartialOrd, Eq, Hash)]
#[derive(Debug)]
pub enum HeaderFieldId {
    EndOfHeader = 0,
    Comment = 1,
    CipherID = 2,         // 16 bytes
    CompressionFlags = 3, // 4 bytes
    MasterSeed = 4,       // 32 bytes
    TransformSeed = 5,    // For v3.1. Obsolete for v4
    TransformRounds = 6,  // For v3.1. Obsolete for v4
    EncryptionIV = 7,     // 16 bytes
    ProtectedStreamKey = 8,
    StreamStartBytes = 9,
    InnerRandomStreamID = 10, // 4 bytes
    KdfParameters = 11, // Serialized as VariantDictionary. See https://keepass.info/help/kb/kdbx_4.html#extkdf
    PluginData = 12,    // Serialized as VariantDictionary.
}

#[derive(Debug)]
pub enum OuterCipherSuite {
    AES256,
    Twofish,
    ChaCha20,
}

impl From<u8> for HeaderFieldId {
    // Required for convertion to/from u8. See also std::convert::Into.
    fn from(value: u8) -> Self {
        match value {
            0 => return HeaderFieldId::EndOfHeader,
            1 => return HeaderFieldId::Comment,
            2 => return HeaderFieldId::CipherID,
            3 => return HeaderFieldId::CompressionFlags,
            4 => return HeaderFieldId::MasterSeed,
            5 => return HeaderFieldId::TransformSeed,
            6 => return HeaderFieldId::TransformRounds,
            7 => return HeaderFieldId::EncryptionIV,
            8 => return HeaderFieldId::ProtectedStreamKey,
            9 => return HeaderFieldId::StreamStartBytes,
            10 => return HeaderFieldId::InnerRandomStreamID,
            11 => return HeaderFieldId::KdfParameters,
            12 => return HeaderFieldId::PluginData,
            _ => panic!("Unable to convert u8 to HeaderFieldId. Unknown value."),
        }
    }
}
