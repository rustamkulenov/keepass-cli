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

pub const KDBX_PREFIX: u32 = 0x9AA2D903;
pub const VER_SIGNATURE_1X: u32 = 0xB54BFB65;
pub const VER_SIGNATURE_2XPRE: u32 = 0xB54BFB66;
pub const VER_SIGNATURE_2XPOST: u32 = 0xB54BFB67;

#[repr(u8)]
pub enum HeaderFieldId {
    EndOfHeader = 0,
    Comment = 1,
    CipherID = 2,
    CompressionFlags = 3,
    MasterSeed = 4,
    TransformSeed = 5,   // For v3.1. Obsolete for v4
    TransformRounds = 6, // For v3.1. Obsolete for v4
    EncryptionIV = 7,
    ProtectedStreamKey = 8,
    StreamStartBytes = 9,
    InnerRandomStreamID = 10,
    KdfParameters = 11,  // Serialized as VariantDictionary. See https://keepass.info/help/kb/kdbx_4.html#extkdf
    PluginData = 12 // Serialized as VariantDictionary.
}

pub enum ProtectedStreamAlgo {
    ArcFourVariant = 1,
    Salsa20 = 2,
}
