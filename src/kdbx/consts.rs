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
