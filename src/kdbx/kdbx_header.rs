pub struct KdbxHeader {
    pub version_format: u32,
    pub version_minor: u16,
    pub version_major: u16,
    pub master_seed: Vec<u8>,
    pub iv: Vec<u8>,
    pub compressed: bool,
}

