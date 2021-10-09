pub fn as_u32_be(array: &[u8]) -> u32 {
    ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + ((array[3] as u32) << 0)
}

pub fn as_u32_le(array: &[u8]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

pub fn as_u16_le(array: &[u8]) -> u16 {
    ((array[0] as u16) << 0)
        + ((array[1] as u16) << 8)
}

