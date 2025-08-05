use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num;

pub const BASE36_RADIX: u32 = 36;

#[derive(Debug, Copy, Clone)]
pub struct Base36;

impl Base36 {
    pub fn decode(s: &str) -> Result<Vec<u8>, ParseBigIntError> {
        Ok(BigUint::from_str_radix(s, BASE36_RADIX)?.to_bytes_be())
    }

    pub fn encode(buf: &[u8]) -> String {
        BigUint::from_bytes_be(buf).to_str_radix(BASE36_RADIX)
    }
}
