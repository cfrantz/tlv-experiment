use aligned::{A4, Aligned};
use zerocopy::IntoBytes;

/// Converts a `&[u32]` to a `&Aligned<A4, [u8]>`.
///
/// # Examples
///
/// ```
/// use aligned::{A4, Aligned};
/// use tlv::aligned_bytes;
///
/// let data: &[u32] = &[0x01020304, 0x05060708];
/// let aligned_bytes: &Aligned<A4, [u8]> = aligned_bytes::from_u32_slice(data);
/// assert_eq!(<&[u8]>::from(&aligned_bytes), &[0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]);
/// ```
pub fn from_u32_slice(buf: &[u32]) -> &Aligned<A4, [u8]> {
    unsafe { &*((buf.as_bytes() as *const [u8]) as *const Aligned<A4, [u8]>) }
}
