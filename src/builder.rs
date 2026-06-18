use zerocopy::{IntoBytes, transmute, transmute_mut};

use crate::{TlvError, TlvHeader, TlvObject};

/// A builder for creating TLV objects.
pub struct TlvBuilder<'a> {
    header: &'a mut TlvHeader,
    remaining: &'a mut [u32],
}

impl<'a> TlvBuilder<'a> {
    /// Creates a new [`TlvBuilder`] for the given buffer.
    ///
    /// The buffer must be aligned to 4 bytes and its length must be a multiple of 4.
    ///
    /// # Panics
    ///
    /// Panics if the buffer length is not a multiple of 4, or if the buffer is not properly aligned.
    pub fn new<TRoot: TlvObject>(data: &'a mut [u32]) -> Result<(&'a mut TRoot, Self), TlvError> {
        let (header_words, remaining) = data
            .split_first_chunk_mut::<{ TlvHeader::HEADER_WORD_COUNT }>()
            .ok_or(TlvError)?;
        let header: &mut TlvHeader = transmute_mut!(header_words);
        *header = TlvHeader {
            tag: TRoot::TAG,
            length: u16::try_from(core::mem::size_of::<TRoot>()).map_err(|_| TlvError)?,
            reserved: 0,
        };
        let (data_words, remaining) = remaining
            .split_at_mut_checked(core::mem::size_of::<TRoot>().div_ceil(4))
            .ok_or(TlvError)?;
        let data = TRoot::mut_from_prefix(data_words.as_mut_bytes()).unwrap().0;
        Ok((data, Self { header, remaining }))
    }

    /// Returns a reference to the header of the TLV object being built.
    pub fn header(&self) -> &TlvHeader {
        self.header
    }

    pub fn add<T: TlvObject>(&mut self) -> Result<&mut T, TlvError> {
        let remaining = std::mem::take(&mut self.remaining);
        let (header_words, remaining) = remaining
            .split_first_chunk_mut::<{ TlvHeader::HEADER_WORD_COUNT }>()
            .ok_or(TlvError)?;
        *header_words = transmute!(TlvHeader {
            tag: T::TAG,
            length: u16::try_from(core::mem::size_of::<T>()).map_err(|_| TlvError)?,
            reserved: 0,
        });
        let (data_words, remaining) = remaining
            .split_at_mut_checked(core::mem::size_of::<T>().div_ceil(4))
            .ok_or(TlvError)?;
        self.remaining = remaining;

        // Update current header length
        let added_bytes = u16::try_from(core::mem::size_of::<TlvHeader>() + data_words.len() * 4)
            .map_err(|_| TlvError)?;
        self.header.length = self
            .header
            .length
            .checked_add(added_bytes)
            .ok_or(TlvError)?;

        // Panic is impossible since data_words is guaranteed to be bigger than T
        Ok(T::mut_from_prefix(data_words.as_mut_bytes()).unwrap().0)
    }

    pub fn add_with_children<T: TlvObject>(
        &mut self,
    ) -> Result<(&'a mut T, TlvBuilder<'a>), TlvError> {
        let remaining = std::mem::take(&mut self.remaining);
        Self::new::<T>(remaining)
    }

    /// Finishes this child builder, restoring and updating the parent builder.
    pub fn finish_with_parent(self, parent: &mut TlvBuilder<'a>) -> Result<(), TlvError> {
        parent.remaining = self.remaining;

        let child_payload_len = usize::from(self.header.length);
        let child_total_len = core::mem::size_of::<TlvHeader>() + ((child_payload_len + 3) & !3);
        let child_total_len_u16 = u16::try_from(child_total_len).map_err(|_| TlvError)?;
        parent.header.length = parent
            .header
            .length
            .checked_add(child_total_len_u16)
            .ok_or(TlvError)?;
        Ok(())
    }

    /// A closure-based helper built on top of our linear primitives.
    /// Automatically finishes the child builder when the closure completes.
    pub fn add_in<T: TlvObject, F>(&mut self, f: F) -> Result<&'a mut T, TlvError>
    where
        F: FnOnce(&mut T, &mut TlvBuilder<'a>) -> Result<(), TlvError>,
    {
        let (data, mut child_builder) = self.add_with_children::<T>()?;
        f(data, &mut child_builder)?;
        child_builder.finish_with_parent(self)?;
        Ok(data)
    }

    pub fn finish(self) -> TlvBuilderFinisher {
        TlvBuilderFinisher {
            start_ptr: self.header as *const _ as *const u32,
            end_ptr: self.remaining.as_mut_ptr(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidBufferError;

pub struct TlvBuilderFinisher {
    start_ptr: *const u32,
    end_ptr: *const u32,
}
impl TlvBuilderFinisher {
    #[inline(always)]
    pub fn into_words<const N: usize>(self, buf: &[u32; N]) -> Result<&[u32], InvalidBufferError> {
        // This is all a sanity check that ensure that the user passed the
        // correct buffer in. Hopefully the optimizer is smart enough to remove
        // it.
        if self.start_ptr != buf.as_ptr()
            || self.end_ptr > buf.as_ptr_range().end
            || self.end_ptr < self.start_ptr
        {
            return Err(InvalidBufferError);
        }
        let len = ((self.end_ptr as usize) - (self.start_ptr as usize)) / 4;
        Ok(&buf[..len])
    }
    #[inline(always)]
    pub fn into_bytes<const N: usize>(self, buf: &[u32; N]) -> Result<&[u8], InvalidBufferError> {
        Ok(self.into_words(buf)?.as_bytes())
    }
}
