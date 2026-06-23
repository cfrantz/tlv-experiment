//! A simple, zero-copy framework for working with Type-Length-Value (TLV) objects.
//!
//! This crate provides tools to overlay structured views onto raw byte buffers,
//! allowing efficient parsing and creation of TLV structures without unnecessary
//! allocations or copies.
//!
//! # Core Concepts
//!
//! *   [`TlvHeader`]: The common prefix for all TLV objects, containing a 4-byte `tag` and a 2-byte `length` (in 32-bit words).
//! *   [`TlvObject`]: A trait representing a typed TLV structure. The [`tlv_struct!`] macro
//!     is used to define these structs and implement this trait.
//! *   [`TlvData`]: A container representing a sequence of TLVs. It can be used to overlay
//!     on a raw buffer and iterate over the contained TLVs.
//! *   [`TlvItem`]: The parsed representation of a TLV, containing the header, the parsed object,
//!     and a reference to the raw bytes (including any extension data).
//! *   [`TlvQuery`]: Extension trait for `TlvItem` to allow casting to specific `TlvObject` types
//!     and accessing extension data.
//!
//! # Defining TLV Structures
//!
//! Use the [`tlv_struct!`] macro to define your TLV structures. You must specify:
//! 1.  The name of the struct.
//! 2.  The 4-byte tag as a byte literal (e.g., `*b"FOO_"`).
//! 3.  The type of the extension: either `[u8]` (raw bytes) or `TlvData` (nested TLVs).
//! 4.  The struct definition.
//!
//! ```rust
//! # use tlv::tlv_struct;
//! tlv_struct! { Foo, *b"FOO_", [u8],
//!     #[derive(Debug)]
//!     pub struct Foo {
//!         pub x: u32,
//!         pub y: [u8; 4],
//!     }
//! }
//! ```
//!
//! # Parsing and Iteration
//!
//! To parse a buffer, use [`TlvData::overlay`] and then iterate over it:
//!
//! ```rust
//! # use tlv::{TlvData, TlvAny};
//! # use zerocopy::IntoBytes;
//! let buf: &[u32] = &[]; // Use u32 slice
//! let tlv_data = TlvData::overlay(buf);
//! for item in tlv_data.iter::<TlvAny>() {
//!     println!("Tag: {}, word_len: {}", item.header.tag, item.header.word_len);
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, transmute_ref};

pub mod aligned_bytes;
mod builder;
#[cfg(feature = "std")]
mod hexdump;
#[cfg(feature = "std")]
pub use hexdump::hexdump;

pub use builder::TlvBuilder;
pub use builder::TlvBuilderFinisher;

/// Generic TLV header.
///
/// Every TLV object starts with this header, defining its type (tag) and the length
/// of the payload (in 32-bit words) following the header.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TlvHeader {
    /// The tag identifying the type of the TLV object. Typically represented as a 4-character ASCII string (FourCC).
    pub tag: u32,
    /// The length of the data following this header, in 32-bit words.
    pub word_len: u16,
    pub flags: u16,
}

impl TlvHeader {
    fn ref_from_words_prefix(words: &[u32]) -> Option<(&TlvHeader, &[u32])> {
        let (header_words, rest) = words.split_first_chunk::<{ word_size_of::<TlvHeader>() }>()?;
        Some((transmute_ref!(header_words), rest))
    }

    #[inline(always)]
    pub fn byte_len(&self) -> usize {
        (usize::from(self.word_len) * 4).saturating_sub(usize::from(self.padding_bytes()))
    }

    #[inline(always)]
    pub fn padding_bytes(&self) -> u16 {
        self.flags & 0x03
    }

    #[inline(always)]
    pub fn set_padding_bytes(&mut self, val: u16) {
        self.flags = (self.flags & !0x03) | val;
    }
}

/// Returns the size of the type `T` in 32-bit words, asserting at compile time
/// that the size of `T` is a multiple of 4 bytes.
#[inline(always)]
pub const fn word_size_of<T>() -> usize {
    const {
        assert!(
            core::mem::size_of::<T>().is_multiple_of(4),
            "TLV struct size must be a multiple of 4 bytes"
        );
    }
    core::mem::size_of::<T>() / 4
}

/// Generic TLV container.
///
/// This type represents a buffer containing zero or more TLV objects. It is a unsized
/// type and is typically used behind a reference (`&TlvData`) to overlay onto raw byte slices.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TlvData {
    data: [u32],
}

/// Zero-sized type that can represent any TLV.
///
/// Used as a generic parameter for [`TlvData::iter`] or [`TlvQuery::cast`] when the
/// specific type is not known or any TLV type is acceptable.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TlvAny;

impl TlvObject for TlvAny {
    type Extension = [u8];
    const TAG: u32 = 0;
    fn make_ext<'a>(header: &TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
        unpad(header, extra)
    }
}

#[doc(hidden)]
pub fn unpad<'a>(header: &TlvHeader, extra: &'a [u32]) -> &'a [u8] {
    let padding_bytes = usize::from(header.padding_bytes());
    let extra_bytes = extra.as_bytes();
    extra_bytes
        .get(..extra_bytes.len().saturating_sub(padding_bytes))
        .unwrap_or(&[])
}

#[derive(Debug, PartialEq, Eq)]
pub struct BadAlignmentError;

impl TlvData {
    /// Constructs a new `TlvData` reference by overlaying onto a word buffer.
    #[inline]
    pub fn overlay(data: &[u32]) -> &Self {
        transmute_ref!(data)
    }

    /// Constructs a new `TlvData` reference by overlaying onto a byte buffer.
    #[inline]
    pub fn overlay_bytes(data: &[u8]) -> Result<&Self, BadAlignmentError> {
        TlvData::ref_from_bytes_with_elems(data, data.len() / 4).map_err(|_| BadAlignmentError)
    }

    /// Returns an iterator over the contained TLV objects of type `T`.
    ///
    /// If `T` is [`TlvAny`], the iterator will yield all TLVs.
    /// Otherwise, it will only yield TLVs with a matching [`TlvObject::TAG`].
    pub fn iter<'a, T: TlvObject>(&'a self) -> TlvIterator<'a, T> {
        TlvIterator {
            data: &self.data,
            target: core::marker::PhantomData,
        }
    }
}

/// Iterator over TLV objects in a [`TlvData`] container.
pub struct TlvIterator<'a, T> {
    data: &'a [u32],
    target: core::marker::PhantomData<T>,
}

/// Item returned by [`TlvIterator`].
pub struct TlvItem<'a, T: TlvObject> {
    /// The TLV header of the object.
    pub header: &'a TlvHeader,
    /// The TLV object itself (parsed struct).
    pub data: &'a T,
    /// Extra data after the parsed struct
    pub extra: &'a [u32],
    /// The underlying payload slice of the TLV.
    pub payload: &'a [u32],
}

impl<'a, T: TlvObject + 'a> Iterator for TlvIterator<'a, T> {
    type Item = TlvItem<'a, T>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.data.is_empty() {
            let (header, rest) = TlvHeader::ref_from_words_prefix(self.data)?;
            let word_len = usize::from(header.word_len);
            let remain = rest.get(word_len..)?;
            let payload = rest.get(..word_len)?;
            if header.tag == T::TAG || T::TAG == 0 {
                let (data_words, extra) = payload.split_at_checked(word_size_of::<T>())?;
                let data = T::ref_from_bytes(data_words.as_bytes()).ok()?;
                self.data = remain;
                return Some(TlvItem {
                    header,
                    data,
                    payload,
                    extra,
                });
            }
            self.data = remain;
        }
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TlvError;

/// A trait for types that represent a TLV object.
///
/// This trait is typically implemented using the [`tlv_struct!`] macro.
pub trait TlvObject: FromBytes + IntoBytes + Immutable + KnownLayout + Sized {
    /// The extension type for this object.
    ///
    /// This is either `[u8]` for raw payload bytes or [`TlvData`] for nested TLV containers.
    type Extension: ?Sized;

    /// The unique 4-byte tag identifying this TLV type.
    const TAG: u32;

    /// Returns the tag of the object.
    fn get_tag(&self) -> u32 {
        Self::TAG
    }

    /// Helper for making the extension object from raw bytes.
    fn make_ext<'a>(header: &TlvHeader, extra: &'a [u32]) -> &'a Self::Extension;
}

/// Extension trait providing helper methods on [`TlvItem`].
///
/// This trait allows casting a generic `TlvItem` (e.g., returned from `iter::<TlvAny>()`)
/// to a specific `TlvObject` type, and retrieving the extension payload of a `TlvItem`.
pub trait TlvQuery {
    /// The type of the extension associated with the item.
    type Extension;

    /// Attempts to cast this item to a specific `TlvObject` type `U`.
    ///
    /// Returns `Some(TlvItem<'t, U>)` if the item's tag matches `U::TAG`, and the
    /// data can be parsed as `U`. Otherwise, returns `None`.
    fn cast<'t, U: TlvObject>(&'t self) -> Option<TlvItem<'t, U>>;

    /// Returns a reference to the extension payload of this item.
    ///
    /// If the `TlvObject` was defined with `[u8]` extension, this returns `&[u8]`.
    /// If it was defined with `TlvData`, this returns `&TlvData` (for nested TLVs).
    fn ext(&self) -> Self::Extension;
}

impl<'a, T: TlvObject> TlvQuery for TlvItem<'a, T> {
    type Extension = &'a T::Extension;
    //fn cast<U: TlvObject>(&self) -> Option<&U> {
    fn cast<'t, U: TlvObject>(&'t self) -> Option<TlvItem<'t, U>> {
        if self.header.tag == U::TAG {
            let (data_words, extra) = self.payload.split_at_checked(word_size_of::<U>())?;
            let data = U::ref_from_bytes(data_words.as_bytes()).ok()?;
            Some(TlvItem {
                header: self.header,
                data,
                extra,
                payload: self.payload,
            })
        } else {
            None
        }
    }
    fn ext(&self) -> Self::Extension {
        T::make_ext(self.header, self.extra)
    }
}

#[cfg(feature = "serde")]
#[typetag::serde]
/// A trait for representing the host "owning" version of the TLV object.
///
/// Unlike the zero-copy types, types implementing `HostTlvObject` own their data
/// (e.g., using `Vec` or `Box`). They can be serialized/deserialized and packed
/// into a flat byte buffer.
pub trait HostTlvObject {
    /// Packs the host object into a flat byte vector, prepending the correct TLV header.
    fn pack(&self) -> Vec<u8>;
}

/// Defines a TLV struct and implements [`TlvObject`] for it.
///
/// This macro generates a zero-copy representation of a TLV object. It also
/// optionally generates a `Host<Name>` struct (e.g., `HostFoo` for `Foo`) when the
/// `serde` feature is enabled, allowing serialization and deserialization.
///
/// # Syntax
///
/// ```ignore
/// tlv_struct! { Name, Tag, ExtensionType,
///     [attributes]
///     pub struct Name {
///         pub field1: Type1,
///         ...
///     }
/// }
/// ```
///
/// *   `Name`: The identifier of the struct.
/// *   `Tag`: A 4-byte tag represented as a dereferenced byte array pointer (e.g., `*b"FOO_"`).
/// *   `ExtensionType`: The type of the extension following the struct fields.
///     *   `[u8]`: Raw byte slice.
///     *   [`TlvData`]: Nested TLV container.
/// *   `definition`: The struct definition itself. Must use `#[repr(C)]` style layout
///     safety guarantees (handled by `zerocopy` derives automatically).
///
/// # Examples
///
/// Defining a struct with a raw byte extension:
///
/// ```rust
/// # use tlv::tlv_struct;
/// tlv_struct! { Foo, *b"FOO_", [u8],
///     #[derive(Debug)]
///     pub struct Foo {
///         pub x: u32,
///         pub y: [u8; 4],
///     }
/// }
/// ```
///
/// Defining a struct with nested TLVs:
///
/// ```rust
/// # use tlv::{tlv_struct, TlvData};
/// tlv_struct! { Bar, *b"BAR_", TlvData,
///     #[derive(Debug)]
///     pub struct Bar {
///         pub version: u32,
///     }
/// }
/// ```
#[macro_export]
macro_rules! tlv_struct {
    // This macro doesn't follow "don't repeat yourself" very well.

    // Branch 1: Defines a TLV struct with a raw byte array ([u8]) extension.
    ($name:ident, $tag:expr, [u8], $($definition:tt)*) => {
        // Expand the user's struct definition. If the "serde" feature is enabled,
        // derive Serialize and Deserialize. Also automatically derive the zerocopy traits
        // required to safely overlay this struct onto a byte buffer.
        #[cfg_attr(feature="serde", derive(serde::Serialize, serde::Deserialize))]
        #[derive(
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Immutable,
            zerocopy::KnownLayout,
        )]
        $($definition)*

        const _: () = {
            assert!(
                core::mem::size_of::<$name>() % 4 == 0,
                "TLV struct size must be a multiple of 4 bytes"
            );
        };

        // Implement the TlvObject trait for the generated zero-copy struct.
        impl $crate::TlvObject for $name {
            type Extension = [u8];
            // Convert the tag from little-endian bytes to a u32 constant.
            const TAG: u32 = u32::from_le_bytes($tag);
            // Returns the raw byte slice as the extension type.
            fn make_ext<'a>(header: &$crate::TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
                $crate::unpad(header, extra)
            }

        }

        // Generate the host-side owning representation if the "serde" feature is enabled.
        $crate::__private::paste! {
            #[cfg(feature="serde")]
            #[derive(serde::Serialize, serde::Deserialize)]
            /// Host-side owning representation of the TLV struct.
            ///
            /// This struct owns its fields and its extension payload (`Vec<u8>`), unlike
            /// the zero-copy counterpart.
            pub struct [< Host $name >] {
                /// The structured zero-copy part of the TLV object.
                #[serde(flatten)]
                pub data: $name,
                /// The owned extension payload bytes.
                #[serde(default, skip_serializing_if = "Vec::is_empty")]
                pub ext: Vec<u8>,
            }

            #[cfg(feature="serde")]
            const _:() = {
                use zerocopy::{IntoBytes};
                use $crate::TlvObject;

                // Implement the HostTlvObject trait to allow serializing and packing.
                #[typetag::serde(name = stringify!($name))]
                impl $crate::HostTlvObject for [< Host $name >] {
                    // Pack the struct and its extension into a single byte vector,
                    // prepended by the appropriate TlvHeader.
                    fn pack(&self) -> Vec<u8> {
                        let data_len =
                            core::mem::size_of_val(&self.data) +
                            self.ext.len();
                        let padded_data_len = (data_len + 3) & !3;
                        let mut v = Vec::with_capacity(
                            core::mem::size_of::<$crate::TlvHeader>() + padded_data_len);
                        let padding = u16::try_from(padded_data_len - data_len).unwrap();
                        let mut header = $crate::TlvHeader {
                            tag:  self.data.get_tag(),
                            word_len: u16::try_from(padded_data_len / 4).unwrap(),
                            flags: 0,
                        };
                        header.set_padding_bytes(padding);
                        v.extend(header.as_bytes());
                        v.extend(self.data.as_bytes());
                        v.extend(self.ext.as_slice());
                        v.resize(core::mem::size_of::<$crate::TlvHeader>() + padded_data_len, 0);
                        v
                    }
                }
            };
        }
    };

    // Branch 2: Defines a TLV struct with a nested TLV container (TlvData) extension.
    ($name:ident, $tag:expr, TlvData, $($definition:tt)*) => {
        // Expand the user's struct definition. Same derivations as Branch 1.
        #[cfg_attr(feature="serde", derive(serde::Serialize, serde::Deserialize))]
        #[derive(
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Immutable,
            zerocopy::KnownLayout,
        )]
        $($definition)*

        const _: () = {
            assert!(
                core::mem::size_of::<$name>() % 4 == 0,
                "TLV struct size must be a multiple of 4 bytes"
            );
        };

        // Implement the TlvObject trait for the generated zero-copy struct.
        impl $crate::TlvObject for $name {
            type Extension = $crate::TlvData;
            // Convert the tag from little-endian bytes to a u32 constant.
            const TAG: u32 = u32::from_le_bytes($tag);
            // Overlays a TlvData view onto the remaining bytes to parse them as nested TLVs.
            fn make_ext<'a>(_header: &$crate::TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
                $crate::TlvData::overlay(extra)
            }
        }

        // Generate the host-side owning representation if the "serde" feature is enabled.
        $crate::__private::paste! {
            #[cfg(feature="serde")]
            #[derive(serde::Serialize, serde::Deserialize)]
            /// Host-side owning representation of the TLV struct with nested TLVs.
            ///
            /// This struct owns its fields and has an extension containing a vector of
            /// boxed host TLV objects representing nested sub-TLVs.
            pub struct [< Host $name >] {
                /// The structured zero-copy part of the TLV object.
                #[serde(flatten)]
                pub data: $name,
                /// The owned, nested sub-TLVs.
                #[serde(default, skip_serializing_if = "Vec::is_empty")]
                pub ext: Vec<Box<dyn $crate::HostTlvObject>>,
            }

            #[cfg(feature="serde")]
            const _:() = {
                use zerocopy::{FromBytes, IntoBytes};
                use $crate::TlvObject;

                // Implement the HostTlvObject trait to allow serializing and packing.
                #[typetag::serde(name = stringify!($name))]
                impl $crate::HostTlvObject for [< Host $name >] {
                    // Recursively pack this TLV and all its nested sub-TLVs.
                    fn pack(&self) -> Vec<u8> {
                        let mut v = Vec::with_capacity(
                            core::mem::size_of::<$crate::TlvHeader>() +
                            core::mem::size_of_val(&self.data));
                        // Start with a temporary header length of 0.
                        v.extend($crate::TlvHeader {
                            tag:  self.data.get_tag(),
                            word_len: 0,
                            flags: 0,
                        }.as_bytes());
                        v.extend(self.data.as_bytes());
                        // Recursively pack and append each nested sub-TLV.
                        for ext in self.ext.iter() {
                            v.extend(ext.pack());
                        }
                        let total_len = v.len();
                        // Backpatch the final packed length into the header.
                        {
                            let header = $crate::TlvHeader::mut_from_bytes(&mut v[..8]).unwrap();
                            // TODO: replace panics with errors
                            header.word_len = u16::try_from((total_len - core::mem::size_of::<$crate::TlvHeader>()) / 4).unwrap();
                        }
                        v
                    }
                }
            };
        }
    };
}

pub mod __private {
    pub use paste::paste;
}

#[cfg(test)]
mod tests {
    use super::*;

    tlv_struct! { Parent, *b"PRNT", TlvData,
        #[derive(Debug, PartialEq, Eq)]
        pub struct Parent {
            pub id: u32,
        }
    }

    tlv_struct! { Child, *b"CHLD", [u8],
        #[derive(Debug, PartialEq, Eq)]
        pub struct Child {
            pub value: u32,
        }
    }

    #[test]
    fn test_build_and_parse_simple() {
        let mut buf = [0u32; 32];

        // Build Parent and Child
        let (parent, mut builder) = TlvBuilder::new::<Parent>(&mut buf).unwrap();
        parent.id = 100;

        let child = builder.add::<Child>().unwrap();
        child.value = 200;

        let result_bytes = builder.finish().into_bytes(&buf).unwrap();
        assert_eq!(result_bytes.len(), 24);

        // Parse back
        let data = TlvData::overlay_bytes(result_bytes).unwrap();

        let mut parent_iter = data.iter::<Parent>();
        let parent_item = parent_iter.next().unwrap();
        assert!(parent_iter.next().is_none());

        assert_eq!(parent_item.header.tag, Parent::TAG);
        assert_eq!(parent_item.data.id, 100);

        // Parse Child from Parent's extension
        let mut child_iter = parent_item.ext().iter::<Child>();
        let child_item = child_iter.next().expect("Should find Child");
        assert!(child_iter.next().is_none());

        assert_eq!(child_item.header.tag, Child::TAG);
        assert_eq!(child_item.data.value, 200);
    }
}
