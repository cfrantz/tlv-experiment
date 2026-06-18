//! A simple, zero-copy framework for working with Type-Length-Value (TLV) objects.
//!
//! This crate provides tools to overlay structured views onto raw byte buffers,
//! allowing efficient parsing and creation of TLV structures without unnecessary
//! allocations or copies.
//!
//! # Core Concepts
//!
//! *   [`TlvHeader`]: The common prefix for all TLV objects, containing a 4-byte `tag` and a 4-byte `length`.
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
//! let buf: &[u32] = &[]; // Use u32 slice to guarantee 4-byte alignment
//! let byte_buf = buf.as_bytes();
//! let tlv_data = TlvData::overlay(byte_buf);
//! for item in tlv_data.iter::<TlvAny>() {
//!     println!("Tag: {}, Length: {}", item.header.tag, item.header.length);
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, transmute_ref};

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
/// of the payload (in bytes) following the header.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TlvHeader {
    /// The tag identifying the type of the TLV object. Typically represented as a 4-character ASCII string (FourCC).
    pub tag: u32,
    /// The length of the data following this header, in bytes.
    pub length: u16,
    pub reserved: u16,
}

impl TlvHeader {
    const HEADER_WORD_COUNT: usize = {
        assert!(core::mem::size_of::<TlvHeader>().is_multiple_of(4));
        core::mem::size_of::<TlvHeader>() / 4
    };

    // The length of the data + padding following this header, in 32-bit words
    fn word_len(&self) -> usize {
        usize::from(self.length).div_ceil(4)
    }

    fn ref_from_words_prefix(words: &[u32]) -> Option<(&TlvHeader, &[u32])> {
        let (header_words, rest) = words.split_first_chunk::<{ Self::HEADER_WORD_COUNT }>()?;
        Some((transmute_ref!(header_words), rest))
    }
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
    fn make_ext(ext: &[u8]) -> &Self::Extension {
        ext
    }
}

impl TlvData {
    /// Constructs a new `TlvData` reference by overlaying onto a byte buffer.
    ///
    /// The buffer must be aligned to 4 bytes and its length must be a multiple of 4.
    ///
    /// # Panics
    ///
    /// Panics if the buffer length is not a multiple of 4, or if the buffer is not properly aligned.
    pub fn overlay(data: &[u8]) -> &Self {
        let count = data.len() / 4;
        TlvData::ref_from_bytes_with_elems(data, count).unwrap()
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
    /// The underlying slice of the TLV: header, data and any extension data.
    pub raw: &'a [u8],
}

impl<'a, T: TlvObject + 'a> Iterator for TlvIterator<'a, T> {
    type Item = TlvItem<'a, T>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.data.is_empty() {
            let (header, rest) = TlvHeader::ref_from_words_prefix(self.data)?;
            let remain = rest.get(header.word_len()..)?;
            let content = rest.as_bytes().get(..usize::from(header.length))?;
            let raw = &self.data.as_bytes()
                [..usize::from(header.length) + core::mem::size_of::<TlvHeader>()];
            let (data, _extra) = T::ref_from_prefix(content).ok()?;
            self.data = remain;
            if header.tag == T::TAG || T::TAG == 0 {
                return Some(TlvItem { header, data, raw });
            }
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
    fn make_ext(ext: &[u8]) -> &Self::Extension;
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
            //let data = &self.raw[core::mem::size_of::<TlvHeader>()..];
            //let (t, _) = U::ref_from_prefix(data).ok()?;
            //Some(t)
            let (header, rest) = TlvHeader::ref_from_prefix(self.raw).ok()?;
            let (data, _extra) = U::ref_from_prefix(rest).ok()?;
            Some(TlvItem {
                header,
                data,
                raw: self.raw,
            })
        } else {
            None
        }
    }
    fn ext(&self) -> Self::Extension {
        if core::mem::size_of::<T>() == 0 {
            const EMPTY: [u32; 0] = [0u32; 0];
            return T::make_ext(EMPTY.as_bytes());
        }

        let offset = core::mem::size_of::<TlvHeader>() + core::mem::size_of::<T>();
        let data = &self.raw[offset..];
        T::make_ext(data)
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

        // Implement the TlvObject trait for the generated zero-copy struct.
        impl $crate::TlvObject for $name {
            type Extension = [u8];
            // Convert the tag from little-endian bytes to a u32 constant.
            const TAG: u32 = u32::from_le_bytes($tag);
            // Returns the raw byte slice as the extension type.
            fn make_ext(ext: &[u8]) -> &Self::Extension {
                ext
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
                        v.extend($crate::TlvHeader {
                            tag:  self.data.get_tag(),
                            // TODO: replace panics with errors
                            length: u16::try_from(data_len).unwrap(),
                            reserved: 0,
                        }.as_bytes());
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

        // Implement the TlvObject trait for the generated zero-copy struct.
        impl $crate::TlvObject for $name {
            type Extension = $crate::TlvData;
            // Convert the tag from little-endian bytes to a u32 constant.
            const TAG: u32 = u32::from_le_bytes($tag);
            // Overlays a TlvData view onto the remaining bytes to parse them as nested TLVs.
            fn make_ext(ext: &[u8]) -> &Self::Extension {
                $crate::TlvData::overlay(ext)
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
                            length: 0,
                            reserved: 0,
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
                            header.length = u16::try_from(total_len - core::mem::size_of::<$crate::TlvHeader>()).unwrap();
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
