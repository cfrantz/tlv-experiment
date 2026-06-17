use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

mod hexdump;
pub use hexdump::hexdump;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TlvHeader {
    pub tag: u32,
    pub length: u32,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TlvData {
    data: [u32],
}

impl TlvData {
    pub fn overlay<'a>(data: &'a [u8]) -> &'a Self {
        let count = data.len() / 4;
        TlvData::ref_from_bytes_with_elems(data, count).unwrap()
    }
    pub fn iter<'a>(&'a self) -> TlvIterator<'a> {
        TlvIterator {
            data: self.data.as_bytes(),
        }
    }
}

pub struct TlvIterator<'a> {
    data: &'a [u8],
}

pub struct TlvItem<'a> {
    pub header: &'a TlvHeader,
    pub data: &'a [u8],
}

impl<'a> Iterator for TlvIterator<'a> {
    type Item = TlvItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (header, rest) = TlvHeader::ref_from_prefix(self.data).ok()?;
        let (data, remain) = rest.split_at(header.length as usize);
        self.data = remain;
        Some(TlvItem { header, data })
    }
}

pub trait TlvObject {
    type Extension: ?Sized;
    const TAG: u32;

    fn get_tag(&self) -> u32 {
        Self::TAG
    }
}

#[cfg(feature = "serde")]
#[typetag::serde]
pub trait HostTlvObject {
    fn pack(&self) -> Vec<u8>;
}

#[macro_export]
macro_rules! tlv_struct {
    ($name:ident, $tag:expr, [u8], $($definition:tt)*) => {
        #[cfg_attr(feature="serde", derive(serde::Serialize, serde::Deserialize))]
        #[derive(
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Immutable,
            zerocopy::KnownLayout,
        )]
        $($definition)*

        impl $crate::TlvObject for $name {
            type Extension = [u8];
            const TAG: u32 = u32::from_le_bytes($tag);
        }

        $crate::__private::paste! {
            #[cfg(feature="serde")]
            #[derive(serde::Serialize, serde::Deserialize)]
            pub struct [< Host $name >] {
                #[serde(flatten)]
                pub data: $name,
                #[serde(default, skip_serializing_if = "Vec::is_empty")]
                pub ext: Vec<u8>,
            }

            const _:() = {
                use zerocopy::{IntoBytes};
                use $crate::TlvObject;

                #[typetag::serde(name = stringify!($name))]
                impl $crate::HostTlvObject for [< Host $name >] {
                    fn pack(&self) -> Vec<u8> {
                        let data_len =
                            std::mem::size_of_val(&self.data) +
                            self.ext.len();
                        let mut v = Vec::with_capacity(
                            std::mem::size_of::<$crate::TlvHeader>() + data_len);
                        v.extend($crate::TlvHeader {
                            tag:  self.data.get_tag(),
                            length: data_len as u32,
                        }.as_bytes());
                        v.extend(self.data.as_bytes());
                        v.extend(self.ext.as_slice());
                        v
                    }
                }
            };
        }
    };

    ($name:ident, $tag:expr, TlvData, $($definition:tt)*) => {
        #[cfg_attr(feature="serde", derive(serde::Serialize, serde::Deserialize))]
        #[derive(
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Immutable,
            zerocopy::KnownLayout,
        )]
        $($definition)*

        impl $crate::TlvObject for $name {
            type Extension = $crate::TlvData;
            const TAG: u32 = u32::from_le_bytes($tag);
        }

        $crate::__private::paste! {
            #[cfg(feature="serde")]
            #[derive(serde::Serialize, serde::Deserialize)]
            pub struct [< Host $name >] {
                #[serde(flatten)]
                pub data: $name,
                #[serde(default, skip_serializing_if = "Vec::is_empty")]
                pub ext: Vec<Box<dyn $crate::HostTlvObject>>,
            }

            const _:() = {
                use zerocopy::{FromBytes, IntoBytes};
                use $crate::TlvObject;

                #[typetag::serde(name = stringify!($name))]
                impl $crate::HostTlvObject for [< Host $name >] {
                    fn pack(&self) -> Vec<u8> {
                        let mut v = Vec::with_capacity(
                            std::mem::size_of::<$crate::TlvHeader>() +
                            std::mem::size_of_val(&self.data));
                        v.extend($crate::TlvHeader {
                            tag:  self.data.get_tag(),
                            length: 0,
                        }.as_bytes());
                        v.extend(self.data.as_bytes());
                        for ext in self.ext.iter() {
                            v.extend(ext.pack());
                        }
                        let total_len = v.len();
                        {
                            let header = $crate::TlvHeader::mut_from_bytes(&mut v[..8]).unwrap();
                            header.length = (total_len - std::mem::size_of::<$crate::TlvHeader>()) as u32;
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
