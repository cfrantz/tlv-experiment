use std::fmt;
use tlv::tlv_struct;
use tlv::HostTlvObject;
use tlv::{TlvAny, TlvData, TlvQuery};
use zerocopy;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(
    zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout, Debug,
)]
#[repr(C)]
pub struct Timestamp {
    pub lo: u32,
    pub hi: u32,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "String", into = "String"))]
#[derive(
    zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout, Clone,
)]
#[repr(C)]
pub struct StringBuf<const N: usize>(pub [u8; N]);

impl<const N: usize> fmt::Debug for StringBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StringBuf")
            .field(&String::from(self.clone()))
            .finish()
    }
}

impl<const N: usize> From<String> for StringBuf<N> {
    fn from(s: String) -> Self {
        let mut data = [0u8; N];
        let n = std::cmp::min(s.len(), N);
        data[..n].copy_from_slice(&s.as_bytes()[..n]);
        StringBuf(data)
    }
}

impl<const N: usize> From<StringBuf<N>> for String {
    fn from(data: StringBuf<N>) -> Self {
        let mut it = data.0.split(|&x| x == 0);
        if let Some(item) = it.next() {
            String::from_utf8_lossy(item).into()
        } else {
            String::new()
        }
    }
}

tlv_struct! { ImageDescriptor, *b"IMGD", TlvData,
    #[derive(Debug)]
    struct ImageDescriptor {
        pub descriptor_offset: u32,
        pub signed_len: u32,
    }
}

tlv_struct! { PayloadVersion, *b"VERS", [u8],
    #[derive(Debug)]
    struct PayloadVersion {
        pub security_version: u32,
        pub image_vendor: StringBuf<8>,
        pub image_family: StringBuf<8>,
        pub image_domain: u32,
        pub image_timestamp: Timestamp,
    }
}

tlv_struct! { Region, *b"REGN", TlvData,
    #[derive(Debug)]
    struct Region {
        pub name: StringBuf<32>,
        pub offset: u32,
        pub size: u32,
        #[serde(default)]
        pub measurement_group: u32,
        #[serde(default)]
        pub version: u16,
        #[serde(default)]
        pub flags: u16,
    }
}

tlv_struct! { Measurement, *b"HASH", [u8],
    #[derive(Debug)]
    struct Measurement {
        pub algorithm: u32,
        pub measurement_group: u32,
    }
}

tlv_struct! { PublicKey, *b"PKEY", TlvData,
    #[derive(Debug)]
    struct PublicKey {
        pub algorithm: u32,
        pub key_domain: u32,
    }
}

tlv_struct! { P256PublicKey, *b"p256", [u8],
    #[derive(Debug)]
    struct P256PublicKey {
        #[serde(default)]
        pub x: [u8; 32],
        #[serde(default)]
        pub y: [u8; 32],
    }
}

const TEST: &'static str = r#"
{
    descriptor_offset: 0,
    signed_len: 0,
    ext: [
        { PayloadVersion: {
            security_version: 0,
            image_vendor: "Google",
            image_family: "Indus",
            image_domain: 0x1234,
            image_timestamp: { lo: 0, hi: 0 },
            ext: [ 1, 0, 0, 0 ],
        }},
        { Region: { name: "bootcode", offset: 0, size: 4096 }},
        { Region: { name: "runtime", offset: 4096, size: 61440 }},
        { Region: { name: "not_writeable", offset: 65536, size: 65536 }},
        { Region: { name: "descriptor", offset: 131072, size: 131072 }},
        { Region: { name: "readable", offset: 262144, size: 65536 }},
        { Region: { name: "not_readable", offset: 327680, size: 65536 }},
        { Region: { name: "writeable", offset: 393216, size: 131072 }},
        { Region: { name: "unused", offset: 524288, size: 33030144 }},
        { Measurement: {
            algorithm: 1,
            measurement_group: 0,
            ext: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
        }},
        { PublicKey: {
            algorithm: 0xfefefefe,
            key_domain: 1,
            ext: [
                { P256PublicKey: {}}
            ],
        }}
    ]
}
"#;

fn fourcc(tag: u32) -> String {
    let mut s = String::new();
    for byte in tag.to_le_bytes() {
        if (0x20..0x7f).contains(&byte) {
            s.push(byte as char);
        } else {
            s.push_str(&format!("\\x{byte:02x}"));
        }
    }
    s
}

fn main() {
    let zz: HostImageDescriptor = serde_json5::from_str(TEST).expect("deserialize");
    let buf = zz.pack();
    tlv::hexdump(buf.as_slice());

    let t = TlvData::overlay(buf.as_slice());
    for item in t.iter::<ImageDescriptor>() {
        println!(
            "tag={} len={} data={:02x?}",
            fourcc(item.header.tag),
            item.header.length,
            item.raw
        );
        for ext in item.ext().iter::<TlvAny>() {
            println!(
                "    tag={} len={} data={:02x?}",
                fourcc(ext.header.tag),
                ext.header.length,
                ext.raw
            );
            if let Some(x) = ext.cast::<PayloadVersion>() {
                println!("    {:?} ext={:x?}\n", x.data, x.ext());
            }
            if let Some(x) = ext.cast::<Measurement>() {
                println!("    {:?} ext={:x?}\n", x.data, x.ext());
            }
            if let Some(x) = ext.cast::<Region>() {
                println!("    {:?}\n", x.data);
            }
            if let Some(x) = ext.cast::<PublicKey>() {
                println!("    {:?}\n", x.data);
            }
        }
    }
}
