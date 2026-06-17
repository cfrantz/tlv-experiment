use tlv::tlv_struct;
use tlv::HostTlvObject;
use tlv::{TlvAny, TlvData, TlvQuery};
use zerocopy;

tlv_struct! { Foo, *b"FOO_", [u8],
    #[derive(Debug)]
    pub struct Foo {
        pub x: u32,
        pub y: [u8; 4],
    }
}

tlv_struct! { Bar, *b"Bar_", TlvData,
    #[derive(Debug)]
    pub struct Bar {
        pub n: u32,
    }
}

tlv_struct! { Baz, *b"Baz_", TlvData,
    #[derive(Debug)]
    pub struct Baz {
        pub n: u32,
    }
}

const TEST: &'static str = r#"
{
  "n": 5,
  "ext": [
    { "Foo": { "x": 20, "y": [ 1, 2, 3, 4 ], "ext": [5,6,7,8] } },
    { "Foo": { "x": 30, "y": [ 10, 20, 30, 40 ] } },
    { "Baz": { "n": 60 } }
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
    let zz: HostBar = serde_json::from_str(TEST).expect("deserialize");
    let buf = zz.pack();
    tlv::hexdump(buf.as_slice());

    let t = TlvData::overlay(buf.as_slice());
    for item in t.iter::<Bar>() {
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
            if let Some(foo) = ext.cast::<Foo>() {
                println!("    {:?} ext={:x?}\n", foo.data, foo.ext());
            }
            if let Some(baz) = ext.cast::<Baz>() {
                println!("    {:?}\n", baz.data);
            }
        }
    }

    //let zz = HostBar {
    //    data: Bar { n: 5 },
    //    ext: vec![
    //        Box::new(HostFoo{
    //            data: Foo{x:20, y:[1,2,3,4]},
    //            ext: vec![],
    //        }) as Box<dyn HostTlvObject>
    //    ],
    //};
    //let s = serde_json::to_string_pretty(&zz).expect("serialize");
    //println!("s = {s}");
}
