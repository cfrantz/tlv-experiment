use zerocopy;
use tlv::tlv_struct;
use tlv::HostTlvObject;
use tlv::TlvData;

tlv_struct!{ Foo, *b"FOO_", [u8],
    pub struct Foo {
        pub x: u32,
        pub y: [u8; 4],
    }
}


tlv_struct!{ Bar, *b"Bar_", TlvData,
    pub struct Bar {
        pub n: u32,
    }
}

tlv_struct!{ Baz, *b"Baz_", TlvData,
    pub struct Baz {
        pub n: u32,
    }
}

const TEST: &'static str = r#"
{
  "n": 5,
  "ext": [
    {
      "Foo": {
        "x": 20,
        "y": [
          1,
          2,
          3,
          4
        ],
        "ext": [5,6,7,8]
      }
    }
  ]
}
"#;

fn main() {
    let zz: HostBar = serde_json::from_str(TEST).expect("deserialize");
    let buf = zz.pack();
    tlv::hexdump(buf.as_slice());

    let t = TlvData::overlay(buf.as_slice());
    for i in t.iter() {
        println!("{:#010x} len={} data={:02x?}", i.header.tag, i.header.length, i.data);
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
