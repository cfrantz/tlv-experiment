use tlv::HostTlvObject;
use tlv::tlv_struct;
use tlv::{TlvAny, TlvData, TlvObject, TlvQuery};

tlv_struct! { Foo, *b"FOO_", [u8],
    #[derive(Debug, PartialEq, Eq)]
    pub struct Foo {
        pub x: u32,
        pub y: [u8; 4],
    }
}

tlv_struct! { Bar, *b"Bar_", TlvData,
    #[derive(Debug, PartialEq, Eq)]
    pub struct Bar {
        pub n: u32,
    }
}

tlv_struct! { Baz, *b"Baz_", TlvData,
    #[derive(Debug, PartialEq, Eq)]
    pub struct Baz {
        pub n: u32,
    }
}

#[test]
fn test_serde_and_parsing() {
    // Deserialize from JSON
    let zz: HostBar = serde_json::from_str(
        r#"{
        "n": 5,
        "ext": [
            { "Foo": { "x": 20, "y": [ 1, 2, 3, 4 ], "ext": [5,6,7,8] } },
            { "Foo": { "x": 30, "y": [ 10, 20, 30, 40 ] } },
            { "Baz": { "n": 60 } }
        ]
    }"#,
    )
    .unwrap();
    assert_eq!(zz.data.n, 5);
    assert_eq!(zz.ext.len(), 3);

    // Pack to a flat binary buffer
    let buf = zz.pack();

    // Verify the exact, complete byte layout of the packed Bar structure:
    let expected_buf = &[
        // Bar Header and data (tag: "Bar_", len: 52, n: 5)
        b'B', b'a', b'r', b'_', 0x34, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        // Foo 1 Header and data (tag: "FOO_", len: 12, x: 20, y: [1, 2, 3, 4], ext: [5, 6, 7, 8])
        b'F', b'O', b'O', b'_', 0x0c, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08,
        // Foo 2 Header and data (tag: "FOO_", len: 8, x: 30, y: [10, 20, 30, 40], ext = [])
        b'F', b'O', b'O', b'_', 0x08, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x0a, 0x14, 0x1e,
        0x28, // Baz Header and data (tag: "Baz_", len: 4, n: 60)
        b'B', b'a', b'z', b'_', 0x04, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
    ];
    assert_eq!(buf, expected_buf);

    // Overlay TlvData and parse the outer container
    let t = TlvData::overlay(buf.as_slice());

    let mut bar_iter = t.iter::<Bar>();
    let bar_item = bar_iter.next().expect("Should have one Bar item");
    assert!(bar_iter.next().is_none());

    assert_eq!(bar_item.header.tag, Bar::TAG);
    assert_eq!(bar_item.header.length, 52);
    assert_eq!(bar_item.data.n, 5);

    // Iterate over Bar's extensions
    let mut ext_iter = bar_item.ext().iter::<TlvAny>();

    // First extension: Foo
    let ext1 = ext_iter.next().expect("Should have first extension");
    assert_eq!(ext1.header.tag, Foo::TAG);
    assert_eq!(ext1.header.length, 12);
    let foo1 = ext1.cast::<Foo>().expect("Should cast to Foo");
    assert_eq!(foo1.data.x, 20);
    assert_eq!(foo1.data.y, [1, 2, 3, 4]);
    assert_eq!(foo1.ext(), &[5, 6, 7, 8]);

    // Second extension: Foo
    let ext2 = ext_iter.next().expect("Should have second extension");
    assert_eq!(ext2.header.tag, Foo::TAG);
    assert_eq!(ext2.header.length, 8);
    let foo2 = ext2.cast::<Foo>().expect("Should cast to Foo");
    assert_eq!(foo2.data.x, 30);
    assert_eq!(foo2.data.y, [10, 20, 30, 40]);
    assert_eq!(foo2.ext(), &[] as &[u8]);

    // Third extension: Baz
    let ext3 = ext_iter.next().expect("Should have third extension");
    assert_eq!(ext3.header.tag, Baz::TAG);
    assert_eq!(ext3.header.length, 4);
    let baz3 = ext3.cast::<Baz>().expect("Should cast to Baz");
    assert_eq!(baz3.data.n, 60);
    // Baz's extension type is TlvData, check that it is empty
    assert!(baz3.ext().iter::<TlvAny>().next().is_none());

    // No further extensions should exist
    assert!(ext_iter.next().is_none());

    // 6. Test serialization back to JSON and round-trip equivalence
    let serialized = serde_json::to_string(&zz).expect("serialize");
    let zz_roundtrip: HostBar = serde_json::from_str(&serialized).expect("deserialize roundtrip");
    assert_eq!(zz_roundtrip.data.n, zz.data.n);
    assert_eq!(zz_roundtrip.ext.len(), zz.ext.len());
    assert_eq!(zz_roundtrip.pack(), buf);
}
