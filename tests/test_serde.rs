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
            { "Foo": { "x": 40, "y": [ 11, 12, 13, 14 ], "ext": [15,16,17] } },
            { "Foo": { "x": 50, "y": [ 21, 22, 23, 24 ], "ext": [25,26,27,28,29] } },
            { "Baz": { "n": 60 } }
        ]
    }"#,
    )
    .unwrap();
    assert_eq!(zz.data.n, 5);
    assert_eq!(zz.ext.len(), 5);

    // Pack to a flat binary buffer
    let buf = zz.pack();

    // Verify the exact, complete byte layout of the packed Bar structure:
    let expected_buf = &[
        // Bar Header and data (tag: "Bar_", len: 96, n: 5)
        b'B', b'a', b'r', b'_', 0x60, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        // Foo 1 Header and data (tag: "FOO_", len: 12, x: 20, y: [1, 2, 3, 4], ext: [5, 6, 7, 8])
        b'F', b'O', b'O', b'_', 0x0c, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08,
        // Foo 2 Header and data (tag: "FOO_", len: 8, x: 30, y: [10, 20, 30, 40], ext = [])
        b'F', b'O', b'O', b'_', 0x08, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x0a, 0x14, 0x1e,
        0x28,
        // Foo 3 Header and data (tag: "FOO_", len: 11, x: 40, y: [11, 12, 13, 14], ext: [15, 16, 17], padded with one zero)
        b'F', b'O', b'O', b'_', 0x0b, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x00,
        // Foo 4 Header and data (tag: "FOO_", len: 13, x: 50, y: [21, 22, 23, 24], ext: [25, 26, 27, 28, 29], padded with three zeros)
        b'F', b'O', b'O', b'_', 0x0d, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 0x00, 0x00, 0x00,
        // Baz Header and data (tag: "Baz_", len: 4, n: 60)
        b'B', b'a', b'z', b'_', 0x04, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
    ];
    assert_eq!(buf, expected_buf);

    // Overlay TlvData and parse the outer container
    let t = TlvData::overlay(buf.as_slice());

    let mut bar_iter = t.iter::<Bar>();
    let bar_item = bar_iter.next().expect("Should have one Bar item");
    assert!(bar_iter.next().is_none());

    assert_eq!(bar_item.header.tag, Bar::TAG);
    assert_eq!(bar_item.header.length, 96);
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

    // Third extension: Foo
    let ext3 = ext_iter.next().expect("Should have third extension");
    assert_eq!(ext3.header.tag, Foo::TAG);
    assert_eq!(ext3.header.length, 11);
    let foo3 = ext3.cast::<Foo>().expect("Should cast to Foo");
    assert_eq!(foo3.data.x, 40);
    assert_eq!(foo3.data.y, [11, 12, 13, 14]);
    assert_eq!(foo3.ext(), &[15, 16, 17]);

    // Fourth extension: Foo
    let ext4 = ext_iter.next().expect("Should have fourth extension");
    assert_eq!(ext4.header.tag, Foo::TAG);
    assert_eq!(ext4.header.length, 13);
    let foo4 = ext4.cast::<Foo>().expect("Should cast to Foo");
    assert_eq!(foo4.data.x, 50);
    assert_eq!(foo4.data.y, [21, 22, 23, 24]);
    assert_eq!(foo4.ext(), &[25, 26, 27, 28, 29]);

    // Fifth extension: Baz
    let ext5 = ext_iter.next().expect("Should have fifth extension");
    assert_eq!(ext5.header.tag, Baz::TAG);
    assert_eq!(ext5.header.length, 4);
    let baz5 = ext5.cast::<Baz>().expect("Should cast to Baz");
    assert_eq!(baz5.data.n, 60);
    // Baz's extension type is TlvData, check that it is empty
    assert!(baz5.ext().iter::<TlvAny>().next().is_none());

    // No further extensions should exist
    assert!(ext_iter.next().is_none());

    // Iterate over only the Foos
    let mut foo_iter = bar_item.ext().iter::<Foo>();
    assert_eq!(foo_iter.next().unwrap().data, foo1.data);
    assert_eq!(foo_iter.next().unwrap().data, foo2.data);
    assert_eq!(foo_iter.next().unwrap().data, foo3.data);
    assert_eq!(foo_iter.next().unwrap().data, foo4.data);
    assert!(foo_iter.next().is_none());

    // Iterate over only the Bazs
    let mut baz_iter = bar_item.ext().iter::<Baz>();
    assert_eq!(baz_iter.next().unwrap().data, baz5.data);
    assert!(baz_iter.next().is_none());

    // Test serialization back to JSON and round-trip equivalence
    let serialized = serde_json::to_string(&zz).expect("serialize");
    let zz_roundtrip: HostBar = serde_json::from_str(&serialized).expect("deserialize roundtrip");
    assert_eq!(zz_roundtrip.data.n, zz.data.n);
    assert_eq!(zz_roundtrip.ext.len(), zz.ext.len());
    assert_eq!(zz_roundtrip.pack(), buf);
}
