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

tlv_struct! { Baf, *b"Baf_", TlvData,
    #[derive(Debug, PartialEq, Eq)]
    pub struct Baf {
        pub a: [u32; 3],
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
            { "Baz": { "n": 60 } },
            { "Baf": { "a": [237482734, 19263432, 81823823] } }
        ]
    }"#,
    )
    .unwrap();
    assert_eq!(zz.data.n, 5);
    assert_eq!(zz.ext.len(), 6);

    // Pack to a flat binary buffer
    let buf = zz.pack();

    // Verify the exact, complete byte layout of the packed Bar structure:
    let expected_buf = &[
        // Bar Header and data (tag: "Bar_", len: 29 words, n: 5)
        b'B', b'a', b'r', b'_', 0x1d, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        // Foo 1 Header and data (tag: "FOO_", len: 3 words, x: 20, y: [1, 2, 3, 4], ext: [5, 6, 7, 8])
        b'F', b'O', b'O', b'_', 0x03, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08,
        // Foo 2 Header and data (tag: "FOO_", len: 2 words, x: 30, y: [10, 20, 30, 40], ext = [])
        b'F', b'O', b'O', b'_', 0x02, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x0a, 0x14, 0x1e,
        0x28,
        // Foo 3 Header and data (tag: "FOO_", len: 3 words, padding_bytes: 1, x: 40, y: [11, 12, 13, 14], ext: [15, 16, 17], padded with one zero)
        b'F', b'O', b'O', b'_', 0x03, 0x00, 0x01, 0x00, 0x28, 0x00, 0x00, 0x00, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x00,
        // Foo 4 Header and data (tag: "FOO_", len: 4 words, padding_bytes: 3 x: 50, y: [21, 22, 23, 24], ext: [25, 26, 27, 28, 29], padded with three zeros)
        b'F', b'O', b'O', b'_', 0x04, 0x00, 0x03, 0x00, 0x32, 0x00, 0x00, 0x00, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 0x00, 0x00, 0x00,
        // Baz Header and data (tag: "Baz_", len: 1 word, n: 60)
        b'B', b'a', b'z', b'_', 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        // Baf Header and data (tag: "Baf_", len: 3 words, a: [237482734, 19263432, 81823823])
        b'B', b'a', b'f', b'_', 0x03, 0x00, 0x00, 0x00, 0xee, 0xb2, 0x27, 0x0e, 0xc8, 0xef, 0x25,
        0x01, 0x4f, 0x88, 0xe0, 0x04,
    ];
    assert_eq!(buf, expected_buf);

    // Overlay TlvData and parse the outer container
    let t = TlvData::overlay_bytes(buf.as_slice()).unwrap();

    let mut bar_iter = t.iter::<Bar>();
    let bar_item = bar_iter.next().expect("Should have one Bar item");
    assert!(bar_iter.next().is_none());

    assert_eq!(bar_item.header.tag, Bar::TAG);
    assert_eq!(bar_item.header.word_len, 29);
    assert_eq!(bar_item.data.n, 5);

    // Iterate over Bar's extensions
    let mut ext_iter = bar_item.ext().iter::<TlvAny>();

    // First extension: Foo
    let ext1 = ext_iter.next().expect("Should have first extension");
    assert_eq!(ext1.header.tag, Foo::TAG);
    assert_eq!(ext1.header.word_len, 3);
    let foo1 = ext1.cast::<Foo>().expect("Should cast to Foo");
    assert_eq!(foo1.data.x, 20);
    assert_eq!(foo1.data.y, [1, 2, 3, 4]);
    assert_eq!(foo1.ext(), &[5, 6, 7, 8]);

    // Second extension: Foo
    let ext2 = ext_iter.next().expect("Should have second extension");
    assert_eq!(ext2.header.tag, Foo::TAG);
    assert_eq!(ext2.header.word_len, 2);
    let foo2 = ext2.cast::<Foo>().expect("Should cast to Foo");
    assert_eq!(foo2.data.x, 30);
    assert_eq!(foo2.data.y, [10, 20, 30, 40]);
    assert_eq!(foo2.ext(), &[] as &[u8]);

    // Third extension: Foo
    let ext3 = ext_iter.next().expect("Should have third extension");
    assert_eq!(ext3.header.tag, Foo::TAG);
    assert_eq!(ext3.header.word_len, 3);
    let foo3 = ext3.cast::<Foo>().expect("Should cast to Foo");
    assert_eq!(foo3.data.x, 40);
    assert_eq!(foo3.data.y, [11, 12, 13, 14]);
    assert_eq!(foo3.ext(), &[15, 16, 17]);

    // Fourth extension: Foo
    let ext4 = ext_iter.next().expect("Should have fourth extension");
    assert_eq!(ext4.header.tag, Foo::TAG);
    assert_eq!(ext4.header.word_len, 4);
    let foo4 = ext4.cast::<Foo>().expect("Should cast to Foo");
    assert_eq!(foo4.data.x, 50);
    assert_eq!(foo4.data.y, [21, 22, 23, 24]);
    assert_eq!(foo4.ext(), &[25, 26, 27, 28, 29]);

    // Fifth extension: Baz
    let ext5 = ext_iter.next().expect("Should have fifth extension");
    assert_eq!(ext5.header.tag, Baz::TAG);
    assert_eq!(ext5.header.word_len, 1);
    let baz5 = ext5.cast::<Baz>().expect("Should cast to Baz");
    assert_eq!(baz5.data.n, 60);
    // Baz's extension type is TlvData, check that it is empty
    assert!(baz5.ext().iter::<TlvAny>().next().is_none());

    // Sixth extension: Baf
    let ext6 = ext_iter.next().expect("Should have sixth extension");
    assert_eq!(ext6.header.tag, Baf::TAG);
    assert_eq!(ext6.header.word_len, 3);
    let baf6 = ext6.cast::<Baf>().expect("Should cast to Baf");
    assert_eq!(baf6.data.a, [237482734, 19263432, 81823823]);

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

    // Iterate over only the Bafs
    let mut baf_iter = bar_item.ext().iter::<Baf>();
    assert_eq!(baf_iter.next().unwrap().data, baf6.data);
    assert!(baf_iter.next().is_none());

    // Test serialization back to JSON and round-trip equivalence
    let serialized = serde_json::to_string(&zz).expect("serialize");
    let zz_roundtrip: HostBar = serde_json::from_str(&serialized).expect("deserialize roundtrip");
    assert_eq!(zz_roundtrip.data.n, zz.data.n);
    assert_eq!(zz_roundtrip.ext.len(), zz.ext.len());
    assert_eq!(zz_roundtrip.pack(), buf);
}

#[test]
fn test_builder_closure() {
    use tlv::TlvBuilder;

    let mut buf = [0u32; 100];
    let (bar, mut tlv) = TlvBuilder::new::<Bar>(&mut buf).unwrap();
    *bar = Bar { n: 5 };
    tlv.add_in::<Baz, _>(|baz, tlv| {
        *baz = Baz { n: 60 };
        *tlv.add::<Foo>()? = Foo {
            x: 20,
            y: [1, 2, 3, 4],
        };
        Ok(())
    })
    .unwrap();
    *tlv.add::<Foo>().unwrap() = Foo {
        x: 30,
        y: [10, 20, 30, 40],
    };
    let result_bytes = tlv.finish().into_bytes(&buf).unwrap();

    // Build the same tree using serde and compare it
    let expected_bytes_serde = serde_json::from_str::<HostBar>(
        r#"{
        "n": 5,
        "ext": [
            {
                "Baz": {
                    "n": 60,
                    "ext": [
                        {
                            "Foo": {
                                "x": 20,
                                "y": [1, 2, 3, 4]
                            }
                        }
                    ]
                }
            },
            {
                "Foo": {
                    "x": 30,
                    "y": [10, 20, 30, 40]
                }
            }
        ]
    }"#,
    )
    .unwrap()
    .pack();
    assert_eq!(expected_bytes_serde, result_bytes);

    let expected_bytes_explicit = &[
        // Bar Header and data (tag: "Bar_", len: 12 words, n: 5)
        b'B', b'a', b'r', b'_', 0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        // Baz Header and data (tag: "Baz_", len: 5 words, n: 60)
        b'B', b'a', b'z', b'_', 0x05, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
        // Foo Header and data inside baz (tag: "FOO_", len: 2 words, x: 20, y: [1, 2, 3, 4])
        b'F', b'O', b'O', b'_', 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        0x04,
        // Foo Header and data inside bar(tag: "FOO_", len: 2 words, x: 30, y: [10, 20, 30, 40])
        b'F', b'O', b'O', b'_', 0x02, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x0a, 0x14, 0x1e,
        0x28,
    ];
    assert_eq!(result_bytes, expected_bytes_explicit);

    // Overlay TlvData and parse the built container to verify round-trip correctness
    use tlv::{TlvAny, TlvData, TlvQuery};
    let t = TlvData::overlay_bytes(result_bytes).unwrap();

    let mut bar_iter = t.iter::<Bar>();
    let bar_item = bar_iter.next().expect("Should have one Bar item");
    assert!(bar_iter.next().is_none());

    assert_eq!(bar_item.header.tag, Bar::TAG);
    assert_eq!(bar_item.header.word_len, 12);
    assert_eq!(bar_item.data.n, 5);

    // Iterate over Bar's extensions
    let mut ext_iter = bar_item.ext().iter::<TlvAny>();

    // First extension: Baz
    let ext_baz = ext_iter.next().expect("Should have Baz extension");
    assert_eq!(ext_baz.header.tag, Baz::TAG);
    assert_eq!(ext_baz.header.word_len, 5);
    let baz_item = ext_baz.cast::<Baz>().expect("Should cast to Baz");
    assert_eq!(baz_item.data.n, 60);

    {
        // Baz's child: Foo (nested inside Baz)
        let mut baz_ext_iter = baz_item.ext().iter::<TlvAny>();
        let ext_foo_in_baz = baz_ext_iter.next().expect("Should have Foo inside Baz");
        assert_eq!(ext_foo_in_baz.header.tag, Foo::TAG);
        assert_eq!(ext_foo_in_baz.header.word_len, 2);
        let foo_in_baz = ext_foo_in_baz
            .cast::<Foo>()
            .expect("Should cast to Foo inside Baz");
        assert_eq!(foo_in_baz.data.x, 20);
        assert_eq!(foo_in_baz.data.y, [1, 2, 3, 4]);
        assert!(baz_ext_iter.next().is_none());
    }

    // Second extension: Foo (flat child of Bar)
    let ext_foo_in_bar = ext_iter.next().expect("Should have Foo inside Bar");
    assert_eq!(ext_foo_in_bar.header.tag, Foo::TAG);
    assert_eq!(ext_foo_in_bar.header.word_len, 2);
    let foo_in_bar = ext_foo_in_bar
        .cast::<Foo>()
        .expect("Should cast to Foo inside Bar");
    assert_eq!(foo_in_bar.data.x, 30);
    assert_eq!(foo_in_bar.data.y, [10, 20, 30, 40]);
    assert!(ext_iter.next().is_none());
}

#[test]
fn test_builder_overflow() {
    use tlv::{TlvBuilder, TlvError};

    // Buffer big enough to hold the large TLVs.
    // 70000 u32 words.
    let mut buf = vec![0u32; 70000];
    let (bar, mut tlv) = TlvBuilder::new::<Bar>(&mut buf).unwrap();
    *bar = Bar { n: 5 };

    // We add 16382 Foo objects (4 words each = 65528 words) and 2 Baz objects
    // (3 words each = 6 words total).
    // This results in a child Baz payload of exactly 65535 words, which fits in u16.
    // But the child total length (payload + 2 words header) is 65537 words,
    // which overflows u16.
    let res = tlv.add_in::<Baz, _>(|baz, child_tlv| {
        *baz = Baz { n: 42 };
        for _ in 0..16382 {
            child_tlv.add::<Foo>()?;
        }
        child_tlv.add::<Baz>()?;
        child_tlv.add::<Baz>()?;
        Ok(())
    });

    // The finish_with_parent call must catch the u16 overflow and return Err(TlvError).
    assert_eq!(res.unwrap_err(), TlvError);
}
