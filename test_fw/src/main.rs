#![no_std]
#![no_main]
#![allow(clippy::disallowed_names)]

use core::hint::black_box;
use tlv::{TlvAny, TlvData, TlvQuery, tlv_struct};

use core::panic::PanicInfo;

tlv_struct! { Foo, *b"FOO_", [u8],
    #[derive(Debug)]
    pub struct Foo {
        pub x: u32,
        pub y: u32,
    }
}

tlv_struct! { Bar, *b"BAR_", [u8],
    #[derive(Debug)]
    pub struct Bar {
        pub a: u32,
        pub b: u32,
    }
}

// Static words representing the TLV stream:
// TLV 1: FOO_ (length 8, payload: x = 42, y = 100)
// TLV 2: BAR_ (length 8, payload: a = 200, b = 300)
static WORDS: &[u32] = &[
    // FOO_ header: tag, length (2 words) | reserved (0)
    0x5f4f4f46, 0x00000002, // FOO_ payload: x = 42, y = 100
    42, 100, // BAR_ header: tag, length (2 words) | reserved (0)
    0x5f524142, 0x00000002, // BAR_ payload: a = 200, b = 300
    200, 300,
];

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let _ = black_box(main_impl(black_box(WORDS)));
    loop {
        core::hint::spin_loop();
    }
}

#[inline(never)]
fn main_impl(words: &[u32]) -> u32 {
    let mut sum: u32 = 0;

    let tlv_data = TlvData::overlay(words);

    for item in tlv_data.iter::<TlvAny>() {
        if let Some(foo) = item.cast::<Foo>() {
            sum = sum.wrapping_add(foo.data.x);
            sum = sum.wrapping_add(foo.data.y);
        }
        if let Some(bar) = item.cast::<Bar>() {
            sum = sum.wrapping_add(bar.data.a);
            sum = sum.wrapping_add(bar.data.b);
        }
    }
    sum
}
