// #![feature(rustc_private)]
extern crate cc;

fn main() {
    cc::Build::new().file("src/socket/socket.c").compile("socket.a");
}