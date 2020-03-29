extern crate mjpeg_rs;
#[macro_use]
extern crate log;

use mjpeg_rs::{MjpegServer};

fn main() {
    env_logger::init();
    let address = "127.0.0.1";
    let port = 5432;
    let server = MjpegServer::new(address, port);
    if let Err(err) = server {
        error!("{}", err);
        std::process::exit(1);
    }
    info!("Server started at the address {} on port {} successfully", address, port);
}