extern crate mjpeg_rs;
#[macro_use]
extern crate log;

use mjpeg_rs::{MjpegServer};

fn main() {
    env_logger::init();
    let address = "0.0.0.0";
    let port = 9000;
    let server = MjpegServer::new(address, port);
    if let Err(err) = server {
        error!("{}", err);
        std::process::exit(1);
    }
    server.unwrap().run();
    info!("Server started at the address {} on port {} successfully", address, port);
}