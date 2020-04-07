extern crate mjpeg_rs;
#[macro_use]
extern crate log;

use mjpeg_rs::{MjpegServer};

fn main() {
    env_logger::init();
    let address = "0.0.0.0";
    let port = 9009;
    // 213.193.89.202:80
    let server = MjpegServer::new(address, port, "62.194.252.21:82", "/mjpg/video.mjpg");
    if let Err(err) = server {
        error!("{}", err);
        std::process::exit(1);
    }
    server.unwrap().run();
    info!("Server started at the address {} on port {} successfully", address, port);
}