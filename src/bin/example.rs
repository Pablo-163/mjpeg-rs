extern crate mjpeg_rs;
#[macro_use]
extern crate log;

use mjpeg_rs::{MjpegServer, HttpAuth};
use std::net::IpAddr;
use std::str::FromStr;

fn main() {

    env_logger::init();
    let address = "0.0.0.0";
    let port = 9009;
    // let server = MjpegServer::new(address, port, "http://root:root@10.0.3.30/mjpg/video.mjpg");
    let server = MjpegServer::new(address, port, "rtsp://admin:Pa$$w0rd@10.0.2.25/cam/realmonitor?channel=1&subtype=0");

    if let Err(err) = server {
        error!("{}", err);
        std::process::exit(1);
    }
    server.unwrap().run();
    info!("Server started at the address {} on port {} successfully", address, port);
}