extern crate mjpeg_rs;
#[macro_use]
extern crate log;

use mjpeg_rs::{MjpegServer, HttpAuth};

fn main() {

    env_logger::init();
    let address = "0.0.0.0";
    let port = 9009;
    let server = MjpegServer::new(address, port, "10.0.3.62:80", "/mjpg/video.mjpg", HttpAuth::BasicAuthType, "root", "root");
    // let server = MjpegServer::new(address, port, "195.211.217.181:80", "/mjpg/video.mjpg", HttpAuth::NoneAuthType, "root", "root");
    // let server = MjpegServer::new(address, port, "172.27.2.13:80", "/mjpg/video.mjpg", HttpAuth::BasicAuthType, "root", "root");
    // let server = MjpegServer::new(address, port, "213.193.89.202:80", "/mjpg/video.mjpg", HttpAuth::NoneAuthType, "root", "root");
    if let Err(err) = server {
        error!("{}", err);
        std::process::exit(1);
    }
    server.unwrap().run();
    info!("Server started at the address {} on port {} successfully", address, port);
}