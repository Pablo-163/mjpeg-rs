extern crate libc;
use std::fmt;
use std::os::raw::c_int;
use std::os::raw::c_char;
use std::ffi::CString;

extern "C" {
    fn create_socket(address: * const c_char, port: c_int) -> c_int;
    fn close_socket(fd: c_int);
    fn create_epoll(fd: c_int) -> c_int;
}

#[derive(Debug, Clone)]
pub struct MjpegServerError {
    description: String,
}

impl fmt::Display for MjpegServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

pub struct MjpegServer {
    fd: i32,
    epoll_fd: i32,
}

impl MjpegServer {
    pub fn new(address: &str, port: i32) -> Result<Self, MjpegServerError> {

        let address_c = CString::new(address).expect("CString::new failed");
        let fd = unsafe {
            create_socket(address_c.as_ptr(), port)
        };
        if fd < 0 {
            return Err(MjpegServerError{description: format!("Server started at the address {} on port {} failed. {}", address, port, errno::Errno(-fd).to_string())});
        }

        let epoll_fd = unsafe {
            create_epoll(fd)
        };
        if epoll_fd < 0 {
            return Err(MjpegServerError{description: format!("Server started at the address {} on port {} failed. {}", address, port, errno::Errno(-fd).to_string())});
        }
        Ok(MjpegServer{fd, epoll_fd})
    }
}

impl Drop for MjpegServer {
    fn drop(&mut self) {
        unsafe {
            close_socket(self.fd);
        }
    }
}

