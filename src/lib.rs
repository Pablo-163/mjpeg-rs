extern crate libc;
use std::fmt;
use std::os::raw::c_int;
use std::os::raw::c_char;
use std::ffi::CString;
use std::collections::BTreeMap;

extern "C" {
    fn create_socket(address: * const c_char, port: c_int) -> c_int;
    fn close_socket(fd: c_int);
    fn create_epoll(fd: c_int) -> c_int;
    fn epoll_update(server_fd: c_int, epoll_fd: c_int, max_events: c_int, connected: * mut c_int, closed: * mut c_int);
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

struct Data {

}

pub struct MjpegServer {
    fd: i32,
    epoll_fd: i32,
    data: BTreeMap<i32, Data>,
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
            unsafe {
                close_socket(fd);
            }
            return Err(MjpegServerError{description: format!("Server started at the address {} on port {} failed. {}", address, port, errno::Errno(-fd).to_string())});
        }
        Ok(MjpegServer{fd, epoll_fd, data: BTreeMap::<i32, Data>::new()})
    }
    pub fn run(&mut self) {
        loop {
            println!("before");
            const MAX_EVENTS: usize = 100;
            let mut connected: [c_int; MAX_EVENTS] = [0; MAX_EVENTS];
            let mut closed: [c_int; MAX_EVENTS] = [0; MAX_EVENTS];
            unsafe {
                epoll_update(self.fd, self.epoll_fd, MAX_EVENTS as i32, connected.as_mut_ptr(), closed.as_mut_ptr());
            }
            for fd in connected.iter() {
                if *fd != 0 {
                    println!("New connection fd = {}", *fd);
                    match self.data.get(fd) {
                        Some(value) => {
                            self.data.remove(fd);
                            self.data.insert(*fd, Data{});
                        },
                        None => {
                            self.data.insert(*fd, Data{});
                        }
                    }
                }
            }
            for fd in closed.iter() {
                if *fd != 0 {
                    println!("Close connection fd = {}", *fd);
                    match self.data.get(fd) {
                        Some(value) => {
                            self.data.remove(fd);
                        },
                        None => {
                        }
                    }
                }
            }
            println!("after");
        }
    }
}

impl Drop for MjpegServer {
    fn drop(&mut self) {
        unsafe {
            close_socket(self.fd);
        }
    }
}

