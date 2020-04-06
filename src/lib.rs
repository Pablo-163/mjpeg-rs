extern crate libc;

use std::fmt;
use std::os::raw::{c_int, c_schar, c_uchar};
use std::os::raw::c_char;
use std::ffi::CString;
use std::collections::{BTreeMap, HashMap};
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::borrow::BorrowMut;
use std::slice::SliceIndex;
use std::ops::DerefMut;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::str::from_utf8;

extern "C" {
    fn create_socket(address: *const c_char, port: c_int) -> c_int;
    fn close_socket(fd: c_int);
    fn create_epoll(fd: c_int) -> c_int;
    fn epoll_update(server_fd: c_int, epoll_fd: c_int, max_events: c_int, connected_sockets: *mut c_int, closed_sockets: *mut c_int, readable_sockets: *mut c_int, writeable_sockets: *mut c_int);
    fn read_socket(fd: c_int, buffer: *mut c_uchar, len: c_int) -> c_int;
    fn access_write_socket(epoll_fd: c_int, fd: c_int) -> c_int;
    fn denied_write_and_read_socket(epoll_fd: c_int, fd: c_int) -> c_int;
    fn write_socket(fd: c_int, buffer: *const c_uchar, len: c_int) -> c_int;
}

static HEADER: &str = "HTTP/1.0 200 OK\x0d\x0aConnection: keep-alive\x0d\x0aMax-Age: 0\x0d\x0aExpires: 0\x0d\x0aCache-Control: no-cache, private\x0d\x0aPragma: no-cache\x0d\x0aContent-Type: multipart/x-mixed-replace; boundary=mjpegstream\x0d\x0a\x0d\x0a";

fn search_bytes(buffer: &[u8], pattern: &[u8]) -> i32 {
    let len = buffer.len() - pattern.len() + 1;
    for i in 0 .. len {
        let mut res = true;
        for j in 0 .. pattern.len() {
            if buffer[i + j] != pattern[j] {
                res = false;
                break;
            }
        }
        if res {
            return i as i32;
        }
    }
    return -1;
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
    auth: bool,
    header_len: i32,
    header_pos: isize,
    image_index: u64,
    payload_len: i32,
    payload_pos: isize,
}

pub struct MjpegServer {
    fd: i32,
    epoll_fd: i32,
    data: HashMap<i32, Data>,
    mutex_queue_images: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    mutex_counter_max: Arc<Mutex<u64>>,
    mutex_counter_min: Arc<Mutex<u64>>,
}

impl MjpegServer {
    pub fn new(address: &str, port: i32) -> Result<Self, MjpegServerError> {
        let address_c = CString::new(address).expect("CString::new failed");
        let fd = unsafe {
            create_socket(address_c.as_ptr(), port)
        };
        if fd < 0 {
            return Err(MjpegServerError { description: format!("Server started at the address {} on port {} failed. {}", address, port, errno::Errno(-fd).to_string()) });
        }

        let epoll_fd = unsafe {
            create_epoll(fd)
        };
        if epoll_fd < 0 {
            unsafe {
                close_socket(fd);
            }
            return Err(MjpegServerError { description: format!("Server started at the address {} on port {} failed. {}", address, port, errno::Errno(-fd).to_string()) });
        }

        Ok(MjpegServer {
            fd,
            epoll_fd,
            data: HashMap::<i32, Data>::new(),
            mutex_queue_images: Arc::new(Mutex::new(HashMap::new())),
            mutex_counter_max: Arc::new(Mutex::new(0)),
            mutex_counter_min: Arc::new(Mutex::new(0)),
        })
    }
    pub fn run(&mut self) {
        /*
        * Запускаем поток для забора видео потока с камеры
        */
        let mutex_btree_image_arc = self.mutex_queue_images.clone();
        let mutex_counter_arc = self.mutex_counter_max.clone();
        thread::spawn(move || {
            match TcpStream::connect("213.193.89.202:80") {
                Ok(mut stream) => {
                    println!("Successfully connected to server {}", "213.193.89.202");
                    let msg = b"GET /mjpg/video.mjpg\r\n\r\n";
                    stream.write(msg).unwrap();

                    let mut boundary = String::from("");
                    let mut buffer = vec![0; 1024 * 1024 * 12];
                    let mut buffer_pos = 0;
                    loop {
                        let mut data = [0 as u8; 4096];
                        match stream.read(&mut data) {
                            Ok(n) => {
                                if buffer_pos + n > 1024 * 1024 * 12 {
                                    println!("Overflowed buffer");
                                    std::process::exit(1);
                                }
                                for i in 0..n {
                                    buffer[buffer_pos + i] = data[i];
                                }
                                buffer_pos += n;
                                println!("{}", buffer_pos);
                                // let text = from_utf8(&data).unwrap();
                                // println!("{}", text);
                            }
                            Err(e) => {
                                println!("Failed to receive data: {}", e);
                                std::process::exit(1);
                            }
                        }
                        match boundary.is_empty() {
                            true => {
                                let pos_boundary_start = search_bytes(&buffer, b"boundary=");
                                let pos_boundary_end = search_bytes(&buffer[pos_boundary_start as usize..], b"\r\n\r\n");
                                boundary = String::from_utf8(Vec::from(&buffer[pos_boundary_start as usize + b"boundary=".len() .. pos_boundary_start as usize + pos_boundary_end as usize])).unwrap_or_else(|_| std::process::exit(1));
                            }
                            false => {
                                let pos_image_start = search_bytes(&buffer, b"\xFF\xD8");
                                let pos_image_end = search_bytes(&buffer[pos_image_start as usize..], b"\xFF\xD9");
                                if pos_image_start != -1 && pos_image_end != -1 {
                                    println!("LENGTH = {}", pos_image_end as usize + b"\xFF\xD9".len());
                                    let HEADER_IMAGE = format!("--mjpegstream\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", pos_image_end as usize + b"\xFF\xD9".len() + 1);
                                    let mut msg = vec![0; HEADER_IMAGE.len() + pos_image_end as usize + b"\xFF\xD9".len() + 1];
                                    for (i, ch) in HEADER_IMAGE.bytes().enumerate() {
                                        msg[i] = ch;
                                    }
                                    for i in pos_image_start as usize .. pos_image_start as usize + pos_image_end as usize + b"\xFF\xD9".len() + 1 {
                                        msg[i + HEADER_IMAGE.len() - pos_image_start as usize] = buffer[i];
                                    }

                                    let mut map = mutex_btree_image_arc.lock().unwrap_or_else(|_| std::process::exit(1));
                                    let mut counter = mutex_counter_arc.lock().unwrap_or_else(|_| std::process::exit(1));
                                    *counter += 1;
                                    map.insert(*counter, msg);

                                    println!("IMAGE ...  !!!");
                                }
                                println!("Sent data, awaiting reply...");
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Failed to connect: {}", e);
                }
            }
        });
        let mut last_image_id = 0;
        loop {
            const MAX_EVENTS: usize = 100;
            let mut connected_sockets: [c_int; MAX_EVENTS] = [0; MAX_EVENTS];
            let mut closed_sockets: [c_int; MAX_EVENTS] = [0; MAX_EVENTS];
            let mut readable_sockets: [c_int; MAX_EVENTS] = [0; MAX_EVENTS];
            let mut writeable_sockets: [c_int; MAX_EVENTS] = [0; MAX_EVENTS];
            /*
            * Опрашиваем сокеты на наличие событий
            */
            unsafe {
                epoll_update(self.fd, self.epoll_fd, MAX_EVENTS as i32,
                             connected_sockets.as_mut_ptr(),
                             closed_sockets.as_mut_ptr(),
                             readable_sockets.as_mut_ptr(),
                             writeable_sockets.as_mut_ptr());
            }
            /*
            * Список закрытых сокетов, зачищаем данные
            */
            for fd in closed_sockets.iter() {
                if *fd == 0 {
                    break;
                }
                println!("Close connection fd = {}", *fd);
                self.data.remove(fd);
            }
            /*
            * Список вновь присоединенных сокетов, заводим структуру данных для каждого.
            */
            for fd in connected_sockets.iter() {
                if *fd == 0 {
                    break;
                }
                println!("New connection fd = {}", *fd);

                let number;
                {
                    number = *self.mutex_counter_max.lock().unwrap();
                }

                let data = Data {
                    auth: true,
                    header_len: HEADER.len() as i32,
                    header_pos: 0,
                    image_index: number,
                    payload_len: 0,
                    payload_pos: 0,
                };

                self.data.insert(*fd, data);
            }
            /*
            * Читаем данные из сокета, нужно только для первого запроса на авторизацию
            * Разбираем заголовок извлекаем token и проводим авторизацию,
            * Даем возможность сокету получать события о готовности отправки данных в него
            */
            for fd in readable_sockets.iter() {
                if *fd == 0 {
                    break;
                }
                println!("Readable connection fd = {}", *fd);
                let mut buffer: [c_uchar; 4096] = [0; 4096];
                let res = unsafe {
                    read_socket(*fd, buffer.as_mut_ptr(), 4096)
                };
                let mut buffer_utf8 = String::new();
                for ch in &buffer[0..res as usize] {
                    if let Some(ch) = std::char::from_u32(*ch as u32) {
                        buffer_utf8.push(ch);
                    }
                }
                println!("{}", buffer_utf8);
                let res = unsafe {
                    access_write_socket(self.epoll_fd, *fd)
                };
                if res == -1 {
                    unsafe {
                        close_socket(*fd);
                    }
                    self.data.remove(fd);
                }
            }

            for fd in writeable_sockets.iter() {
                if *fd == 0 {
                    break;
                }
                let map = self.mutex_queue_images.lock().unwrap();
                let max_image_index = *self.mutex_counter_max.lock().unwrap();
                if !map.is_empty() {
                    if let Some(data) = self.data.get_mut(fd) {
                        if data.header_len > 0 {
                            let res = unsafe {
                                write_socket(*fd, HEADER.as_ptr().offset(data.header_pos), data.header_len)
                            };
                            if res == -1 {
                                unsafe {
                                    close_socket(*fd);
                                }
                                self.data.remove(fd);
                            } else {
                                data.header_len -= res;
                                data.header_pos += res as isize;
                                if data.header_len == 0 {
                                    let res = unsafe {
                                        denied_write_and_read_socket(self.epoll_fd, *fd)
                                    };
                                    if res == -1 {
                                        unsafe {
                                            close_socket(*fd);
                                        }
                                        self.data.remove(fd);
                                    }
                                }
                            }
                        } else {
                            if data.payload_len > 0 {
                                match map.get(&data.image_index) {
                                    Some(bytes) => {
                                        let res = unsafe {
                                            write_socket(*fd, bytes.as_ptr().offset(data.payload_pos), data.payload_len)
                                        };
                                        if res == -1 {
                                            unsafe {
                                                close_socket(*fd);
                                            }
                                            self.data.remove(fd);
                                        } else {
                                            data.payload_len -= res;
                                            data.payload_pos += res as isize;
                                            if data.payload_len == 0 {
                                                data.image_index += 1;
                                                let res = unsafe {
                                                    denied_write_and_read_socket(self.epoll_fd, *fd)
                                                };
                                                if res == -1 {
                                                    unsafe {
                                                        close_socket(*fd);
                                                    }
                                                    self.data.remove(fd);
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    _ => {
                                        data.image_index += 1;
                                    }
                                }
                            } else {
                                while data.image_index <= max_image_index {
                                    println!("image index = {}", data.image_index);
                                    match map.get(&data.image_index) {
                                        Some(bytes) => {
                                            data.payload_pos = 0;
                                            data.payload_len = bytes.len() as i32;
                                            let res = unsafe {
                                                write_socket(*fd, bytes.as_ptr().offset(data.payload_pos), data.payload_len)
                                            };
                                            if res == -1 {
                                                unsafe {
                                                    close_socket(*fd);
                                                }
                                                self.data.remove(fd);
                                            } else {
                                                data.payload_len -= res;
                                                data.payload_pos += res as isize;
                                                if data.payload_len == 0 {
                                                    data.image_index += 1;
                                                    let res = unsafe {
                                                        denied_write_and_read_socket(self.epoll_fd, *fd)
                                                    };
                                                    if res == -1 {
                                                        unsafe {
                                                            close_socket(*fd);
                                                        }
                                                        self.data.remove(fd);
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                        _ => {
                                            data.image_index += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // println!("Writeable connection fd = {}", *fd);
            }
            /*
            * Чистим очередь
            */
            let mut keys = vec![];
            {
                let btree_image = self.mutex_queue_images.lock().unwrap();
                for key in btree_image.keys() {
                    keys.push(*key);
                }
                keys.sort();
            }

            {
                let mut queue_images = self.mutex_queue_images.lock().unwrap();
                if queue_images.len() > 100 {
                    let mut count = queue_images.len() - 100;
                    for key in &keys {
                        if count == 0 {
                            break;
                        }
                        queue_images.remove(key);
                        count -= 1;
                    }
                }
            }

            let mut bad_connections = vec![];

            if !keys.is_empty() && last_image_id < keys[keys.len() - 1].clone() {
                last_image_id = keys[keys.len() - 1];
                for (fd, data) in &self.data {
                    if data.auth == true && data.payload_len == 0 {
                        let res = unsafe {
                            access_write_socket(self.epoll_fd, *fd)
                        };
                        if res == -1 {
                            unsafe {
                                close_socket(*fd);
                            }
                            bad_connections.push(*fd);
                        }
                    }
                }
            }
            for fd in bad_connections {
                self.data.remove(&fd);
            }
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

