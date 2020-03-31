extern crate libc;

use std::fmt;
use std::os::raw::{c_int, c_schar, c_uchar};
use std::os::raw::c_char;
use std::ffi::CString;
use std::collections::BTreeMap;
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::borrow::BorrowMut;
use std::slice::SliceIndex;
use std::ops::DerefMut;

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
    image_index: u64,
    payload_len: i32,
    payload_pos: isize,
}

pub struct MjpegServer {
    fd: i32,
    epoll_fd: i32,
    data: BTreeMap<i32, Data>,
    mutex_btree_image: Arc<Mutex<BTreeMap<u64, Vec<u8>>>>,
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
            data: BTreeMap::<i32, Data>::new(),
            mutex_btree_image: Arc::new(Mutex::new(BTreeMap::new())),
            mutex_counter_max: Arc::new(Mutex::new(0)),
            mutex_counter_min: Arc::new(Mutex::new(0)),
        })
    }
    pub fn run(&mut self) {
        /*
        * Запускаем поток для забора видео потока с камеры
        */
        let mutex_btree_image_arc = self.mutex_btree_image.clone();
        let mutex_counter_arc = self.mutex_counter_max.clone();
        thread::spawn(move || {
            use std::fs::{File, metadata};
            use std::io::Read;
            let mut f = File::open("/home/myduomilia/test.jpg").expect("no file found");
            let met = metadata("/home/myduomilia/test.jpg").expect("unable to read metadata");
            let mut buffer = vec![0; met.len() as usize];
            f.read(&mut buffer).expect("buffer overflow");

            let header = format!("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-length:{}\r\n\r\n", buffer.len());
            let mut msg = vec![0; header.len() + buffer.len()];
            for (i, ch) in header.bytes().enumerate() {
                msg[i] = ch;
            }
            for (i, byte) in buffer.iter().enumerate() {
                msg[i + header.len()] = buffer[i];
            }
            loop {

                {
                    /*
                    * Получаем новое изображение от видео потока и обмениваем со старым
                    */

                    let mut map = mutex_btree_image_arc.lock().unwrap();
                    let mut counter = mutex_counter_arc.lock().unwrap();
                    *counter += 1;
                    map.insert(*counter, msg.clone());
                }
                std::thread::sleep(Duration::from_millis(80));
            }
        });
        loop {
            println!("before");
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
                let mut buffer: [c_uchar; 1024] = [0; 1024];
                let res = unsafe {
                    read_socket(*fd, buffer.as_mut_ptr(), 1024)
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
                let map = self.mutex_btree_image.lock().unwrap();
                let max_image_index = *self.mutex_counter_max.lock().unwrap();
                if !map.is_empty() {
                    if let Some(data) = self.data.get_mut(fd) {
                        if data.payload_len > 0 {
                            println!(">");
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
                            println!("0");
                            println!("!!! index = {}", data.image_index);
                            while data.image_index <= max_image_index {
                                println!("index = {}", data.image_index);
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

                println!("Writeable connection fd = {}", *fd);
            }

            /*
            * Чистим очередь
            */

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

