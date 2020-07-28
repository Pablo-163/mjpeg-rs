extern crate libc;
extern crate base64;

use std::{fmt, ptr};
use std::os::raw::{c_int, c_uchar};
use std::os::raw::c_char;
use std::ffi::CString;
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, SystemTime};
use std::sync::{Arc, Mutex};
use std::net::{TcpStream, SocketAddr, IpAddr};
use std::io::{Read, Write};
use std::str::FromStr;
use std::cmp::{max, min};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

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

fn search_bytes(buffer: &[u8], pattern: &[u8], limit: usize) -> i32 {
    if buffer.len() < pattern.len() {
        return -1;
    }
    let len = buffer.len() - pattern.len() + 1;
    for i in 0..min(len, limit) {
        let mut res = true;
        for j in 0..pattern.len() {
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

#[derive(Clone)]
pub enum HttpAuth {
    NoneAuthType = 0,
    BasicAuthType = 1,
    DigestAuthType = 2,
}

pub struct MjpegServer {
    fd: i32,
    epoll_fd: i32,
    connections: HashMap<i32, Data>,
    video_source_ip: String,
    video_source_uri: String,
    mutex_image_queue: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    mutex_counter_max: Arc<Mutex<u64>>,
    mutex_counter_active_sessions: Arc<Mutex<u64>>,
    auth: HttpAuth,
    login: String,
    password: String,
}

impl MjpegServer {
    pub fn new(address: &str, port: i32, video_source_ip: &str, video_source_uri: &str, auth: HttpAuth, login: &str, password: &str) -> Result<Self, MjpegServerError> {
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
            video_source_ip: String::from(video_source_ip),
            video_source_uri: String::from(video_source_uri),
            connections: HashMap::<i32, Data>::new(),
            mutex_image_queue: Arc::new(Mutex::new(HashMap::new())),
            mutex_counter_max: Arc::new(Mutex::new(0)),
            mutex_counter_active_sessions: Arc::new(Mutex::new(0)),
            auth,
            login: String::from(login),
            password: String::from(password),
        })
    }
    pub fn run(&mut self) {
        /*
        * Запускаем поток для забора видео потока с камеры
        */
        const MAX_BUFFER_LENGTH: usize = 1024 * 1024 * 12;
        const SOCKET_BUFFER_LENGTH: usize = 4 * 4096;
        let mutex_image_queue_clone = self.mutex_image_queue.clone();
        let mutex_counter_max_clone = self.mutex_counter_max.clone();
        let mutex_counter_active_sessions_clone = self.mutex_counter_active_sessions.clone();
        let mut video_source_ip = self.video_source_ip.clone();
        let video_source_uri = self.video_source_uri.clone();

        let auth = self.auth.clone();
        let login = self.login.clone();
        let password = self.password.clone();

        thread::spawn(move || {
            loop {
                video_source_ip = video_source_ip.replace("http://", "");
                let seq: Vec<&str> = video_source_ip.split(":").collect();
                let sock_address = match seq.len() {
                    2 => {
                        let ip = match IpAddr::from_str(&seq[0]) {
                            Ok(value) => value,
                            Err(_) => {
                                let mut resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap_or_else(|_| std::process::exit(1));
                                let res = resolver.lookup_ip(&seq[0]).unwrap_or_else(|_| std::process::exit(1));
                                res.iter().next().unwrap_or_else(|| std::process::exit(1))
                            }
                        };
                        SocketAddr::new(ip, seq[1].parse::<u16>().unwrap_or(80))
                    }
                    1 => {
                        let ip = match IpAddr::from_str(&seq[0]) {
                            Ok(value) => value,
                            Err(_) => {
                                let mut resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap_or_else(|_| std::process::exit(1));
                                let res = resolver.lookup_ip(&seq[0]).unwrap_or_else(|_| std::process::exit(1));
                                res.iter().next().unwrap_or_else(|| std::process::exit(1))
                            }
                        };
                        SocketAddr::new(ip, 80)
                    }
                    _ => {
                        std::process::exit(1);
                    }
                };
                match TcpStream::connect_timeout(&sock_address, Duration::from_secs(10)) {
                    Ok(mut stream) => {
                        let mut ready = true;
                        let mut is_auth = false;
                        use base64::encode;
                        match auth {
                            HttpAuth::NoneAuthType => {
                                let mut msg = format!("GET {}\r\n\r\n", &video_source_uri);
                                let mut buffer;
                                unsafe {
                                    buffer = msg.as_bytes_mut();
                                }
                                stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap_or_else(|_|std::process::exit(1));
                                match stream.write_all(&mut buffer) {
                                    Ok(_) => {}
                                    Err(_) => {
                                        ready = false;
                                    }
                                }
                                is_auth = true;
                            }
                            HttpAuth::BasicAuthType => {
                                let mut msg = format!("GET {} HTTP/1.0\r\nAuthorization: Basic {}\r\n\r\n", &video_source_uri, encode(format!("{}:{}", login, password)));
                                let mut buffer;
                                unsafe {
                                    buffer = msg.as_bytes_mut();
                                }
                                stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap_or_else(|_|std::process::exit(1));
                                match stream.write_all(&mut buffer) {
                                    Ok(_) => {}
                                    Err(_) => {
                                        ready = false;
                                    }
                                }
                            }
                            HttpAuth::DigestAuthType => {
                                std::process::exit(1);
                            }
                        }
                        if !ready {
                            continue;
                        }

                        let mut boundary = String::from("");
                        let mut buffer = vec![0; MAX_BUFFER_LENGTH];
                        let mut buffer_pos = 0;

                        let mut first_sep= -1;
                        let mut second_sep = -1;

                        let mut start_old_search_boundary_pos = -1;
                        let mut image_old_search_end_pos = -1;
                        loop {
                            let mutex = mutex_counter_active_sessions_clone.lock().unwrap_or_else(|_| std::process::exit(1));
                            let counter_active_session = *mutex;
                            drop(mutex);

                            if counter_active_session == 0 {
                                std::thread::sleep(std::time::Duration::from_secs(1));
                                continue;
                            }

                            let mut data = [0 as u8; SOCKET_BUFFER_LENGTH];
                            stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap_or_else(|_| std::process::exit(1));
                            match stream.read(&mut data) {
                                Ok(n) => {
                                    if n == 0 {
                                        break;
                                    }
                                    if buffer_pos + n >= MAX_BUFFER_LENGTH {
                                        std::process::exit(1);
                                    }
                                    for i in 0..n {
                                        buffer[buffer_pos + i] = data[i];
                                    }
                                    buffer_pos += n;
                                }
                                Err(_) => {
                                    // const RESOURCE_TEMPORARILY_UNAVAILABLE: i32 = 11;
                                    // if e.raw_os_error().unwrap() != RESOURCE_TEMPORARILY_UNAVAILABLE {
                                    //     println!("Connection lose");
                                    //     break;
                                    // }
                                    break;
                                }
                            }

                            if boundary.is_empty() {
                                let res = search_bytes(&buffer, b"\r\n\r\n", buffer_pos);
                                match res {
                                    -1 => {
                                        continue;
                                    }
                                    _ => {
                                        /*
                                        * Извлекаем boundary
                                        */
                                        let boundary_start_pos = search_bytes(&buffer, b"boundary=", buffer_pos);
                                        if boundary_start_pos != -1 {
                                            let boundary_end_pos = search_bytes(&buffer[boundary_start_pos as usize..], b"\r\n\r\n", buffer_pos - boundary_start_pos as usize);
                                            if boundary_end_pos != -1 {
                                                let res = String::from_utf8(Vec::from(&buffer[boundary_start_pos as usize + b"boundary=".len()..boundary_start_pos as usize + boundary_end_pos as usize]));
                                                match res {
                                                    Ok(value) => {
                                                        boundary = format!("--{}", value);
                                                    }
                                                    Err(_) => {
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        /*
                                        * Проверяем авторизацию
                                        */
                                        if !is_auth {
                                            let res = search_bytes(&buffer, b"200 OK", buffer_pos);
                                            match res {
                                                -1 => {
                                                    std::process::exit(1);
                                                }
                                                _ => {
                                                    is_auth = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if first_sep == -1 {
                                first_sep = search_bytes(&buffer, boundary.as_bytes(), buffer_pos);
                            } else {
                                if start_old_search_boundary_pos == -1 {
                                    start_old_search_boundary_pos = first_sep + 1;
                                }
                                second_sep = search_bytes(&buffer[start_old_search_boundary_pos as usize..], boundary.as_bytes(), buffer_pos - start_old_search_boundary_pos as usize);
                                start_old_search_boundary_pos = buffer_pos as i32;
                            }

                            if first_sep != -1 && second_sep != -1 {
                                let image_start_pos = search_bytes(&buffer, b"\xFF\xD8", buffer_pos);
                                let mut image_length = 0;
                                image_old_search_end_pos = image_start_pos;
                                if image_start_pos != -1 {
                                    image_length = search_bytes(&buffer[image_start_pos as usize..], b"\xFF\xD9", buffer_pos - image_old_search_end_pos as usize);
                                }
                                image_old_search_end_pos = max((buffer_pos - 2) as i32, 0);

                                if image_start_pos != -1 && image_length != -1 {
                                    let header_image = format!("--mjpegstream\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", image_length as usize + b"\xFF\xD9".len());
                                    let mut msg = vec![0; header_image.len() + image_length as usize + b"\xFF\xD9".len()];
                                    for (i, ch) in header_image.bytes().enumerate() {
                                        msg[i] = ch;
                                    }
                                    for i in image_start_pos as usize..image_start_pos as usize + image_length as usize + b"\xFF\xD9".len() {
                                        msg[i + header_image.len() - image_start_pos as usize] = buffer[i];
                                    }

                                    let mut mutex = mutex_counter_max_clone.lock().unwrap_or_else(|_| std::process::exit(1));
                                    let value = *mutex + 1;
                                    *mutex += 1;
                                    drop(mutex);
                                    let mut image_queue = mutex_image_queue_clone.lock().unwrap_or_else(|_| std::process::exit(1));
                                    image_queue.insert(value, msg);
                                    if image_queue.len() > 200 {
                                        let mut keys = vec![];
                                        for key in image_queue.keys() {
                                            keys.push(*key);
                                        }
                                        keys.sort();

                                        let mut count = image_queue.len() - 100;
                                        for key in &keys {
                                            if count == 0 {
                                                break;
                                            }
                                            image_queue.remove(key);
                                            count -= 1;
                                        }
                                    }
                                    drop(image_queue);

                                    let mut buffer_update_pos = 0;
                                    let start = image_start_pos as usize + image_length as usize + b"\xFF\xD9".len() + boundary.len();
                                    for i in start..buffer_pos {
                                        buffer.swap(i, i - start);
                                        buffer_update_pos += 1;
                                    }
                                    buffer_pos = buffer_update_pos;
                                    second_sep = -1;
                                    start_old_search_boundary_pos = -1;
                                    image_old_search_end_pos = -1;
                                }
                            }
                        }
                    }
                    Err(_) => {}
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
                if *fd != 0 {
                    break;
                }
                self.connections.remove(fd);
            }
            /*
            * Список вновь присоединенных сокетов, заводим структуру данных для каждого.
            */
            let mutex = self.mutex_counter_max.lock().unwrap_or_else(|_| std::process::exit(1));
            let number = *mutex;
            drop(mutex);
            for fd in connected_sockets.iter() {
                if *fd == 0 {
                    break;
                }
                let data = Data {
                    auth: true,
                    header_len: HEADER.len() as i32,
                    header_pos: 0,
                    image_index: number,
                    payload_len: 0,
                    payload_pos: 0,
                };
                self.connections.insert(*fd, data);
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
                let mut buffer: [c_uchar; 4096] = [0; 4096];
                let res = unsafe {
                    read_socket(*fd, buffer.as_mut_ptr(), 4096)
                };
                if res == -1 {
                    unsafe {
                        close_socket(*fd);
                    }
                    self.connections.remove(fd);
                }
                let res = unsafe {
                    access_write_socket(self.epoll_fd, *fd)
                };
                if res == -1 {
                    unsafe {
                        close_socket(*fd);
                    }
                    self.connections.remove(fd);
                }
            }

            for fd in writeable_sockets.iter() {
                if *fd == 0 {
                    break;
                }

                let mutex = self.mutex_counter_max.lock().unwrap_or_else(|_| std::process::exit(1));
                let max_image_index = *mutex;
                drop(mutex);

                let mutex_image_queue = self.mutex_image_queue.lock().unwrap_or_else(|_| std::process::exit(1));
                if !mutex_image_queue.is_empty() {
                    if let Some(connection) = self.connections.get_mut(fd) {
                        if connection.header_len > 0 {
                            let res = unsafe {
                                write_socket(*fd, HEADER.as_ptr().offset(connection.header_pos), connection.header_len)
                            };
                            if res == -1 {
                                unsafe {
                                    close_socket(*fd);
                                }
                                self.connections.remove(fd);
                            } else {
                                connection.header_len -= res;
                                connection.header_pos += res as isize;
                                if connection.header_len == 0 {
                                    let res = unsafe {
                                        denied_write_and_read_socket(self.epoll_fd, *fd)
                                    };
                                    if res == -1 {
                                        unsafe {
                                            close_socket(*fd);
                                        }
                                        self.connections.remove(fd);
                                    }
                                }
                            }
                        } else {
                            if connection.payload_len > 0 {
                                match mutex_image_queue.get(&connection.image_index) {
                                    Some(bytes) => {
                                        let res = unsafe {
                                            write_socket(*fd, bytes.as_ptr().offset(connection.payload_pos), connection.payload_len)
                                        };
                                        if res == -1 {
                                            unsafe {
                                                close_socket(*fd);
                                            }
                                            self.connections.remove(fd);
                                        } else {
                                            connection.payload_len -= res;
                                            connection.payload_pos += res as isize;
                                            if connection.payload_len == 0 {
                                                connection.image_index += 1;
                                                let res = unsafe {
                                                    denied_write_and_read_socket(self.epoll_fd, *fd)
                                                };
                                                if res == -1 {
                                                    unsafe {
                                                        close_socket(*fd);
                                                    }
                                                    self.connections.remove(fd);
                                                }
                                            }
                                        }
                                        // break;
                                    }
                                    _ => {
                                        connection.payload_len = 0;
                                        connection.payload_pos = 0;
                                        // connection.image_index += 1;
                                    }
                                }
                            } else {
                                while connection.image_index <= max_image_index {
                                    match mutex_image_queue.get(&connection.image_index) {
                                        Some(bytes) => {
                                            connection.payload_pos = 0;
                                            connection.payload_len = bytes.len() as i32;
                                            let res = unsafe {
                                                write_socket(*fd, bytes.as_ptr().offset(connection.payload_pos), connection.payload_len)
                                            };
                                            if res == -1 {
                                                unsafe {
                                                    close_socket(*fd);
                                                }
                                                self.connections.remove(fd);
                                                break;
                                            } else {
                                                connection.payload_len -= res;
                                                connection.payload_pos += res as isize;
                                                if connection.payload_len == 0 {
                                                    connection.image_index += 1;
                                                    let res = unsafe {
                                                        denied_write_and_read_socket(self.epoll_fd, *fd)
                                                    };
                                                    if res == -1 {
                                                        unsafe {
                                                            close_socket(*fd);
                                                        }
                                                        self.connections.remove(fd);
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                        _ => {
                                            connection.image_index += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut bad_connections = vec![];

            let mutex = self.mutex_counter_max.lock().unwrap_or_else(|_| std::process::exit(1));
            let max_image_id = *mutex;
            drop(mutex);
            if last_image_id < max_image_id {
                last_image_id = max_image_id;
                for (fd, data) in &self.connections {
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
                self.connections.remove(&fd);
            }

            let mut mutex = self.mutex_counter_active_sessions.lock().unwrap_or_else(|_| std::process::exit(1));
            *mutex = self.connections.len() as u64;
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

