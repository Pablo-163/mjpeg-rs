#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>

static int setNonBlockingModeSocket(int fd) {
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_socket(const char* address, int port) {

    struct sockaddr_in server_addr;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        close(fd);
        return -errno;
    }
    if (setNonBlockingModeSocket(fd) == -1) {
        close(fd);
        return -errno;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(address);
    server_addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        close(fd);
        return -errno;
    }

    if (listen(fd, SOMAXCONN) < 0) {
        close(fd);
        return -errno;
    };
    return fd;
}

void close_socket(int fd) {
    close(fd);
}

int create_epoll(int fd){
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) return -errno;
    struct epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
    return epoll_fd;
}

void epoll_update(int server_fd, int epoll_fd, int max_events, int * connected, int * closed){

    struct sockaddr_in peer_addr;
    int address_length = sizeof(peer_addr);
    struct epoll_event events[max_events];
    struct epoll_event event;
    int fds = epoll_wait(epoll_fd, events, max_events, 1000);
    int pos_connected = 0;
    int pos_closed = 0;
    for (int i = 0; i < fds; i++) {
        if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (events[i].events & EPOLLRDHUP)) {
            close(events[i].data.fd);
            closed[pos_closed++] = events[i].data.fd;
            continue;
        }
        if (events[i].data.fd == server_fd) {
            int conn_sock = accept(server_fd, (struct sockaddr *) &peer_addr, (socklen_t *) &address_length);
            if (conn_sock > (int) 10000) {
                close(conn_sock);
                continue;
            }
            if (conn_sock == -1) {
                close(conn_sock);
                continue;
            }
            if (setNonBlockingModeSocket(conn_sock) == -1) {
                close(conn_sock);
                continue;
            }
            event.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
            event.data.fd = conn_sock;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_sock, &event) == -1) {
                close(conn_sock);
                continue;
            }
            connected[pos_connected++] = conn_sock;
        } else {
        }

    }
}