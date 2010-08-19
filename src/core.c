#define _GNU_SOURCE
#include <assert.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "core.h"

static void ws_data_callback(EV_P_ ws_connection_t *conn, int revents) {
    if(revents & EV_READ) {
        //TODO
        printf("READ\n");
    }
    assert(!(revents & EV_ERROR));
}

static void ws_data_timeout(EV_P_ ev_timer *timer, int revents) {
    ws_connection_t *conn = (ws_connection_t*)((char *)timer
        - offsetof(ws_connection_t, timeo));
    if(revents & EV_TIMER) {
    // TODO
    }
    assert(!(revents & EV_ERROR));
}

static void ws_connection_init(int fd, ws_server_t *serv,
    struct sockaddr_in *addr) {
    ws_connection_t *conn = (ws_connection_t*)malloc(serv->_conn_size);
    if(!conn) {
        close(fd);
        return;
    }
    memcpy(&conn->addr, addr, sizeof(struct sockaddr_in));
    conn->network_timeout = serv->network_timeout;
    conn->_req_size = serv->_req_size;
    conn->serv = serv;
    conn->loop = serv->loop;
    memcpy(conn->req_callbacks, serv->req_callbacks,
        sizeof(conn->req_callbacks));
    memcpy(conn->conn_callbacks, serv->conn_callbacks,
        sizeof(conn->conn_callbacks));
    ev_io_init(&conn->watcher,
        (void (*)(EV_P_ struct ev_io *,int))ws_data_callback, fd, EV_READ);
    ev_timer_init(&conn->timeo, ws_data_timeout, conn->network_timeout, 0);
    ws_connection_cb cb = conn->conn_callbacks[WS_CONN_CB_CONNECT];
    if(cb && cb(conn) < 0) {
        close(fd);
        free(conn);
        return;
    }
    ev_io_start(serv->loop, &conn->watcher);
    ev_timer_start(serv->loop, &conn->timeo);
}

static void ws_accept_callback(EV_P_ ws_listener_t *l, int revents) {
    if(revents & EV_READ) {
        struct sockaddr_in addr;
        int addrlen = sizeof(addr);
        int fd = accept4(l->watcher.fd, &addr, &addrlen,
            SOCK_NONBLOCK|SOCK_CLOEXEC);
        if(fd < 0) {
            switch(fd) {
            case EAGAIN: case ENETDOWN: case EPROTO: case ENOPROTOOPT:
            case EHOSTDOWN: case ENONET: case EHOSTUNREACH: case EOPNOTSUPP:
            case ENETUNREACH:
                break;
            default:
                perror("Socket error");
                abort();
            }
        }
        ws_connection_init(fd, l->serv, &addr);
    }
    assert(!(revents & EV_ERROR));
}

int ws_server_init(ws_server_t *serv, struct ev_loop *loop) {
    serv->loop = loop;
    serv->_conn_size = sizeof(ws_connection_t);
    serv->_req_size = sizeof(ws_request_t);
    serv->listeners = NULL;
    serv->listeners_num = 0;
    serv->first_conn = NULL;
    serv->last_conn = NULL;
    serv->connection_num = 0;
    serv->network_timeout = 10.0;
    bzero(serv->req_callbacks, sizeof(serv->req_callbacks));
    bzero(serv->conn_callbacks, sizeof(serv->conn_callbacks));
    return 0;
}

int ws_add_fd(ws_server_t *serv, int fd) {
    ws_listener_t *l = (ws_listener_t *)malloc(sizeof(ws_listener_t));
    if(!l) {
        return -1;
    }
    ev_io_init(&l->watcher,
        (void (*)(EV_P_ ev_io *, int))ws_accept_callback, fd, EV_READ);
    l->serv = serv;

    l->next = serv->listeners;
    serv->listeners = l;
    serv->listeners_num += 1;

    ev_io_start(serv->loop, &l->watcher);
    return 0;
}

int ws_add_tcp(ws_server_t *serv, in_addr_t ip, int port) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = htons(port);
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    if(bind(fd, &addr, sizeof(addr)) < 0) return -1;
    if(listen(fd, 4096) < 0) return -1;
    ws_add_fd(serv, fd);
}

void ws_quickstart(ws_server_t *serv, const char *host,
    int port, ws_request_cb cb) {
    struct in_addr addr;
    if(ws_server_init(serv, ev_default_loop(0)) < 0
       || inet_aton(host, &addr) < 0
       || ws_add_tcp(serv, addr.s_addr, port) < 0) {
        perror("ws_quickstart");
    }
    ws_REQUEST_CB(serv, cb);
}
