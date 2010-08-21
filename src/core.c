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

#define bool int
#define TRUE 1
#define FALSE 0

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

static void ws_request_init(ws_request_t *req, ws_connection_t *conn, char*buf){
    obstack_init(&req->pieces);
    req->conn = conn;
    memcpy(&req->req_callbacks,conn->req_callbacks, sizeof(req->req_callbacks));
    req->network_timeout = conn->network_timeout;
    req->headers_buf = buf;
    req->bufposition = 0;
    req->headerlen = 0;
    req->next = NULL;
    req->prev = NULL;
}

static void ws_request_free(ws_request_t *req) {
    if(req->headerlen) {
        ws_request_cb cb = req->req_callbacks[WS_REQ_CB_FINISH];
        cb(req);
    }
    obstack_free(&req->pieces, NULL);
    free(req);
}

static void ws_connection_close(ws_connection_t *conn) {
    ws_request_t *req = conn->first_req;
    while(req) {
        ws_request_free(req);
        req = req->next;
    };
    if(&conn->watcher.active) {
        ev_io_stop(conn->loop, &conn->watcher);
    }
    if(&conn->timeo.active) {
        ev_timer_stop(conn->loop, &conn->timeo);
    }
}

static void ws_graceful_finish(ws_connection_t *conn, bool eat_last) {
    shutdown(conn->watcher.fd, SHUT_RD);
    ev_io_stop(conn->loop, &conn->watcher);
    if(conn->request_num) {
        if(eat_last) {
            ws_request_t *prev = conn->last_req->prev;
            if(prev) {
                prev->next = NULL;
                conn->last_req = prev;
                -- conn->request_num;
                conn->close_on_finish = TRUE;
            } else {
                conn->last_req = NULL;
                conn->first_req = NULL;
                --conn->request_num;
                ws_connection_close(conn);
            }
        } else {
            conn->close_on_finish = TRUE;
        }
    } else {
        ws_connection_close(conn);
    }
}

static void ws_try_read(ws_request_t *req) {
    int r = read(req->conn->watcher.fd, req->headers_buf+req->bufposition,
        req->conn->max_header_size - req->bufposition);
    if(r < 0) {
        switch(errno) {
            case EAGAIN:
            case EINTR:
                return;
            default:
                ws_connection_close(req->conn);
                return;
        }
    }
    if(r == 0) {
        ws_graceful_finish(req->conn, TRUE);
        return;
    }
    req->bufposition = r;
    void *e1 = memmem(req->headers_buf, r, "\r\n\r\n", 4);
    void *e2 = memmem(req->headers_buf, r, "\n\n", 2);
    if(e2 < e1 && e2 != req->headers_buf || e1 == req->headers_buf) {
        e1 = e2;
    }
    req->bufposition += r;
    if(e1 == req->headers_buf) { // no end of headers
        if(req->bufposition >= req->conn->max_header_size) {
            ws_graceful_finish(req->conn, TRUE);
        }
        return;
    }
    ws_request_cb cb = req->req_callbacks[WS_REQ_CB_HEADERS];
    if(cb) {
        int res = cb(req);
        if(res < 0) {
            req->headerlen = 0;
            ws_request_free(req);
        }
    }
}

static void ws_data_callback(struct ev_loop *loop, ws_connection_t *conn,
    int revents) {
    if(revents & EV_READ) {
        if(!conn->last_req || conn->last_req->headerlen) {
            ws_request_t *req = (ws_request_t*)malloc(conn->_req_size
                + conn->max_header_size);
            if(!req) {
                ws_graceful_finish(conn, FALSE);
                return;
            }
            ws_request_init(req, conn, (char *)req + conn->_req_size);
            if(conn->last_req) {
                conn->last_req->next = req;
                req->prev = conn->last_req;
            } else {
                conn->first_req = req;
            }
            conn->last_req = req;
            ++conn->request_num;
        }
        ws_try_read(conn->last_req);
    }
    assert(!(revents & EV_ERROR));
}

static void ws_data_timeout(struct ev_loop *loop, ev_timer *timer,
    int revents) {
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
    conn->max_header_size = serv->max_header_size;
    conn->close_on_finish = FALSE;
    memcpy(conn->req_callbacks, serv->req_callbacks,
        sizeof(conn->req_callbacks));
    memcpy(conn->conn_callbacks, serv->conn_callbacks,
        sizeof(conn->conn_callbacks));
    ev_io_init(&conn->watcher,
        (void (*)(struct ev_loop*, struct ev_io *,int))ws_data_callback,
        fd, EV_READ);
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

static void ws_accept_callback(struct ev_loop *loop, ws_listener_t *l,
    int revents) {
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
    serv->max_header_size = 16384;
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
        (void (*)(struct ev_loop*, ev_io *, int))ws_accept_callback,
        fd, EV_READ);
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
    int size = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
        &size, sizeof(size)) < 0) return -1;
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
