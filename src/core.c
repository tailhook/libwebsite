#define _GNU_SOURCE
#include <assert.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "core.h"

#define bool int
#define TRUE 1
#define FALSE 0

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

static int ws_head_slice(ws_request_t *req, int size);
static int ws_body_slice(ws_request_t *req, int size);
static void ws_graceful_finish(ws_connection_t *conn, bool eat_last);

static void ws_request_init(ws_request_t *req, ws_connection_t *conn, char*buf){
    obstack_init(&req->pieces);
    req->conn = conn;
    memcpy(&req->req_callbacks,conn->req_callbacks, sizeof(req->req_callbacks));
    req->network_timeout = conn->network_timeout;
    req->headers_buf = buf;
    req->bufposition = 0;
    req->headerlen = 0;
    req->body = 0;
    req->bodylen = 0;
    req->bodyposition = 0;
    req->next = NULL;
    req->prev = NULL;
    req->reply_state = 0;
    req->reply_head = NULL;
    req->reply_head_size = 0;
    req->reply_body = NULL;
    req->reply_body_size = 0;
    req->reply_pos = 0;
    req->reply_watch.active = 0;
}

static void ws_request_new(ws_connection_t *conn) {
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

static void ws_request_free(ws_request_t *req) {
    if(req->headerlen) {
        ws_request_cb cb = req->req_callbacks[WS_REQ_CB_FINISH];
        if(cb) {
            cb(req);
        }
    }
    if(req->reply_watch.active) {
        ev_io_stop(req->conn->loop, &req->reply_watch);
    }
    if(req->next) {
        req->next->prev = req->prev;
    } else {
        req->conn->last_req = req->prev;
    }
    if(req->prev) {
        req->prev->next = req->prev;
    } else {
        req->conn->first_req = req->next;
    }
    req->conn->request_num -= 1;
    obstack_free(&req->pieces, NULL);
    free(req);
}

static void ws_connection_close(ws_connection_t *conn) {
    while(conn->first_req) {
        ws_request_free(conn->first_req);
    };
    if(&conn->watcher.active) {
        ev_io_stop(conn->loop, &conn->watcher);
    }
    if(&conn->timeo.active) {
        ev_timer_stop(conn->loop, &conn->timeo);
    }
    close(conn->watcher.fd);
    ws_connection_cb cb = conn->conn_callbacks[WS_CONN_CB_DISCONNECT];
    if(cb) {
        cb(conn);
    }
    if(conn->next) {
        conn->next->prev = conn->prev;
    } else {
        conn->serv->last_conn = conn->prev;
    }
    if(conn->prev) {
        conn->prev->next = conn->next;
    } else {
        conn->serv->first_conn = conn->next;
    }
    free(conn);
}

static void ws_graceful_finish(ws_connection_t *conn, bool eat_last) {
    shutdown(conn->watcher.fd, SHUT_RD);
    ev_io_stop(conn->loop, &conn->watcher);
    if(conn->request_num) {
        if(eat_last) {
            ws_request_free(conn->last_req);
            if(conn->last_req) {
                conn->close_on_finish = TRUE;
            } else {
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
    int r;
    if(req->headerlen) {
        assert(req->body);
        r = read(req->conn->watcher.fd, req->body+req->bodyposition,
            req->bodylen - req->bodyposition);
    } else {
        r = read(req->conn->watcher.fd, req->headers_buf+req->bufposition,
            req->conn->max_header_size - req->bufposition);
    }

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
    ws_request_t *creq = req;
    while(r > 0) {
        int nr;
        char *tailbuf;
        if(creq->headerlen) {
            nr = ws_body_slice(creq, r);
            tailbuf = creq->body+creq->bodylen;
        } else {
            nr = ws_head_slice(creq, r);
            tailbuf = creq->headers_buf+r-nr;
        }
        if(nr == -2) {
            creq->headerlen = 0;
        }
        if(nr < 0) {
            ws_graceful_finish(creq->conn, TRUE);
        }
        if(nr > 0) { // Requests pipelining
            ws_request_new(creq->conn);
            ws_request_t *nreq = creq->conn->last_req;
            memcpy(nreq->headers_buf, tailbuf, nr);
            creq = nreq;
        }
        r = nr;
    }
}

static int ws_body_slice(ws_request_t *req, int size) {
    req->bodyposition += size;
    if(req->bodyposition >= req->bodylen) {
        req->reply_state = WS_R_EMPTY;

        char *item = req->headerindex[WS_H_CONNECTION];
        if(req->http_version == WS_HTTP_10) {
            if(!item || strcasecmp(item, "Keep-Alive")) {
                ws_graceful_finish(req->conn, FALSE);
            }
        } else {
            if(item && !strcasecmp(item, "close")) {
                ws_graceful_finish(req->conn, FALSE);
            }
        }
        ws_request_cb cb = req->req_callbacks[WS_REQ_CB_REQUEST];
        if(cb) {
            int res = cb(req);
            if(res < 0) {
                return -3;
            }
        }
        return req->bodyposition - req->bodylen;
    }
    return 0;
}

static int ws_head_slice(ws_request_t *req, int size) {
    req->bufposition += size;
    char *e1 = memmem(req->headers_buf, size, "\r\n\r\n", 4);
    char *e2 = memmem(req->headers_buf, size, "\n\n", 2);
    size_t reallen;
    if(e2 < e1 && e2 || !e1) {
        e1 = e2;
        reallen = e1 - req->headers_buf + 2;
    } else if(e1) {
        reallen = e1 - req->headers_buf + 4;
    }
    if(!e1) { // no end of headers
        if(req->bufposition >= req->conn->max_header_size) {
            ws_graceful_finish(req->conn, TRUE);
        }
        return 0;
    }
    req->headerlen = e1 - req->headers_buf;
    *e1 = '\0';
    char *c = req->headers_buf;
    req->method = c;
    if(*c == '\r') ++c;
    if(*c == '\n') ++c;
    while(*++c && !isspace(*c));
    *c = '\0';
    if(c == e1) return -2;
    while(isspace(*++c));
    if(c == e1) return -2;
    req->uri = c;
    while(*++c && !isspace(*c));
    *c = '\0';
    if(c == e1) return -2;
    while(isspace(*++c));
    char *ver = c;
    while(*++c && !isspace(*c));
    if(c == e1 || *c != '\r' && *c != '\n') return -2;
    *c++ = '\0';
    if(!strcmp("HTTP/1.1", ver)) {
        req->http_version = WS_HTTP_11;
    } else if(!strcmp("HTTP/1.0", ver)) {
        req->http_version = WS_HTTP_10;
    } else {
        return -2;
    }
    ws_hparser_t *hp = &req->conn->serv->header_parser;
    int header_count = 1; // sentinel
    req->headerindex = obstack_alloc(&req->pieces,
        sizeof(req->headerindex[0])*hp->count);
    bzero(req->headerindex, sizeof(req->headerindex[0])*hp->count);
    obstack_blank(&req->pieces, 0);
    bool finish = FALSE;
    while(!finish) {
        if(!*c) break;
        while(isspace(*++c));
        char *hname = c;
        while(*++c && *c != ':');
        if(!*c) return -2;
        *c = '\0';
        while(isblank(*++c));
        if(isspace(*c) || !*c) return -2;
        char *hvalue = c;
        while(*++c && *c != '\r' && *c != '\n');
        finish = !*c;
        *c++ = '\0';
        size_t index = 0;
        if(ws_imatch(hp->index, hname, &index)) {
            req->headerindex[index] = hvalue;
        }
        obstack_ptr_grow(&req->pieces, hname);
        obstack_ptr_grow(&req->pieces, hvalue);
    }
    obstack_ptr_grow(&req->pieces, NULL);
    obstack_ptr_grow(&req->pieces, NULL);
    req->allheaders = obstack_finish(&req->pieces);

    char *item = req->headerindex[WS_H_CONTENT_LENGTH];
    if(item && strcmp(item, "0")) {
        char *end;
        req->bodylen = strtol(item, &end, 10);
        if(end == item || *end != '\0') {
            req->bodylen = 0;
        }
    } else {
        req->bodylen = 0;
    }

    ws_request_cb cb = req->req_callbacks[WS_REQ_CB_HEADERS];
    if(cb) {
        int res = cb(req);
        if(res < 0) {
            return -2;
        }
    }
    if(req->bodylen <= req->bufposition - reallen) {
        if(req->bodylen) {
            req->body = req->headers_buf + reallen;
        }
        req->reply_state = WS_R_EMPTY;

        item = req->headerindex[WS_H_CONNECTION];
        if(req->http_version == WS_HTTP_10) {
            if(!item || strcasecmp(item, "Keep-Alive")) {
                ws_graceful_finish(req->conn, FALSE);
            }
        } else {
            if(item && !strcasecmp(item, "close")) {
                ws_graceful_finish(req->conn, FALSE);
            }
        }
        cb = req->req_callbacks[WS_REQ_CB_REQUEST];
        if(cb) {
            int res = cb(req);
            if(res < 0) {
                return -3;
            }
        }

        return req->bufposition - reallen - req->bodylen;
    } else {
        if(req->bodylen + reallen <= req->conn->max_header_size) {
            req->body = req->headers_buf + reallen;
            req->bodyposition = req->bufposition - reallen;
        } else {
            req->body = obstack_alloc(&req->pieces, req->bodylen);
            req->bodyposition = req->bufposition - reallen;
            memcpy(req->body, req->headers_buf + reallen, req->bodyposition);
        }
        return 0;
    }
}

static void ws_data_callback(struct ev_loop *loop, ws_connection_t *conn,
    int revents) {
    if(revents & EV_READ) {
        if(!conn->last_req || conn->last_req->headerlen
            && conn->last_req->bodyposition == conn->last_req->bodylen) {
            ws_request_new(conn);
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
    assert(serv->_conn_size >= sizeof(ws_connection_t));
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
    conn->last_req = NULL;
    conn->first_req = NULL;
    conn->request_num = 0;
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
    conn->next = NULL;
    conn->prev = serv->last_conn;
    if(conn->prev) {
        conn->prev->next = conn;
    } else {
        serv->first_conn = conn;
    }
    serv->last_conn = conn;
    ev_io_start(serv->loop, &conn->watcher);
    ev_timer_start(serv->loop, &conn->timeo);
}

static void ws_accept_callback(struct ev_loop *loop, ws_listener_t *l,
    int revents) {
    if(revents & EV_READ) {
        struct sockaddr_in addr;
        int addrlen = sizeof(addr);
/*        int fd = accept4(l->watcher.fd, &addr, &addrlen,*/
/*            SOCK_NONBLOCK|SOCK_CLOEXEC);*/
        int fd = accept(l->watcher.fd, &addr, &addrlen);
        //SOCK_NONBLOCK|SOCK_CLOEXEC);
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
    serv->header_parser.index = ws_match_new();
    serv->header_parser.count = WS_STD_HEADERS;
    int hindex;
    hindex = ws_match_iadd(serv->header_parser.index,
        "Content-Length", WS_H_CONTENT_LENGTH);
    assert(hindex == WS_H_CONTENT_LENGTH);
    hindex = ws_match_iadd(serv->header_parser.index,
        "Connection", WS_H_CONNECTION);
    assert(hindex == WS_H_CONNECTION);
    hindex = ws_match_iadd(serv->header_parser.index,
        "Upgrade", WS_H_UPGRADE);
    assert(hindex == WS_H_UPGRADE);
    bzero(serv->req_callbacks, sizeof(serv->req_callbacks));
    bzero(serv->conn_callbacks, sizeof(serv->conn_callbacks));
    return 0;
}

int ws_server_start(ws_server_t *serv) {
    ws_match_compile(serv->header_parser.index);
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

int ws_add_unix(ws_server_t *serv, const char *filename, size_t len) {
    struct sockaddr_un addr;
    addr.sun_family = AF_LOCAL;
    memcpy(addr.sun_path, filename, len);
    int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    int size = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
        &size, sizeof(size)) < 0) return -1;
    if(bind(fd, &addr, sizeof(addr.sun_path)+len) < 0) return -1;
    if(listen(fd, 4096) < 0) return -1;
    ws_add_fd(serv, fd);
}

int ws_index_header(ws_server_t *serv, const char *name) {
    int res = ws_match_iadd(serv->header_parser.index, name,
        serv->header_parser.count);
    if(res == serv->header_parser.count) {
        ++serv->header_parser.count;
    }
    return res;
}

static int ws_start_reply(ws_request_t *req);

static void ws_send_reply(struct ev_loop *loop,
    struct ev_io *watch, int revents) {
    ws_request_t *req = (ws_request_t*)(((char *)watch)
        - offsetof(ws_request_t, reply_watch));
    if(revents & EV_WRITE) {
        assert(req->reply_head_size);
        int res;
        if(req->reply_head_size <= req->reply_pos) { //only the second part
            res = write(watch->fd,
                req->reply_body + req->reply_pos - req->reply_head_size,
                req->reply_body_size - req->reply_pos + req->reply_head_size);
        } else {
            struct iovec data[2] = {
                { iov_base: req->reply_head + req->reply_pos,
                  iov_len: req->reply_head_size - req->reply_pos },
                { iov_base: req->reply_body,
                  iov_len: req->reply_body_size},
                };
            res = writev(watch->fd, data, 2);
        }
        if(res < 0) {
            switch(errno) {
                case EAGAIN:
                case EINTR:
                    break;
                default:
                    ws_connection_close(req->conn);
                    return;
            }
        } else if(res == 0) {
            ws_connection_close(req->conn);
            return;
        }
        req->reply_pos += res;
        if(req->reply_pos >= req->reply_head_size + req->reply_body_size) {
            req->reply_state = WS_R_SENT;
            ev_io_stop(loop, watch);
        }
        ws_connection_t *conn = req->conn;
        ws_request_free(req);
        if(conn->first_req) {
            ws_start_reply(conn->first_req);
        } else if(conn->close_on_finish) {
            ws_connection_close(conn);
        }
    }
    assert(!(revents & EV_ERROR));
}

static int ws_start_reply(ws_request_t *req) {
    if(req->reply_state < WS_R_BODY) {
        errno = EAGAIN;
        return -1;
    }
    if(req->reply_state >= WS_R_SENDING) {
        errno = EALREADY;
        return -1;
    }
    req->reply_state = WS_R_SENDING;
    ev_io_init(&req->reply_watch, ws_send_reply,
        req->conn->watcher.fd, EV_WRITE);
    ev_io_start(req->conn->loop, &req->reply_watch);
    return 0;
}

void ws_quickstart(ws_server_t *serv, const char *host,
    int port, ws_request_cb cb) {
    struct in_addr addr;
    if(ws_server_init(serv, ev_default_loop(0)) < 0
       || inet_aton(host, &addr) < 0
       || ws_add_tcp(serv, addr.s_addr, port) < 0
       || ws_server_start(serv) < 0) {
        perror("ws_quickstart");
    }
    ws_REQUEST_CB(serv, cb);
}

int ws_statusline(ws_request_t *req, const char *line) {
    if(req->reply_state <= WS_R_UNDEFINED) {
        errno = EAGAIN;
        return -1;
    }
    if(req->reply_state >= WS_R_STATUS){
        errno = EALREADY;
        return -1;
    }
    obstack_blank(&req->pieces, 0);
    obstack_grow(&req->pieces, "HTTP/1.1 ", 9);
    obstack_grow(&req->pieces, line, strlen(line));
    obstack_grow(&req->pieces, "\r\n", 2);
    req->reply_state = WS_R_STATUS;
    ws_add_header(req, "Content-Length", "           0");
    req->_contlen_offset = obstack_object_size(&req->pieces)-14;
    if(req->conn->close_on_finish && req->conn->last_req == req) {
        ws_add_header(req, "Connection", "close");
    } else {
        ws_add_header(req, "Connection", "Keep-Alive");
    }
}

int ws_add_header(ws_request_t *req, const char *name, const char *value) {
    if(req->reply_state <= WS_R_UNDEFINED) {
        errno = EAGAIN;
        return -1;
    }
    if(req->reply_state >= WS_R_HEADERS) {
        errno = EALREADY;
        return -1;
    }
    if(req->reply_state < WS_R_STATUS) {
        if(ws_statusline(req, "200 OK") < 0) {
            return -1;
        }
    }
    obstack_grow(&req->pieces, name, strlen(name));
    obstack_grow(&req->pieces, ": ", 2);
    obstack_grow(&req->pieces, value, strlen(value));
    obstack_grow(&req->pieces, "\r\n", 2);
}

int ws_finish_headers(ws_request_t *req) {
    if(req->reply_state <= WS_R_UNDEFINED) {
        errno = EAGAIN;
        return -1;
    }
    if(req->reply_state >= WS_R_HEADERS) {
        errno = EALREADY;
        return -1;
    }
    if(req->reply_state < WS_R_STATUS) {
        if(ws_statusline(req, "200 OK") < 0) {
            return -1;
        }
    }
    obstack_grow(&req->pieces, "\r\n", 2);
    req->reply_head_size = obstack_object_size(&req->pieces);
    req->reply_head = obstack_finish(&req->pieces);
    req->reply_state = WS_R_HEADERS;
}

int ws_reply_data(ws_request_t *req, const char *data, size_t len) {
    if(req->reply_state <= WS_R_UNDEFINED) {
        errno = EAGAIN;
        return -1;
    }
    if(req->reply_state >= WS_R_BODY) {
        errno = EALREADY;
        return -1;
    }
    if(req->reply_state < WS_R_HEADERS) {
        if(ws_finish_headers(req) < 0) {
            return -1;
        }
    }
    req->reply_body = (char *)data;
    req->reply_body_size = len;
    int lenlen = sprintf(req->reply_head + req->_contlen_offset, "%12d", len);
    assert(lenlen == 12);
    *(req->reply_head + req->_contlen_offset+12) = '\r';
    req->reply_state = WS_R_BODY;
    if(!req->prev) {
        ws_start_reply(req);
    }
    return 0;
}
