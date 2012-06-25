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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <math.h>
#include <endian.h>

#include <openssl/sha.h>

#include "core.h"

#define bool int
#define TRUE 1
#define FALSE 0

#define LWARN(holder, msg, ...) if((holder)->logmsg_cb) { \
    (holder)->logmsg_cb(WS_LOG_WARN, __FILE__, __LINE__, msg, ##__VA_ARGS__); \
    }
#define SWARN(holder) if((holder)->logstd_cb) { \
    (holder)->logstd_cb(WS_LOG_WARN, __FILE__, __LINE__, ""); \
    }
#define LALERT(holder, msg, ...) if((holder)->logmsg_cb) { \
    (holder)->logmsg_cb(WS_LOG_ALERT, __FILE__, __LINE__, msg, ##__VA_ARGS__); \
    }
#define SALERT(holder) if((holder)->logstd_cb) { \
    (holder)->logstd_cb(WS_LOG_ALERT, __FILE__, __LINE__, ""); \
    }

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};

void base64(const char *data, size_t dlen, char *output) {
    for (int i = 0, j = 0; i < dlen;) {
        uint32_t octet_a = (unsigned char)data[i++];
        uint32_t octet_b = i < dlen ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < dlen ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        output[j++] = encoding_table[(triple >> (3 * 6)) & 0x3F];
        output[j++] = encoding_table[(triple >> (2 * 6)) & 0x3F];
        output[j++] = encoding_table[(triple >> (1 * 6)) & 0x3F];
        output[j++] = encoding_table[(triple >> (0 * 6)) & 0x3F];
    }

    size_t olen = (size_t)(4.0 * ceil((double)dlen / 3.0));
    for(int i = 0; i < mod_table[dlen % 3]; i++)
        output[olen - 1 - i] = '=';
    output[olen] = '\0';
}

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

static int ws_head_slice(ws_request_t *req, int size);
static int ws_body_slice(ws_request_t *req, int size);
static void ws_graceful_finish(ws_connection_t *conn, bool eat_last);
static int ws_start_reply(ws_request_t *req);
static void ws_send_reply(struct ev_loop *loop,
    struct ev_io *watch, int revents);

static void ws_request_init(ws_request_t *req, ws_connection_t *conn, char*buf){
    obstack_init(&req->pieces);
    req->conn = conn;
    memcpy(&req->req_callbacks,conn->req_callbacks, sizeof(req->req_callbacks));
    req->network_timeout = conn->network_timeout;
    req->logstd_cb = conn->logstd_cb;
    req->logmsg_cb = conn->logmsg_cb;
    req->headers_buf = buf;
    req->bufposition = 0;
    req->headerlen = 0;
    req->body = 0;
    req->bodylen = 0;
    req->bodyposition = 0;
    req->request_state = WS_R_RECVHEADERS;
    req->reply_head = NULL;
    req->reply_head_size = 0;
    req->reply_body = NULL;
    req->reply_body_size = 0;
    req->reply_pos = 0;
    req->websocket = FALSE;
}

static ws_request_t *ws_request_new(ws_connection_t *conn) {
    ws_request_t *req = (ws_request_t*)malloc(conn->_req_size
        + conn->max_header_size);
    if(!req) {
        ws_graceful_finish(conn, FALSE);
        return NULL;
    }
    ws_request_init(req, conn, (char *)req + conn->_req_size);
    TAILQ_INSERT_TAIL(&conn->requests, req, lst);
    ++conn->request_num;
    return req;
}

int ws_request_free(ws_request_t *req) {
    obstack_free(&req->pieces, NULL);
    free(req);
}

static void ws_request_finish(ws_request_t *req) {
    TAILQ_REMOVE(&req->conn->requests, req, lst);
    req->conn->request_num -= 1;
    if(!req->conn->request_num && req->conn->reply_watch.active) {
        // this is entered when closing connection prematurely
        ev_io_stop(req->conn->loop, &req->conn->reply_watch);
    }
    bool need_free = TRUE;
    if(req->request_state >= WS_R_RECVBODY) {
        ws_request_cb cb = req->req_callbacks[WS_REQ_CB_FINISH];
        if(cb) {
            need_free = cb(req) <= 0;
        }
    }
    if(need_free) {
        ws_request_free(req);
    }
}

void ws_connection_close(ws_connection_t *conn) {
    ws_request_t *cur, *nxt;
    for(cur = TAILQ_FIRST(&conn->requests); cur; cur = nxt) {
        nxt = TAILQ_NEXT(cur, lst);
        ws_request_finish(cur);
    };
    if(conn->watch.active) {
        ev_io_stop(conn->loop, &conn->watch);
    }
    if(conn->reply_watch.active) {
        ev_io_stop(conn->loop, &conn->reply_watch);
    }
    if(conn->flush_watch.active) {
        ev_idle_stop(conn->loop, &conn->flush_watch);
    }
    if(conn->network_timer.active) {
        ev_timer_stop(conn->loop, &conn->network_timer);
    }
    close(conn->watch.fd);
    ws_connection_cb cb = conn->conn_callbacks[WS_CONN_CB_DISCONNECT];
    if(cb) {
        cb(conn);
    }
    if(conn->websocket_buf) {
        for(int i = conn->websocket_qlen, j = conn->websocket_qstart;
            i > 0; --i, ++j) {
            if(j >= conn->websocket_queue_size) {
                j -= conn->websocket_queue_size;
            }
            ws_MESSAGE_DECREF(conn->websocket_queue[j]);
        }
        free(conn->websocket_buf);
        if(conn->websocket_partial) {
            ws_MESSAGE_DECREF(conn->websocket_partial);
        }
    }
    free(conn);
}

static void ws_graceful_finish(ws_connection_t *conn, bool eat_last) {
    shutdown(conn->watch.fd, SHUT_RD);
    ev_io_stop(conn->loop, &conn->watch);
    if(conn->websocket_buf) {
        free(conn->websocket_buf);
    }
    if(conn->request_num) {
        if(eat_last) {
            ws_request_finish(TAILQ_LAST(&conn->requests, ws_req_list_s));
            if(TAILQ_LAST(&conn->requests, ws_req_list_s)) {
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
        r = read(req->conn->watch.fd, req->body+req->bodyposition,
            req->bodylen - req->bodyposition);
    } else {
        r = read(req->conn->watch.fd, req->headers_buf+req->bufposition,
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
            ws_request_t *nreq = TAILQ_LAST(&creq->conn->requests, ws_req_list_s);
            memcpy(nreq->headers_buf, tailbuf, nr);
            creq = nreq;
        }
        r = nr;
    }
}

static int check_websocket(ws_request_t *req) {
    char *key =  req->headerindex[WS_H_WEBSOCKET_KEY];
    if(!key || strlen(key) < 10) {
        return -1;
    }
    char *sver = req->headerindex[WS_H_WEBSOCKET_VERSION];
    if(!sver) {
        return -1;
    }
    char *vend;
    long ver = strtol(sver, &vend, 10);
    if(*vend) {
        return -1;
    }
    if(ver != 8 && ver != 13) {
        return -1;
    }
    return 0;
}

ws_message_t *ws_message_copy_data(ws_connection_t *conn,
    void *data, size_t len) {
    ws_message_t *res = (ws_message_t *)malloc(conn->_message_size+len+1);
    if(!res) return NULL;
    memcpy((char *)res + conn->_message_size, data, len);
    res->refcnt = 1;
    res->data = (char *)res + conn->_message_size;
    res->data[len] = 0; // for easier dealing with that as string
    res->length = len;
    res->flags = WS_MSG_TEXT;
    res->free_cb = NULL;
    return res;
}

ws_message_t *ws_message_new_size(ws_connection_t *conn, size_t len) {
    ws_message_t *res = (ws_message_t *)malloc(conn->_message_size+len+1);
    if(!res) return NULL;
    res->refcnt = 1;
    res->data = (char *)res + conn->_message_size;
    res->data[len] = 0; // for easier dealing with that as string
    res->length = len;
    res->flags = WS_MSG_TEXT;
    res->free_cb = NULL;
    return res;
}

ws_message_t *ws_message_resize(ws_message_t *msg, size_t len) {
    size_t msg_size = msg->data - (char *)msg;
    ws_message_t *res = (ws_message_t *)realloc(msg, msg_size+len+1);
    if(!res) return NULL;
    res->data = (char *)res + msg_size;
    res->data[len] = 0; // for easier dealing with that as string
    res->length = len;
    assert(res->free_cb == NULL);
    return res;
}

ws_message_t *ws_message_new(ws_connection_t *conn) {
    ws_message_t *res = (ws_message_t *)malloc(conn->_message_size);
    if(!res) return NULL;
    if(ws_message_init(res)) {
        free(res);
        return NULL;
    }
    return res;
}

int ws_message_init(ws_message_t *res) {
    res->refcnt = 1;
    res->data = NULL;
    res->length = 0;
    res->flags = WS_MSG_TEXT;
    res->free_cb = NULL;
    return 0;
}


void ws_message_free(ws_message_t *msg) {
    if(msg->free_cb) {
        msg->free_cb(msg);
    }
    free(msg);
}

int ws_message_send(ws_connection_t *conn, ws_message_t *msg) {
    if(conn->websocket_qlen >= conn->websocket_queue_size) {
        errno = EXFULL;
        return -1;
    }
    ws_MESSAGE_INCREF(msg);
    int end = conn->websocket_qstart + conn->websocket_qlen;
    if(end >= conn->websocket_queue_size) {
        end -= conn->websocket_queue_size;
    }
    conn->websocket_queue[end] = msg;
    if(!conn->reply_watch.active) {
        ev_io_start(conn->loop, &conn->reply_watch);
        if(conn->flush_watch.active) {
            ev_idle_stop(conn->loop, &conn->flush_watch);
        }
    }
    conn->websocket_qlen += 1;
    return 0;
}

static int unmask_and_check(ws_message_t *msg, char *mask, int offset) {
    if(msg->flags == WS_MSG_TEXT) {
        unsigned char *c = msg->data + offset, *e = msg->data + msg->length;
        int state = 0;
        int uchar = 0;
        int mincode = 0;
        if(offset && c[-1] & 0x80) {
            unsigned char *sc = c-1;
            while((*sc & 0xc0) == 0x80) --sc;
            while(sc < c) {
                char cc = *sc++;
                if(!state) {
                    if(cc & 0x80) {
                        if((cc & 0xc0) == 0x80) return -1;
                        else if((cc & 0xe0) == 0xc0) {
                            state = 1;
                            uchar = cc & 0x1f;
                            mincode = 0x80;
                        } else if((cc & 0xf0) == 0xe0) {
                            state = 2;
                            uchar = cc & 0x0f;
                            mincode = 0x800;
                        } else if((cc & 0xf8) == 0xf0) {
                            state = 3;
                            uchar = cc & 0x07;
                            mincode = 0x10000;
                        } else return -1;
                    }
                } else {
                    if((cc & 0xc0) != 0x80) return -1;
                    uchar = (uchar << 6) | (cc & 0x3f);
                    if(!-- state) {
                        if(uchar < mincode) return -1;
                        else if(uchar >= 0xd800 && uchar <= 0xdfff) return -1;
                        else if(uchar > 0x10ffff) return -1;
                        uchar = 0;
                    }
                }
            }
        }
        for(int i = 0; c < e; ++c, ++i) {
            *c = *c ^ mask[(size_t)i & 3];
            char cc = *c;
            if(!state) {
                if(cc & 0x80) {
                    if((cc & 0xc0) == 0x80) return -1;
                    else if((cc & 0xe0) == 0xc0) {
                        state = 1;
                        uchar = cc & 0x1f;
                        mincode = 0x80;
                    } else if((cc & 0xf0) == 0xe0) {
                        state = 2;
                        uchar = cc & 0x0f;
                        mincode = 0x800;
                    } else if((cc & 0xf8) == 0xf0) {
                        state = 3;
                        uchar = cc & 0x07;
                        mincode = 0x10000;
                    } else return -1;
                }
            } else {
                if((cc & 0xc0) != 0x80) return -1;
                uchar = (uchar << 6) | (cc & 0x3f);
                if(!-- state) {
                    if(uchar < mincode) return -1;
                    else if(uchar >= 0xd800 && uchar <= 0xdfff) return -1;
                    else if(uchar > 0x10ffff) return -1;
                    uchar = 0;
                }
            }
        }
        if(state == 1 && uchar >= (0xd800 >> 6) && uchar <= (0xdfff >> 6))
            return -1;  // fail faster
        return state;
    } else {
        char *c = msg->data + offset, *e = msg->data + msg->length;
        for(int i = 0; c < e; ++c, ++i) {
            *c = *c ^ mask[(size_t)i & 3];
        }
        return 0;
    }
}

static void read_websocket(struct ev_loop *loop, struct ev_io *watch,
    int revents) {
    assert(!(revents & EV_ERROR));
    ws_connection_t *conn = (ws_connection_t *)((char *)watch
        - offsetof(ws_connection_t, watch));
    if(!(revents & EV_READ)) return;
    if(conn->websocket_partial
        && conn->websocket_partial_len < conn->websocket_partial->length) {
        int r = read(conn->watch.fd,
            conn->websocket_partial->data + conn->websocket_partial_len,
            conn->websocket_partial->length - conn->websocket_partial_len);
        if(r < 0) {
            switch(errno) {
                case EAGAIN:
                case EINTR:
                    return;
                default:
                    ws_connection_close(conn);
                    return;
            }
        }
        if(r == 0) {
            ws_connection_close(conn);
            return;
        }
        conn->websocket_partial_len += r;
        if(conn->websocket_partial_len >= conn->websocket_partial->length) {
            int ures = unmask_and_check(conn->websocket_partial,
                conn->websocket_partial_mask, conn->websocket_partial_frame);
            if(conn->websocket_partial_fin) {
                if(ures) goto error;
                ws_websocket_cb cb = \
                    conn->wsock_callbacks[WS_WEBSOCKET_CB_MESSAGE];
                int res = -1;
                if(cb) {
                    res = cb(conn, conn->websocket_partial);
                }
                ws_MESSAGE_DECREF(conn->websocket_partial);
                conn->websocket_partial = NULL;
                if(res < 0) {
                    ws_connection_close(conn);
                    return;
                }
            } else {
                if(ures < 0) goto error;
            }
            // TODO(tailhook) optimize, do more reads
        }
    } else {
        int r = read(conn->watch.fd,
            conn->websocket_buf+conn->websocket_buf_offset,
            conn->websocket_buf_size - conn->websocket_buf_offset);
        if(r < 0) {
            switch(errno) {
                case EAGAIN:
                case EINTR:
                    return;
                default:
                    ws_connection_close(conn);
                    return;
            }
        }
        if(r == 0) {
            ws_connection_close(conn);
            return;
        }
        int len = conn->websocket_buf_offset + r;
        char *start = conn->websocket_buf;
        int part_len;
        char *part_start;
        while(1) {
            part_len = len;
            part_start = start;
            if(len < 2) break;
            int fin = *start & 0x80;
            int opcode = *start & 0xF;
            int rsv = (*start >> 4) & 7;
            if(rsv) goto error;
            size_t msglen = start[1] & 0x7f;
            int has_mask = start[1] & 0x80;
            if(!has_mask) goto error;
            switch(msglen) {
            case 126:
                if(len < 4) goto stop_reading; // more bytes to read
                msglen = htobe16(*(uint16_t*)(start+2));
                start += 4;
                len -= 4;
                break;
            case 127:
                if(len < 10) goto stop_reading; // more bytes to read
                msglen = htobe64(*(uint64_t*)(start+2));
                start += 10;
                len -= 10;
                break;
            default:
                start += 2;
                len -= 2;
                break;
            }
            if(msglen > conn->max_message_size) goto error;
            if(len < 4) break;  // read more
            char *mask = start;
            start += 4;
            len -= 4;
            if(len >= msglen  // whole message in 1 frame in a buffer
                && opcode  // and it's not a continuation
                && (fin || opcode >= WS_MSG_CLOSE)) {
                if(opcode == WS_MSG_CLOSE) {
                    // TODO(tailhook) implement graceful close
                    ws_connection_close(conn);
                    return;
                }
                ws_message_t *msg = ws_message_copy_data(conn, start, msglen);
                msg->flags = opcode;
                if(unmask_and_check(msg, mask, 0)) {
                    ws_MESSAGE_DECREF(msg);
                    goto error;
                }
                switch(opcode) {
                case WS_MSG_BINARY:
                case WS_MSG_TEXT: {
                    if(conn->websocket_partial) goto error;
                    ws_websocket_cb cb = \
                        conn->wsock_callbacks[WS_WEBSOCKET_CB_MESSAGE];
                    int res = -1;
                    if(cb) {
                        res = cb(conn, msg);
                    }
                    ws_MESSAGE_DECREF(msg);
                    if(res < 0) {
                        ws_connection_close(conn);
                        return;
                    }
                    } break;
                case WS_MSG_PING:
                    if(msglen > 125 || !fin) {
                        ws_MESSAGE_DECREF(msg);
                        goto error;
                    }
                    msg->flags = WS_MSG_PONG;
                    ws_message_send(conn, msg);
                    ws_MESSAGE_DECREF(msg);
                    break;
                case WS_MSG_PONG:
                    // TODO(tailhook) check pong response
                    ws_MESSAGE_DECREF(msg);
                    if(msglen > 125 || !fin) goto error;
                    break;
                default:
                    ws_MESSAGE_DECREF(msg);
                    ws_connection_close(conn);
                    return;
                }
                start += msglen;
                len -= msglen;
            } else if(!opcode) { // continuation of partial
                ws_message_t *msg = conn->websocket_partial;
                if(!msg) goto error;
                msg = ws_message_resize(msg, msg->length + msglen);
                if(!msg) goto error;
                conn->websocket_partial = msg;  // after realloc
                conn->websocket_partial_frame = conn->websocket_partial_len;
                if(len >= msglen) {
                    memcpy(msg->data + conn->websocket_partial_len,
                        start, msglen);
                    int ures = unmask_and_check(msg, mask,
                        conn->websocket_partial_frame);
                    conn->websocket_partial_len += msglen;
                    if(fin) {
                        if(ures) goto error;
                        ws_websocket_cb cb = \
                            conn->wsock_callbacks[WS_WEBSOCKET_CB_MESSAGE];
                        int res = -1;
                        if(cb) {
                            res = cb(conn, msg);
                        }
                        ws_MESSAGE_DECREF(msg);
                        conn->websocket_partial = NULL;
                        if(res < 0) {
                            ws_connection_close(conn);
                            return;
                        }
                    } else {
                        if(ures < 0) goto error;
                    }
                    start += msglen;
                    len -= msglen;
                } else {
                    memcpy(msg->data + conn->websocket_partial_len,
                        start, len);
                    conn->websocket_partial_len += len;
                    conn->websocket_partial_fin = fin;
                    memcpy(conn->websocket_partial_mask, mask, 4);
                    conn->websocket_buf_offset = 0;
                    return;
                }
            } else {  // start of partial message
                if(opcode >= 8) break; // let's wait whole frame
                if(opcode != WS_MSG_TEXT && opcode != WS_MSG_BINARY)
                    goto error;
                ws_message_t *msg = ws_message_new_size(conn, msglen);
                if(opcode == WS_MSG_BINARY) {
                    msg->flags = WS_MSG_BINARY;
                }
                size_t part = msglen;
                if(len < part) part = len;
                memcpy(msg->data, start, part);
                conn->websocket_partial = msg;
                conn->websocket_partial_len = part;
                conn->websocket_partial_frame = 0;
                conn->websocket_partial_fin = fin;
                memcpy(conn->websocket_partial_mask, mask, 4);
                if(len >= msglen) {
                    if(unmask_and_check(msg, mask, 0) < 0) goto error;
                    start += msglen;
                    len -= msglen;
                } else {
                    conn->websocket_buf_offset = 0;
                    return;
                }
            }
        }
stop_reading:
        if(part_len && conn->websocket_buf != part_start) {
            memmove(conn->websocket_buf, part_start, part_len);
        }
        conn->websocket_buf_offset = part_len;
    }
    return;
error:
    ws_connection_close(conn);
    return;
}
static void write_websocket(struct ev_loop *loop, struct ev_io *watch,
    int revents) {
    ws_connection_t *conn = (ws_connection_t *)((char *)watch
        - offsetof(ws_connection_t, reply_watch));
    if(revents & EV_WRITE) {
        while(1) {
            char header[10];
            int headlen = 2;
            ws_message_t *msg = conn->websocket_queue[conn->websocket_qstart];
            header[0] = 0x80 | (msg->flags & WS_MSG_TYPE);
            if(msg->length > 65535) {
                header[1] = 127;
                *(uint64_t*)(header+2) = htobe64(msg->length);
                headlen = 10;
            } else if(msg->length > 125) {
                header[1] = 126;
                *(uint16_t*)(header+2) = htobe16(msg->length);
                headlen = 4;
            } else {
                header[1] = msg->length;
            }
            int off = conn->websocket_queue_offset;
            if(off < headlen) {
                // we use TCP_CORK which is potentially more useful
                // than writev
                int res = write(watch->fd, header + off, headlen - off);
                if(res <= 0) {
                    switch(errno) {
                        case EAGAIN:
                        case EINTR:
                            return;
                        default:
                            ws_connection_close(conn);
                            return;
                    }
                }
                if(res + off < headlen) {
                    conn->websocket_queue_offset = off;
                    return;
                }
                off += res;
            }
            off -= headlen;
            int res = write(watch->fd, msg->data + off, msg->length - off);
            off += res;
            if(off >= msg->length) {
                ws_MESSAGE_DECREF(msg);
                conn->websocket_queue_offset = 0;
                conn->websocket_qstart += 1;
                if(conn->websocket_qstart >= conn->websocket_queue_size) {
                    conn->websocket_qstart -= conn->websocket_queue_size;
                }
                if(!--conn->websocket_qlen) {
                    ev_io_stop(conn->loop, &conn->reply_watch);
                    ev_idle_start(conn->loop, &conn->flush_watch);
                    break;
                } else {
                    continue;
                }
            } else {
                conn->websocket_queue_offset = off + headlen;
                break;
            }
        }
    }
    assert(!(revents & EV_ERROR));
}

static int ws_enable_websocket(ws_request_t *req) {
    int rc;
    ws_connection_t *conn = req->conn;
    ev_io_stop(conn->loop, &conn->watch);
    assert(TAILQ_LAST(&conn->requests, ws_req_list_s) == req);

    conn->websocket_buf = malloc(conn->websocket_buf_size
        + conn->max_message_queue*sizeof(ws_message_t*));
    conn->websocket_queue = (ws_message_t **)(conn->websocket_buf
        + conn->websocket_buf_size);
    conn->websocket_queue_size = conn->max_message_queue;
    conn->websocket_qstart = 0;
    conn->websocket_qlen = 0;
    conn->websocket_queue_offset = 0;
    if(!req->conn->websocket_buf) {
        return -1;
    }
    assert(req->request_state == WS_R_RECVHEADERS);
    req->request_state = WS_R_EMPTY;
    rc = ws_statusline(req, "101 WebSocket Protocol Handshake");
    if(rc < 0) return -1;
    rc = ws_add_header(req, "Upgrade", "WebSocket");
    if(rc < 0) return -1;
    rc = ws_add_header(req, "Connection", "Upgrade");
    if(rc < 0) return -1;
    char *key = req->headerindex[WS_H_WEBSOCKET_KEY];
    int klen = strlen(key);
    char buf[klen+36];
    char hash[20];
    memcpy(buf, key, klen);
    memcpy(buf+klen, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
    SHA1(buf, klen+36, hash);
    base64(hash, 20, buf);
    rc = ws_add_header(req, "Sec-WebSocket-Accept", buf);
    if(rc < 0) return -1;
    rc = ws_finish_headers(req);
    if(rc < 0) return -1;
    rc = ws_reply_data(req, "", 0);
    if(rc < 0) return -1;

    ev_set_cb(&conn->watch, read_websocket);
    ev_io_start(conn->loop, &conn->watch);
    return 0;
}

static int ws_body_slice(ws_request_t *req, int size) {
    req->bodyposition += size;
    if(req->bodyposition >= req->bodylen) {
        req->request_state = WS_R_EMPTY;

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
    char *e1 = memmem(req->headers_buf, req->bufposition, "\r\n\r\n", 4);
    char *e2 = memmem(req->headers_buf, req->bufposition, "\n\n", 2);
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
    if(req->headerindex[WS_H_UPGRADE]) {
        if(!strcasecmp(req->headerindex[WS_H_UPGRADE], "WebSocket")) {
            req->websocket = TRUE;
            int res = 0;
            if(check_websocket(req) == 0) {
                ws_request_cb cb = req->req_callbacks[WS_REQ_CB_WEBSOCKET];
                if(cb) {
                    res = cb(req);
                } else {
                    res = -1;
                }
            } else {
                res = -1;
            }
            if(res < 0) {
                return -2;
            } else if(ws_enable_websocket(req) < 0) {
                return -3;
            }
            return 0;
        } else {
            ws_graceful_finish(req->conn, TRUE);
            return 0;
        }
    } else {
        ws_request_cb cb = req->req_callbacks[WS_REQ_CB_HEADERS];
        if(cb) {
            int res = cb(req);
            if(res < 0) {
                return -2;
            }
        }
    }
    req->request_state = WS_R_RECVBODY;
    if(req->bodylen <= req->bufposition - reallen) {
        if(req->bodylen) {
            req->body = req->headers_buf + reallen;
            req->bodyposition = req->bodylen;
        }
        req->request_state = WS_R_EMPTY;

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
        ws_request_cb cb = req->req_callbacks[WS_REQ_CB_REQUEST];
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

static void ws_data_callback(struct ev_loop *loop, struct ev_io *watch,
    int revents) {
    ws_connection_t *conn = (ws_connection_t *)((char *)watch
        - offsetof(ws_connection_t, watch));
    if(revents & EV_READ) {
        ws_request_t *lreq = TAILQ_LAST(&conn->requests, ws_req_list_s);
        if(!lreq || lreq->headerlen && lreq->bodyposition == lreq->bodylen) {
            lreq = ws_request_new(conn);
        }
        if(lreq) {
            ws_try_read(lreq);
        }
    }
    assert(!(revents & EV_ERROR));
}

static void flush_buffers(struct ev_loop *loop, struct ev_idle *watch,
    int revents) {
    ws_connection_t *conn = (ws_connection_t *)((char *)watch
        - offsetof(ws_connection_t, flush_watch));
    if((conn->websocket_buf)
        ? !conn->websocket_qlen
        : !TAILQ_FIRST(&conn->requests)) {
        int opt = 1;
        // setting NODELAY flushs buffers, but we are still in tcp cork mode
        setsockopt(conn->watch.fd,
            IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    ev_idle_stop(loop, watch);
}

static void network_close(struct ev_loop *loop, struct ev_timer *timer,
    int revents) {
    ws_connection_t *conn = (ws_connection_t *)((char *)timer
        - offsetof(ws_connection_t, network_timer));
    ws_connection_close(conn);
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
    conn->logstd_cb = serv->logstd_cb;
    conn->logmsg_cb = serv->logmsg_cb;
    conn->_req_size = serv->_req_size;
    conn->_message_size = serv->_message_size;
    conn->serv = serv;
    conn->loop = serv->loop;
    conn->max_header_size = serv->max_header_size;
    conn->max_message_size = serv->max_message_size;
    conn->max_message_queue = serv->max_message_queue;
    conn->close_on_finish = FALSE;
    TAILQ_INIT(&conn->requests);
    conn->request_num = 0;
    conn->websocket_buf = NULL;
    conn->websocket_buf_size = 4096;
    conn->websocket_buf_offset = 0;
    conn->websocket_partial = NULL;
    memcpy(conn->req_callbacks, serv->req_callbacks,
        sizeof(conn->req_callbacks));
    memcpy(conn->conn_callbacks, serv->conn_callbacks,
        sizeof(conn->conn_callbacks));
    memcpy(conn->wsock_callbacks, serv->wsock_callbacks,
        sizeof(conn->wsock_callbacks));
    ev_io_init(&conn->watch,
        (void (*)(struct ev_loop*, struct ev_io *,int))ws_data_callback,
        fd, EV_READ);
    ev_io_init(&conn->reply_watch,
        (void (*)(struct ev_loop*, struct ev_io *,int))ws_send_reply,
        fd, EV_WRITE);
    ev_idle_init(&conn->flush_watch,
        (void (*)(struct ev_loop*, struct ev_idle *,int))flush_buffers);
    ev_timer_init(&conn->network_timer, network_close,
        conn->network_timeout, conn->network_timeout);
    ws_connection_cb cb = conn->conn_callbacks[WS_CONN_CB_CONNECT];
    if(cb && cb(conn) < 0) {
        close(fd);
        free(conn);
        return;
    }
    ev_io_start(serv->loop, &conn->watch);
    ev_timer_start(serv->loop, &conn->network_timer);
}

static void wake_up_accept(struct ev_loop *loop, struct ev_timer *w, int rev) {
    ws_server_t *serv = (ws_server_t *)(((char *)w)
        - offsetof(ws_server_t, accept_sleeper));
    for(ws_listener_t *l=serv->listeners; l; l = l->next) {
        if(!l->watch.active) {
            ev_io_start(loop, &l->watch);
        }
    }
    ev_timer_stop(loop, &serv->accept_sleeper);
}

static void accept_callback(struct ev_loop *loop, ws_listener_t *l,
    int revents) {
    if(revents & EV_READ) {
        struct sockaddr_in addr;
        int addrlen = sizeof(addr);
        int fd = accept4(l->watch.fd, &addr, &addrlen,
            SOCK_NONBLOCK|SOCK_CLOEXEC);
        if(fd < 0) {
            switch(errno) {
            case EAGAIN: case ENETDOWN: case EPROTO: case ENOPROTOOPT:
            case EHOSTDOWN: case ENONET: case EHOSTUNREACH: case EOPNOTSUPP:
            case ENETUNREACH: case ECONNABORTED:
                break;
            case EMFILE:
            case ENFILE:
                LWARN(l->serv, "Not enought file descriptors. "
                      "Please set ulimit -n xxxxxx with bigger value");
                ev_io_stop(loop, &l->watch);
                ev_timer_again(loop, &l->serv->accept_sleeper);
                break;
            default:
                SALERT(l->serv);
                abort();
            }
        } else {
            int opt = 1;
            // let's set NODELAY to work faster, but don't care if doesn't work
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
            // let's also cork our connection to send in smaller number of
            // packets
            setsockopt(fd, IPPROTO_TCP, TCP_CORK, &opt, sizeof(opt));
            ws_connection_init(fd, l->serv, &addr);
        }
    }
    assert(!(revents & EV_ERROR));
}

int ws_server_init(ws_server_t *serv, struct ev_loop *loop) {
    serv->loop = loop;
    serv->_conn_size = sizeof(ws_connection_t);
    serv->_req_size = sizeof(ws_request_t);
    serv->_message_size = sizeof(ws_message_t);
    serv->listeners = NULL;
    serv->listeners_num = 0;
    serv->connection_num = 0;
    serv->network_timeout = 120.0;
    serv->max_header_size = 16384;
    serv->max_message_size = 16384;
    serv->max_message_queue = 1024;
    serv->header_parser.index = ws_match_new();
    serv->header_parser.count = WS_STD_HEADERS;
    int hindex;
    hindex = ws_match_iadd(serv->header_parser.index,
        "Host", WS_H_HOST);
    assert(hindex == WS_H_HOST);
    hindex = ws_match_iadd(serv->header_parser.index,
        "Content-Length", WS_H_CONTENT_LENGTH);
    assert(hindex == WS_H_CONTENT_LENGTH);
    hindex = ws_match_iadd(serv->header_parser.index,
        "Connection", WS_H_CONNECTION);
    assert(hindex == WS_H_CONNECTION);
    hindex = ws_match_iadd(serv->header_parser.index,
        "Upgrade", WS_H_UPGRADE);
    assert(hindex == WS_H_UPGRADE);
    hindex = ws_match_iadd(serv->header_parser.index,
        "Origin", WS_H_ORIGIN);
    assert(hindex == WS_H_ORIGIN);
    hindex = ws_match_iadd(serv->header_parser.index,
        "Sec-WebSocket-Key", WS_H_WEBSOCKET_KEY);
    assert(hindex == WS_H_WEBSOCKET_KEY);
    hindex = ws_match_iadd(serv->header_parser.index,
        "Sec-WebSocket-Version", WS_H_WEBSOCKET_VERSION);
    assert(hindex == WS_H_WEBSOCKET_VERSION);
    bzero(serv->req_callbacks, sizeof(serv->req_callbacks));
    bzero(serv->conn_callbacks, sizeof(serv->conn_callbacks));
    serv->logstd_cb = NULL;
    serv->logmsg_cb = NULL;
    ev_timer_init(&serv->accept_sleeper, wake_up_accept, 30, 30);
    return 0;
}

int ws_server_destroy(ws_server_t *serv) {
    ws_match_free(serv->header_parser.index);
    for(ws_listener_t *p, *l=serv->listeners; l; p = l, l = l->next, free(p)) {
        if(l->watch.active) {
            ev_io_stop(serv->loop, &l->watch);
        }
        close(l->watch.fd);
    }
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
    ev_io_init(&l->watch,
        (void (*)(struct ev_loop*, ev_io *, int))accept_callback,
        fd, EV_READ);
    l->serv = serv;

    l->next = serv->listeners;
    serv->listeners = l;
    serv->listeners_num += 1;

    ev_io_start(serv->loop, &l->watch);
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
    return ws_add_fd(serv, fd);
}

int ws_add_unix(ws_server_t *serv, const char *filename, size_t len) {
    struct sockaddr_un addr;
    addr.sun_family = AF_LOCAL;
    assert(len + sizeof(addr.sun_family) <= sizeof(struct sockaddr_un));
    memcpy(addr.sun_path, filename, len);
    int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    int size = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
        &size, sizeof(size)) < 0) return -1;
    if(!access(filename, F_OK)) {
        if(connect(fd, &addr, sizeof(addr.sun_family)+len) < 0) {
            if(unlink(filename) < 0) return -1;
        }
    }
    if(bind(fd, &addr, sizeof(addr.sun_family)+len) < 0) return -1;
    if(listen(fd, 4096) < 0) return -1;
    return ws_add_fd(serv, fd);
}

int ws_index_header(ws_server_t *serv, const char *name) {
    int res = ws_match_iadd(serv->header_parser.index, name,
        serv->header_parser.count);
    if(res == serv->header_parser.count) {
        ++serv->header_parser.count;
    }
    return res;
}

static void ws_send_reply(struct ev_loop *loop,
    struct ev_io *watch, int revents) {
    ws_request_t *req = TAILQ_FIRST(&((ws_connection_t*)(((char *)watch)
        - offsetof(ws_connection_t, reply_watch)))->requests);
    if(revents & EV_WRITE) {
        assert(req->reply_head_size);
        size_t total = req->reply_body_size + req->reply_head_size;
        struct iovec data[2];
        int iovnum = 0;
        if(req->reply_pos < req->reply_head_size) {
            data[iovnum].iov_base = req->reply_head + req->reply_pos;
            data[iovnum].iov_len = req->reply_head_size - req->reply_pos;
            iovnum ++;
        }
        if(req->reply_pos < req->reply_head_size + req->reply_body_size) {
            if(iovnum) {
                data[iovnum].iov_base = req->reply_body;
                data[iovnum].iov_len = req->reply_body_size;
            } else {
                size_t off = req->reply_pos - req->reply_head_size;
                data[iovnum].iov_base = req->reply_body + off;
                data[iovnum].iov_len = req->reply_body_size - off;
            }
            iovnum ++;
        }
        int res;
        res = writev(watch->fd, data, iovnum);
        if(res < 0) {
            switch(errno) {
                case EAGAIN:
                case EINTR:
                    return;
                default:
                    ws_connection_close(req->conn);
                    return;
            }
        } else if(res == 0) {
            ws_connection_close(req->conn);
            return;
        }
        ev_timer_again(req->conn->loop, &req->conn->network_timer);
        req->reply_pos += res;
        if(req->reply_pos >= total) {
            req->request_state = WS_R_SENT;
            ev_io_stop(loop, watch);

            ws_connection_t *conn = req->conn;
            ws_request_finish(req);
            if(TAILQ_FIRST(&conn->requests)) {
                ws_start_reply(TAILQ_FIRST(&conn->requests));
            } else if(conn->close_on_finish) {
                ws_connection_close(conn);
            } else if(conn->websocket_buf) {
                ev_timer_stop(conn->loop, &conn->network_timer);
                ev_set_cb(&conn->reply_watch, write_websocket);
                if(conn->websocket_qlen) {
                    ev_io_start(loop, watch);
                }
            } else {
                ev_idle_start(conn->loop, &conn->flush_watch);
            }
        }
    }
    assert(!(revents & EV_ERROR));
}

static int ws_start_reply(ws_request_t *req) {
    if(req->request_state < WS_R_DONE) {
        errno = EAGAIN;
        return -1;
    }
    if(req->request_state >= WS_R_SENDING) {
        errno = EALREADY;
        return -1;
    }
    req->request_state = WS_R_SENDING;
    ev_io_start(req->conn->loop, &req->conn->reply_watch);
    if(req->conn->flush_watch.active) {
        ev_idle_stop(req->conn->loop, &req->conn->flush_watch);
    }
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
    return ws_statusline_len(req, line, strlen(line));
}

int ws_statusline_len(ws_request_t *req, const char *line, int len) {
    if(req->request_state < WS_R_EMPTY) {
        errno = EAGAIN;
        return -1;
    }
    if(req->request_state >= WS_R_STATUS){
        errno = EALREADY;
        return -1;
    }
    obstack_blank(&req->pieces, 0);
    obstack_grow(&req->pieces, "HTTP/1.1 ", 9);
    obstack_grow(&req->pieces, line, len);
    obstack_grow(&req->pieces, "\r\n", 2);
    req->request_state = WS_R_STATUS;
    if(!req->websocket) {
        ws_add_header(req, "Content-Length", "           0");
        req->_contlen_offset = obstack_object_size(&req->pieces)-14;
        if(req->conn->close_on_finish
            && TAILQ_LAST(&req->conn->requests, ws_req_list_s) == req) {
            ws_add_header(req, "Connection", "close");
        } else {
            ws_add_header(req, "Connection", "Keep-Alive");
        }
    }
    return 0;
}

int ws_add_header(ws_request_t *req, const char *name, const char *value) {
    if(req->request_state < WS_R_EMPTY) {
        errno = EAGAIN;
        return -1;
    }
    if(req->request_state >= WS_R_HEADERS) {
        errno = EALREADY;
        return -1;
    }
    if(req->request_state < WS_R_STATUS) {
        if(ws_statusline(req, "200 OK") < 0) {
            return -1;
        }
    }
    obstack_grow(&req->pieces, name, strlen(name));
    obstack_grow(&req->pieces, ": ", 2);
    obstack_grow(&req->pieces, value, strlen(value));
    obstack_grow(&req->pieces, "\r\n", 2);
    return 0;
}

int ws_finish_headers(ws_request_t *req) {
    if(req->request_state < WS_R_EMPTY) {
        errno = EAGAIN;
        return -1;
    }
    if(req->request_state >= WS_R_HEADERS) {
        errno = EALREADY;
        return -1;
    }
    if(req->request_state < WS_R_STATUS) {
        if(ws_statusline(req, "200 OK") < 0) {
            return -1;
        }
    }
    obstack_grow(&req->pieces, "\r\n", 2);
    req->reply_head_size = obstack_object_size(&req->pieces);
    req->reply_head = obstack_finish(&req->pieces);
    req->request_state = WS_R_BODY;
    return 0;
}

int ws_reply_data(ws_request_t *req, const char *data, size_t len) {
    if(req->request_state < WS_R_EMPTY) {
        errno = EAGAIN;
        return -1;
    }
    if(req->request_state > WS_R_BODY) {
        errno = EALREADY;
        return -1;
    }
    if(req->request_state <= WS_R_HEADERS) {
        if(ws_finish_headers(req) < 0) {
            return -1;
        }
    }
    req->reply_body = (char *)data;
    req->reply_body_size = len;
    if(!req->websocket) {
        int lenlen = sprintf(req->reply_head + req->_contlen_offset,
            "%12lu", len);
        assert(lenlen == 12);
        *(req->reply_head + req->_contlen_offset+12) = '\r';
    }
    req->request_state = WS_R_DONE;
    if(TAILQ_FIRST(&req->conn->requests) == req) {
        ws_start_reply(req);
    }
    return 0;
}
