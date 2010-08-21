#ifndef WS_WEBSITE_H
#define WS_WEBSITE_H

#include <ev.h>
#include <obstack.h>
#include <netinet/in.h>

#define ws_CONNECTION_STRUCT(targ, typ) (targ)->_conn_size = sizeof(typ)
#define ws_REQUEST_STRUCT(targ, typ) (targ)->_conn_size = sizeof(typ)
#define ws_HEADERS_CB(targ, fun) \
    (targ)->req_callbacks[WS_REQ_CB_HEADERS] = (ws_request_cb)fun
#define ws_REQUEST_CB(targ, fun) \
    (targ)->req_callbacks[WS_REQ_CB_REQUEST] = (ws_request_cb)fun
#define ws_FINISH_CB(targ, fun) \
    (targ)->req_callbacks[WS_REQ_CB_FINISH] = (ws_request_cb)fun
#define ws_CONNECT_CB(targ, fun) \
    (targ)->conn_callbacks[WS_CONN_CB_CONNECT] = (ws_connection_cb)fun
#define ws_DISCONNECT_CB(targ, fun) \
    (targ)->conn_callbacks[WS_CONN_CB_DISCONNECT] = (ws_connection_cb)fun
#define ws_SET_TIMEOUT(targ, value) (targ)->network_timeout = (value)

typedef enum {
    WS_REQ_CB_HEADERS, // got headers
    WS_REQ_CB_REQUEST, // got request body
    WS_REQ_CB_FINISH, // response fully sent
    WS_REQ_CB_COUNT,
} ws_request_cb_enum;

typedef enum {
    WS_CONN_CB_CONNECT,
    WS_CONN_CB_DISCONNECT,
    WS_CONN_CB_COUNT,
} ws_connection_cb_enum;

struct ws_request_s;
struct ws_connection_s;

typedef int (*ws_request_cb)(struct ws_request_s *req);
typedef int (*ws_connection_cb)(struct ws_connection_s *conn);

typedef struct ws_request_s {
    struct obstack pieces;
    struct ws_connection_s *conn;
    ws_request_cb req_callbacks[WS_REQ_CB_COUNT];
    ev_tstamp network_timeout;
    char *headers_buf;
    int bufposition;
    int headerlen;
    struct ws_request_s *next;
    struct ws_request_s *prev;
} ws_request_t;

typedef struct ws_connection_s {
    struct ev_io watcher;
    struct ev_timer timeo;
    struct ev_loop *loop;
    struct sockaddr_in addr;
    ev_tstamp network_timeout;
    int _req_size;
    int max_header_size;
    struct ws_server_s *serv;
    ws_request_cb req_callbacks[WS_REQ_CB_COUNT];
    ws_connection_cb conn_callbacks[WS_CONN_CB_COUNT];
    struct ws_request_s *first_req;
    struct ws_request_s *last_req;
    size_t request_num;
    int close_on_finish;
} ws_connection_t;

typedef struct ws_server_s {
    struct ev_loop *loop;
    ev_tstamp network_timeout;
    int max_header_size;
    int _conn_size;
    int _req_size;
    struct ws_listener_s *listeners;
    size_t listeners_num;
    struct ws_connection_s *first_conn;
    struct ws_connection_s *last_conn;
    size_t connection_num;
    ws_request_cb req_callbacks[WS_REQ_CB_COUNT];
    ws_connection_cb conn_callbacks[WS_CONN_CB_COUNT];
} ws_server_t;

int ws_set_statuscode(ws_request_t *req, int code);
int ws_set_statusline(ws_request_t *req, const char *line);
int ws_add_header(ws_request_t *req, const char *name, const char *value);
int ws_reply_data(ws_request_t *req, const char *data, size_t data_size);

int ws_server_init(ws_server_t *serv, struct ev_loop *loop);
int ws_add_tcp(ws_server_t *serv, in_addr_t addr, int port);
int ws_add_unix(ws_server_t *serv, const char *filename);
int ws_add_fd(ws_server_t *serv, int fd);

void ws_quickstart(ws_server_t *serv, const char *hostname,
    int port, ws_request_cb cb);

#endif // WS_WEBSITE_H
