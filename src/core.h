#ifndef WS_H_CORE
#define WS_H_CORE

#include <ev.h>
#include <website.h>

typedef enum {
    WS_R_NEW,
    WS_R_RECVHEADERS,
    WS_R_RECVBODY,
    WS_R_EMPTY,
    WS_R_STATUS, // has buffer on top of obstack
    WS_R_HEADERS,
    WS_R_BODY,
    WS_R_DONE,
    WS_R_SENDING,
    WS_R_SENT, // no more buffer on top of obstack
    WS_R_WEBSOCK = 100,
} ws_reply_state;

typedef struct ws_listener_s {
    ev_io watch;
    struct ws_listener_s *next;
    ws_server_t *serv;
} ws_listener_t;

#endif // WS_H_CORE
