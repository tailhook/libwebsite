#ifndef WS_H_CORE
#define WS_H_CORE

#include <ev.h>
#include <website.h>

typedef enum {
    WS_R_UNDEFINED,
    WS_R_EMPTY,
    WS_R_STATUS, // has buffer on top of obstack
    WS_R_HEADERS,
    WS_R_BODY,
    WS_R_SENDING,
    WS_R_SENT, // no more buffer on top of obstack
} ws_reply_state;

typedef struct ws_listener_s {
    ev_io watcher;
    struct ws_listener_s *next;
    ws_server_t *serv;
} ws_listener_t;

#endif // WS_H_CORE
