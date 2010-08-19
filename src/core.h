#ifndef WS_H_CORE
#define WS_H_CORE

#include <ev.h>
#include <website.h>

typedef struct ws_listener_s {
    ev_io watcher;
    struct ws_listener_s *next;
    ws_server_t *serv;
} ws_listener_t;

#endif // WS_H_CORE
