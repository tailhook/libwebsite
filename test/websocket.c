#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ev.h>
#include <website.h>

char infopage[] = "<!DOCTYPE html>\n"
    "<html>\n"
    "    <head>\n"
    "        <title>Web socket test</title>\n"
    "    </head>\n"
    "    <body>\n"
    "        <h1>Web socket test</h1>\n"
    "    </body>\n"
    "</html>\n";

int reply(ws_request_t *req) {
    char buf[32];
    ws_statusline(req, "200 OK");
    ws_add_header(req, "Content-Type", "text/html");
    ws_finish_headers(req);
    ws_reply_data(req, infopage, sizeof(infopage)-1);
    return 0;
}

int websocket(ws_request_t *req) {

}

int message(const char *message, int len) {
}

int main(int argc, char **argv) {
    struct ev_loop *loop = ev_default_loop(0);
    ws_server_t server;
    ws_server_init(&server, loop);
    ws_add_tcp(&server, inet_addr("127.0.0.1"), 8080);
    ws_REQUEST_CB(&server, reply);
    ws_WEBSOCKET_CB(&server, websocket);
    ws_MESSAGE_CB(&server, message);
    ws_server_start(&server);
	ev_loop (loop, 0);
	return 0;
}
