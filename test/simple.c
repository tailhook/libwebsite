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

char testdata[] = "<!DOCTYPE html>\n"
    "<html>\n"
    "  <head><title>Hello from sample</title></head>\n"
    "  <body>\n"
    "    <h1>Hello from sample</h1>\n"
    "  </body>\n"
    "</html>\n";

int reply(ws_request_t *req) {
    ws_statusline(req, "200 OK");
    ws_reply_data(req, testdata, sizeof(testdata)-1);
    return WS_REPLY_FINISHED;
}


int main(int argc, char **argv) {
    ws_server_t serv;
    ws_quickstart(&serv, "127.0.0.1", 8080, reply);
	ev_loop (ev_default_loop(0), 0);
	return 0;
}
