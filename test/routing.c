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

#define TRUE 1
#define FALSE 0

char firstpage[] = "<!DOCTYPE html>\n"
    "<html>\n"
    "  <head><title>First Page</title></head>\n"
    "  <body>\n"
    "    <h1>First Page Title</h1>\n"
    "  </body>\n"
    "</html>\n";
char secondpage[] = "<!DOCTYPE html>\n"
    "<html>\n"
    "  <head><title>Second Page</title></head>\n"
    "  <body>\n"
    "    <h1>Second Page Title</h1>\n"
    "  </body>\n"
    "</html>\n";
char thirdpage[] = "<!DOCTYPE html>\n"
    "<html>\n"
    "  <head><title>Third Page</title></head>\n"
    "  <body>\n"
    "    <h1>Third Page Title</h1>\n"
    "  </body>\n"
    "</html>\n";
char error[] = "<!DOCTYPE html>\n"
    "<html>\n"
    "  <head><title>404 Not Found</title></head>\n"
    "  <body>\n"
    "    <h1>404 Page Not Found</h1>\n"
    "  </body>\n"
    "</html>\n";

void *routes;

int reply(ws_request_t *req) {
    ws_statusline(req, "200 OK");
    char *data;
    if(ws_fuzzy(routes, req->uri, (size_t *)&data)) {
        ws_reply_data(req, data, strlen(data));
    } else {
        ws_reply_data(req, error, sizeof(error)-1);
    }
    return WS_REPLY_FINISHED;
}


int main(int argc, char **argv) {

    routes = ws_fuzzy_new();
    ws_fuzzy_add(routes, "/1", FALSE, (size_t)firstpage);
    ws_fuzzy_add(routes, "/first", TRUE, (size_t)firstpage);
    ws_fuzzy_add(routes, "/second", FALSE, (size_t)secondpage);
    ws_fuzzy_add(routes, "/second/", FALSE, (size_t)secondpage);
    ws_fuzzy_add(routes, "/second/", TRUE, (size_t)thirdpage);
    ws_fuzzy_compile(routes);

    ws_server_t serv;
    ws_quickstart(&serv, "127.0.0.1", 8080, reply);
	ev_loop (ev_default_loop(0), 0);
	return 0;
}
