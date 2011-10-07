#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include <ev.h>
#include <website.h>

char *infopage;
int infopage_len;

int reply(ws_request_t *req) {
    printf("REPLY! ``%s''\n", req->uri);
    char buf[32];
    ws_statusline(req, "200 OK");
    ws_add_header(req, "Content-Type", "text/html");
    ws_finish_headers(req);
    ws_reply_data(req, infopage, infopage_len);
    return 0;
}

int websocket(ws_request_t *req) {
    printf("WEBSOCKET!\n");
    return 0;
}

void close_conn(struct ev_loop *loop, struct ev_idle *watch, int revents) {
    ws_connection_close((ws_connection_t *)watch->data);
    ev_idle_stop(loop, watch);
    free(watch);
}

int message(ws_connection_t *conn, ws_message_t *msg) {
    if(!strncmp(msg->data, "bye", 3)) {
        struct ev_idle *val = malloc(sizeof(struct ev_idle));
        ev_idle_init(val, close_conn);
        val->data = conn;
        ev_idle_start(conn->serv->loop, val);
        return 0;
    }
    ws_message_send(conn, msg);
    return 0;
}

void init_page() {
    int file = open("test/websock.html", O_RDONLY);
    struct stat info;
    fstat(file, &info);
    infopage_len = info.st_size;
    infopage = malloc(infopage_len);
    read(file, infopage, infopage_len);
    close(file);
}

int main(int argc, char **argv) {
    init_page();
    struct ev_loop *loop = ev_default_loop(0);
    ws_server_t server;
    ws_server_init(&server, loop);
    server.max_message_size = 16 << 20;
    ws_add_tcp(&server, inet_addr("127.0.0.1"), 8080);
    ws_REQUEST_CB(&server, reply);
    ws_WEBSOCKET_CB(&server, websocket);
    ws_MESSAGE_CB(&server, message);
    ws_server_start(&server);
	ev_loop (loop, 0);
	return 0;
}
