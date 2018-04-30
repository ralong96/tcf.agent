/*******************************************************************************
 * Copyright (c) 2018 Xilinx, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Xilinx - initial API and implementation
 *******************************************************************************/

/*
 * Implementation of HTTP interface.
 */

#include <tcf/config.h>

#if ENABLE_HttpServer

#include <time.h>
#include <stdarg.h>
#include <assert.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/events.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/streams.h>
#include <tcf/framework/mdep-inet.h>
#include <tcf/framework/asyncreq.h>
#include <tcf/framework/link.h>
#include <tcf/http/http.h>

typedef struct HttpServer {
    LINK link_all;
    LINK link_clients;
    AsyncReqInfo req_acc;
    struct sockaddr * addr_buf;
    int addr_len;
    int sock;
} HttpServer;

typedef struct HttpClient {
    LINK link_all;
    HttpServer * server;
    int sock;
    int addr_len;
    struct sockaddr * addr_buf;
    AsyncReqInfo req_rd;
    AsyncReqInfo req_wr;
    char * recv_buf;
    size_t recv_pos;
    size_t recv_max;
    char * http_method;
    char * http_uri;
    char * http_ver;
    HttpParam * http_args;
    HttpParam * http_hdrs;
    int read_request_done;
    int keep_alive;
    ByteArrayOutputStream out;
    char * hdrs_data;
    size_t hdrs_size;
    size_t hdrs_done;
    char * send_data;
    size_t send_size;
    size_t send_done;
    int page_code;
    int page_cache;
    const char * page_type;
} HttpClient;

static LINK server_list;
static HttpListener ** listener_arr = NULL;
static unsigned listener_cnt = 0;
static unsigned listener_max = 0;
static OutputStream * out = NULL;

#define out2client(x)  ((HttpClient *)((char *)(x) - offsetof(HttpClient, out.out)))

static void clear_client(HttpClient * client) {
    loc_free(client->hdrs_data);
    loc_free(client->send_data);
    loc_free(client->http_method);
    loc_free(client->http_uri);
    loc_free(client->http_ver);
    while (client->http_args != NULL) {
        HttpParam * h = client->http_args;
        client->http_args = h->next;
        loc_free(h->name);
        loc_free(h->value);
        loc_free(h);
    }
    while (client->http_hdrs != NULL) {
        HttpParam * h = client->http_hdrs;
        client->http_hdrs = h->next;
        loc_free(h->name);
        loc_free(h->value);
        loc_free(h);
    }
    memset(&client->req_wr, 0, sizeof(client->req_wr));
    client->recv_pos = 0;
    client->http_method = NULL;
    client->http_uri = NULL;
    client->http_ver = NULL;
    client->read_request_done = 0;
    client->keep_alive = 0;
    client->hdrs_data = NULL;
    client->hdrs_size = 0;
    client->hdrs_done = 0;
    client->send_data = NULL;
    client->send_size = 0;
    client->send_done = 0;
    client->page_code = 0;
    client->page_cache = 0;
    client->page_type = 0;
}

static void close_client(HttpClient * client) {
    clear_client(client);
    closesocket(client->sock);
    list_remove(&client->link_all);
    loc_free(client->recv_buf);
    loc_free(client->addr_buf);
    loc_free(client);
}

OutputStream * get_http_stream(void) {
    return out;
}

HttpParam * get_http_params(void) {
    HttpClient * client = out2client(out);
    return client->http_args;
}

HttpParam * get_http_headers(void) {
    HttpClient * client = out2client(out);
    return client->http_hdrs;
}

void http_send(char ch) {
    write_stream(out, (unsigned char)ch);
}

void http_send_block(const char * buf, size_t size) {
    write_block_stream(out, buf, size);
}

void http_printf(const char * fmt, ...) {
    va_list ap;
    char arr[0x100];
    void * mem = NULL;
    char * buf = arr;
    size_t len = sizeof(arr);
    int n = 0;

    while (1) {
        va_start(ap, fmt);
        n = vsnprintf(buf, len, fmt, ap);
        va_end(ap);
        if (n < 0) {
            if (len > 0x100000) break;
            len *= 2;
        }
        else {
            if (n < (int)len) break;
            len = n + 1;
        }
        mem = loc_realloc(mem, len);
        buf = (char *)mem;
    }
    write_block_stream(out, buf, n);
    if (mem != NULL) loc_free(mem);
}

static void http_send_done(void * x) {
    AsyncReqInfo * req = (AsyncReqInfo *)x;
    HttpClient * client = (HttpClient *)req->client_data;
    ssize_t len = client->req_wr.u.sio.rval;

    assert(is_dispatch_thread());

    if (len < 0) {
        trace(LOG_ALWAYS,  "Socket write error: %s", errno_to_str(req->error));
    }
    else {
        if (client->hdrs_done < client->hdrs_size) {
            assert(client->req_wr.u.sio.bufp == client->hdrs_data + client->hdrs_done);
            assert(client->req_wr.u.sio.bufsz == client->hdrs_size - client->hdrs_done);
            client->hdrs_done += len;
            if (client->hdrs_done < client->hdrs_size) {
                client->req_wr.u.sio.bufp = client->hdrs_data + client->hdrs_done;
                client->req_wr.u.sio.bufsz = client->hdrs_size - client->hdrs_done;
                async_req_post(&client->req_wr);
                return;
            }
        }
        else {
            assert(client->req_wr.u.sio.bufp == client->send_data + client->send_done);
            assert(client->req_wr.u.sio.bufsz == client->send_size - client->send_done);
            client->send_done += len;
        }
        if (client->send_done < client->send_size) {
            client->req_wr.u.sio.bufp = client->send_data + client->send_done;
            client->req_wr.u.sio.bufsz = client->send_size - client->send_done;
            async_req_post(&client->req_wr);
            return;
        }
        if (client->keep_alive) {
            clear_client(client);
            client->req_rd.u.sio.bufp = client->recv_buf;
            client->req_rd.u.sio.bufsz = client->recv_max;
            async_req_post(&client->req_rd);
            return;
        }
    }
    close_client(client);
}

static void send_reply(HttpClient * client) {
    const char * reason = "OK";
    unsigned i;

    out = create_byte_array_output_stream(&client->out);
    for (i = 0; i < listener_cnt; i++) {
        if (listener_arr[i]->get_page(client->http_uri)) break;
    }
    if (client->out.pos == 0) {
        reason = "NOT FOUND";
        client->page_code = 404;
        http_printf("Not found: %s\n", client->http_uri);
    }
    get_byte_array_output_stream_data(&client->out, &client->send_data, &client->send_size);

    out = create_byte_array_output_stream(&client->out);
    if (client->page_code == 0) client->page_code = 200;
    if (client->page_type == NULL) client->page_type = "text/html";
    http_printf("HTTP/1.1 %d %s\n", client->page_code, reason);
    http_printf("Content-Type: %s\n", client->page_type);
    if (client->page_cache) {
        http_printf("Cache-Control: private, max-age=300\n");
    }
    else {
        http_printf("Cache-Control: no-cache\n");
    }
    if (client->keep_alive) {
        http_printf("Connection: keep-alive\n");
    }
    http_printf("Content-Length: %u\n", (unsigned)client->send_size);
    http_send('\n');
    get_byte_array_output_stream_data(&client->out, &client->hdrs_data, &client->hdrs_size);
    out = NULL;

    client->req_wr.done = http_send_done;
    client->req_wr.client_data = client;
    client->req_wr.type = AsyncReqSend;
    client->req_wr.u.sio.sock = client->sock;
    client->req_wr.u.sio.bufp = client->hdrs_data;
    client->req_wr.u.sio.bufsz = client->hdrs_size;
    client->req_wr.u.sio.flags = 0;
    async_req_post(&client->req_wr);
}

static void read_http_request(HttpClient * client) {
    while (client->recv_pos > 0 && !client->read_request_done) {
        unsigned i = 0;
        while (client->recv_buf[i++] != '\n') {
            if (i >= client->recv_pos) return;
        }
        if (i > 0) {
            if (client->http_method == NULL) {
                unsigned j = 0;
                unsigned k = 0;
                while (j < i) {
                    char * s = client->recv_buf + j;
                    while (j < i && client->recv_buf[j] > ' ') j++;
                    while (j < i && client->recv_buf[j] <= ' ') client->recv_buf[j++] = 0;
                    switch (k++) {
                    case 0: client->http_method = loc_strdup(s); break;
                    case 1: client->http_uri = loc_strdup(s); break;
                    case 2: client->http_ver = loc_strdup(s); break;
                    }
                }
            }
            else {
                unsigned j = 0;
                unsigned k = i;
                while (k > 0 && client->recv_buf[k - 1] <= ' ') client->recv_buf[--k] = 0;
                if (k == 0) {
                    client->read_request_done = 1;
                }
                else {
                    while (j < k && client->recv_buf[j] != ':') j++;
                    if (j < k) {
                        HttpParam * h = (HttpParam *)loc_alloc_zero(sizeof(HttpParam));
                        client->recv_buf[j++] = 0;
                        while (j < k && client->recv_buf[j] == ' ') client->recv_buf[j++] = 0;
                        h->name = loc_strdup(client->recv_buf);
                        h->value = loc_strdup(client->recv_buf + j);
                        h->next = client->http_hdrs;
                        if (strcmp(h->name, "Connection") == 0 && strcmp(h->value, "keep-alive") == 0) {
                            client->keep_alive = 1;
                        }
                        client->http_hdrs = h;
                    }
                }
            }
        }
        memmove(client->recv_buf, client->recv_buf + i, client->recv_pos - i);
        client->recv_pos -= i;
    }
}

static void http_read_done(void * x) {
    AsyncReqInfo * req = (AsyncReqInfo *)x;
    HttpClient * client = (HttpClient *)req->client_data;
    ssize_t len = 0;

    assert(is_dispatch_thread());
    assert(client->req_rd.u.sio.bufp == client->recv_buf + client->recv_pos);
    assert(client->req_rd.u.sio.bufsz == client->recv_max - client->recv_pos);
    len = client->req_rd.u.sio.rval;

    if (len < 0) {
        close_client(client);
    }
    else if (len > 0) {
        client->recv_pos += len;
        assert(client->recv_pos <= client->recv_max);
        read_http_request(client);
        if (client->read_request_done) {
            send_reply(client);
        }
        else {
            if (client->recv_pos >= client->recv_max) {
                client->recv_max *= 2;
                client->recv_buf = (char *)loc_realloc(client->recv_buf, client->recv_max);
            }
            req->u.sio.bufp = client->recv_buf + client->recv_pos;
            req->u.sio.bufsz = client->recv_max - client->recv_pos;
            async_req_post(req);
        }
    }
}

static void http_server_accept_done(void * x) {
    AsyncReqInfo * req = (AsyncReqInfo *)x;
    HttpServer * server = (HttpServer *)req->client_data;

    if (server->sock < 0) {
        /* Server closed. */
        assert(list_is_empty(&server->link_all));
        assert(list_is_empty(&server->link_clients));
        loc_free(server->addr_buf);
        loc_free(server);
        return;
    }
    if (req->error) {
        trace(LOG_ALWAYS, "HTTP Socket accept failed: %s", errno_to_str(req->error));
    }
    else {
        HttpClient * client = (HttpClient *)loc_alloc_zero(sizeof(HttpClient));
        list_add_first(&client->link_all, &server->link_clients);
        client->server = server;
        client->sock = req->u.acc.rval;
        client->addr_buf = loc_alloc(server->addr_len);
        memcpy(client->addr_buf, server->addr_buf, server->addr_len);
        client->addr_len = server->addr_len;
        client->recv_max = 0x300;
        client->recv_buf = (char *)loc_alloc(client->recv_max);
        client->req_rd.done = http_read_done;
        client->req_rd.client_data = client;
        client->req_rd.type = AsyncReqRecv;
        client->req_rd.u.sio.sock = client->sock;
        client->req_rd.u.sio.bufp = client->recv_buf;
        client->req_rd.u.sio.bufsz = client->recv_max;
        client->req_rd.u.sio.flags = 0;
        async_req_post(&client->req_rd);
    }
    server->req_acc.u.acc.addrlen = server->addr_len;
    async_req_post(req);
}

int start_http_server(const char * host, const char * port) {
    struct addrinfo hints;
    struct addrinfo * reslist = NULL;
    struct addrinfo * res;
    const char * reason = NULL;
    HttpServer * server = NULL;
    int error = 0;
    int sock = -1;

    assert(is_dispatch_thread());
    if (port == NULL) port = "80";

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    error = loc_getaddrinfo(host, port, &hints, &reslist);
    if (error) {
        trace(LOG_ALWAYS, "getaddrinfo error: %s", loc_gai_strerror(error));
        set_gai_errno(error);
        return -1;
    }

    for (res = reslist; res != NULL; res = res->ai_next) {
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) {
            error = errno;
            reason = "create";
            continue;
        }
#if !(defined(_WIN32) || defined(__CYGWIN__))
        {
            const int i = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&i, sizeof(i)) < 0) {
                error = errno;
                reason = "setsockopt";
                closesocket(sock);
                sock = -1;
                continue;
            }
        }
#endif
        if (bind(sock, res->ai_addr, res->ai_addrlen)) {
            error = errno;
            reason = "bind";
            closesocket(sock);
            sock = -1;
            continue;
        }
        if (listen(sock, 16)) {
            error = errno;
            reason = "listen on";
            closesocket(sock);
            sock = -1;
            continue;
        }

        /* Only create one server at a time */
        break;
    }
    loc_freeaddrinfo(reslist);
    if (sock < 0) {
        trace(LOG_ALWAYS, "Socket %s error: %s", reason, errno_to_str(error));
        set_fmt_errno(error, "Socket %s error", reason);
        return -1;
    }

    server = (HttpServer *)loc_alloc_zero(sizeof(HttpServer));
    list_add_first(&server->link_all, &server_list);
    list_init(&server->link_clients);
    server->sock = sock;
#if defined(_WRS_KERNEL)
    /* vxWorks requires buffer size to be exactly sizeof(struct sockaddr) */
    server->addr_len = sizeof(struct sockaddr);
#elif defined(SOCK_MAXADDRLEN)
    server->addr_len = SOCK_MAXADDRLEN;
#else
    server->addr_len = 0x1000;
#endif
    server->addr_buf = (struct sockaddr *)loc_alloc_zero(server->addr_len);
    server->req_acc.done = http_server_accept_done;
    server->req_acc.client_data = server;
    server->req_acc.type = AsyncReqAccept;
    server->req_acc.u.acc.sock = sock;
    server->req_acc.u.acc.addr = server->addr_buf;
    server->req_acc.u.acc.addrlen = server->addr_len;
    async_req_post(&server->req_acc);

    return 0;
}

void add_http_listener(HttpListener * l) {
    if (listener_cnt >= listener_max) {
        listener_max += 8;
        listener_arr = (HttpListener **)loc_realloc(listener_arr, listener_max * sizeof(HttpListener *));
    }
    listener_arr[listener_cnt++] = l;
}

void ini_http(void) {
    list_init(&server_list);
}

#endif
