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
 * This module supports execution of TCF commands over HTTP connection.
 */

#include <tcf/config.h>

#if ENABLE_HttpServer

#include <assert.h>
#include <tcf/framework/json.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/events.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/streams.h>
#include <tcf/framework/protocol.h>
#include <tcf/http/http.h>
#include <tcf/http/http-tcf.h>

#define BUF_SIZE 0x1000

typedef struct ClientData {
    LINK link_all;
    Channel channel;
    unsigned lock_cnt;
    char * id;
    char * cmd_data;
    size_t cmd_size;
    ByteArrayOutputStream out_buf;
    OutputStream * http_out;
    OutputStream * sse_out;
    LINK link_messages;
    char * wait_token;
    int wait_done;
    int sse_posted;
    unsigned timeout;
} ClientData;

typedef struct Message {
    LINK link;
    char type[4];
    char token[64];
    char service[64];
    char command[64];
    char ** args_buf;
    unsigned arg_cnt;
    unsigned arg_max;
    int error;
} Message;

static unsigned token_cnt = 0;
static ChannelServer server = { NULL };
static LINK link_clients;

#define inp2channel(x)  ((Channel *)((char *)(x) - offsetof(Channel, inp)))
#define out2channel(x)  ((Channel *)((char *)(x) - offsetof(Channel, out)))

#define link2msg(x)  ((Message *)((char *)(x) - offsetof(Message, link)))

#define all2client(x) ((ClientData *)((char *)(x) - offsetof(ClientData, link_all)))
#define channel2client(x) ((ClientData *)((char *)(x) - offsetof(ClientData, channel)))

static void close_client(ClientData * client) {
    Channel * channel = &client->channel;
    list_remove(&client->link_all);
    channel->state = ChannelStateDisconnected;
    notify_channel_closed(channel);
    if (channel->disconnected) {
        channel->disconnected(channel);
    }
    else {
        trace(LOG_PROTOCOL, "channel %#" PRIxPTR " disconnected", (uintptr_t)channel);
        if (channel->protocol != NULL) protocol_release(channel->protocol);
    }
    channel->protocol = NULL;
    channel_unlock(channel);
}

static void free_message(Message * m) {
    unsigned i;
    for (i = 0; i < m->arg_cnt; i++) {
        loc_free(m->args_buf[i]);
    }
    loc_free(m->args_buf);
    loc_free(m);
}

static void http_message(OutputStream * out, Message * m) {
    write_string(out, "{\n");
    if (m->error != 0) {
        json_write_string(out, "Error");
        write_string(out, " : ");
        json_write_string(out, errno_to_str(m->error));
        write_string(out, ",\n");
    }
    if (m->token[0]) {
        json_write_string(out, "Token");
        write_string(out, " : ");
        json_write_string(out, m->token);
        write_string(out, ",\n");
    }
    if (m->service[0]) {
        json_write_string(out, "Service");
        write_string(out, " : ");
        json_write_string(out, m->service);
        write_string(out, ",\n");
    }
    if (m->command[0]) {
        if (strcmp(m->type, "E") == 0) {
            json_write_string(out, "Event");
        }
        else {
            json_write_string(out, "Command");
        }
        write_string(out, " : ");
        json_write_string(out, m->command);
        write_string(out, ",\n");
    }
    json_write_string(out, "Type");
    write_string(out, " : ");
    json_write_string(out, m->type);
    if (m->arg_cnt == 0) {
        write_stream(out, '\n');
    }
    else {
        unsigned i;
        write_string(out, ",\n");
        json_write_string(out, "Args");
        write_string(out, " : [\n");
        for (i = 0; i < m->arg_cnt; i++) {
            write_string(out, "  ");
            if (m->args_buf[i] == NULL) {
                write_string(out, "null");
            }
            else {
                write_string(out, m->args_buf[i]);
            }
            if (i < m->arg_cnt - 1) write_stream(out, ',');
            write_stream(out, '\n');
        }
        write_string(out, "]\n");
    }
    write_string(out, "}\n");
}

static void send_http_reply(ClientData * cd) {
    OutputStream * out = cd->http_out;
    write_string(out, "[\n");
    while (!list_is_empty(&cd->link_messages)) {
        Message * m = link2msg(cd->link_messages.next);
        list_remove(&m->link);
        http_message(out, m);
        if (!list_is_empty(&cd->link_messages)) write_stream(out, ',');
        write_stream(out, '\n');
        free_message(m);
    }
    write_string(out, "]\n");
}

static void read_stringz(InputStream * inp, char * str, size_t size) {
    unsigned len = 0;
    for (;;) {
        int ch = read_stream(inp);
        if (ch <= 0) {
            if (ch == 0) break;
            exception(ERR_PROTOCOL);
        }
        if (len < size - 1) str[len++] = (char)ch;
    }
    str[len] = 0;
}

static void read_args(InputStream * inp, Message * m) {
    for (;;) {
        char * arg = NULL;
        int ch = peek_stream(inp);
        if (ch == MARKER_EOS) break;
        if (ch != MARKER_EOA) {
            arg = json_read_object(inp);
            ch = peek_stream(inp);
        }
        if (ch != MARKER_EOA) exception(ERR_PROTOCOL);
        if (m->arg_cnt >= m->arg_max) {
            m->arg_max += 16;
            m->args_buf = (char **)loc_realloc(m->args_buf, m->arg_max * sizeof(char *));
        }
        m->args_buf[m->arg_cnt++] = arg;
        read_stream(inp);
    }
}

static void sse_event(void * arg) {
    ClientData * cd = (ClientData *)arg;
    cd->sse_posted = 0;
    if (cd->sse_out != NULL && !list_is_empty(&cd->link_messages)) {
        http_resume(cd->sse_out);
        http_printf("data: event\n");
        http_flush();
    }
}

static void http_channel_lock(Channel * channel) {
    ClientData * client = channel2client(channel);
    client->lock_cnt++;
}

static void http_channel_unlock(Channel * channel) {
    ClientData * client = channel2client(channel);
    assert(client->lock_cnt > 0);
    client->lock_cnt--;
    if (client->lock_cnt == 0) {
        ClientData * cd = channel2client(channel);
        channel_clear_broadcast_group(channel);
        while (!list_is_empty(&cd->link_messages)) {
            Message * e = link2msg(cd->link_messages.next);
            list_remove(&e->link);
            free_message(e);
        }
        loc_free(cd->out_buf.mem);
        loc_free(cd->cmd_data);
        loc_free(cd->id);
        loc_free(cd);
    }
}

static void http_channel_start_comm(Channel * channel) {
    notify_channel_created(channel);
    if (channel->connecting) {
        channel->connecting(channel);
    }
    else {
        send_hello_message(channel);
    }
}

static int http_channel_read(InputStream * inp) {
    if (inp->cur == NULL) return MARKER_EOS;
    if (inp->cur < inp->end) return *inp->cur++;
    inp->cur = inp->end = NULL;
    return MARKER_EOM;
}

static int http_channel_peek(InputStream * inp) {
    if (inp->cur == NULL) return MARKER_EOS;
    if (inp->cur < inp->end) return *inp->cur;
    return MARKER_EOM;
}

static void http_channel_write(OutputStream * out, int byte) {
    Channel * ch = out2channel(out);
    ClientData * cd = channel2client(ch);
    if (ch->state == ChannelStateDisconnected) return;
    if (byte == MARKER_EOM) {
        Trap trap;
        char * data = NULL;
        size_t size = 0;
        ByteArrayInputStream inp_buf;
        InputStream * inp = NULL;
        Message * m = (Message *)loc_alloc_zero(sizeof(Message));
        get_byte_array_output_stream_data(&cd->out_buf, &data, &size);
        inp = create_byte_array_input_stream(&inp_buf, data, size);
        if (set_trap(&trap)) {
            read_stringz(inp, m->type, sizeof(m->type));
            if (strcmp(m->type, "C") == 0) {
                read_stringz(inp, m->token, sizeof(m->token));
                read_stringz(inp, m->service, sizeof(m->service));
                read_stringz(inp, m->command, sizeof(m->command));
                read_args(inp, m);
            }
            else if (strcmp(m->type, "P") == 0) {
                read_stringz(inp, m->token, sizeof(m->token));
                read_args(inp, m);
            }
            else if (strcmp(m->type, "R") == 0) {
                read_stringz(inp, m->token, sizeof(m->token));
                read_args(inp, m);
            }
            else if (strcmp(m->type, "E") == 0) {
                read_stringz(inp, m->service, sizeof(m->service));
                read_stringz(inp, m->command, sizeof(m->command));
                read_args(inp, m);
            }
            else if (strcmp(m->type, "N") == 0) {
                read_stringz(inp, m->token, sizeof(m->token));
            }
            else {
                exception(ERR_PROTOCOL);
            }
            clear_trap(&trap);
        }
        m->error = trap.error;
        list_add_last(&m->link, &cd->link_messages);
        int reply = strcmp(m->type, "R") == 0 || strcmp(m->type, "N") == 0;
        if (reply && cd->wait_token != NULL && strcmp(cd->wait_token, m->token) == 0) {
            assert(cd->http_out != NULL);
            cd->wait_done = 1;
            if (cd->http_out != get_http_stream()) {
                http_resume(cd->http_out);
                send_http_reply(cd);
                cd->http_out = NULL;
                http_flush();
                loc_free(cd->wait_token);
                cd->wait_token = NULL;
                cd->wait_done = 0;
            }
        }
        loc_free(data);
        if (cd->sse_out != NULL && !list_is_empty(&cd->link_messages) && !cd->sse_posted) {
            post_event(sse_event, cd);
            cd->sse_posted = 1;
        }
    }
    else {
        write_stream(&cd->out_buf.out, byte);
    }
}

static void http_channel_write_block(OutputStream * out, const char * bytes, size_t size) {
    unsigned i;
    for (i = 0; i < size; i++) http_channel_write(out, (unsigned char)bytes[i]);
}

static ssize_t http_channel_splice_block(OutputStream * out, int fd, size_t size, int64_t * offset) {
    ssize_t rd;
    char buffer[BUF_SIZE];
    assert(is_dispatch_thread());
    if (size == 0) return 0;
    if (size > BUF_SIZE) size = BUF_SIZE;
    if (offset != NULL) {
        rd = pread(fd, buffer, size, (off_t)*offset);
        if (rd > 0) *offset += rd;
    }
    else {
        rd = read(fd, buffer, size);
    }
    if (rd > 0) http_channel_write_block(out, buffer, rd);
    return rd;
}

static void timer_event(void * arg) {
    LINK * l = link_clients.next;
    while (l != &link_clients) {
        ClientData * x = all2client(l);
        l = l->next;
        x->timeout++;
        if (x->timeout > 10) {
            close_client(x);
        }
    }
    if (list_is_empty(&link_clients)) return;
    post_event_with_delay(timer_event, NULL, 60000000);
}

static ClientData * find_client(void) {
    ClientData * cd = NULL;
    HttpParam * h = get_http_headers();
    const char * id = "";
    LINK * l = NULL;

    while (h != NULL) {
        if (strcmp(h->name, "X-Session-ID") == 0) {
            id = h->value;
            break;
        }
        h = h->next;
    }

    for (l = link_clients.next; l != &link_clients; l = l->next) {
        ClientData * x = all2client(l);
        if (strcmp(x->id, id) == 0) return x;
    }

    if (list_is_empty(&link_clients)) post_event_with_delay(timer_event, NULL, 60000000);

    cd = (ClientData *)loc_alloc_zero(sizeof(ClientData));
    cd->lock_cnt = 1;
    cd->channel.state = ChannelStateStartWait;
    cd->channel.lock = http_channel_lock;
    cd->channel.unlock = http_channel_unlock;
    cd->channel.start_comm = http_channel_start_comm;
    cd->channel.inp.peek = http_channel_peek;
    cd->channel.inp.read = http_channel_read;
    cd->channel.out.write = http_channel_write;
    cd->channel.out.write_block = http_channel_write_block;
    cd->channel.out.splice_block = http_channel_splice_block;
    create_byte_array_output_stream(&cd->out_buf);
    list_init(&cd->link_messages);
    cd->id = loc_strdup(id);
    list_add_first(&cd->link_all, &link_clients);
    if (cd->channel.state == ChannelStateStartWait) {
        server.new_conn(&server, &cd->channel);
    }
    return cd;
}

static unsigned decode_digit(char * s, unsigned * i) {
    unsigned d = 0;
    char ch = s[*i];

    if (ch >= '0' && ch <= '9') {
        d = ch - '0';
        (*i)++;
    }
    else if (ch >= 'A' && ch <= 'F') {
        d = ch - 'A' + 10;
        (*i)++;
    }
    else if (ch >= 'a' && ch <= 'f') {
        d = ch - 'a' + 10;
        (*i)++;
    }

    return d;
}

static void decode(char * s) {
    unsigned i = 0;
    unsigned j = 0;
    for (;;) {
        char ch = s[i++];
        if (ch == '%') {
            unsigned d1 = decode_digit(s, &i);
            unsigned d2 = decode_digit(s, &i);
            ch = (char)((d1 << 4) | d2);
        }
        s[j++] = ch;
        if (ch == 0) break;
    }
}

static int get_page(const char * uri) {
    int no_token = 0;
    const char * type = NULL;
    if (strncmp(uri, "/tcf/s/", 7) == 0) {
        type = "C"; no_token = 1;
    }
    else if (strncmp(uri, "/tcf/c/", 7) == 0) type = "C";
    else if (strncmp(uri, "/tcf/e/", 7) == 0) type = "E";
    if (type != NULL) {
        unsigned i = 7;
        unsigned j = i;
        char * token = NULL;
        char * service = NULL;
        char * command = NULL;
        char * query = NULL;
        char ** attribute = NULL;
        unsigned attribute_cnt = 0;
        unsigned attribute_max = 0;
        char sep = '/';
        for (;;) {
            char ch = uri[j];
            switch (ch) {
            case 0:
            case '/':
            case '?':
            case '&':
                if ((sep == '?' || sep == '&') && (ch == '?' || ch == '/')) {
                    /* '?' and '/' may appear unencoded as data within the query */
                    break;
                }
                else {
                    char * s = (char *)tmp_alloc_zero(j - i + 1);
                    memcpy(s, uri + i, j - i);
                    decode(s);
                    if (sep == '/') {
                        if (type[0] == 'C' && token == NULL && !no_token) token = s;
                        else if (service == NULL) service = s;
                        else if (command == NULL) command = s;
                        else return 0;
                    }
                    else if (sep == '?') {
                        if (query == NULL) query = s;
                        else return 0;
                    }
                    else if (sep == '&') {
                        if (attribute_cnt >= attribute_max) {
                            attribute_max += 8;
                            attribute = (char **)tmp_realloc(attribute, attribute_max * sizeof(char *));
                        }
                        attribute[attribute_cnt++] = s;
                    }
                }
                i = j + 1;
                sep = ch;
                break;
            }
            if (sep == 0) break;
            j++;
        }
        if (service != NULL && command != NULL) {
            Trap trap;
            ClientData * cd = find_client();
            Channel * ch = &cd->channel;
            ch->inp.cur = NULL;
            ch->inp.end = NULL;
            loc_free(cd->cmd_data);
            cd->cmd_data = NULL;
            cd->cmd_size = 0;
            cd->wait_done = 0;
            cd->timeout = 0;
            cd->http_out = get_http_stream();
            http_content_type("application/json");
            if (set_trap(&trap)) {
                ByteArrayOutputStream buf;
                OutputStream * out = create_byte_array_output_stream(&buf);
                if (is_channel_closed(ch)) exception(ERR_CHANNEL_CLOSED);
                if (ch->state != ChannelStateConnected) {
                    ch->state = ChannelStateConnected;
                    notify_channel_opened(ch);
                    if (ch->connected) ch->connected(ch);
                }
                assert(cd->wait_token == NULL);
                write_stringz(out, type);
                if (type[0] == 'C') {
                    if (token != NULL) {
                        write_stringz(out, token);
                    }
                    else {
                        cd->wait_token = loc_printf("%04X", token_cnt++ & 0xffff);
                        write_stringz(out, cd->wait_token);
                    }
                }
                write_stringz(out, service);
                write_stringz(out, command);
                if (query != NULL) {
                    write_stringz(out, query);
                    for (i = 0; i < attribute_cnt; i++) write_stringz(out, attribute[i]);
                }
                get_byte_array_output_stream_data(&buf, &cd->cmd_data, &cd->cmd_size);
                ch->inp.cur = (unsigned char *)cd->cmd_data;
                ch->inp.end = ch->inp.cur + cd->cmd_size;
                handle_protocol_message(ch);
                if (cd->wait_token != NULL && !cd->wait_done) {
                    assert(cd->http_out != NULL);
                    http_suspend();
                }
                else {
                    send_http_reply(cd);
                    loc_free(cd->wait_token);
                    cd->wait_token = NULL;
                    cd->wait_done = 0;
                    cd->http_out = NULL;
                }
                clear_trap(&trap);
            }
            else {
                OutputStream * out = cd->http_out;
                write_string(out, "[\n");
                write_string(out, "{\n");
                json_write_string(out, "Error");
                write_string(out, " : ");
                json_write_string(out, errno_to_str(trap.error));
                write_string(out, "\n");
                write_string(out, "}\n");
                write_string(out, "]\n");
                loc_free(cd->wait_token);
                cd->wait_token = NULL;
                cd->wait_done = 0;
                cd->http_out = NULL;
            }
            return 1;
        }
    }
    else if (strcmp(uri, "/tcf/sse") == 0) {
        ClientData * cd = find_client();
        cd->sse_out = get_http_stream();
        http_content_type("text/event-stream");
        return 1;
    }
    return 0;
}

void http_connection_closed(OutputStream * out) {
    LINK * l;
    for (l = link_clients.next; l != &link_clients; l = l->next) {
        ClientData * cd = all2client(l);
        if (cd->http_out == out) {
            cd->http_out = NULL;
            if (cd->wait_token != NULL) {
                loc_free(cd->wait_token);
                cd->wait_token = NULL;
                cd->wait_done = 0;
            }
        }
        if (cd->sse_out == out) {
            cd->sse_out = NULL;
        }
    }
}

ChannelServer * ini_http_tcf(PeerServer * ps) {
    static HttpListener l = { get_page };
    assert(list_is_empty(&server.servlink));
    add_http_listener(&l);
    server.ps = ps;
    list_init(&link_clients);
    list_add_last(&server.servlink, &channel_server_root);
    return &server;
}

#endif
