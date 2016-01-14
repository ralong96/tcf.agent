/*******************************************************************************
 * Copyright (c) 2016 Xilinx, Inc. and others.
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


#include <tcf/config.h>

#if ENABLE_DebugContext

#include <assert.h>

#include <tcf/framework/errors.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/mdep-inet.h>
#include <tcf/framework/asyncreq.h>
#include <tcf/framework/context.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/link.h>
#include <tcf/services/runctrl.h>

#include <tcf/main/gdb-rsp.h>

#ifndef DEBUG_RSP
#  define DEBUG_RSP 0
#endif

typedef struct GdbServer {
    LINK link_a2s;
    LINK link_s2c;
    int disposed;
    AsyncReqInfo req;
    char isa[32];
} GdbServer;

typedef struct GdbClient {
    LINK link_s2c;
    LINK link_c2t;
    size_t buf_max;
    uint8_t * buf;
    AsyncReqInfo req;
    GdbServer * server;

    /* Command packet */
    char * cmd_buf;
    unsigned cmd_pos;
    unsigned cmd_max;
    unsigned cmd_end;
    int cmd_esc;

    /* Response packet */
    char * res_buf;
    unsigned res_pos;
    unsigned res_max;

    unsigned thread_cnt;
    unsigned cur_c_thread;
    unsigned cur_g_thread;
    int non_stop;
    int extended;
} GdbClient;

typedef struct GdbThread {
    LINK link_c2t;
    LINK link_ctx2t;
    GdbClient * client;
    unsigned id;
    Context * ctx;
} GdbThread;

#define link_a2s(x) ((GdbServer *)((char *)(x) - offsetof(GdbServer, link_a2s)))
#define link_s2c(x) ((GdbClient *)((char *)(x) - offsetof(GdbClient, link_s2c)))
#define link_c2t(x) ((GdbThread *)((char *)(x) - offsetof(GdbThread, link_c2t)))
#define link_ctx2t(x) ((GdbThread *)((char *)(x) - offsetof(GdbThread, link_ctx2t)))

#define EXT(ctx) ((LINK *)((char *)(ctx) + context_extension_offset))

#define ALL_THREADS (~0u)

static size_t context_extension_offset = 0;
static int ini_done = 0;
static LINK link_a2s;

static const char * regs_i386 =
    " <reg name='eax' bitsize='32' type='int32'/>\n"
    " <reg name='ecx' bitsize='32' type='int32'/>\n"
    " <reg name='edx' bitsize='32' type='int32'/>\n"
    " <reg name='ebx' bitsize='32' type='int32'/>\n"
    " <reg name='esp' bitsize='32' type='data_ptr'/>\n"
    " <reg name='ebp' bitsize='32' type='data_ptr'/>\n"
    " <reg name='esi' bitsize='32' type='int32'/>\n"
    " <reg name='edi' bitsize='32' type='int32'/>\n"
    " <reg name='eip' bitsize='32' type='code_ptr'/>\n"
    " <reg name='eflags' bitsize='32' type='i386_eflags'/>\n"
    " <reg name='cs'  bitsize='32' type='int32'/>\n"
    " <reg name='ss'  bitsize='32' type='int32'/>\n"
    " <reg name='ds'  bitsize='32' type='int32'/>\n"
    " <reg name='es'  bitsize='32' type='int32'/>\n"
    " <reg name='fs'  bitsize='32' type='int32'/>\n"
    " <reg name='gs'  bitsize='32' type='int32'/>\n"
    " <reg name='st0' bitsize='80' type='i387_ext'/>\n"
    " <reg name='st1' bitsize='80' type='i387_ext'/>\n"
    " <reg name='st2' bitsize='80' type='i387_ext'/>\n"
    " <reg name='st3' bitsize='80' type='i387_ext'/>\n"
    " <reg name='st4' bitsize='80' type='i387_ext'/>\n"
    " <reg name='st5' bitsize='80' type='i387_ext'/>\n"
    " <reg name='st6' bitsize='80' type='i387_ext'/>\n"
    " <reg name='st7' bitsize='80' type='i387_ext'/>\n"
    " <reg name='fctrl' bitsize='32' type='int' group='float'/>\n"
    " <reg name='fstat' bitsize='32' type='int' group='float'/>\n"
    " <reg name='ftag' bitsize='32' type='int' group='float'/>\n"
    " <reg name='fiseg' bitsize='32' type='int' group='float'/>\n"
    " <reg name='fioff' bitsize='32' type='int' group='float'/>\n"
    " <reg name='foseg' bitsize='32' type='int' group='float'/>\n"
    " <reg name='fooff' bitsize='32' type='int' group='float'/>\n"
    " <reg name='fop' bitsize='32' type='int' group='float'/>\n";

static void add_thread(GdbClient * c, Context * ctx) {
    GdbThread * t = (GdbThread *)loc_alloc_zero(sizeof(GdbThread));
    LINK * l = EXT(ctx);
    t->client = c;
    t->id = c->thread_cnt++;
    t->ctx = ctx;
    if (l->next == NULL) list_init(l);
    list_add_last(&t->link_ctx2t, l);
    list_add_last(&t->link_c2t, &c->link_c2t);
}

static GdbThread * find_thread(GdbClient * c, unsigned id) {
    LINK * l;
    for (l = c->link_c2t.next; l != &c->link_c2t; l = l->next) {
        GdbThread * t = link_c2t(l);
        if (id == 0 || t->id == id) return t;
    }
    return NULL;
}

static void free_thread(GdbThread * t) {
    list_remove(&t->link_ctx2t);
    list_remove(&t->link_c2t);
    loc_free(t);
}

static int open_server(const char * port) {
    int err = 0;
    int sock = -1;
    struct addrinfo hints;
    struct addrinfo * reslist = NULL;
    struct addrinfo * res = NULL;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    err = loc_getaddrinfo(NULL, port, &hints, &reslist);
    if (err) {
        set_gai_errno(err);
        return -1;
    }

    for (res = reslist; res != NULL; res = res->ai_next) {
        const int i = 1;
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) continue;

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&i, sizeof(i)) < 0) err = errno;
        if (!err && bind(sock, res->ai_addr, res->ai_addrlen)) err = errno;
        if (!err && listen(sock, 4)) err = errno;
        if (!err) break;

        closesocket(sock);
        sock = -1;
    }

    freeaddrinfo(reslist);
    return sock;
}

static void dispose_server(GdbServer * s) {
    list_remove(&s->link_a2s);
    closesocket(s->req.u.acc.sock);
    s->req.u.acc.sock = -1;
    s->disposed = 1;
    if (list_is_empty(&s->link_s2c)) {
        loc_free(s);
    }
}

static int start_client(GdbClient * c) {
    LINK * l;
    c->thread_cnt = 1;
    for (l = context_root.next; l != &context_root; l = l->next) {
        Context * ctx = ctxl2ctxp(l);
        if (context_has_state(ctx)) {
            add_thread(c, ctx);
        }
    }
    c->req.u.sio.rval = 0;
    async_req_post(&c->req);
    return 0;
}

static void dispose_client(GdbClient * c) {
    GdbServer * s = c->server;

    while (!list_is_empty(&c->link_c2t)) {
        free_thread(link_c2t(c->link_c2t.next));
    }

    closesocket(c->req.u.sio.sock);
    list_remove(&c->link_s2c);
    loc_free(c->cmd_buf);
    loc_free(c->buf);
    loc_free(c);

    if (s->disposed && list_is_empty(&s->link_s2c)) {
        loc_free(s);
    }
}

static void add_res_ch_no_esc(GdbClient * c, char ch) {
    if (c->res_pos >= c->res_max) {
        c->res_max = c->res_max == 0 ? 0x1000 : c->res_max * 2;
        c->res_buf = (char *)loc_realloc(c->res_buf, c->res_max);
    }
    c->res_buf[c->res_pos++] = ch;
}

static void add_res_ch(GdbClient * c, char ch) {
    switch (ch) {
    case '}':
    case '$':
    case '#':
        add_res_ch_no_esc(c, '}');
        ch ^= 0x20;
        break;
    }
    add_res_ch_no_esc(c, ch);
}

static void add_res_str(GdbClient * c, const char * s) {
    while (*s != 0) add_res_ch(c, *s++);
}

static void add_res_hex_digit(GdbClient * c, unsigned d) {
    assert(d < 0x10);
    if (d < 10) add_res_ch(c, (char)('0' + d));
    else add_res_ch(c, (char)('A' + d - 10));
}

static void add_res_hex(GdbClient * c, uint32_t n) {
    char s[9];
    unsigned i = sizeof(s);
    s[--i] = 0;
    do {
        unsigned d = n & 0xf;
        add_res_hex_digit(c, d);
        n = n >> 4;
    }
    while (n != 0 && i > 0);
    add_res_str(c, s + i);
}

#if 0 /* Not used */
static void add_res_bin(GdbClient * c, const char * s) {
    while (*s != 0) {
        char ch = *s++;
        add_res_hex_digit(c, (ch >> 4) & 0xf);
        add_res_hex_digit(c, ch & 0xf);
    }
}
#endif

static void add_res_checksum(GdbClient * c) {
    unsigned i;
    unsigned char sum = 0;
    assert(c->res_pos > 0);
    assert(c->res_buf[0] == '$');
    for (i = 1; i < c->res_pos; i++) {
        sum += (unsigned char)c->res_buf[i];
    }
    add_res_ch_no_esc(c, '#');
    add_res_hex_digit(c, (sum >> 4) & 0xf);
    add_res_hex_digit(c, sum & 0xf);
}

static char * get_cmd_word(GdbClient * c, char ** p) {
    char * s = *p;
    char * e = s;
    char * w = NULL;
    while (e < c->cmd_buf + c->cmd_end) {
        if (*e == ':') break;
        if (*e == ';') break;
        e++;
    }
    w = (char *)tmp_alloc_zero(e - s + 1);
    memcpy(w, s, e - s);
    *p = e;
    return w;
}

static const char * get_regs(GdbClient * c) {
    if (strcmp(c->server->isa, "i386") == 0) return regs_i386;
    set_fmt_errno(ERR_OTHER, "Unsupported ISA %s", c->server->isa);
    return NULL;
}

static int add_res_target_info(GdbClient * c) {
    const char * regs = get_regs(c);
    if (regs == NULL) return -1;
    add_res_str(c, "l<?xml version=\"1.0\"?>\n");
    add_res_str(c, "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n");
    add_res_str(c, "<target version=\"1.0\">\n");
    add_res_str(c, "<architecture>");
    add_res_str(c, c->server->isa);
    add_res_str(c, "</architecture>\n");
    add_res_str(c, "<feature name=\"org.gnu.gdb.");
    add_res_str(c, c->server->isa);
    add_res_str(c, ".core\">\n");
    add_res_str(c, "</feature>\n");
    add_res_str(c, regs);
    add_res_str(c, "</target>\n");
    return 0;
}

static void read_reg_attributes(const char * p, char ** name, unsigned * bits) {
    const char * p0 = p;
    *name = NULL;
    *bits = 0;
    for (;;) {
        if (*p == 0) break;
        if (*p == '\n') break;
        if (p[0] == '=' && (p[1] == '"' || p[1] == '\'')) {
            char q = p[1];
            const char * n0 = p;
            const char * n1 = p;
            const char * v0 = p + 2;
            const char * v1 = p + 2;
            while (*v1 != 0 && *v1 != q) v1++;
            while (n0 > p0 && *(n0 - 1) != ' ') n0--;
            if (n1 - n0 == 4 && strncmp(n0, "name", 4) == 0) {
                size_t l = v1 - v0;
                *name = (char *)tmp_alloc_zero(l + 1);
                memcpy(*name, v0, l);
            }
            if (n1 - n0 == 7 && strncmp(n0, "bitsize", 7) == 0) {
                *bits = (unsigned)atoi(v0);
            }
            if (*v1 != q) break;
            p = v1;
        }
        p++;
    }
}

static int handle_g_command(GdbClient * c) {
    /* Read general registers */
    const char * regs = get_regs(c);
    const char * p = regs;
    const char * s = regs;
    if (p == NULL) return -1;
    while (*p) {
        if (*p++ == '\n') {
            char * name = NULL;
            unsigned bits = 0;
            read_reg_attributes(s, &name, &bits);
            if (name != NULL && bits != 0) {
                unsigned i = 0;
                while (i < bits) {
                    add_res_str(c, "xx");
                    i += 8;
                }
            }
            s = p;
        }
    }
    return 0;
}

static int handle_q_command(GdbClient * c) {
    char * s = c->cmd_buf + 2;
    char * w = get_cmd_word(c, &s);
    if (strcmp(w, "Supported") == 0) {
        add_res_str(c, "PacketSize=4000");
        add_res_str(c, ";qXfer:features:read+");
        add_res_str(c, ";multiprocess+;QNonStop+");
#if 0
        add_res_str(c, ";QAgent+");
        add_res_str(c, ";QStartNoAckMode+");
        add_res_str(c, ";QPassSignals+;QProgramSignals+");
        add_res_str(c, ";ConditionalBreakpoints+;BreakpointCommands+");
        add_res_str(c, ";qXfer:osdata:read+;qXfer:threads:read+");
        add_res_str(c, ";qXfer:libraries-svr4:read+");
        add_res_str(c, ";qXfer:auxv:read+");
        add_res_str(c, ";qXfer:spu:read+;qXfer:spu:write+");
        add_res_str(c, ";qXfer:siginfo:read+;qXfer:siginfo:write+");
#endif
    }
    if (strcmp(w, "Attached") == 0) {
        /* When server replies 1, GDB sends a "detach" command at the end of a debugging
           session otherwise GDB sends "kill" */
        add_res_str(c, "1");
        return 0;
    }
    if (strcmp(w, "TStatus") == 0) {
        add_res_str(c, "T0");
        return 0;
    }
    if (strcmp(w, "C") == 0) {
        add_res_str(c, "QC");
        add_res_hex(c, c->cur_g_thread);
        return 0;
    }
    if (strcmp(w, "Xfer") == 0) {
        if (*s++ == ':') {
            w = get_cmd_word(c, &s);
            if (strcmp(w, "features") == 0) {
                if (*s++ == ':') {
                    w = get_cmd_word(c, &s);
                    if (strcmp(w, "read") == 0) {
                        if (*s++ == ':') {
                            w = get_cmd_word(c, &s);
                            return add_res_target_info(c);
                        }
                    }
                }
            }
        }
        return 0;
    }
    return 0;
}

static int handle_Q_command(GdbClient * c) {
    char * s = c->cmd_buf + 2;
    char * w = get_cmd_word(c, &s);
    if (strcmp(w, "NonStop") == 0) {
        if (s + 2 == c->cmd_buf + c->cmd_end) {
            if (strncmp(s, ":0", 2) == 0) {
                add_res_str(c, "OK");
                c->non_stop = 0;
                return 0;
            }
            if (strncmp(s, ":1", 2) == 0) {
                add_res_str(c, "OK");
                c->non_stop = 1;
                return 0;
            }
        }
        add_res_str(c, "E01");
        return 0;
    }
    return 0;
}

static int handle_H_command(GdbClient * c) {
    if (c->cmd_end > 2) {
        char * s = c->cmd_buf + 3;
        char * e = c->cmd_buf + c->cmd_end;
        unsigned n = 0;
        int neg = 0;
        if (s < e && *s == '-') {
            neg = 1;
            s++;
        }
        while (s < e) {
            unsigned d = *s++;
            if (d >= '0' && d <= '9') {
                n = (n << 4) + (d - '0');
            }
            else if (d >= 'A' && d <= 'F') {
                n = (n << 4) + (d - 'A' + 10);
            }
            else if (d >= 'a' && d <= 'f') {
                n = (n << 4) + (d - 'a' + 10);
            }
        }
        if (neg) {
            /* ‘-1’ - all processes or threads */
            if (n != 1) {
                add_res_str(c, "E01");
                return 0;
            }
            n = ALL_THREADS;
        }
        else if (n == 0) {
            /* ‘0’ - an arbitrary process or thread. */
            n = c->thread_cnt - 1;
        }
        if (c->cmd_buf[2] == 'c') {
            c->cur_c_thread = n;
        }
        else {
            c->cur_g_thread = n;
        }
    }
    add_res_str(c, "OK");
    return 0;
}

static int handle_qm_command(GdbClient * c) {
    if (c->non_stop) {
#if 0
        LINK * l;
        for (l = c->link_c2t.next; l != &c->link_c2t; l = l->next) {
            GdbThread * t = link_c2t(l);
            if (is_intercepted(t->ctx)) {

            }
        }
#endif
    }
    else {
        GdbThread * t = find_thread(c, c->cur_g_thread);
        if (t != NULL) {
            add_res_str(c, "S05");
            return 0;
        }
        add_res_str(c, "S00");
    }
    return 0;
}

static int handle_command(GdbClient * c) {
    if (c->cmd_end < 2) return 0;
    switch (c->cmd_buf[1]) {
    case 'A': add_res_str(c, "E01"); return 0;
    case 'b': return 0;
    case 'B': return 0;
    case 'd': return 0;
    case 'g': return handle_g_command(c);
    case 'q': return handle_q_command(c);
    case 'Q': return handle_Q_command(c);
    case 'H': return handle_H_command(c);
    case '!': c->extended = 1; add_res_str(c, "OK"); return 0;
    case '?': return handle_qm_command(c);
    }
    return 0;
}

static int read_packet(GdbClient * c, unsigned len) {
    unsigned char * p = c->buf;
    unsigned char * e = p + len;

    while (p < e) {
        char ch = *p++;
        if (c->cmd_pos > 0 || ch == '$') {
            if (c->cmd_pos == 0) {
                c->cmd_esc = 0;
            }
            if (ch == 0x7d && !c->cmd_esc) {
                c->cmd_esc = 1;
                continue;
            }
            if (ch == '#') {
                c->cmd_end = c->cmd_pos;
            }
            if (c->cmd_esc) {
                c->cmd_esc = 0;
                ch = (char)(ch ^ 0x20);
            }
            if (c->cmd_pos >= c->cmd_max) {
                c->cmd_max = c->cmd_max == 0 ? 0x100 : c->cmd_max * 2;
                c->cmd_buf = (char *)loc_realloc(c->cmd_buf, c->cmd_max);
            }
            c->cmd_buf[c->cmd_pos++] = ch;
            if (c->cmd_end > 0 && c->cmd_pos == c->cmd_end + 3) {
                if (send(c->req.u.sio.sock, "+", 1, 0) < 0) return -1;
#if DEBUG_RSP
                printf("GDB -> %.*s\n", c->cmd_pos, c->cmd_buf);
#endif
                c->res_pos = 0;
                add_res_ch_no_esc(c, '$');
                if (handle_command(c) < 0) return -1;
                if (c->res_pos > 0) {
                    add_res_checksum(c);
#if DEBUG_RSP
                    printf("GDB <- %.*s\n", c->res_pos, c->res_buf);
#endif
                    if (send(c->req.u.sio.sock, c->res_buf, c->res_pos, 0) < 0) return -1;
                }
                c->cmd_pos = 0;
                c->cmd_end = 0;
            }
            else if (ch == '-' && c->res_pos > 0) {
                if (send(c->req.u.sio.sock, c->res_buf, c->res_pos, 0) < 0) return -1;
            }
        }
    }

    return 0;
}

static void recv_done(void * args) {
    GdbClient * c = (GdbClient *)((AsyncReqInfo *)args)->client_data;
    if (c->req.error) {
        trace(LOG_ALWAYS, "GDB Server connection closed: %s", errno_to_str(c->req.error));
        dispose_client(c);
        return;
    }
    else {
        if (read_packet(c, c->req.u.sio.rval) < 0) {
            trace(LOG_ALWAYS, "GDB Server connection terminated: %s", errno_to_str(errno));
            dispose_client(c);
            return;
        }
        c->req.u.sio.rval = 0;
        async_req_post(&c->req);
    }
}

static void accept_done(void * args) {
    GdbServer * s = (GdbServer *)((AsyncReqInfo *)args)->client_data;
    GdbClient * c = NULL;
    const int opt = 1;
    int sock = 0;

    if (s->req.error) {
        trace(LOG_ALWAYS, "GDB Server terminated: %s", errno_to_str(s->req.error));
        dispose_server(s);
        return;
    }

    sock = s->req.u.acc.rval;
    c = (GdbClient *)loc_alloc_zero(sizeof(GdbClient));
    c->server = s;
    c->buf_max = 0x1000;
    c->buf = (uint8_t *)loc_alloc(c->buf_max);
    c->req.type = AsyncReqRecv;
    c->req.client_data = c;
    c->req.done = recv_done;
    c->req.u.sio.sock = sock;
    c->req.u.sio.bufp = c->buf;
    c->req.u.sio.bufsz = c->buf_max;
    c->req.u.sio.flags = 0;
    list_init(&c->link_c2t);
    list_add_last(&c->link_s2c, &s->link_s2c);

    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)) < 0) {
        trace(LOG_ALWAYS, "GDB Server setsockopt failed: %s", errno_to_str(errno));
        dispose_client(c);
        return;
    }

    if (start_client(c) < 0) {
        trace(LOG_ALWAYS, "GDB Server open port failed: %s", errno_to_str(errno));
        dispose_client(c);
        return;
    }

    s->req.u.acc.rval = 0;
    async_req_post(&s->req);
}

static void event_context_created(Context * ctx, void * args) {
    if (context_has_state(ctx)) {
        LINK * l, * n;
        for (l = link_a2s.next; l != &link_a2s; l = l->next) {
            GdbServer * s = link_a2s(l);
            for (n = s->link_s2c.next; n != &s->link_s2c; n = n->next) {
                GdbClient * c = link_s2c(n);
                add_thread(c, ctx);
            }
        }
    }
}

static void event_context_exited(Context * ctx, void * args) {
    LINK * l = EXT(ctx);
    while (!list_is_empty(l)) {
        free_thread(link_ctx2t(l->next));
    }
}

static ContextEventListener context_listener = {
    event_context_created,
    event_context_exited,
    NULL,
    NULL,
    NULL,
    NULL
};

int ini_gdb_rsp(const char * conf) {
    GdbServer * s = NULL;
    char port[32];
    char isa[32];
    const char * sep = strchr(conf, ':');
    int sock = -1;
    strlcpy(port, conf, sizeof(port));
    if (sep != NULL) {
        if ((size_t)(sep - conf) < sizeof(port)) port[sep - conf] = 0;
        strlcpy(isa, sep + 1, sizeof(isa));
    }
    else {
        strlcpy(isa, "i386", sizeof(isa));
    }
    sock = open_server(port);
    if (sock < 0) return -1;
    if (!ini_done) {
        list_init(&link_a2s);
        context_extension_offset = context_extension(sizeof(LINK));
        add_context_event_listener(&context_listener, NULL);
        ini_done = 1;
    }
    s = (GdbServer *)loc_alloc_zero(sizeof(GdbServer));
    list_init(&s->link_s2c);
    list_add_last(&s->link_a2s, &link_a2s);
    s->req.type = AsyncReqAccept;
    s->req.client_data = s;
    s->req.done = accept_done;
    s->req.u.acc.sock = sock;
    s->req.u.acc.rval = 0;
    strlcpy(s->isa, isa, sizeof(s->isa));
    async_req_post(&s->req);
    return 0;
}

#endif /* ENABLE_DebugContext */
