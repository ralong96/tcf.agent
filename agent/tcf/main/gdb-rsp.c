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

#if !defined(ENABLE_GdbRemoteSerialProtocol)
#  define ENABLE_GdbRemoteSerialProtocol 0
#endif

#if ENABLE_GdbRemoteSerialProtocol

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

/*
(gdb) set remotetimeout 1000
(gdb) target remote localhost:3000
*/

#ifndef DEBUG_RSP
#  define DEBUG_RSP 0
#endif

typedef struct GdbServer {
    LINK link_a2s;
    LINK link_s2c;
    int disposed;
    AsyncReqInfo req;
    char isa[32];
    RegisterDefinition ** regs_nm_map;
    unsigned regs_nm_map_index_mask;
} GdbServer;

typedef struct GdbClient {
    LINK link_s2c;
    LINK link_c2t;
    size_t buf_max;
    uint8_t * buf;
    AsyncReqInfo req;
    GdbServer * server;
    Channel channel;
    int lock_cnt;
    int closed;

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
    unsigned xfer_range_offs;
    unsigned xfer_range_size;

    unsigned start_timer;
    unsigned thread_id_cnt;
    unsigned cur_c_thread;
    unsigned cur_g_thread;
    int no_ack_mode;
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

#define channel2gdb(c)  ((GdbClient *)((char *)(c) - offsetof(GdbClient, channel)))

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

static const char * regs_arm =
    " <reg name='r0' bitsize='32' type='uint32'/>\n"
    " <reg name='r1' bitsize='32' type='uint32'/>\n"
    " <reg name='r2' bitsize='32' type='uint32'/>\n"
    " <reg name='r3' bitsize='32' type='uint32'/>\n"
    " <reg name='r4' bitsize='32' type='uint32'/>\n"
    " <reg name='r5' bitsize='32' type='uint32'/>\n"
    " <reg name='r6' bitsize='32' type='uint32'/>\n"
    " <reg name='r7' bitsize='32' type='uint32'/>\n"
    " <reg name='r8' bitsize='32' type='uint32'/>\n"
    " <reg name='r9' bitsize='32' type='uint32'/>\n"
    " <reg name='r10' bitsize='32' type='uint32'/>\n"
    " <reg name='r11' bitsize='32' type='uint32'/>\n"
    " <reg name='r12' bitsize='32' type='uint32'/>\n"
    " <reg name='sp' bitsize='32' type='data_ptr'/>\n"
    " <reg name='lr' bitsize='32'/>\n"
    " <reg name='pc' bitsize='32' type='code_ptr'/>\n"
    " <reg name='cpsr' bitsize='32' regnum='25'/>\n";

static void add_thread(GdbClient * c, Context * ctx) {
    GdbThread * t = (GdbThread *)loc_alloc_zero(sizeof(GdbThread));
    LINK * l = EXT(ctx);
    t->client = c;
    t->id = c->thread_id_cnt++;
    t->ctx = ctx;
    if (l->next == NULL) list_init(l);
    list_add_last(&t->link_ctx2t, l);
    list_add_last(&t->link_c2t, &c->link_c2t);
    if (suspend_debug_context(ctx) < 0) {
        char * name = ctx->name;
        if (name == NULL) name = ctx->id;
        trace(LOG_ALWAYS, "GDB Server: cannot suspend context %s: %s", errno_to_str(errno));
    }
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

static const char * get_regs(GdbClient * c) {
    if (strcmp(c->server->isa, "i386") == 0) return regs_i386;
    if (strcmp(c->server->isa, "arm") == 0) return regs_arm;
    set_fmt_errno(ERR_OTHER, "Unsupported ISA %s", c->server->isa);
    return NULL;
}

static unsigned reg_name_hash(const char * name) {
    unsigned h = 5381;
    while (*name) h = ((h << 5) + h) + *name++;
    return h;
}

static RegisterDefinition * find_register(GdbClient * c, Context * ctx, const char * name) {
    GdbServer * s = c->server;
    RegisterDefinition ** map = s->regs_nm_map;
    unsigned n = 0;

    if (map == NULL) {
        unsigned map_len = 0;
        unsigned map_len_p2 = 1;
        RegisterDefinition * def = get_reg_definitions(ctx);
        if (def == NULL) return NULL;
        while (def->name != NULL) {
            map_len++;
            def++;
        }
        if (map_len == 0) return NULL;
        while (map_len_p2 < map_len * 3) map_len_p2 <<= 2;
        map = (RegisterDefinition **)loc_alloc_zero(sizeof(RegisterDefinition *) * map_len_p2);
        s->regs_nm_map_index_mask = map_len_p2 - 1;
        def = get_reg_definitions(ctx);
        while (def->name != NULL) {
            unsigned h = reg_name_hash(def->name) & s->regs_nm_map_index_mask;
            while (map[h] != NULL) h = (h + 1) & s->regs_nm_map_index_mask;
            map[h] = def;
            def++;
        }
        s->regs_nm_map = map;
    }
    n = reg_name_hash(name) & s->regs_nm_map_index_mask;
    while (map[n] != NULL) {
        if (strcmp(map[n]->name, name) == 0) return map[n];
        n = (n + 1) & s->regs_nm_map_index_mask;
    }
    return NULL;
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

static void start_client(void * args) {
    LINK * l;
    unsigned has_state_cnt = 0;
    unsigned intercepted_cnt = 0;
    GdbClient * c = (GdbClient *)args;

    for (l = context_root.next; l != &context_root; l = l->next) {
        Context * ctx = ctxl2ctxp(l);
        if (context_has_state(ctx)) {
            if (is_intercepted(ctx)) intercepted_cnt++;
            has_state_cnt++;
        }
    }

    if (c->start_timer > 10 || (has_state_cnt > 0 && intercepted_cnt == has_state_cnt)) {
        c->req.u.sio.rval = 0;
        async_req_post(&c->req);
    }
    else {
        post_event_with_delay(start_client, args, 500000);
        c->start_timer++;
    }
}

static void dispose_client(GdbClient * c) {
    GdbServer * s = c->server;

    if (!c->closed) {
        c->closed = 1;
        closesocket(c->req.u.sio.sock);
        notify_channel_closed(&c->channel);
    }

    if (c->lock_cnt > 0) return;

    while (!list_is_empty(&c->link_c2t)) {
        free_thread(link_c2t(c->link_c2t.next));
    }

    list_remove(&c->channel.chanlink);
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

static void add_res_reg_value(GdbClient * c, GdbThread * t, const char * name, unsigned bits) {
    RegisterDefinition * def = NULL;
    unsigned size = (bits + 7) / 8;
    void * buf = tmp_alloc_zero(size);
    unsigned i = 0;
    if (t != NULL) def = find_register(c, t->ctx, name);
    if (def != NULL && context_read_reg(t->ctx, def, 0, size, buf) < 0) def = NULL;
    while (i < size) {
        if (def == NULL) {
            add_res_str(c, "xx");
        }
        else {
            unsigned byte = ((uint8_t *)buf)[i];
            add_res_hex_digit(c, (byte >> 4) & 0xf);
            add_res_hex_digit(c, byte & 0xf);
        }
        i++;
    }
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

static uint64_t get_cmd_uint64(GdbClient * c, char ** p) {
    char * s = *p;
    uint64_t n = 0;
    while (s < c->cmd_buf + c->cmd_end) {
        char c = *s;
        if (c >= '0' && c <= '9') n = (n << 4) + (c - '0');
        else if (c >= 'A' && c <= 'F') n = (n << 4) + (c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') n = (n << 4) + (c - 'a' + 10);
        else break;
        s++;
    }
    *p = s;
    return n;
}

static void get_xfer_range(GdbClient * c, char ** p) {
    c->xfer_range_offs = (unsigned)get_cmd_uint64(c, p);
    if (**p != ',') return;
    (*p)++;
    c->xfer_range_size = (unsigned)get_cmd_uint64(c, p);
}

static void read_reg_attributes(const char * p, char ** name, unsigned * bits, unsigned * regnum) {
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
            if (n1 - n0 == 6 && strncmp(n0, "regnum", 6) == 0) {
                *regnum = (unsigned)atoi(v0);
            }
            if (*v1 != q) break;
            p = v1;
        }
        p++;
    }
}

static int handle_g_command(GdbClient * c) {
    /* Read general registers */
    GdbThread * t = find_thread(c, c->cur_g_thread);
    const char * regs = get_regs(c);
    const char * p = regs;
    const char * s = regs;
    if (p == NULL) return -1;
    while (*p) {
        if (*p++ == '\n') {
            char * name = NULL;
            unsigned bits = 0;
            unsigned regnum = 0;
            read_reg_attributes(s, &name, &bits, &regnum);
            if (name != NULL && bits != 0) {
                add_res_reg_value(c, t, name, bits);
                regnum++;
            }
            s = p;
        }
    }
    return 0;
}

static int handle_m_command(GdbClient * c) {
    /* Read memory */
    GdbThread * t = find_thread(c, c->cur_g_thread);
    char * s = c->cmd_buf + 2;
    ContextAddress addr = (ContextAddress)get_cmd_uint64(c, &s);
    void * buf = NULL;
    size_t size = 0;
    if (*s == ',') {
        s++;
        size = (size_t)get_cmd_uint64(c, &s);
    }
    buf = tmp_alloc_zero(size);
    if (t == NULL || context_read_mem(t->ctx, addr, buf, size) < 0) {
        add_res_str(c, "E01");
    }
    else {
        unsigned i = 0;
        while (i < size) {
            unsigned byte = ((uint8_t *)buf)[i];
            add_res_hex_digit(c, (byte >> 4) & 0xf);
            add_res_hex_digit(c, byte & 0xf);
            i++;
        }
    }
    return 0;
}

static int handle_p_command(GdbClient * c) {
    /* Read register */
    char * s = c->cmd_buf + 2;
    GdbThread * t = find_thread(c, c->cur_g_thread);
    unsigned reg = (unsigned)get_cmd_uint64(c, &s);
    const char * regs = get_regs(c);
    const char * p = regs;
    const char * r = regs;
    if (p == NULL) return -1;
    while (*p) {
        if (*p++ == '\n') {
            char * name = NULL;
            unsigned bits = 0;
            unsigned regnum = 0;
            read_reg_attributes(r, &name, &bits, &regnum);
            if (name != NULL && bits != 0) {
                if (regnum == reg) {
                    add_res_reg_value(c, t, name, bits);
                    break;
                }
                regnum++;
            }
            r = p;
        }
    }
    return 0;
}

static int handle_q_command(GdbClient * c) {
    char * s = c->cmd_buf + 2;
    char * w = get_cmd_word(c, &s);
    if (strcmp(w, "Supported") == 0) {
        add_res_str(c, "PacketSize=4000");
        add_res_str(c, ";QStartNoAckMode+");
        add_res_str(c, ";qXfer:features:read+");
        add_res_str(c, ";multiprocess+;QNonStop+");
#if 0
        add_res_str(c, ";QAgent+");
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
    if (strcmp(w, "Xfer") == 0 && *s++ == ':') {
        w = get_cmd_word(c, &s);
        if (strcmp(w, "features") == 0 && *s++ == ':') {
            w = get_cmd_word(c, &s);
            if (strcmp(w, "read") == 0 &&  *s++ == ':') {
                w = get_cmd_word(c, &s);
                if (strcmp(w, "target.xml") == 0) {
                    if (add_res_target_info(c) < 0) return -1;
                    if (*s++ == ':') get_xfer_range(c, &s);
                    return 0;
                }
            }
        }
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
    if (strcmp(w, "StartNoAckMode") == 0) {
        add_res_str(c, "OK");
        c->no_ack_mode = 1;
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
            n = c->thread_id_cnt - 1;
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
    case 'm': return handle_m_command(c);
    case 'p': return handle_p_command(c);
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
                if (!c->no_ack_mode && send(c->req.u.sio.sock, "+", 1, 0) < 0) return -1;
#if DEBUG_RSP
                printf("GDB -> %.*s\n", c->cmd_pos, c->cmd_buf);
#endif
                c->res_pos = 0;
                c->xfer_range_offs = 0;
                c->xfer_range_size = 0;
                add_res_ch_no_esc(c, '$');
                if (handle_command(c) < 0) return -1;
                if (c->xfer_range_offs > 0 || c->xfer_range_size + 1 > c->res_pos) {
                    unsigned offs = c->xfer_range_offs + 1; /* First byte is '$' */
                    unsigned size = c->xfer_range_size;
                    if (offs >= c->res_pos) {
                        offs = 1;
                        size = 0;
                    }
                    else if (offs + size > c->res_pos) {
                        size = c->res_pos - offs;
                    }
                    memmove(c->res_buf + 1, c->res_buf + offs, size);
                    c->res_pos = size + 1;
                }
                add_res_checksum(c);
#if DEBUG_RSP
                printf("GDB <- %.*s\n", c->res_pos, c->res_buf);
#endif
                if (send(c->req.u.sio.sock, c->res_buf, c->res_pos, 0) < 0) return -1;
                c->cmd_pos = 0;
                c->cmd_end = 0;
                c->cmd_esc = 0;
            }
        }
        else if (!c->no_ack_mode && ch == '-' && c->res_pos > 0) {
            if (send(c->req.u.sio.sock, c->res_buf, c->res_pos, 0) < 0) return -1;
        }
    }

    return 0;
}

static void recv_done(void * args) {
    GdbClient * c = (GdbClient *)((AsyncReqInfo *)args)->client_data;
    if (c->req.error) {
        trace(LOG_ALWAYS, "GDB Server connection closed: %s", errno_to_str(c->req.error));
        dispose_client(c);
    }
    else if (c->req.u.sio.rval == 0) {
        dispose_client(c);
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

static void gdb_lock(Channel * channel) {
    GdbClient * c = channel2gdb(channel);
    assert(is_dispatch_thread());
    c->lock_cnt++;
}

static void gdb_unlock(Channel * channel) {
    GdbClient * c = channel2gdb(channel);
    assert(is_dispatch_thread());
    assert(c->lock_cnt > 0);
    c->lock_cnt--;
    if (c->lock_cnt == 0) {
        dispose_client(c);
    }
}

static int gdb_is_closed(Channel * channel) {
    GdbClient * c = channel2gdb(channel);
    return c->closed;
}

static void accept_done(void * args) {
    GdbServer * s = (GdbServer *)((AsyncReqInfo *)args)->client_data;
    GdbClient * c = NULL;
    const int opt = 1;
    int sock = 0;
    LINK * l;

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
    c->thread_id_cnt = 1;
    c->channel.lock = gdb_lock;
    c->channel.unlock = gdb_unlock;
    c->channel.is_closed = gdb_is_closed;
    list_init(&c->link_c2t);
    list_add_last(&c->link_s2c, &s->link_s2c);
    list_add_last(&c->channel.chanlink, &channel_root);
    notify_channel_created(&c->channel);

    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)) < 0) {
        trace(LOG_ALWAYS, "GDB Server setsockopt failed: %s", errno_to_str(errno));
        dispose_client(c);
        return;
    }

    for (l = context_root.next; l != &context_root; l = l->next) {
        Context * ctx = ctxl2ctxp(l);
        if (context_has_state(ctx)) {
            add_thread(c, ctx);
        }
    }

    post_event(start_client, c);
    notify_channel_opened(&c->channel);
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

#endif /* ENABLE_GdbRemoteSerialProtocol */
