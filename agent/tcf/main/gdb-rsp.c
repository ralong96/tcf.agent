/*******************************************************************************
 * Copyright (c) 2016-2017 Xilinx, Inc. and others.
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
#include <tcf/services/registers.h>

#include <tcf/main/gdb-rsp.h>

/*
(gdb) set remotetimeout 1000
(gdb) target extended-remote localhost:3000
*/

#ifndef DEBUG_RSP
#  define DEBUG_RSP 1
#endif

#define ID_ANY ~0u

typedef struct GdbServer {
    LINK link_a2s;
    LINK link_s2c;
    int disposed;
    AsyncReqInfo req;
    char isa[32];
} GdbServer;

typedef struct GdbClient {
    LINK link_s2c;
    LINK link_c2p;
    size_t buf_max;
    uint8_t * buf;
    AsyncReqInfo req;
    GdbServer * server;
    ClientConnection client;
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
    unsigned process_id_cnt;
    unsigned cur_c_pid;
    unsigned cur_c_tid;
    unsigned cur_g_pid;
    unsigned cur_g_tid;
    int no_ack_mode;
    int extended;
    int stopped;
    int waiting;
} GdbClient;

typedef struct GdbProcess {
    LINK link_c2p;
    LINK link_p2t;
    GdbClient * client;
    unsigned pid;
    Context * ctx;
    unsigned thread_id_cnt;
    int attached;
} GdbProcess;

typedef struct GdbThread {
    LINK link_p2t;
    GdbProcess * process;
    unsigned tid;
    Context * ctx;
    RegisterDefinition ** regs_nm_map;
    unsigned regs_nm_map_index_mask;
    int locked;
} GdbThread;

typedef struct MonitorCommand {
    const char * name;
    void (*func)(GdbClient *, const char *);
} MonitorCommand;

#define link_a2s(x) ((GdbServer *)((char *)(x) - offsetof(GdbServer, link_a2s)))
#define link_s2c(x) ((GdbClient *)((char *)(x) - offsetof(GdbClient, link_s2c)))
#define link_c2p(x) ((GdbProcess *)((char *)(x) - offsetof(GdbProcess, link_c2p)))
#define link_p2t(x) ((GdbThread *)((char *)(x) - offsetof(GdbThread, link_p2t)))

#define client2gdb(c)  ((GdbClient *)((char *)(c) - offsetof(GdbClient, client)))

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
    " <reg name='eflags' bitsize='32' type='int32'/>\n"
    " <reg name='cs'  bitsize='16' type='int32'/>\n"
    " <reg name='ss'  bitsize='16' type='int32'/>\n"
    " <reg name='ds'  bitsize='16' type='int32'/>\n"
    " <reg name='es'  bitsize='16' type='int32'/>\n"
    " <reg name='fs'  bitsize='16' type='int32'/>\n"
    " <reg name='gs'  bitsize='16' type='int32'/>\n"
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

static GdbProcess * add_process(GdbClient * c, Context * ctx) {
    GdbProcess * p = (GdbProcess *)loc_alloc_zero(sizeof(GdbProcess));
    assert(ctx->mem == ctx);
    p->client = c;
    p->pid = ++c->process_id_cnt;
    p->ctx = ctx;
    list_init(&p->link_p2t);
    list_add_last(&p->link_c2p, &c->link_c2p);
    return p;
}

static GdbProcess * find_process_pid(GdbClient * c, unsigned pid) {
    LINK * l;
    for (l = c->link_c2p.next; l != &c->link_c2p; l = l->next) {
        GdbProcess * p = link_c2p(l);
        if (p->pid == pid) return p;
    }
    return NULL;
}

static GdbProcess * find_process_ctx(GdbClient * c, Context * ctx) {
    LINK * l;
    for (l = c->link_c2p.next; l != &c->link_c2p; l = l->next) {
        GdbProcess * p = link_c2p(l);
        if (p->ctx == ctx) return p;
    }
    return NULL;
}

static void add_thread(GdbClient * c, Context * ctx) {
    GdbThread * t = (GdbThread *)loc_alloc_zero(sizeof(GdbThread));
    t->process = find_process_ctx(c, context_get_group(ctx, CONTEXT_GROUP_PROCESS));
    t->tid = ++t->process->thread_id_cnt;
    t->ctx = ctx;
    list_add_last(&t->link_p2t, &t->process->link_p2t);
    if (c->stopped) {
        t->locked = 1;
        run_ctrl_ctx_lock(ctx);
        if (suspend_debug_context(ctx) < 0) {
            char * name = ctx->name;
            if (name == NULL) name = ctx->id;
            trace(LOG_ALWAYS, "GDB Server: cannot suspend context %s: %s", errno_to_str(errno));
        }
    }
}

static GdbThread * find_thread(GdbClient * c, unsigned pid, unsigned tid) {
    LINK * l;
    GdbProcess * p = find_process_pid(c, pid);
    if (p != NULL) {
        for (l = p->link_p2t.next; l != &p->link_p2t; l = l->next) {
            GdbThread * t = link_p2t(l);
            if (t->tid == tid) return t;
        }
    }
    return NULL;
}

static void free_thread(GdbThread * t) {
    if (t->process->client->stopped) {
        assert(t->locked);
        run_ctrl_ctx_unlock(t->ctx);
        t->locked = 0;
    }
    loc_free(t->regs_nm_map);
    list_remove(&t->link_p2t);
    loc_free(t);
}

static void free_process(GdbProcess * p) {
    while (!list_is_empty(&p->link_p2t)) {
        assert(p->attached);
        free_thread(link_p2t(p->link_p2t.next));
    }
    list_remove(&p->link_c2p);
    loc_free(p);
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

static RegisterDefinition * find_register(GdbThread * t, const char * name) {
    RegisterDefinition ** map = t->regs_nm_map;
    unsigned n = 0;

    if (map == NULL) {
        unsigned map_len = 0;
        unsigned map_len_p2 = 1;
        RegisterDefinition * def = get_reg_definitions(t->ctx);
        if (def == NULL) return NULL;
        while (def->name != NULL) {
            map_len++;
            def++;
        }
        if (map_len == 0) return NULL;
        while (map_len_p2 < map_len * 3) map_len_p2 <<= 2;
        map = (RegisterDefinition **)loc_alloc_zero(sizeof(RegisterDefinition *) * map_len_p2);
        t->regs_nm_map_index_mask = map_len_p2 - 1;
        def = get_reg_definitions(t->ctx);
        while (def->name != NULL) {
            unsigned h = reg_name_hash(def->name) & t->regs_nm_map_index_mask;
            while (map[h] != NULL) h = (h + 1) & t->regs_nm_map_index_mask;
            map[h] = def;
            def++;
        }
        t->regs_nm_map = map;
    }
    n = reg_name_hash(name) & t->regs_nm_map_index_mask;
    while (map[n] != NULL) {
        if (strcmp(map[n]->name, name) == 0) return map[n];
        n = (n + 1) & t->regs_nm_map_index_mask;
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

static void lock_threads(GdbClient * c) {
    LINK * l;
    assert(!c->closed);
    if (c->stopped) return;
    for (l = c->link_c2p.next; l != &c->link_c2p; l = l->next) {
        LINK * m;
        GdbProcess * p = link_c2p(l);
        for (m = p->link_p2t.next; m != &p->link_p2t; m = m->next) {
            GdbThread * t = link_p2t(m);
            Context * ctx = t->ctx;
            assert(!t->locked);
            assert(!t->ctx->exited);
            run_ctrl_ctx_lock(ctx);
            if (suspend_debug_context(ctx) < 0) {
                char * name = ctx->name;
                if (name == NULL) name = ctx->id;
                trace(LOG_ALWAYS, "GDB Server: cannot suspend context %s: %s", errno_to_str(errno));
            }
            t->locked = 1;
        }
    }
    c->stopped = 1;
}

static void unlock_threads(GdbClient * c) {
    LINK * l;
    if (!c->stopped) return;
    for (l = c->link_c2p.next; l != &c->link_c2p; l = l->next) {
        LINK * m;
        GdbProcess * p = link_c2p(l);
        for (m = p->link_p2t.next; m != &p->link_p2t; m = m->next) {
            GdbThread * t = link_p2t(m);
            Context * ctx = t->ctx;
            assert(t->locked);
            assert(!t->ctx->exited);
            run_ctrl_ctx_unlock(ctx);
            t->locked = 0;
        }
    }
    c->stopped = 0;
}

static void attach_process(GdbProcess * p) {
    GdbClient * c = p->client;
    LINK * l;
    if (p->attached) return;
    p->attached = 1;
    for (l = context_root.next; l != &context_root; l = l->next) {
        Context * ctx = ctxl2ctxp(l);
        if (!ctx->exited && context_has_state(ctx) && context_get_group(ctx, CONTEXT_GROUP_PROCESS) == p->ctx) {
            add_thread(c, ctx);
        }
    }
}

static void detach_process(GdbProcess * p) {
    if (!p->attached) return;
    while (!list_is_empty(&p->link_p2t)) {
        free_thread(link_p2t(p->link_p2t.next));
    }
    p->attached = 0;
}

static void start_client(void * args) {
    LINK * l;
    unsigned has_state_cnt = 0;
    GdbClient * c = (GdbClient *)args;

    for (l = context_root.next; l != &context_root; l = l->next) {
        Context * ctx = ctxl2ctxp(l);
        if (!ctx->exited && context_has_state(ctx)) {
            has_state_cnt++;
        }
    }

    if (c->start_timer > 10 || has_state_cnt > 0) {

        /* Select initial debug target */
        for (l = context_root.next; l != &context_root; l = l->next) {
            Context * ctx = ctxl2ctxp(l);
            Context * prs = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
            if (!ctx->exited && context_has_state(ctx)) {
                attach_process(find_process_ctx(c, prs));
                lock_threads(c);
                break;
            }
        }

        c->req.u.sio.rval = 0;
        async_req_post(&c->req);
    }
    else {
        post_event_with_delay(start_client, args, 500000);
        c->start_timer++;
    }
}

static void close_client(GdbClient * c) {
    if (!c->closed) {
        c->closed = 1;
        unlock_threads(c);
        closesocket(c->req.u.sio.sock);
        notify_client_disconnected(&c->client);
    }
}

static void dispose_client(ClientConnection * cc) {
    GdbClient * c = client2gdb(cc);
    GdbServer * s = c->server;

    assert(c->closed);
    while (!list_is_empty(&c->link_c2p)) {
        free_process(link_c2p(c->link_c2p.next));
    }
    list_remove(&c->link_s2c);
    loc_free(c->cmd_buf);
    loc_free(c->buf);
    loc_free(c);

    if (s->disposed && list_is_empty(&s->link_s2c)) {
        loc_free(s);
    }
}

static char hex_digit(unsigned d) {
    assert(d < 0x10);
    if (d < 10) return (char)('0' + d);
    return (char)('A' + d - 10);
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
    case '*':
        add_res_ch_no_esc(c, '}');
        ch ^= 0x20;
        break;
    }
    add_res_ch_no_esc(c, ch);
}

static void add_res_str(GdbClient * c, const char * s) {
    while (*s != 0) add_res_ch(c, *s++);
}

static void add_res_hex(GdbClient * c, uint32_t n) {
    char s[9];
    unsigned i = sizeof(s);
    s[--i] = 0;
    do {
        unsigned d = n & 0xf;
        s[--i] = hex_digit(d);
        n = n >> 4;
    }
    while (n != 0 && i > 0);
    add_res_str(c, s + i);
}

static void add_res_hex8(GdbClient * c, unsigned n) {
    char s[3];
    unsigned i = sizeof(s);
    s[--i] = 0;
    do {
        unsigned d = n & 0xf;
        s[--i] = hex_digit(d);
        n = n >> 4;
    }
    while (i > 0);
    add_res_str(c, s);
}

static void add_res_ptid(GdbClient * c, unsigned pid, unsigned tid) {
    add_res_ch(c, 'p');
    add_res_hex(c, pid);
    add_res_ch(c, '.');
    add_res_hex(c, tid);
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
    add_res_str(c, regs);
    add_res_str(c, "</feature>\n");
    add_res_str(c, "</target>\n");
    return 0;
}

static void add_res_reg_value(GdbClient * c, GdbThread * t, const char * name, unsigned bits) {
    RegisterDefinition * def = NULL;
    unsigned size = (bits + 7) / 8;
    void * buf = tmp_alloc_zero(size);
    unsigned i = 0;
    if (t != NULL) def = find_register(t, name);
    if (def != NULL && context_read_reg(t->ctx, def, 0, size, buf) < 0) def = NULL;
    while (i < size) {
        if (def == NULL) {
            add_res_str(c, "xx");
        }
        else {
            unsigned byte = ((uint8_t *)buf)[i];
            add_res_hex8(c, byte);
        }
        i++;
    }
}

static int send_res(GdbClient * c) {
    unsigned i;
    unsigned char sum = 0;
    assert(c->res_pos > 0);
    assert(c->res_buf[0] == '$');
    for (i = 1; i < c->res_pos; i++) {
        sum += (unsigned char)c->res_buf[i];
    }
    add_res_ch_no_esc(c, '#');
    add_res_hex8(c, sum);
#if DEBUG_RSP
    printf("GDB <- %.*s\n", c->res_pos, c->res_buf);
#endif
    return send(c->req.u.sio.sock, c->res_buf, c->res_pos, 0);
}

static char * get_cmd_word(GdbClient * c, char ** p) {
    char * s = *p;
    char * e = s;
    char * w = NULL;
    while (e < c->cmd_buf + c->cmd_end) {
        if (*e == ':') break;
        if (*e == ';') break;
        if (*e == ',') break;
        e++;
    }
    w = (char *)tmp_alloc_zero(e - s + 1);
    memcpy(w, s, e - s);
    *p = e;
    return w;
}

static uint8_t get_cmd_uint8(GdbClient * c, char ** p) {
    char * s = *p;
    uint8_t n = 0;
    while (s < c->cmd_buf + c->cmd_end && s < *p + 2) {
        char ch = *s;
        if (ch >= '0' && ch <= '9') n = (n << 4) + (ch - '0');
        else if (ch >= 'A' && ch <= 'F') n = (n << 4) + (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f') n = (n << 4) + (ch - 'a' + 10);
        else break;
        s++;
    }
    *p = s;
    return n;
}

static unsigned get_cmd_uint(GdbClient * c, char ** p) {
    char * s = *p;
    unsigned n = 0;
    while (s < c->cmd_buf + c->cmd_end) {
        char ch = *s;
        if (ch >= '0' && ch <= '9') n = (n << 4) + (ch - '0');
        else if (ch >= 'A' && ch <= 'F') n = (n << 4) + (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f') n = (n << 4) + (ch - 'a' + 10);
        else break;
        s++;
    }
    *p = s;
    return n;
}

static uint64_t get_cmd_uint64(GdbClient * c, char ** p) {
    char * s = *p;
    uint64_t n = 0;
    while (s < c->cmd_buf + c->cmd_end && s < *p + 16) {
        char ch = *s;
        if (ch >= '0' && ch <= '9') n = (n << 4) + (ch - '0');
        else if (ch >= 'A' && ch <= 'F') n = (n << 4) + (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f') n = (n << 4) + (ch - 'a' + 10);
        else break;
        s++;
    }
    *p = s;
    return n;
}

static void get_cmd_ptid(GdbClient * c, char ** pp, unsigned * res_pid, unsigned * res_tid) {
    char * s = *pp;
    unsigned pid = 0;
    unsigned tid = 0;
    int neg_pid = 0;
    int neg_tid = 0;
    if (*s == 'p') {
        s++;
        if (*s == '-') {
            neg_pid = 1;
            s++;
        }
        pid = get_cmd_uint(c, &s);
    }
    if (*s == '.') s++;
    if (*s == '-') {
        neg_tid = 1;
        s++;
    }
    tid = get_cmd_uint(c, &s);
    if (neg_pid) {
        pid = ID_ANY;
    }
    else if (pid == 0) {
        LINK * l;
        pid = 0;
        for (l = c->link_c2p.next; l != &c->link_c2p; l = l->next) {
            GdbProcess * p = link_c2p(l);
            if (p->attached) {
                pid = p->pid;
                break;
            }
        }
    }
    if (neg_tid || pid == ID_ANY) {
        tid = ID_ANY;
    }
    else if (tid == 0) {
        GdbProcess * p = find_process_pid(c, pid);
        tid = 0;
        if (p != NULL && !list_is_empty(&p->link_p2t)) {
            tid = link_p2t(p->link_p2t.next)->tid;
        }
    }
    *pp = s;
    *res_pid = pid;
    *res_tid = tid;
}

static void get_xfer_range(GdbClient * c, char ** p) {
    c->xfer_range_offs = get_cmd_uint(c, p);
    if (**p != ',') return;
    (*p)++;
    c->xfer_range_size = get_cmd_uint(c, p);
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

static void monitor_ps(GdbClient * c, const char * args) {
    LINK * l;
    unsigned cnt = 0;
    for (l = c->link_c2p.next; l != &c->link_c2p; l = l->next) {
        char s[256];
        char * m = s;
        GdbProcess * p = link_c2p(l);
        snprintf(s, sizeof(s), "%u: %s\n", (unsigned)p->pid, p->ctx->name ? p->ctx->name : p->ctx->id);
        while (*m) add_res_hex8(c, *m++);
        cnt++;
    }
    if (cnt == 0) {
        const char * m = "No processes\n";
        while (*m) add_res_hex8(c, *m++);
    }
}

static MonitorCommand mon_cmds[] = {
    { "ps", monitor_ps },
    { NULL }
};

static int handle_g_command(GdbClient * c) {
    /* Read general registers */
    GdbThread * t = find_thread(c, c->cur_g_pid, c->cur_g_tid);
    const char * regs = get_regs(c);
    const char * p = regs;
    const char * s = regs;
    unsigned regnum = 0;
    if (p == NULL) return -1;
    while (*p) {
        if (*p++ == '\n') {
            char * name = NULL;
            unsigned bits = 0;
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
    char * s = c->cmd_buf + 2;
    ContextAddress addr = (ContextAddress)get_cmd_uint64(c, &s);
    GdbThread * t = find_thread(c, c->cur_g_pid, c->cur_g_tid);
    void * buf = NULL;
    size_t size = 0;
    if (*s == ',') {
        s++;
        size = (size_t)get_cmd_uint(c, &s);
    }
    buf = tmp_alloc_zero(size);
    if (t == NULL || context_read_mem(t->ctx, addr, buf, size) < 0) {
        add_res_str(c, "E01");
    }
    else {
        unsigned i = 0;
        while (i < size) {
            unsigned byte = ((uint8_t *)buf)[i];
            add_res_hex8(c, byte);
            i++;
        }
    }
    return 0;
}

static int handle_p_command(GdbClient * c) {
    /* Read register */
    char * s = c->cmd_buf + 2;
    GdbThread * t = find_thread(c, c->cur_g_pid, c->cur_g_tid);
    unsigned reg = get_cmd_uint(c, &s);
    const char * regs = get_regs(c);
    const char * p = regs;
    const char * r = regs;
    unsigned regnum = 0;
    if (p == NULL) return -1;
    while (*p) {
        if (*p++ == '\n') {
            char * name = NULL;
            unsigned bits = 0;
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
        add_res_str(c, ";multiprocess+");
#if 0
        add_res_str(c, ";QNonStop+;QAgent+");
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
        add_res_str(c, "1");
        return 0;
    }
    if (strcmp(w, "TStatus") == 0) {
        add_res_str(c, "T0");
        return 0;
    }
    if (strcmp(w, "C") == 0) {
        add_res_str(c, "QC");
        add_res_ptid(c, c->cur_g_pid, c->cur_g_tid);
        return 0;
    }
    if (strcmp(w, "Xfer") == 0 && *s++ == ':') {
        w = get_cmd_word(c, &s);
        if (strcmp(w, "features") == 0 && *s++ == ':') {
            w = get_cmd_word(c, &s);
            if (strcmp(w, "read") == 0 && *s++ == ':') {
                w = get_cmd_word(c, &s);
                if (strcmp(w, "target.xml") == 0) {
                    if (add_res_target_info(c) < 0) return -1;
                    if (*s++ == ':') get_xfer_range(c, &s);
                    return 0;
                }
            }
        }
    }
    if (strcmp(w, "fThreadInfo") == 0) {
        LINK * l;
        unsigned cnt = 0;
        for (l = c->link_c2p.next; l != &c->link_c2p; l = l->next) {
            GdbProcess * p = link_c2p(l);
            LINK * m;
            for (m = p->link_p2t.next; m != &p->link_p2t; m = m->next) {
                GdbThread * t = link_p2t(m);
                if (cnt == 0) add_res_ch(c, 'm');
                else add_res_ch(c, ',');
                add_res_ptid(c, p->pid, t->tid);
                cnt++;
            }
        }
        if (cnt == 0) add_res_ch(c, 'l');
        return 0;
    }
    if (strcmp(w, "sThreadInfo") == 0) {
        add_res_ch(c, 'l');
        return 0;
    }
    if (strcmp(w, "ThreadExtraInfo") == 0) {
        const char * m = NULL;
        if (*s++ == ',') {
            unsigned pid = 0;
            unsigned tid = 0;
            GdbThread * t = NULL;
            get_cmd_ptid(c, &s, &pid, &tid);
            t = find_thread(c, pid, tid);
            if (t != NULL) {
                Context * ctx = t->ctx;
                const char * state = get_context_state_name(ctx);
                m = ctx->name;
                if (m == NULL) m = ctx->id;
                if (state != NULL && *state) {
                    m = tmp_strdup2(m, ": ");
                    m = tmp_strdup2(m, state);
                }
            }
        }
        if (m == NULL) m = "Invalid ID";
        while (*m) add_res_hex8(c, *m++);
        return 0;
    }
    if (strcmp(w, "Rcmd") == 0) {
        if (*s++ == ',') {
            unsigned i = 0;
            unsigned max = (c->cmd_buf + c->cmd_end - s) / 2 + 2;
            char * cmd = (char *)tmp_alloc_zero(max);
            MonitorCommand * mon_cmd = NULL;
            unsigned mon_cnt = 0;
            unsigned cmd_pos = 0;
            const char * res = NULL;
            while (i < max - 1) {
                char ch = get_cmd_uint8(c, &s);
                if (ch == 0) break;
                cmd[i++] = ch;
            }
            for (i = 0;; i++) {
                unsigned j;
                MonitorCommand * m = mon_cmds + i;
                if (m->name == NULL) break;
                for (j = 0;; j++) {
                    if (cmd[j] != m->name[j] || m->name[j] == 0) {
                        if (j > 0 && (cmd[j] == ' ' || cmd[j] == 0)) {
                            mon_cmd = m;
                            cmd_pos = j;
                            mon_cnt++;
                        }
                        break;
                    }
                }
            }
            if (mon_cnt > 1) {
                res = "Ambiguous command\n";
            }
            else if (mon_cmd == NULL) {
                res = "Invalid command\n";
            }
            else {
                while (cmd[cmd_pos] == ' ') cmd_pos++;
                mon_cmd->func(c, cmd + cmd_pos);
            }
            if (res) {
                while (*res) add_res_hex8(c, *res++);
            }
            return 0;
        }
        add_res_str(c, "E02");
    }
    return 0;
}

static int handle_Q_command(GdbClient * c) {
    char * s = c->cmd_buf + 2;
    char * w = get_cmd_word(c, &s);
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
        if (c->cmd_buf[2] == 'c') {
            get_cmd_ptid(c, &s, &c->cur_c_pid, &c->cur_c_tid);
        }
        else {
            get_cmd_ptid(c, &s, &c->cur_g_pid, &c->cur_g_tid);
        }
    }
    add_res_str(c, "OK");
    return 0;
}

static int handle_qm_command(GdbClient * c) {
    GdbThread * t = find_thread(c, c->cur_g_pid, c->cur_g_tid);
    if (t != NULL) {
        if (is_intercepted(t->ctx)) {
            add_res_str(c, "S00");
        }
        else {
            suspend_debug_context(t->ctx);
            c->waiting = 1;
        }
        return 0;
    }
    add_res_str(c, "W00");
    return 0;
}

static int handle_v_command(GdbClient * c) {
    char * s = c->cmd_buf + 2;
    char * w = get_cmd_word(c, &s);
    if (strcmp(w, "Attach") == 0) {
        if (*s++ == ';') {
            unsigned pid = get_cmd_uint(c, &s);
            GdbProcess * p = find_process_pid(c, pid);
            if (p != NULL) {
                if (!p->attached) attach_process(p);
                if (list_is_empty(&p->link_p2t)) {
                    add_res_str(c, "N");
                }
                else {
                    GdbThread * t = link_p2t(p->link_p2t.next);
                    if (is_intercepted(t->ctx)) {
                        c->cur_g_pid = p->pid;
                        c->cur_g_tid = t->tid;
                        add_res_str(c, "S00");
                    }
                    else {
                        suspend_debug_context(t->ctx);
                        c->waiting = 1;
                    }
                }
                return 0;
            }
        }
        add_res_str(c, "E01");
        return 0;
    }
    if (strcmp(w, "Cont?") == 0) {
        add_res_str(c, "vCont;c;C;s;S;t;r");
        return 0;
    }
    if (strcmp(w, "Cont") == 0) {
        while (*s++ == ';') {
            char mode = *s++;
            unsigned sig = 0;
            ContextAddress range_fr = 0;
            ContextAddress range_to = 0;
            switch (mode) {
            case 'C':
            case 'S':
                sig = get_cmd_uint8(c, &s);
                break;
            case 'r':
                range_fr = (ContextAddress)get_cmd_uint64(c, &s);
                if (*s == ',') {
                    s++;
                    range_to = (ContextAddress)get_cmd_uint64(c, &s);
                }
                break;
            }
            if (*s == ':') {
                s++;
                get_cmd_ptid(c, &s, &c->cur_g_pid, &c->cur_g_tid);
            }
            if (c->cur_g_tid == ID_ANY) {
                GdbProcess * p = find_process_pid(c, c->cur_g_pid);
                switch (mode) {
                case 'c':
                    continue_debug_context(p->ctx, NULL, RM_RESUME, 1, 0, 0);
                    break;
                case 't':
                    suspend_debug_context(p->ctx);
                    break;
                }
            }
            else {
                GdbThread * t = find_thread(c, c->cur_g_pid, c->cur_g_tid);
                if (t != NULL) {
                    sigset_clear(&t->ctx->pending_signals);
                    switch (mode) {
                    case 'c':
                        continue_debug_context(t->ctx, NULL, RM_RESUME, 1, 0, 0);
                        break;
                    case 'C':
                        sigset_set(&t->ctx->pending_signals, sig, 1);
                        continue_debug_context(t->ctx, NULL, RM_RESUME, 1, 0, 0);
                        break;
                    case 's':
                        continue_debug_context(t->ctx, NULL, RM_STEP_INTO, 1, 0, 0);
                        break;
                    case 'S':
                        sigset_set(&t->ctx->pending_signals, sig, 1);
                        continue_debug_context(t->ctx, NULL, RM_STEP_INTO, 1, 0, 0);
                        break;
                    case 'r':
                        continue_debug_context(t->ctx, NULL, RM_STEP_INTO_RANGE, 1, range_fr, range_to);
                        break;
                    case 't':
                        suspend_debug_context(t->ctx);
                        break;
                    }
                }
            }
        }
        if (list_is_empty(&c->link_c2p)) {
            add_res_str(c, "N");
        }
        else {
            unlock_threads(c);
            c->waiting = 1;
        }
        return 0;
    }
    return 0;
}

static int handle_T_command(GdbClient * c) {
    char * s = c->cmd_buf + 2;
    unsigned pid = 0;
    unsigned tid = 0;
    GdbThread * t = NULL;
    get_cmd_ptid(c, &s, &pid, &tid);
    t = find_thread(c, pid, tid);
    if (t != NULL) {
        add_res_str(c, "OK");
    }
    else {
        add_res_str(c, "E01");
    }
    return 0;
}

static int handle_D_command(GdbClient * c) {
    char * s = c->cmd_buf + 2;
    if (*s++ == ';') {
        unsigned pid = get_cmd_uint(c, &s);
        GdbProcess * p = find_process_pid(c, pid);
        if (p != NULL) {
            detach_process(p);
            add_res_str(c, "OK");
            return 0;
        }
    }
    add_res_str(c, "E01");
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
    case 'v': return handle_v_command(c);
    case 'T': return handle_T_command(c);
    case 'D': return handle_D_command(c);
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
                c->waiting = 0;
                lock_threads(c);
                c->res_pos = 0;
                c->xfer_range_offs = 0;
                c->xfer_range_size = 0;
                add_res_ch_no_esc(c, '$');
                if (handle_command(c) < 0) return -1;
                if (!c->waiting || c->res_pos > 1) {
                    c->waiting = 0;
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
                    if (send_res(c) < 0) return -1;
                }
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
        close_client(c);
    }
    else if (c->req.u.sio.rval == 0) {
        close_client(c);
    }
    else {
        if (read_packet(c, c->req.u.sio.rval) < 0) {
            trace(LOG_ALWAYS, "GDB Server connection terminated: %s", errno_to_str(errno));
            close_client(c);
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
    list_init(&c->link_c2p);
    list_add_last(&c->link_s2c, &s->link_s2c);
    c->client.dispose = dispose_client;

    for (l = context_root.next; l != &context_root; l = l->next) {
        Context * ctx = ctxl2ctxp(l);
        if (!ctx->exited && context_has_state(ctx)) {
            Context * prs = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
            GdbProcess * p = find_process_ctx(c, prs);
            if (p == NULL) p = add_process(c, prs);
        }
    }

    notify_client_connected(&c->client);
    async_req_post(&s->req);

    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)) < 0) {
        trace(LOG_ALWAYS, "GDB Server setsockopt failed: %s", errno_to_str(errno));
        close_client(c);
        return;
    }

    post_event(start_client, c);
}

static int is_all_intercepted(GdbClient * c) {
    LINK * l, * m;
    for (l = c->link_c2p.next; l != &c->link_c2p; l = l->next) {
        GdbProcess * p = link_c2p(l);
        for (m = p->link_p2t.next; m != &p->link_p2t; m = m->next) {
            GdbThread * t = link_p2t(m);
            assert(p->attached);
            assert(!t->ctx->exited);
            assert(context_has_state(t->ctx));
            if (!is_intercepted(t->ctx)) return 0;
        }
    }
    return 1;
}

static void event_context_created(Context * ctx, void * args) {
    if (context_has_state(ctx)) {
        LINK * l, * n;
        Context * prs = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
        for (l = link_a2s.next; l != &link_a2s; l = l->next) {
            GdbServer * s = link_a2s(l);
            for (n = s->link_s2c.next; n != &s->link_s2c; n = n->next) {
                GdbClient * c = link_s2c(n);
                GdbProcess * p = find_process_ctx(c, prs);
                if (p == NULL) p = add_process(c, prs);
                else if (p->attached) add_thread(c, ctx);
            }
        }
    }
}

static void event_context_exited(Context * ctx, void * args) {
    LINK * l, *n, *m, *o;
    for (l = link_a2s.next; l != &link_a2s; l = l->next) {
        GdbServer * s = link_a2s(l);
        for (n = s->link_s2c.next; n != &s->link_s2c; n = n->next) {
            GdbClient * c = link_s2c(n);
            for (m = c->link_c2p.next; m != &c->link_c2p; m = m->next) {
                GdbProcess * p = link_c2p(m);
                if (p->ctx == ctx) {
                    if (c->waiting) {
                        lock_threads(c);
                        if (is_all_intercepted(c)) {
                            c->res_pos = 0;
                            c->waiting = 0;
                            add_res_ch_no_esc(c, '$');
                            add_res_str(c, "W00;process:");
                            add_res_hex(c, p->pid);
                            if (send_res(c) < 0) trace(LOG_ALWAYS, "GDB Server send error: %s", errno_to_str(errno));
                        }
                    }
                    free_process(p);
                    break;
                }
                for (o = p->link_p2t.next; o != &p->link_p2t; o = o->next) {
                    GdbThread * t = link_p2t(o);
                    if (t->ctx == ctx) {
                        free_thread(t);
                        break;
                    }
                }
            }
        }
    }
}

static void event_register_definitions_changed(void * args) {
    LINK * l, * n, * m, * o;
    for (l = link_a2s.next; l != &link_a2s; l = l->next) {
        GdbServer * s = link_a2s(l);
        for (n = s->link_s2c.next; n != &s->link_s2c; n = n->next) {
            GdbClient * c = link_s2c(n);
            for (m = c->link_c2p.next; m != &c->link_c2p; m = m->next) {
                GdbProcess * p = link_c2p(m);
                for (o = p->link_p2t.next; o != &p->link_p2t; o = o->next) {
                    GdbThread * t = link_p2t(o);
                    loc_free(t->regs_nm_map);
                    t->regs_nm_map = NULL;
                }
            }
        }
    }
}

static void event_context_intercepted(Context * ctx, void * args) {
    LINK * l, *n, *m, *o;
    for (l = link_a2s.next; l != &link_a2s; l = l->next) {
        GdbServer * s = link_a2s(l);
        for (n = s->link_s2c.next; n != &s->link_s2c; n = n->next) {
            GdbClient * c = link_s2c(n);
            if (c->waiting) {
                for (m = c->link_c2p.next; m != &c->link_c2p; m = m->next) {
                    GdbProcess * p = link_c2p(m);
                    for (o = p->link_p2t.next; o != &p->link_p2t; o = o->next) {
                        GdbThread * t = link_p2t(o);
                        if (t->ctx == ctx) {
                            if (!c->stopped) {
                                c->cur_g_pid = t->process->pid;
                                c->cur_g_tid = t->tid;
                            }
                            lock_threads(c);
                            if (is_all_intercepted(c)) {
                                c->res_pos = 0;
                                c->waiting = 0;
                                add_res_ch_no_esc(c, '$');
                                add_res_str(c, "S00");
                                if (send_res(c) < 0) trace(LOG_ALWAYS, "GDB Server send error: %s", errno_to_str(errno));
                            }
                        }
                    }
                }
            }
        }
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

static RegistersEventListener registers_listener = {
    NULL,
    event_register_definitions_changed
};

static RunControlEventListener run_ctrl_listener = {
    event_context_intercepted,
    NULL,
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
        add_registers_event_listener(&registers_listener, NULL);
        add_run_control_event_listener(&run_ctrl_listener, NULL);
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
