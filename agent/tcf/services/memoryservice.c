/*******************************************************************************
 * Copyright (c) 2007, 2013 Wind River Systems, Inc. and others.
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
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * TCF Memory - memory access service.
 */

#include <tcf/config.h>

#if SERVICE_Memory

#include <assert.h>
#include <tcf/framework/protocol.h>
#include <tcf/framework/context.h>
#include <tcf/framework/json.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/channel.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/cache.h>
#include <tcf/services/memoryservice.h>
#include <tcf/services/runctrl.h>

static const char * MEMORY = "Memory";

static TCFBroadcastGroup * broadcast_group = NULL;

#define BYTE_VALID        0x00
#define BYTE_UNKNOWN      0x01
#define BYTE_INVALID      0x02
#define BYTE_CANNOT_READ  0x04
#define BYTE_CANNOT_WRITE 0x08

#define CMD_GET     1
#define CMD_SET     2
#define CMD_FILL    3

#define BUF_SIZE    (128 * MEM_USAGE_FACTOR)

typedef struct MemoryCommandArgs {
    Channel * c;
    char token[256];
    ContextAddress addr;
    unsigned long size;
    int word_size;
    int mode;
    Context * ctx;
    JsonReadBinaryState state;
    char * buf;
    size_t pos;
    size_t max;
} MemoryCommandArgs;

static void write_context(OutputStream * out, Context * ctx) {
    assert(!ctx->exited);

    write_stream(out, '{');

    json_write_string(out, "ID");
    write_stream(out, ':');
    json_write_string(out, ctx->id);

    if (ctx->parent != NULL) {
        write_stream(out, ',');
        json_write_string(out, "ParentID");
        write_stream(out, ':');
        json_write_string(out, ctx->parent->id);
    }

    write_stream(out, ',');
    json_write_string(out, "ProcessID");
    write_stream(out, ':');
    json_write_string(out, context_get_group(ctx, CONTEXT_GROUP_PROCESS)->id);

    if (ctx->name != NULL) {
        write_stream(out, ',');
        json_write_string(out, "Name");
        write_stream(out, ':');
        json_write_string(out, ctx->name);
    }

    write_stream(out, ',');
    json_write_string(out, "BigEndian");
    write_stream(out, ':');
    json_write_boolean(out, ctx->big_endian);

    if (ctx->mem_access) {
        int cnt = 0;

        write_stream(out, ',');
        json_write_string(out, "AddressSize");
        write_stream(out, ':');
        json_write_ulong(out, context_word_size(ctx));

        write_stream(out, ',');
        json_write_string(out, "AccessTypes");
        write_stream(out, ':');
        write_stream(out, '[');
        if (ctx->mem_access & MEM_ACCESS_INSTRUCTION) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "instruction");
        }
        if (ctx->mem_access & MEM_ACCESS_DATA) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "data");
        }
        if (ctx->mem_access & MEM_ACCESS_IO) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "io");
        }
        if (ctx->mem_access & MEM_ACCESS_USER) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "user");
        }
        if (ctx->mem_access & MEM_ACCESS_SUPERVISOR) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "supervisor");
        }
        if (ctx->mem_access & MEM_ACCESS_HYPERVISOR) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "hypervisor");
        }
        if (ctx->mem_access & MEM_ACCESS_VIRTUAL) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "virtual");
        }
        if (ctx->mem_access & MEM_ACCESS_PHYSICAL) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "physical");
        }
        if (ctx->mem_access & MEM_ACCESS_CACHE) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "cache");
        }
        if (ctx->mem_access & MEM_ACCESS_TLB) {
            if (cnt++) write_stream(out, ',');
            json_write_string(out, "tlb");
        }
        write_stream(out, ']');
    }

    write_stream(out, '}');
}

static void write_ranges(OutputStream * out, ContextAddress addr, int offs, int status, MemoryErrorInfo * err_info) {
    int cnt = 0;
    size_t size_valid = 0;
    size_t size_error = 0;

    if (err_info->error) {
        size_valid = err_info->size_valid + offs;
        size_error = err_info->size_error;
    }
    else {
        size_valid = offs;
    }

    write_stream(out, '[');
    if (size_valid > 0) {
        write_stream(out, '{');

        json_write_string(out, "addr");
        write_stream(out, ':');
        json_write_uint64(out, addr);
        write_stream(out, ',');

        json_write_string(out, "size");
        write_stream(out, ':');
        json_write_ulong(out, size_valid);
        write_stream(out, ',');

        json_write_string(out, "stat");
        write_stream(out, ':');
        json_write_ulong(out, 0);

        write_stream(out, '}');
        cnt++;
    }
    if (size_error > 0) {
        if (cnt > 0) write_stream(out, ',');
        write_stream(out, '{');

        json_write_string(out, "addr");
        write_stream(out, ':');
        json_write_uint64(out, addr + size_valid);
        write_stream(out, ',');

        json_write_string(out, "size");
        write_stream(out, ':');
        json_write_ulong(out, size_error);
        write_stream(out, ',');

        json_write_string(out, "stat");
        write_stream(out, ':');
        json_write_ulong(out, BYTE_INVALID | status);
        write_stream(out, ',');

        json_write_string(out, "msg");
        write_stream(out, ':');
        write_error_object(out, err_info->error);

        write_stream(out, '}');
    }
    write_stream(out, ']');
    write_stream(out, 0);
}

static void command_get_context(char * token, Channel * c) {
    int err = 0;
    char id[256];
    Context * ctx = NULL;

    json_read_string(&c->inp, id, sizeof(id));
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    ctx = id2ctx(id);

    if (ctx == NULL || ctx->mem_access == 0) err = ERR_INV_CONTEXT;
    else if (ctx->exited) err = ERR_ALREADY_EXITED;

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);
    write_errno(&c->out, err);
    if (err == 0) {
        write_context(&c->out, ctx);
    }
    else {
        write_string(&c->out, "null");
    }
    write_stream(&c->out, 0);
    write_stream(&c->out, MARKER_EOM);
}

static void command_get_children(char * token, Channel * c) {
    char id[256];

    json_read_string(&c->inp, id, sizeof(id));
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    write_stringz(&c->out, "R");
    write_stringz(&c->out, token);

    write_errno(&c->out, 0);

    write_stream(&c->out, '[');
    if (id[0] == 0) {
        LINK * qp;
        int cnt = 0;
        for (qp = context_root.next; qp != &context_root; qp = qp->next) {
            Context * ctx = ctxl2ctxp(qp);
            if (ctx->parent != NULL) continue;
            if (ctx->exited) continue;
            if (ctx->mem_access == 0 && list_is_empty(&ctx->children)) continue;
            if (cnt > 0) write_stream(&c->out, ',');
            json_write_string(&c->out, ctx->id);
            cnt++;
        }
    }
    else {
        Context * parent = id2ctx(id);
        if (parent != NULL) {
            LINK * l;
            int cnt = 0;
            for (l = parent->children.next; l != &parent->children; l = l->next) {
                Context * ctx = cldl2ctxp(l);
                assert(ctx->parent == parent);
                if (ctx->exited) continue;
                if (ctx->mem_access == 0 && list_is_empty(&ctx->children)) continue;
                if (cnt > 0) write_stream(&c->out, ',');
                json_write_string(&c->out, ctx->id);
                cnt++;
            }
        }
    }
    write_stream(&c->out, ']');
    write_stream(&c->out, 0);

    write_stream(&c->out, MARKER_EOM);
}

static void read_memory_fill_array_cb(InputStream * inp, void * args) {
    MemoryCommandArgs * buf = (MemoryCommandArgs *)args;
    if (buf->pos >= buf->max) {
        buf->max = buf->max == 0 ? BUF_SIZE : buf->max * 2;
        buf->buf = (char *)loc_realloc(buf->buf, buf->max);
    }
    buf->buf[buf->pos++] = (char)json_read_ulong(inp);
}

static MemoryCommandArgs * read_command_args(char * token, Channel * c, int cmd) {
    int err = 0;
    char id[256];
    MemoryCommandArgs buf;
    memset(&buf, 0, sizeof(buf));

    json_read_string(&c->inp, id, sizeof(id));
    json_test_char(&c->inp, MARKER_EOA);
    buf.addr = (ContextAddress)json_read_uint64(&c->inp);
    json_test_char(&c->inp, MARKER_EOA);
    buf.word_size = (int)json_read_long(&c->inp);
    json_test_char(&c->inp, MARKER_EOA);
    buf.size = (int)json_read_long(&c->inp);
    json_test_char(&c->inp, MARKER_EOA);
    buf.mode = (int)json_read_long(&c->inp);
    json_test_char(&c->inp, MARKER_EOA);
    switch (cmd) {
    case CMD_SET:
        json_read_binary_start(&buf.state, &c->inp);
        buf.buf = (char *)loc_alloc(buf.max = BUF_SIZE);
        buf.pos = json_read_binary_data(&buf.state, buf.buf, buf.max);
        break;
    case CMD_GET:
        buf.buf = (char *)loc_alloc(buf.max = buf.size > BUF_SIZE ? BUF_SIZE : buf.size);
        json_test_char(&c->inp, MARKER_EOM);
        break;
    case CMD_FILL:
        json_read_array(&c->inp, read_memory_fill_array_cb, &buf);
        json_test_char(&c->inp, MARKER_EOA);
        json_test_char(&c->inp, MARKER_EOM);
        break;
    }

    buf.ctx = id2ctx(id);
    if (buf.ctx == NULL) err = ERR_INV_CONTEXT;
    else if (buf.ctx->exited) err = ERR_ALREADY_EXITED;
    else if (buf.ctx->mem_access == 0) err = ERR_INV_CONTEXT;

    if (err != 0) {
        if (cmd == CMD_SET) {
            int ch;
            do ch = read_stream(&c->inp);
            while (ch != MARKER_EOM && ch != MARKER_EOS);
        }

        write_stringz(&c->out, "R");
        write_stringz(&c->out, token);
        if (cmd == CMD_GET) write_stringz(&c->out, "null");
        write_errno(&c->out, err);
        write_stringz(&c->out, "null");
        write_stream(&c->out, MARKER_EOM);
        return NULL;
    }
    else {
        MemoryCommandArgs * args = (MemoryCommandArgs *)loc_alloc(sizeof(MemoryCommandArgs));
        *args = buf;
        args->c = c;
        strlcpy(args->token, token, sizeof(args->token));
        channel_lock_with_msg(c, MEMORY);
        context_lock(buf.ctx);
        return args;
    }
}

void send_event_memory_changed(Context * ctx, ContextAddress addr, unsigned long size) {
    OutputStream * out = &broadcast_group->out;

    if (!context_has_state(ctx) || is_intercepted(ctx)) {
        write_stringz(out, "E");
        write_stringz(out, MEMORY);
        write_stringz(out, "memoryChanged");

        json_write_string(out, ctx->id);
        write_stream(out, 0);

        /* <array of addres ranges> */
        write_stream(out, '[');
        write_stream(out, '{');

        json_write_string(out, "addr");
        write_stream(out, ':');
        json_write_uint64(out, addr);

        write_stream(out, ',');

        json_write_string(out, "size");
        write_stream(out, ':');
        json_write_ulong(out, size);

        write_stream(out, '}');
        write_stream(out, ']');
        write_stream(out, 0);

        write_stream(out, MARKER_EOM);
    }
}

static void memory_set_cache_client(void * parm) {
    MemoryCommandArgs * args = (MemoryCommandArgs *)parm;
    Channel * c = args->c;
    Context * ctx = args->ctx;
    ContextAddress addr0 = args->addr;
    ContextAddress addr = args->addr;
    unsigned long size = 0;
    MemoryErrorInfo err_info;
    int err = 0;

    memset(&err_info, 0, sizeof(err_info));
    if (ctx->exiting || ctx->exited) err = ERR_ALREADY_EXITED;

    /* First write needs to be done before cache_exit() */
    if (err == 0) {
        /* TODO: word size, mode */
        if (context_write_mem(ctx, addr, args->buf, args->pos) < 0) {
            err = errno;
#if ENABLE_ExtendedMemoryErrorReports
            context_get_mem_error_info(&err_info);
#endif
        }
        else {
            addr += args->pos;
        }
    }
    size += args->pos;

    cache_exit();

    if (!is_channel_closed(c)) {
        InputStream * inp = &c->inp;
        OutputStream * out = &c->out;
        char * token = args->token;

        for (;;) {
            size_t rd = json_read_binary_data(&args->state, args->buf, args->max);
            if (rd == 0) break;
            if (err == 0) {
                /* TODO: word size, mode */
                if (context_write_mem(ctx, addr, args->buf, rd) < 0) {
                    err = errno;
#if ENABLE_ExtendedMemoryErrorReports
                    context_get_mem_error_info(&err_info);
#endif
                }
                else {
                    addr += rd;
                }
            }
            size += rd;
        }
        json_read_binary_end(&args->state);
        json_test_char(inp, MARKER_EOA);
        json_test_char(inp, MARKER_EOM);

        send_event_memory_changed(ctx, addr0, size);

        write_stringz(out, "R");
        write_stringz(out, token);
        write_errno(out, err);
        if (err == 0) {
            write_stringz(out, "null");
        }
        else {
            write_ranges(out, addr0, (int)(addr - addr0), BYTE_CANNOT_WRITE, &err_info);
        }
        write_stream(out, MARKER_EOM);
    }
    loc_free(args->buf);
    context_unlock(ctx);
    run_ctrl_unlock();
}

static void safe_memory_set(void * parm) {
    MemoryCommandArgs * args = (MemoryCommandArgs *)parm;
    Channel * c = args->c;
    Context * ctx = args->ctx;

    if (!is_channel_closed(c)) {
        run_ctrl_lock();
        context_lock(ctx);
        cache_enter(memory_set_cache_client, c, args, sizeof(MemoryCommandArgs));
    }
    else {
        loc_free(args->buf);
    }
    channel_unlock_with_msg(c, MEMORY);
    context_unlock(ctx);
    loc_free(args);
}

static void command_set(char * token, Channel * c) {
    MemoryCommandArgs * args = read_command_args(token, c, CMD_SET);
    if (args != NULL) post_safe_event(args->ctx, safe_memory_set, args);
}

static void memory_get_cache_client(void * parm) {
    MemoryCommandArgs * args = (MemoryCommandArgs *)parm;
    Context * ctx = args->ctx;
    Channel * c = cache_channel();
    ContextAddress addr0 = args->addr;
    ContextAddress addr = args->addr;
    unsigned long size = args->size;
    unsigned long pos = 0;
    int err = 0;
    MemoryErrorInfo err_info;
    JsonWriteBinaryState state;

    memset(&err_info, 0, sizeof(err_info));
    if (ctx->exiting || ctx->exited) err = ERR_ALREADY_EXITED;

    /* First read needs to be done before cache_exit() */
    if (size > 0) {
        size_t rd = size;
        if (rd > args->max) rd = args->max;
        /* TODO: word size, mode */
        memset(args->buf, 0, rd);
        if (err == 0) {
            if (context_read_mem(ctx, addr, args->buf, rd) < 0) {
                err = errno;
#if ENABLE_ExtendedMemoryErrorReports
                context_get_mem_error_info(&err_info);
#endif
            }
            else {
                addr += rd;
            }
        }
        pos += rd;
    }

    cache_exit();

    if (!is_channel_closed(c)) {
        OutputStream * out = &c->out;

        write_stringz(out, "R");
        write_stringz(out, args->token);

        json_write_binary_start(&state, out, size);
        json_write_binary_data(&state, args->buf, pos);
        while (pos < size) {
            size_t rd = size - pos;
            if (rd > args->max) rd = args->max;
            /* TODO: word size, mode */
            memset(args->buf, 0, rd);
            if (err == 0) {
                if (context_read_mem(ctx, addr, args->buf, rd) < 0) {
                    err = errno;
#if ENABLE_ExtendedMemoryErrorReports
                    context_get_mem_error_info(&err_info);
#endif
                }
                else {
                    addr += rd;
                }
            }
            json_write_binary_data(&state, args->buf, rd);
            pos += rd;
        }
        json_write_binary_end(&state);
        write_stream(out, 0);

        write_errno(out, err);
        if (err == 0) {
            write_stringz(out, "null");
        }
        else {
            write_ranges(out, addr0, (int)(addr - addr0), BYTE_CANNOT_READ, &err_info);
        }
        write_stream(out, MARKER_EOM);
    }
    loc_free(args->buf);
    context_unlock(ctx);
    run_ctrl_unlock();
}

static void safe_memory_get(void * parm) {
    MemoryCommandArgs * args = (MemoryCommandArgs *)parm;
    Channel * c = args->c;
    Context * ctx = args->ctx;

    if (!is_channel_closed(c)) {
        run_ctrl_lock();
        context_lock(ctx);
        cache_enter(memory_get_cache_client, c, args, sizeof(MemoryCommandArgs));
    }
    else {
        loc_free(args->buf);
    }
    channel_unlock_with_msg(c, MEMORY);
    context_unlock(ctx);
    loc_free(args);
}

static void command_get(char * token, Channel * c) {
    MemoryCommandArgs * args = read_command_args(token, c, CMD_GET);
    if (args != NULL) post_safe_event(args->ctx, safe_memory_get, args);
}

static void memory_fill_cache_client(void * parm) {
    MemoryCommandArgs * args = (MemoryCommandArgs *)parm;
    Channel * c = args->c;
    Context * ctx = args->ctx;
    char * tmp = (char *)tmp_alloc(args->pos);
    ContextAddress addr0 = args->addr;
    ContextAddress addr = args->addr;
    unsigned long size = args->size;
    MemoryErrorInfo err_info;
    int err = 0;

    memset(&err_info, 0, sizeof(err_info));
    if (ctx->exiting || ctx->exited) err = ERR_ALREADY_EXITED;

    while (err == 0 && addr < addr0 + size) {
        /* Note: context_write_mem() modifies buffer contents */
        unsigned wr = (unsigned)(addr0 + size - addr);
        if (wr > args->pos) wr = args->pos;
        /* TODO: word size, mode */
        memcpy(tmp, args->buf, wr);
        if (context_write_mem(ctx, addr, tmp, wr) < 0) {
            err = errno;
#if ENABLE_ExtendedMemoryErrorReports
            context_get_mem_error_info(&err_info);
#endif
        }
        else {
            addr += wr;
        }
    }

    cache_exit();

    send_event_memory_changed(ctx, addr0, size);

    if (!is_channel_closed(c)) {
        OutputStream * out = &c->out;
        char * token = args->token;

        write_stringz(out, "R");
        write_stringz(out, token);
        write_errno(out, err);
        if (err == 0) {
            write_stringz(out, "null");
        }
        else {
            write_ranges(out, addr0, (int)(addr - addr0), BYTE_CANNOT_WRITE, &err_info);
        }
        write_stream(out, MARKER_EOM);
    }
    loc_free(args->buf);
    context_unlock(ctx);
    run_ctrl_unlock();
}

static void safe_memory_fill(void * parm) {
    MemoryCommandArgs * args = (MemoryCommandArgs *)parm;
    Channel * c = args->c;
    Context * ctx = args->ctx;

    if (!is_channel_closed(c)) {
        run_ctrl_lock();
        context_lock(ctx);
        /* Grow buffer for faster execution */
        while (args->pos < args->size && args->pos <= args->max / 2) {
            if (args->pos == 0) {
                args->buf[args->pos++] = 0;
            }
            else {
                memcpy(args->buf + args->pos, args->buf, args->pos);
                args->pos *= 2;
            }
        }
        cache_enter(memory_fill_cache_client, c, args, sizeof(MemoryCommandArgs));
    }
    else {
        loc_free(args->buf);
    }
    channel_unlock_with_msg(c, MEMORY);
    context_unlock(ctx);
    loc_free(args);
}

static void command_fill(char * token, Channel * c) {
    MemoryCommandArgs * args = read_command_args(token, c, CMD_FILL);
    if (args != NULL) post_safe_event(args->ctx, safe_memory_fill, args);
}

static void send_event_context_added(Context * ctx) {
    OutputStream * out = &broadcast_group->out;

    write_stringz(out, "E");
    write_stringz(out, MEMORY);
    write_stringz(out, "contextAdded");

    /* <array of context data> */
    write_stream(out, '[');
    write_context(out, ctx);
    write_stream(out, ']');
    write_stream(out, 0);

    write_stream(out, MARKER_EOM);
}

static void send_event_context_changed(Context * ctx) {
    OutputStream * out = &broadcast_group->out;

    write_stringz(out, "E");
    write_stringz(out, MEMORY);
    write_stringz(out, "contextChanged");

    /* <array of context data> */
    write_stream(out, '[');
    write_context(out, ctx);
    write_stream(out, ']');
    write_stream(out, 0);

    write_stream(out, MARKER_EOM);
}

static void send_event_context_removed(Context * ctx) {
    OutputStream * out = &broadcast_group->out;

    write_stringz(out, "E");
    write_stringz(out, MEMORY);
    write_stringz(out, "contextRemoved");

    /* <array of context IDs> */
    write_stream(out, '[');
    json_write_string(out, ctx->id);
    write_stream(out, ']');
    write_stream(out, 0);

    write_stream(out, MARKER_EOM);
}

static void event_context_created(Context * ctx, void * args) {
    if (ctx->mem_access == 0) return;
    send_event_context_added(ctx);
}

static void event_context_changed(Context * ctx, void * args) {
    if (ctx->mem_access == 0) return;
    send_event_context_changed(ctx);
}

static void event_context_exited(Context * ctx, void * args) {
    if (ctx->mem_access == 0) return;
    send_event_context_removed(ctx);
}

void ini_memory_service(Protocol * proto, TCFBroadcastGroup * bcg) {
    static ContextEventListener listener = {
        event_context_created,
        event_context_exited,
        NULL,
        NULL,
        event_context_changed
    };
    broadcast_group = bcg;
    add_context_event_listener(&listener, NULL);
    add_command_handler(proto, MEMORY, "getContext", command_get_context);
    add_command_handler(proto, MEMORY, "getChildren", command_get_children);
    add_command_handler(proto, MEMORY, "set", command_set);
    add_command_handler(proto, MEMORY, "get", command_get);
    add_command_handler(proto, MEMORY, "fill", command_fill);
}

#endif /* SERVICE_Memory */
