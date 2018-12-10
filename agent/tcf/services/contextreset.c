/*******************************************************************************
 * Copyright (c) 2019.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *******************************************************************************/
#include <tcf/config.h>

#if SERVICE_ContextReset

#include <tcf/framework/context.h>
#include <tcf/framework/json.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/trace.h>
#include <tcf/services/contextreset.h>

#include <assert.h>

typedef struct ResetInfo ResetInfo;

typedef struct ContextExtensionReset {
    ResetInfo * resets;
    unsigned resets_cnt;
    unsigned resets_max;
} ContextExtensionRS;

struct ResetInfo {
    const char * type;
    const char * desc;
    ContextReset * reset;
};

static const char * CONTEXT_RESET = "ContextReset";
static size_t context_extension_offset = 0;

#define EXT(ctx) (ctx ? ((ContextExtensionRS *)((char *)(ctx) + context_extension_offset)) : NULL)

static ResetInfo * find_reset(Context * ctx, const char * type) {
    if (type != NULL) {
        unsigned i = 0;
        ContextExtensionRS * ext = EXT(ctx);
        while (i < ext->resets_cnt) {
            if (strcmp(ext->resets[i].type, type) == 0)
                return ext->resets + i;
            i++;
        }
    }
    return NULL;
}

void add_reset(Context * ctx, const char * type, const char * desc, ContextReset * reset) {
    ContextExtensionRS * ext = EXT(ctx);
    ResetInfo * ri;
    assert(ctx == context_get_group(ctx, CONTEXT_GROUP_CPU));

    ri = find_reset(ctx, type);
    if (ri == NULL) {
        if (ext->resets_cnt >= ext->resets_max) {
            ext->resets_max += 4;
            ext->resets = (ResetInfo *)loc_realloc(ext->resets, sizeof(ResetInfo) * ext->resets_max);
        }
        ri = ext->resets + ext->resets_cnt++;
        ri->type = loc_strdup(type);
    }
    else {
        loc_free(ri->desc);
    }
    ri->desc = loc_strdup(desc);
    ri->reset = reset;
}

static void command_get_capabilities(char * token, Channel * c) {
    char id[256];
    Context * ctx;
    OutputStream * out = &c->out;
    int err = 0;

    json_read_string(&c->inp, id, sizeof(id));
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    ctx = id2ctx(id);
    if (ctx == NULL) err = ERR_INV_CONTEXT;
    else if (ctx->exited) err = ERR_ALREADY_EXITED;

    write_stringz(out, "R");
    write_stringz(out, token);
    write_errno(out, err);
    write_stream(out, '[');
    if (!err) {
        ContextExtensionRS * ext = EXT(context_get_group(ctx, CONTEXT_GROUP_CPU));
        unsigned i;
        for (i = 0; i < ext->resets_cnt; i++) {
            ResetInfo * ri = ext->resets + i;
            if (i > 0) write_stream(&c->out, ',');
            write_stream(out, '{');
            json_write_string(out, "Type");
            write_stream(out, ':');
            json_write_string(out, ri->type);
            write_stream(out, ',');
            json_write_string(out, "Description");
            write_stream(out, ':');
            json_write_string(out, ri->desc);
            write_stream(out, '}');
        }
    }
    write_stream(out, ']');
    write_stream(out, 0);
    write_stream(out, MARKER_EOM);
}

static void read_reset_params(InputStream * inp, const char * name, void * x) {
    ResetParams * params = (ResetParams *)x;

    if (strcmp(name, "Suspend") == 0) {
        params->suspend = json_read_boolean(inp);
    }
    else {
        ResetParameter * param = (ResetParameter *)loc_alloc_zero(sizeof(ResetParameter));
        param->name = loc_strdup(name);
        param->value = json_read_object(inp);
        param->next = params->list;
        params->list = param;
    }
}

static void command_reset(char * token, Channel * c) {
    char id[256];
    char type[256];
    Context * ctx;
    OutputStream * out = &c->out;
    ResetParams params;
    int err = 0;

    memset(&params, 0, sizeof(params));
    json_read_string(&c->inp, id, sizeof(id));
    json_test_char(&c->inp, MARKER_EOA);
    json_read_string(&c->inp, type, sizeof(type));
    json_test_char(&c->inp, MARKER_EOA);
    json_read_struct(&c->inp, read_reset_params, &params);
    json_test_char(&c->inp, MARKER_EOA);
    json_test_char(&c->inp, MARKER_EOM);

    ctx = id2ctx(id);
    if (ctx == NULL) err = ERR_INV_CONTEXT;
    else if (ctx->exited) err = ERR_ALREADY_EXITED;

    write_stringz(out, "R");
    write_stringz(out, token);
    if (!err) {
        Context * cpu = context_get_group(ctx, CONTEXT_GROUP_CPU);
        ResetInfo * rst = find_reset(cpu, type);
        if (rst == NULL) err = set_errno(ERR_OTHER, "Unsupported reset type");
        else if (rst->reset(ctx, &params) < 0) err = errno;
    }
    while (params.list != NULL) {
        ResetParameter * p = params.list;
        params.list = p->next;
        loc_free(p->name);
        loc_free(p->value);
        loc_free(p);
    }

    write_errno(out, err);
    write_stream(out, 0);
    write_stream(out, MARKER_EOM);
}

static void event_context_disposed(Context * ctx, void * args) {
    ContextExtensionRS * ext = EXT(ctx);
    unsigned i;

    (void)args;
    for (i = 0; i < ext->resets_cnt; i++) {
        ResetInfo * ri = ext->resets + i;
        loc_free(ri->type);
        loc_free(ri->desc);
    }
    loc_free(ext->resets);
}

void ini_context_reset_service(Protocol * proto) {
    static ContextEventListener listener = {
        .context_disposed = event_context_disposed
    };
    add_context_event_listener(&listener, NULL);
    context_extension_offset = context_extension(sizeof(ContextExtensionRS));
    add_command_handler(proto, CONTEXT_RESET, "getCapabilities", command_get_capabilities);
    add_command_handler(proto, CONTEXT_RESET, "reset", command_reset);
}

#endif /* SERVICE_ContextReset */
