/*******************************************************************************
 * Copyright (c) 2016-2017 Wind River Systems, Inc.
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
 * Implements input and output stream over WebSocket (both secured and
 * insecured).
 * This is implemented on top of libwebsockets library; for more information
 * about libwebsockets, look at https://libwebsockets.org/.
 */
#if defined(__GNUC__) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE
#endif
#include <tcf/config.h>

#if ENABLE_LibWebSockets
#include <fcntl.h>
#include <stddef.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#if defined(__linux__)
#include <sys/epoll.h>
#endif
#include <tcf/framework/mdep-threads.h>
#include <tcf/framework/mdep-fs.h>
#include <tcf/framework/mdep-inet.h>
#include <tcf/framework/tcf.h>
#include <tcf/framework/channel.h>
#include <tcf/framework/channel_lws.h>
#include <tcf/framework/channel_lws_ext.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/protocol.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/events.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/json.h>
#include <tcf/framework/peer.h>
#include <tcf/framework/ip_ifc.h>
#include <tcf/framework/asyncreq.h>
#include <tcf/framework/inputbuf.h>
#include <tcf/framework/outputbuf.h>
#include <tcf/services/discovery.h>
#include <libwebsockets.h>

#ifdef WIN32
#ifndef ECONNREFUSED
#define ECONNREFUSED    WSAECONNREFUSED
#endif
#endif

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

#if defined(__linux__)
#define ENABLE_Epoll    1
#else
#define ENABLE_Epoll    0
#endif

/* It seems that epoll and poll events macros are identical. This is
 * tested in the init routine. Let's make the conversion routine a nop.
 */
#define POLL_TO_EPOLL_EVENT(events,eevents) eevents = events;
#define EPOLL_TO_POLL_EVENT(events,eevents) events = eevents;

#define BUF_SIZE                    OUTPUT_QUEUE_BUF_SIZE
#define CHANNEL_MAGIC               0x43253234
#define MAX_IFC                     10
#define MAX_CONTEXT_THREADS         8
#define MAX_CONN_REQUESTS           16

typedef struct ChannelConnectInfo {
    LINK link;
    ChannelConnectCallBack callback;
    void *      callback_args;
    int         is_ssl;
    int         self_signed;
    int         port;
    char *      host;
    const char * get_url;
    int error;
    struct SessionData * data;
    const char * ca_filepath;
    const char * certificate;
    const char * cipher_list;
    const char * key;
    unsigned int options;
} ChannelConnectInfo;

typedef struct ServerCreateInfo {
    LINK link;
    int port;
    int error;
    const char * ca_filepath;
    const char * certificate;
    const char * key;
    const char * cipher_list;
    unsigned int options;
    struct ServerWS * si;
} ServerCreateInfo;

#define link2cci(A)  ((ChannelConnectInfo *)((char *)(A) - offsetof(ChannelConnectInfo, link)))
#define link2sci(A)  ((ServerCreateInfo *)((char *)(A) - offsetof(ServerCreateInfo, link)))

typedef struct ChannelWS {
    Channel * chan;         /* Public channel information - must be first */
    int magic;              /* Magic number */
    int lock_cnt;           /* Stream lock count, when > 0 channel cannot be deleted */
    int read_pending;       /* Read request is pending */
    int read_done_posted;
    unsigned char * read_buf;
    ssize_t read_buf_size;
    int read_done;

    /* Input stream buffer */
    InputBuf ibuf;

    /* Output stream state */
    unsigned char * out_bin_block;
    OutputBuffer * obuf;
    int out_errno;
    int out_flush_cnt;      /* Number of posted lazy flush events */
    int out_eom_cnt;        /* Number of end-of-message markers in the output buffer */
    OutputQueue out_queue;
    int is_ssl;
    struct {
        char data [BUF_SIZE +  LWS_SEND_BUFFER_PRE_PADDING +
                        LWS_SEND_BUFFER_POST_PADDING];
        ssize_t len;
        ssize_t written;
        int error;
    } outbuf;
    struct ChannelInputBuffer * inbuf;
    struct SessionData * data;
    int closing;
} ChannelWS;

typedef struct ChannelInputBuffer ChannelInputBuffer;
struct ChannelInputBuffer {
    void * in;
    ssize_t len;
    struct ChannelInputBuffer * next;
    int error;
    struct SessionData * data;
};

typedef struct ServerWS {
    ChannelServer serv;
    LINK        servlink;
    int         is_ssl;
    int         exiting;
} ServerWS;

typedef struct SessionData {
     pthread_mutex_t    mutex;
     ChannelWS * c;
     ServerWS * si;     /* server structure (null if client connection) */
     struct lws * wsi;
     struct sockaddr * addr_buf; /* Socket remote address */
     socklen_t addr_len;
     char ** prop_names;
     char ** prop_values;
     unsigned prop_cnt;
} SessionData;

typedef struct WSIUserData {
    SessionData * data;         /* session data */
    ChannelConnectInfo * args;  /* connection args (client connection only) */
    void * cb_arg;
} WSIUserData;

static size_t           channel_lws_extension_offset = 0;

#define EXT(ctx)        ((ChannelWS **)((char *)(ctx) + channel_lws_extension_offset))

#define channel2ws(A)   (*EXT(A))
#define inp2channel(A)  ((Channel *)((char *)(A) - offsetof(Channel, inp)))
#define out2channel(A)  ((Channel *)((char *)(A) - offsetof(Channel, out)))
#define server2ws(A)    ((ServerWS *)((char *)(A) - offsetof(ServerWS, serv)))
#define servlink2np(A)  ((ServerWS *)((char *)(A) - offsetof(ServerWS, servlink)))
#define ibuf2ws(A)      ((ChannelWS *)((char *)(A) - offsetof(ChannelWS, ibuf)))
#define obuf2ws(A)      ((ChannelWS *)((char *)(A) - offsetof(ChannelWS, out_queue)))

static void lws_channel_read_done(void * x);
static void handle_channel_msg(void * x);
static int lws_tcf_callback(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len);
static void server_lws_connect_done(void * x);
static void channel_lws_connect_done(void * x);
static void lws_shutdown(ChannelWS * c);
static void done_write_request(void * args);
static void lws_lock(Channel * channel);
static void lws_unlock(Channel * channel);

static LINK server_list;
static pthread_mutex_t lws_list_mutex;
static LINK client_connect_list = TCF_LIST_INIT(client_connect_list);
static LINK server_create_list = TCF_LIST_INIT(server_create_list);
static int pending_connections = 0; /* number of simultaneous pending connections */
static int dummy_socket = -1; /* dummy IP socket we use for various operations */
static struct lws_vhost * client_vhost = NULL;

#if ENABLE_Epoll
static int epoll_fd;            /* epoll file descriptor for lws context */
static uint32_t * epoll_events; /* epoll events for lws context */
static int dummy_pipe_fds[2];
#endif
static int deny_deflate;
static pthread_mutex_t poll_mutex;
static struct lws_context *lws_ctx;


/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] = {
    {"tcf", lws_tcf_callback, sizeof(WSIUserData), BUF_SIZE},
    {NULL, NULL, 0, 0 } /* end */
};

static const struct lws_extension exts[] = {
    {
        "permessage-deflate",
        lws_extension_callback_pm_deflate,
        "permessage-deflate; client_max_window_bits"
    },
    {
        "deflate-frame",
        lws_extension_callback_pm_deflate,
        "deflate_frame"
    },
    {NULL, NULL, NULL /* terminator */ }
};

#if ENABLE_Epoll
static void channel_lws_abort_epoll() {
    char buf = 0;
    if (write(dummy_pipe_fds[1], &buf, 1));
}
#endif

static void lws_channel_event_read (void * args) {
    ChannelInputBuffer * buf = (ChannelInputBuffer *)args;
    ChannelWS * c;

    pthread_mutex_lock(&buf->data->mutex);
    c = buf->data->c;
    if (buf->data->c) {
        if (c->inbuf) {
            ChannelInputBuffer * inbuf;
            for (inbuf = c->inbuf; inbuf->next != NULL ; inbuf =
                    inbuf->next)
                ;
            assert (inbuf->next == NULL);
            buf->next = NULL;
            inbuf->next = buf;
        }
        else {
            buf->next = NULL;
            c->inbuf = buf;
        }
        if (buf->len == 0) c->closing = 1;
        if (c->read_pending) {
            if (!c->read_done_posted) {
                c->read_done_posted = 1;
                post_event(lws_channel_read_done, c);
            }
        }
        if (c->closing) {
            /* The channel is now closed; post an additional lws_unlock
             * call to trigger the deletion of the channel. The original
             * lock was done when the channel was established
             */
            post_event((EventCallBack *)lws_unlock, c->chan);
        }
    }
    pthread_mutex_unlock(&buf->data->mutex);
}

static void lws_add_channel_property(SessionData * data, char * name, char * value) {
    data->prop_names = (char **)loc_realloc(data->prop_names, (data->prop_cnt + 1) * sizeof(char *));
    data->prop_values = (char **)loc_realloc(data->prop_values, (data->prop_cnt + 1) * sizeof(char *));
    data->prop_names[data->prop_cnt] = name;
    data->prop_values[data->prop_cnt] = value;
    data->prop_cnt++;
}

static void lws_parse_http_header(SessionData * data, struct lws * wsi) {
    int n = 0, len;
    char * prop_name;
    char * prop_value;

    /* Do not extract all properties but only the one that we (currently)
     * consider as useful; that is the URI and URI args. Extracting
     * all properties may require a lot of memory (especially with cookies).
     */
    len = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
    if (len) {
        prop_name = (char *)loc_strdup("get_uri");
        prop_value = (char *)loc_alloc_zero(len + 1);
        lws_hdr_copy(wsi, prop_value, len + 1, WSI_TOKEN_GET_URI);
        lws_add_channel_property(data, prop_name, prop_value);
    }
    len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_URI_ARGS);
    if (len) {
        char * buf = (char *)loc_alloc_zero(len + 1);
        n = 0;
        while (lws_hdr_copy_fragment(wsi, buf, len + 1,
                                     WSI_TOKEN_HTTP_URI_ARGS, n) > 0) {
            prop_name = (char *)loc_alloc_zero(32);
            sprintf(prop_name, "uri-args_%d", n);
            prop_value = loc_strdup(buf);
            lws_add_channel_property(data, prop_name, prop_value);
            n++;
        }
        loc_free(buf);
    }
}

static int lws_tcf_callback(struct lws * wsi, enum lws_callback_reasons reason, void * user, void *in, size_t len) {
    struct lws_pollargs *pa = (struct lws_pollargs *)in;
    WSIUserData * userdata = (WSIUserData *) user;

    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
        case LWS_CALLBACK_ESTABLISHED:
            {
                assert (userdata != NULL);
                int is_server = (reason == LWS_CALLBACK_ESTABLISHED);

                /* Allocate session data. Note that the session data will
                 * be freed from the dispatch thread to avoid any race
                 * condition. Any update to the SessionData will be done
                 * while holding the session data mutex.
                 */

                SessionData * data;

                if (LWS_CALLBACK_USER_HOOK(&userdata->cb_arg, wsi, reason, user, in, len)) return 1;

                data = (SessionData *)loc_alloc_zero(sizeof (SessionData));
#if defined(SOCK_MAXADDRLEN)
                data->addr_len = SOCK_MAXADDRLEN;
#else
                data->addr_len = 0x1000;
#endif
                pthread_mutex_init(&data->mutex, NULL);
                data->wsi = wsi;
                data->addr_buf = (struct sockaddr *)loc_alloc_zero(data->addr_len);
                if (getpeername(lws_get_socket_fd(wsi),
                        data->addr_buf, &data->addr_len) != 0) {
                    data->addr_len = 0;
                }

                userdata->data = data;
                if (is_server) {
                    data->si = *(ServerWS **) lws_protocol_vh_priv_get(lws_vhost_get(wsi), protocols);
#if defined(LWS_OPENSSL_SUPPORT)
                    X509 * certificate = NULL;
                    if (in) certificate = SSL_get_peer_certificate((const SSL *)in);
                    if (certificate) {
                        char * name = X509_NAME_oneline(X509_get_subject_name(certificate), 0, 0);
                        if (name) lws_add_channel_property(data, loc_strdup("PeerCertName"), loc_strdup(name));
                        free(name);
                        X509_free(certificate);
                    }
#endif
                    lws_parse_http_header(data, wsi);

                    post_event(server_lws_connect_done, data);
                }
                else {
                    ChannelConnectInfo * args = userdata->args;
                    args->data = data;
                    userdata->args = NULL;
                    post_event(channel_lws_connect_done, args);
                }
                break;
            }
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            {
                assert (userdata != NULL);
                ChannelConnectInfo * args = userdata->args;

                /* connection error hook is called multiple times; make
                 * sure we do not call the channel connection callback
                 * multiple times; use the error field to detect this.
                 */
                if (args) {
                    args->error = ECONNREFUSED;
                    userdata->args = NULL;
                    (void) LWS_CALLBACK_USER_HOOK(&userdata->cb_arg, wsi, reason, user, in, len);
                    post_event(channel_lws_connect_done, args);
                }
            }
            break;

        case LWS_CALLBACK_CLOSED:
            {
                assert (userdata != NULL);
                SessionData * data = userdata->data;

                if (data != NULL) {
                    ChannelInputBuffer * buf = (ChannelInputBuffer *)loc_alloc_zero(sizeof(ChannelInputBuffer));

                    buf->data = data;
                    pthread_mutex_lock(&buf->data->mutex);
                    assert (buf->data->wsi != NULL);
                    buf->data->wsi = NULL;
                    /* The channel can now be closed. The channel was original locked when
                     * it was created to make sure it can be safely referenced in the service
                     * thread; at this point we know it will no longer be used; we can
                     * unlock it.
                     */
                    if (data->c)  {
                        if (data->c->outbuf.len > 0 && data->c->outbuf.written == 0) {
                            data->c->outbuf.written = -1;
                            data->c->outbuf.len = 0;
                            data->c->outbuf.error = ECONNRESET;
                            post_event(done_write_request, data->c);
                        }
                    }
                    post_event(lws_channel_event_read, buf);
                    pthread_mutex_unlock(&data->mutex);

                    /* At this point, this session data will no longer be used
                     * again by the LWS context; we can safely delete it from
                     * the dispatch thread.
                     */

                 }
                (void)LWS_CALLBACK_USER_HOOK(&userdata->cb_arg, wsi, reason, user, in, len);
            }
            break;

        case LWS_CALLBACK_RECEIVE:
        case LWS_CALLBACK_CLIENT_RECEIVE:
            assert (userdata != NULL);

            if (len > 0) {
                ChannelInputBuffer * buf = (ChannelInputBuffer *)loc_alloc_zero(sizeof(ChannelInputBuffer));
                SessionData * data = userdata->data;
                buf->in = loc_alloc_zero(len);
                buf->len = len;
                buf->data = data;
                memcpy(buf->in, in, len);
                post_event(lws_channel_event_read, buf);
            }
            break;

        case LWS_CALLBACK_SERVER_WRITEABLE:
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            {
                assert (userdata != NULL);
                SessionData * data = userdata->data;
                int n;
                pthread_mutex_lock(&data->mutex);
                if (data->c->outbuf.written != 0 || data->c->outbuf.len == 0) {
                    pthread_mutex_unlock(&data->mutex);
                    return 0;
                }
                if (data->c->outbuf.len == -1) {
                    /* close connection */
                    pthread_mutex_unlock(&data->mutex);
                    return 1;
                }
                n = lws_write(wsi, (unsigned char *)data->c->outbuf.data + LWS_SEND_BUFFER_PRE_PADDING, data->c->outbuf.len, LWS_WRITE_BINARY);
                if (n < 0) {
                    data->c->outbuf.written = -1;
                    data->c->outbuf.error = errno;
                } else {
                    data->c->outbuf.written = n;
                    data->c->outbuf.error = 0;
                }
                data->c->outbuf.len = 0;
                pthread_mutex_unlock(&data->mutex);
                post_event(done_write_request, data->c);
            }
            break;

        case LWS_CALLBACK_WSI_DESTROY:
            if (lws_vhost_get(wsi) == client_vhost) {
                loc_free(userdata);
            }
            break;

        case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
            if (LWS_CALLBACK_USER_HOOK(&userdata->cb_arg, wsi, reason, user, in, len)) return 1;
            if ((strcmp((const char *)in, "deflate-stream") == 0) && deny_deflate) {
                lwsl_notice("denied deflate-stream extension\n");
                return 1;
            }
            if ((strcmp((const char *)in, "x-webkit-deflate-frame") == 0)) return 1;
            if ((strcmp((const char *)in, "deflate-frame") == 0)) return 1;
            break;

#if defined(LWS_OPENSSL_SUPPORT)
        case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
        {
            int preverify_ok = len;
            X509_STORE_CTX *ctx = (X509_STORE_CTX *)user;
            char    buf[256];
            int     err, depth;

            if (LWS_CALLBACK_USER_HOOK(&userdata->cb_arg, wsi, reason, user, in, len)) return 1;

            err = X509_STORE_CTX_get_error(ctx);

            if (!preverify_ok) {
                X509 * err_cert = X509_STORE_CTX_get_current_cert(ctx);
                X509_NAME_oneline(X509_get_subject_name(err_cert), buf,
                        sizeof(buf));
                depth = X509_STORE_CTX_get_error_depth(ctx);
                trace( LOG_PROTOCOL, "Client certificate verify error:num=%d:%s:depth=%d:%s", err,
                X509_verify_cert_error_string(err), depth, buf);
            }

            /*
             * At this point, err contains the last verification error. We can use
             * it for something special
             */
            if (!preverify_ok
                    && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
                X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf,
                        sizeof(buf));
                trace( LOG_PROTOCOL, "Client certificate issuer= %s", buf);
            }

            if (!preverify_ok) return 1;
            break;
        }
#endif

        case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
            (void)LWS_CALLBACK_USER_HOOK(&userdata->cb_arg, wsi, reason, user, in, len);
            break;

        case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
            (void)LWS_CALLBACK_USER_HOOK(&userdata->cb_arg, wsi, reason, user, in, len);
            break;

        /*
         * callbacks for managing the external poll() array appear in
         * protocol 0 callback
         */

        case LWS_CALLBACK_LOCK_POLL:
            /*
             * lock mutex to protect pollfd state
             * called before any other POLL related callback
             * if protecting wsi lifecycle change, len == 1
             */
            if (len) pthread_mutex_lock(&poll_mutex);
            break;

        case LWS_CALLBACK_UNLOCK_POLL:
            /*
             * unlock mutex to protect pollfd state when
             * called after any other POLL related callback
             * if protecting wsi lifecycle change, len == 1
             */
            if (len) pthread_mutex_unlock(&poll_mutex);
            break;

#if ENABLE_Epoll
        case LWS_CALLBACK_ADD_POLL_FD:
        {
            struct epoll_event event;
            POLL_TO_EPOLL_EVENT(pa->events, epoll_events[pa->fd]);
            memset(&event, 0, sizeof(struct epoll_event));
            event.data.fd = pa->fd;
            event.events = epoll_events[pa->fd];
            if (epoll_ctl (epoll_fd, EPOLL_CTL_ADD, pa->fd, &event) != 0) return 1;
            break;
        }

        case LWS_CALLBACK_DEL_POLL_FD:
            if (epoll_ctl (epoll_fd, EPOLL_CTL_DEL, pa->fd, NULL) != 0) return 1;
            break;

        case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
        {
            struct epoll_event event;
            memset(&event, 0, sizeof(struct epoll_event));
            POLL_TO_EPOLL_EVENT(pa->events, epoll_events[pa->fd]);
            event.data.fd = pa->fd;
            event.events = epoll_events[pa->fd];
            if (epoll_ctl (epoll_fd, EPOLL_CTL_MOD, pa->fd, &event) != 0) return 1;
            break;
        }
#endif

        case LWS_CALLBACK_GET_THREAD_ID:
            {
                /*
                 * For lws multi-thread support, we need to return a different
                 * thread ID for each thread.
                 *
                 * On Windows, thread ID does not fit on a 32-bit, let's use
                 * thread index instead of thread ID. Note that we must never
                 * return 0 since this will disable locking.
                 */

                if (is_dispatch_thread()) return 1;
                else return 2;
            }
            break;
        default:
            if (LWS_CALLBACK_USER_HOOK(&userdata->cb_arg, wsi, reason, user, in, len)) return 1;
            break;
    }
    return 0;
}

static void delete_channel(ChannelWS * c) {
    unsigned ix;
    trace(LOG_PROTOCOL, "Deleting channel %#lx", c);
    assert(c->lock_cnt == 0);
    assert(c->out_flush_cnt == 0);
    assert(c->magic == CHANNEL_MAGIC);
    assert(c->read_pending == 0);
    assert(c->ibuf.handling_msg != HandleMsgTriggered);
    channel_clear_broadcast_group(c->chan);
    list_remove(&c->chan->chanlink);
    if (list_is_empty(&channel_root) && list_is_empty(&channel_server_root))
        shutdown_set_stopped(&channel_shutdown);
    c->magic = 0;
    output_queue_clear(&c->out_queue);
    output_queue_free_obuf(c->obuf);
    loc_free(c->ibuf.buf);
    loc_free(c->chan->peer_name);
    loc_free(c->data->addr_buf);
    if (c->data->prop_cnt) {
        for (ix = 0; ix < c->data->prop_cnt; ix++) {
            loc_free(c->data->prop_names[ix]);
            loc_free(c->data->prop_values[ix]);
        }
        loc_free(c->data->prop_names);
        loc_free(c->data->prop_values);
    }
    loc_free(c->data);
    channel_free(c->chan);
    loc_free(c);
}

static void lws_lock(Channel * channel) {
    ChannelWS * c = channel2ws(channel);
    assert(is_dispatch_thread());
    assert(c->magic == CHANNEL_MAGIC);
    c->lock_cnt++;
}

static void lws_unlock(Channel * channel) {
    ChannelWS * c = channel2ws(channel);
    assert(is_dispatch_thread());
    assert(c->magic == CHANNEL_MAGIC);
    assert(c->lock_cnt > 0);
    c->lock_cnt--;
    if (c->lock_cnt == 0) {
        assert(!c->read_pending);
        delete_channel(c);
    }
}
static int lws_is_closed(Channel * channel) {
    ChannelWS * c = channel2ws(channel);
    assert(is_dispatch_thread());
    assert(c->magic == CHANNEL_MAGIC);
    assert(c->lock_cnt > 0);
    return c->chan->state == ChannelStateDisconnected;
}

static void done_write_request(void * args) {
    ChannelWS * c = (ChannelWS *)args;
    int size = 0;
    int error = 0;

    assert (c->out_errno == 0);
    pthread_mutex_lock(&c->data->mutex);
    if (c->outbuf.written < 0) error = c->outbuf.error;
    size = c->outbuf.written;
    c->outbuf.written = 0;
    c->outbuf.len = 0;
    pthread_mutex_unlock(&c->data->mutex);
    output_queue_done(&c->out_queue, error, size);
    if (error) c->out_errno = error;
    if (output_queue_is_empty(&c->out_queue) &&
        c->chan->state == ChannelStateDisconnected) lws_shutdown(c);
    lws_unlock(c->chan);
}

static void post_write_request(OutputBuffer * bf) {
    ChannelWS * c = obuf2ws(bf->queue);
    int posted = 0;

    pthread_mutex_lock(&c->data->mutex);

    /* We should not enter here before previous send has been handled */
    assert (c->outbuf.len == 0);

    if (!c->closing && c->data->wsi) {
        int res = 0;
        c->outbuf.written = 0;
        c->outbuf.len = bf->buf_len - bf->buf_pos;
        if (c->outbuf.len > BUF_SIZE) c->outbuf.len = BUF_SIZE;
        memcpy((unsigned char*)c->outbuf.data + LWS_SEND_BUFFER_PRE_PADDING, bf->buf + bf->buf_pos, c->outbuf.len);
        res = lws_callback_on_writable(c->data->wsi);
        if (res >= 0) {
            posted = 1;
            lws_lock(c->chan);
        }
    }

    if (!posted) {
        c->outbuf.written = -1;
        c->outbuf.error = ECONNRESET;
        post_event(done_write_request, c);
        lws_lock(c->chan);
    }
    pthread_mutex_unlock(&c->data->mutex);
}

static void lws_flush_with_flags(ChannelWS * c, int flags) {
    unsigned char * p = c->obuf->buf;
    assert(is_dispatch_thread());
    assert(c->magic == CHANNEL_MAGIC);
    assert(c->chan->out.end == p + sizeof(c->obuf->buf));
    assert(c->out_bin_block == NULL);
    assert(c->chan->out.cur >= p);
    assert(c->chan->out.cur <= p + sizeof(c->obuf->buf));
    if (c->chan->out.cur == p) return;
    if (c->chan->state != ChannelStateDisconnected && c->out_errno == 0) {
        c->obuf->buf_len = c->chan->out.cur - p;
        c->out_queue.post_io_request = post_write_request;
        trace(LOG_PROTOCOL, "Outbuf add size:%d",c->obuf->buf_len);

        output_queue_add_obuf(&c->out_queue, c->obuf);
        c->obuf = output_queue_alloc_obuf();
        c->chan->out.end = c->obuf->buf + sizeof(c->obuf->buf);
    }
    c->chan->out.cur = c->obuf->buf;
    c->out_eom_cnt = 0;
}

static void lws_flush_event(void * x) {
    ChannelWS * c = (ChannelWS *)x;
    assert(c->magic == CHANNEL_MAGIC);
    if (--c->out_flush_cnt == 0) {
        int congestion_level = c->chan->congestion_level;
        if (congestion_level > 0) usleep(congestion_level * 2500);
        lws_flush_with_flags(c, 0);
        lws_unlock(c->chan);
    }
    else if (c->out_eom_cnt > 3) {
        lws_flush_with_flags(c, 0);
    }
}

static void lws_bin_block_start(ChannelWS * c) {
    *c->chan->out.cur++ = ESC;
    *c->chan->out.cur++ = 3;
#if BUF_SIZE > 0x4000
    *c->chan->out.cur++ = 0;
#endif
    *c->chan->out.cur++ = 0;
    *c->chan->out.cur++ = 0;
    c->out_bin_block = c->chan->out.cur;
}

static void lws_bin_block_end(ChannelWS * c) {
    size_t len = c->chan->out.cur - c->out_bin_block;
    if (len == 0) {
#if BUF_SIZE > 0x4000
        c->chan->out.cur -= 5;
#else
        c->chan->out.cur -= 4;
#endif
    }
    else {
#if BUF_SIZE > 0x4000
        *(c->out_bin_block - 3) = (len & 0x7fu) | 0x80u;
        *(c->out_bin_block - 2) = ((len >> 7) & 0x7fu) | 0x80u;
        *(c->out_bin_block - 1) = (unsigned char)(len >> 14);
#else
        *(c->out_bin_block - 2) = (len & 0x7fu) | 0x80u;
        *(c->out_bin_block - 1) = (unsigned char)(len >> 7);
#endif
    }
    c->out_bin_block = NULL;
}

static void lws_write_stream(OutputStream * out, int byte) {
    ChannelWS * c = channel2ws(out2channel(out));
    assert(c->magic == CHANNEL_MAGIC);
    if (!c->chan->out.supports_zero_copy || c->chan->out.cur >= c->chan->out.end - 32 || byte < 0) {
        if (c->out_bin_block != NULL) lws_bin_block_end(c);
        if (c->chan->out.cur == c->chan->out.end) lws_flush_with_flags(c, MSG_MORE);
        if (byte < 0 || byte == ESC) {
            char esc = 0;
            *c->chan->out.cur++ = ESC;
            if (byte == ESC) esc = 0;
            else if (byte == MARKER_EOM) esc = 1;
            else if (byte == MARKER_EOS) esc = 2;
            else assert(0);
            if (c->chan->out.cur == c->chan->out.end) lws_flush_with_flags(c, MSG_MORE);
            *c->chan->out.cur++ = esc;
            if (byte == MARKER_EOM) {
                c->out_eom_cnt++;
                if (c->out_flush_cnt < 2) {
                    if (c->out_flush_cnt++ == 0) lws_lock(c->chan);
                    /*post_event_with_delay(lws_flush_event, c, 0);*/
                    post_event(lws_flush_event, c);
                }
            }
            return;
        }
    }
    else if (c->out_bin_block == NULL) {
        lws_bin_block_start(c);
    }
    *c->chan->out.cur++ = (char)byte;
}

static void lws_write_block_stream(OutputStream * out, const char * bytes, size_t size) {
    unsigned char * src = (unsigned char *)bytes;
    ChannelWS * c = channel2ws(out2channel(out));
    while (size > 0) {
        size_t n = out->end - out->cur;
        if (n > size) n = size;
        if (n == 0) {
            lws_write_stream(out, *src++);
            size--;
        }
        else if (c->out_bin_block) {
            memcpy(out->cur, src, n);
            out->cur += n;
            size -= n;
            src += n;
        }
        else if (*src != ESC) {
            unsigned char * dst = out->cur;
            unsigned char * end = dst + n;
            do {
                unsigned char ch = *src;
                if (ch == ESC) break;
                *dst++ = ch;
                src++;
            }
            while (dst < end);
            size -= dst - out->cur;
            out->cur = dst;
        }
        else {
            lws_write_stream(out, *src++);
            size--;
        }
    }
}

static ssize_t lws_splice_block_stream(OutputStream * out, int fd, size_t size, int64_t * offset) {
    assert(is_dispatch_thread());
    if (size == 0) return 0;
    {
        ssize_t rd;
        char buffer[BUF_SIZE];
        if (size > BUF_SIZE) size = BUF_SIZE;
        if (offset != NULL) {
            rd = pread(fd, buffer, size, (off_t)*offset);
            if (rd > 0) *offset += rd;
        }
        else {
            rd = read(fd, buffer, size);
        }
        if (rd > 0) lws_write_block_stream(out, buffer, rd);
        return rd;
    }
}

static void lws_post_read(InputBuf * ibuf, unsigned char * buf, size_t size) {
    ChannelWS * c = ibuf2ws(ibuf);
    if (c->read_pending) return;
    c->read_pending = 1;
    c->read_buf = buf;
    c->read_buf_size = size;
    if (c->inbuf) {
        if (!c->read_done_posted) {
            c->read_done_posted = 1;
            post_event(lws_channel_read_done, c);
        }
    }
    else if (c->closing) {
        if (!c->read_done_posted) {
            c->read_done_posted = 1;
            post_event(lws_channel_read_done, c);
        }
    }
}

static void lws_wait_read(InputBuf * ibuf) {
    ChannelWS * c = ibuf2ws(ibuf);

    /* Wait for read to complete */
    assert(c->lock_cnt > 0);
    assert(c->read_pending != 0);
    if (c->read_done_posted) cancel_event(lws_channel_read_done, c, 1);
    lws_channel_read_done(c);
}

static int lws_read_stream(InputStream * inp) {
    Channel * channel = inp2channel(inp);
    ChannelWS * c = channel2ws(channel);

    assert(c->lock_cnt > 0);
    if (inp->cur < inp->end) return *inp->cur++;
    return ibuf_get_more(&c->ibuf, 0);
}

static int lws_peek_stream(InputStream * inp) {
    Channel * channel = inp2channel(inp);
    ChannelWS * c = channel2ws(channel);

    assert(c->lock_cnt > 0);
    if (inp->cur < inp->end) return *inp->cur;
    return ibuf_get_more(&c->ibuf, 1);
}

static void lws_shutdown(ChannelWS * c) {
    pthread_mutex_lock(&c->data->mutex);
    if (c->data->wsi) {
        c->outbuf.len = -1;
        /* Post a write request that will trigger a close of the channel */
        lws_callback_on_writable(c->data->wsi);
    }
    pthread_mutex_unlock(&c->data->mutex);

}

static void send_eof_and_close(Channel * channel, int err) {
    ChannelWS * c = channel2ws(channel);

    assert(c->magic == CHANNEL_MAGIC);
    if (channel->state == ChannelStateDisconnected) return;
    ibuf_flush(&c->ibuf);
    if (c->ibuf.handling_msg == HandleMsgTriggered) {
        /* Cancel pending message handling */
        cancel_event(handle_channel_msg, c, 0);
        c->ibuf.handling_msg = HandleMsgIdle;
    }
    write_stream(&c->chan->out, MARKER_EOS);
    write_errno(&c->chan->out, err);
    write_stream(&c->chan->out, MARKER_EOM);
    lws_flush_with_flags(c, 0);
    if (output_queue_is_empty(&c->out_queue)) lws_shutdown(c);
    c->chan->state = ChannelStateDisconnected;
    lws_post_read(&c->ibuf, c->ibuf.buf, c->ibuf.buf_size);
    notify_channel_closed(channel);
    if (channel->disconnected) {
        channel->disconnected(channel);
    }
    else {
        trace(LOG_PROTOCOL, "channel %#lx disconnected", c);
        if (channel->protocol != NULL) protocol_release(channel->protocol);
    }
    channel->protocol = NULL;
}

static void handle_channel_msg(void * x) {
    Trap trap;
    ChannelWS * c = (ChannelWS *)x;
    int has_msg;

    assert(is_dispatch_thread());
    assert(c->magic == CHANNEL_MAGIC);
    assert(c->ibuf.handling_msg == HandleMsgTriggered);
    assert(c->ibuf.message_count);

    has_msg = ibuf_start_message(&c->ibuf);
    if (has_msg <= 0) {
        if (has_msg < 0 && c->chan->state != ChannelStateDisconnected) {
            trace(LOG_PROTOCOL, "Socket is shutdown by remote peer, channel %#lx %s", c, c->chan->peer_name);
            channel_close(c->chan);
        }
    }
    else if (set_trap(&trap)) {
        if (c->chan->receive) {
            c->chan->receive(c->chan);
        }
        else {
            handle_protocol_message(c->chan);
            assert(c->out_bin_block == NULL);
        }
        clear_trap(&trap);
    }
    else {
        trace(LOG_ALWAYS, "Exception in message handler: %s", errno_to_str(trap.error));
        send_eof_and_close(c->chan, trap.error);
    }
}

static void channel_check_pending(Channel * channel) {
    ChannelWS * c = channel2ws(channel);

    assert(is_dispatch_thread());
    if (c->ibuf.handling_msg == HandleMsgIdle && c->ibuf.message_count) {
        post_event(handle_channel_msg, c);
        c->ibuf.handling_msg = HandleMsgTriggered;
    }
}

static void lws_trigger_message(InputBuf * ibuf) {
    ChannelWS * c = ibuf2ws(ibuf);

    assert(is_dispatch_thread());
    assert(c->ibuf.message_count > 0);
    if (c->ibuf.handling_msg == HandleMsgIdle) {
        post_event(handle_channel_msg, c);
        c->ibuf.handling_msg = HandleMsgTriggered;
    }
}

static int channel_get_message_count(Channel * channel) {
    ChannelWS * c = channel2ws(channel);
    assert(is_dispatch_thread());
    if (c->ibuf.handling_msg != HandleMsgTriggered) return 0;
    return c->ibuf.message_count;
}

static void lws_channel_read_done(void * x) {
    ChannelWS * c = (ChannelWS *)x;
    ssize_t total_length = 0;
    ssize_t read_length = 0;

    assert(is_dispatch_thread());
    assert(c->magic == CHANNEL_MAGIC);
    assert(c->read_pending != 0);
    assert(c->lock_cnt > 0);


    c->read_pending = 0;
    c->read_done_posted = 0;
    /* some data is available retrieve it */
    {
        total_length = c->inbuf ? c->inbuf->len : 0;

        if (c->inbuf && c->inbuf->error) {
            if (c->chan->state != ChannelStateDisconnected) {
                trace(LOG_ALWAYS, "Can't read from Web Socket: %s", errno_to_str(c->inbuf->error));
            }
            total_length = 0; /* Treat error as EOF */
        }
        if (total_length > 0) {
            read_length = c->inbuf->len > c->read_buf_size ? c->read_buf_size : c->inbuf->len;
            memcpy(c->read_buf, c->inbuf->in, read_length);
            c->inbuf->len -= read_length;
            if (c->inbuf->len != 0) {
                memmove((unsigned char *)c->inbuf->in, (unsigned char *)c->inbuf->in + read_length, c->inbuf->len);
            }
        }
        else {
            /* In case of error, free all received buffers */
            while (c->inbuf) {
                ChannelInputBuffer * old_buf = c->inbuf;
                c->inbuf = old_buf->next;
                loc_free(old_buf->in);
                loc_free(old_buf);
            }
        }

        if (c->inbuf && c->inbuf->len == 0) {
            ChannelInputBuffer * old_buf = c->inbuf;
            c->inbuf = old_buf->next;
            loc_free(old_buf->in);
            loc_free(old_buf);
        }
    }
    if (c->chan->state != ChannelStateDisconnected) {
        ibuf_read_done(&c->ibuf, read_length);
    }
    else if (total_length > 0) {
        lws_post_read(&c->ibuf, c->ibuf.buf, c->ibuf.buf_size);
    }
    else {
        lws_unlock(c->chan);
    }
}

static void start_channel(Channel * channel) {
    ChannelWS * c = channel2ws(channel);

    assert(is_dispatch_thread());
    assert(c->magic == CHANNEL_MAGIC);
    notify_channel_created(c->chan);
    if (c->chan->connecting) {
        c->chan->connecting(c->chan);
    }
    else {
        trace(LOG_PROTOCOL, "channel server connecting");
        send_hello_message(c->chan);
    }
    ibuf_trigger_read(&c->ibuf);
}

static ChannelWS * create_channel(int is_ssl, int server) {
    ChannelWS * c;

    c = (ChannelWS *)loc_alloc_zero(sizeof *c);
    c->chan = channel_alloc();
    channel2ws(c->chan) = c;
    c->magic = CHANNEL_MAGIC;
    c->is_ssl = is_ssl;
    c->chan->inp.read = lws_read_stream;
    c->chan->inp.peek = lws_peek_stream;
    c->obuf = output_queue_alloc_obuf();
    c->chan->out.cur = c->obuf->buf;
    c->chan->out.end = c->obuf->buf + sizeof(c->obuf->buf);
    c->chan->out.write = lws_write_stream;
    c->chan->out.write_block = lws_write_block_stream;
    c->chan->out.splice_block = lws_splice_block_stream;
    list_add_last(&c->chan->chanlink, &channel_root);
    shutdown_set_normal(&channel_shutdown);
    c->chan->state = ChannelStateStartWait;
    c->chan->incoming = server;
    c->chan->start_comm = start_channel;
    c->chan->check_pending = channel_check_pending;
    c->chan->message_count = channel_get_message_count;
    c->chan->lock = lws_lock;
    c->chan->unlock = lws_unlock;
    c->chan->is_closed = lws_is_closed;
    c->chan->close = send_eof_and_close;
    ibuf_init(&c->ibuf, &c->chan->inp);
    c->ibuf.post_read = lws_post_read;
    c->ibuf.wait_read = lws_wait_read;
    c->ibuf.trigger_message = lws_trigger_message;
    c->lock_cnt = 1;
    output_queue_ini(&c->out_queue);
    return c;
}

static void refresh_peer_server(int sock, PeerServer * ps) {
    unsigned i;
    const char * transport = peer_server_getprop(ps, "TransportName", NULL);
    assert(transport != NULL);
    const char *str_port = peer_server_getprop(ps, "Port", NULL);

    int ifcind;
    struct in_addr src_addr;
    ip_ifc_info ifclist[MAX_IFC];

    /* For now, we do not support binding WebSocket to a specific interface;
     * let's return all interfaces.
     */
    ifcind = build_ifclist(sock, MAX_IFC, ifclist);
    while (ifcind-- > 0) {
        char str_host[64];
        char str_id[64];
        PeerServer * ps2;
        src_addr.s_addr = ifclist[ifcind].addr;
        ps2 = peer_server_alloc();
        ps2->flags = ps->flags | PS_FLAG_LOCAL | PS_FLAG_DISCOVERABLE;
        for (i = 0; i < ps->ind; i++) {
            peer_server_addprop(ps2, loc_strdup(ps->list[i].name),
                    loc_strdup(ps->list[i].value));
        }
        inet_ntop(AF_INET, &src_addr, str_host, sizeof(str_host));
        snprintf(str_id, sizeof(str_id), "%s:%s:%s", transport, str_host, str_port);
        peer_server_addprop(ps2, loc_strdup("ID"), loc_strdup(str_id));
        peer_server_addprop(ps2, loc_strdup("Host"), loc_strdup(str_host));
        peer_server_addprop(ps2, loc_strdup("Port"), loc_strdup(str_port));
        peer_server_add(ps2, PEER_DATA_RETENTION_PERIOD * 2);
    }
}

static void refresh_all_peer_servers(void * x) {
    LINK * l = server_list.next;
    while (l != &server_list) {
        ServerWS * si = servlink2np(l);
        refresh_peer_server(dummy_socket, si->serv.ps);
        l = l->next;
    }
    post_event_with_delay(refresh_all_peer_servers, NULL, PEER_DATA_REFRESH_PERIOD * 1000000);
}

static void set_peer_addr(ChannelWS * c, struct sockaddr * addr, int addr_len) {
    char nbuf[128];
    /* Create a human readable channel name that uniquely identifies remote peer */
    char name[128];
    if (addr_len == 0) return;
    assert(addr->sa_family == AF_INET);
    snprintf(name, sizeof(name), "%s:%s:%d",
            c->is_ssl ? "WSS" : "WS",
            inet_ntop(addr->sa_family,
            &((struct sockaddr_in *)addr)->sin_addr,
            nbuf, sizeof(nbuf)),
            ntohs(((struct sockaddr_in *)addr)->sin_port));
    c->chan->peer_name = loc_strdup(name);
}


static void lws_server_exit(void * x) {
    ServerWS * s = (ServerWS *) x;
    if (s->exiting) return;
    s->exiting = 1;
    list_remove(&s->serv.servlink);
    if (list_is_empty(&channel_root) && list_is_empty(&channel_server_root))
        shutdown_set_stopped(&channel_shutdown);
    list_remove(&s->servlink);
    peer_server_free(s->serv.ps);
}

static void server_close(ChannelServer * serv) {
    /* ServerWS * s = server2ws(serv);*/

    assert(is_dispatch_thread());
    /* Closing a running server is not supported for now. This is
     * because there is no way (AFAIK) to close a virtual host in
     * libwebsockets library.*/
    /* lws_server_exit(s); */
}

/* following _wt_ functions are called from a worker thread so caution is required
 * to keep its operations thread safe
 */

static ChannelServer * channel_server_create(PeerServer * ps) {
    ServerWS * si = (ServerWS *)loc_alloc_zero(sizeof *si);
    si->serv.close = server_close;
    si->serv.ps = ps;
    if (server_list.next == NULL) {
        list_init(&server_list);
        post_event_with_delay(refresh_all_peer_servers, NULL, PEER_DATA_REFRESH_PERIOD * 1000000);
    }
    list_add_last(&si->serv.servlink, &channel_server_root);
    shutdown_set_normal(&channel_shutdown);
    list_add_last(&si->servlink, &server_list);
    refresh_peer_server(dummy_socket, ps);
    return &si->serv;
}

/* LWS service thread */

static void * lws_service_thread(void * x) {
    struct lws_context_creation_info context_creation_info;
    int vhost_created = 0;

    memset(&context_creation_info, 0, sizeof context_creation_info);
    context_creation_info.gid = -1;
    context_creation_info.uid = -1;
    context_creation_info.max_http_header_pool = MAX_CONN_REQUESTS;
    context_creation_info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT|LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    context_creation_info.server_string = "tcf";

    lws_ctx = lws_create_context(&context_creation_info);
    if (lws_ctx == NULL) {
        trace (LOG_ALWAYS, "Error creating libwebsockets client context: %s", strerror(errno));
        return NULL;
    }

    while (1) {
        if (vhost_created) {
#if ENABLE_Epoll
            int i, n;
            struct epoll_event events[16];
            n = epoll_wait (epoll_fd, events, 16, 1000);
            if (n == 0) {
                lws_service_fd(lws_ctx, NULL);
            }
            else {
                for (i = 0; i < n; i++) {
                    struct lws_pollfd pollfd;
                    if (events[i].data.fd == dummy_pipe_fds[0]) {
                        char buf;
                        /* consume events; it will be handled at the end of the loop */
                        if (read(events[i].data.fd, &buf, 1));
                        continue;
                    }
                    pollfd.fd = events[i].data.fd;
                    EPOLL_TO_POLL_EVENT(pollfd.events, epoll_events[events[i].data.fd]);
                    EPOLL_TO_POLL_EVENT(pollfd.revents, events[i].events);
                    if (lws_service_fd(lws_ctx, &pollfd) < 0) continue;
                }
            }
#else
            lws_service(lws_ctx, 1000);
#endif
        }
        else {
            usleep (10000);
        }
        pthread_mutex_lock(&lws_list_mutex);

        /* The libwebsockets library only allows up to MAX_CONN_REQUESTS simultaneous
         * connection requests (this is a parameter provided when creating the context;
         * exceeding this number of pending requests can leads to crashes in the
         * libwebsockets library.
         */

        while (!list_is_empty(&server_create_list)) {
            struct lws_context_creation_info vhost_creation_info;
            ServerCreateInfo * args = link2sci(server_create_list.next);
            struct lws_vhost *lws_vh;
            ServerWS ** si;
            memset(&vhost_creation_info, 0, sizeof vhost_creation_info);
            vhost_creation_info.port = args->port;
            vhost_creation_info.protocols = protocols;
            vhost_creation_info.options = args->options;
            vhost_creation_info.ssl_cipher_list = "AES128-SHA256";

            /* Currently, the certificate is shared for all connections;
             * this is specified for the first created connection and used
             * for subsequent ones. This would need some rework to either
             * make this a global property of the agent (instead of a per
             * connection) making this more natural or we should fix the
             * libwebsockets code to move this info to the connection info level
             * instead of the context/vhost level.
             */
            vhost_creation_info.ssl_cert_filepath = args->certificate;
            vhost_creation_info.ssl_private_key_filepath = args->key;
            vhost_creation_info.ssl_ca_filepath = args->ca_filepath;
            vhost_creation_info.ssl_cipher_list = args->cipher_list;

            list_remove(&args->link);
            pthread_mutex_unlock(&lws_list_mutex);
            if ((lws_vh = lws_create_vhost(lws_ctx, &vhost_creation_info)) == NULL) {
                trace (LOG_ALWAYS, "Error creating libwebsockets vhost: %s", strerror(errno));
                post_event(lws_server_exit, args->si);
            }
            else {
                vhost_created = 1;
                si = (ServerWS **)lws_protocol_vh_priv_zalloc(lws_vh, protocols, sizeof(ChannelServer *));
                *si = args->si;
            }
            loc_free(args);
            pthread_mutex_lock(&lws_list_mutex);
        }

        while (pending_connections < MAX_CONN_REQUESTS && !list_is_empty(&client_connect_list)) {
            struct lws_client_connect_info client_connect_info;
            ChannelConnectInfo * args = link2cci(client_connect_list.next);
            WSIUserData * userdata = (WSIUserData *) loc_alloc_zero(sizeof (WSIUserData));

            if (client_vhost == NULL) {
                struct lws_context_creation_info vhost_creation_info;
                memset(&vhost_creation_info, 0, sizeof vhost_creation_info);
                vhost_creation_info.port = CONTEXT_PORT_NO_LISTEN;
                vhost_creation_info.protocols = protocols;
                vhost_creation_info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
                vhost_creation_info.ssl_ca_filepath = args->ca_filepath;
                vhost_creation_info.ssl_cert_filepath = args->certificate;
                vhost_creation_info.ssl_private_key_filepath = args->key;
                vhost_creation_info.ssl_cipher_list = args->cipher_list;

                client_vhost = lws_create_vhost(lws_ctx, &vhost_creation_info);
            }
            if (client_vhost == NULL) {
                trace (LOG_ALWAYS, "Error creating libwebsockets client context: %s", strerror(errno));
            }
            else vhost_created = 1;

            list_remove(&args->link);
            pending_connections++;
            pthread_mutex_unlock(&lws_list_mutex);

            userdata->args = args;

            memset(&client_connect_info, 0, sizeof(client_connect_info));
            client_connect_info.context = lws_ctx;
            client_connect_info.path = args->get_url;
            if (args->is_ssl) {
                client_connect_info.ssl_connection = args->self_signed ? 2 : 1;
            }
            client_connect_info.address = args->host;
            client_connect_info.host = client_connect_info.address;
            client_connect_info.port = args->port;
            client_connect_info.origin = client_connect_info.address;
            client_connect_info.ietf_version_or_minus_one = -1;
            client_connect_info.client_exts = exts;
            client_connect_info.userdata = userdata;
            client_connect_info.vhost = client_vhost;
            client_connect_info.protocol = "tcf";

            if (lws_client_connect_via_info(&client_connect_info));
            pthread_mutex_lock(&lws_list_mutex);
        }
        pthread_mutex_unlock(&lws_list_mutex);
    }
    return NULL;
}

static ChannelServer * channel_lws_server(PeerServer * ps) {
    const char * port_str = peer_server_getprop(ps, "Port", NULL);
    const char * host = peer_server_getprop(ps, "Host", NULL);
    const char * certificate = peer_server_getprop(ps, "Cert", NULL);
    const char * key = peer_server_getprop(ps, "Key", NULL);
    const char * client_cert = peer_server_getprop(ps, "ReqClientCert", NULL);
    ChannelServer * server;
    int is_ssl = strcmp(peer_server_getprop(ps, "TransportName", ""), "WSS") == 0;
    const char * ca_filepath = peer_server_getprop(ps, "CAfile", NULL);
    const char * cipher_list = peer_server_getprop(ps, "CipherList", NULL);
    ServerCreateInfo * args;
    int port = 0;

    if (port_str != NULL) port = atoi(port_str);
    if (port == 0) {
        trace(LOG_ALWAYS, "Specifying a port number in WebSocket server URL is mandatory");
        set_fmt_errno(ERR_OTHER, "Specifying a port number in WebSocket server URL is mandatory");
        return NULL;
    }
    if (host != NULL) {
        trace(LOG_ALWAYS, "Specifying host in WebSocket server URL is not supported");
        set_fmt_errno(ERR_OTHER, "Specifying host in WebSocket server URL is not supported");
        return NULL;
    }
    if (is_ssl) {
        if (key == NULL) {
            trace(LOG_ALWAYS, "Key parameter needs to be specified for secured WebSocket connection");
            set_fmt_errno(ERR_OTHER, "Key parameter needs to be specified for secured WebSocket connection");
            return NULL;
        }
        if (certificate == NULL) {
            trace(LOG_ALWAYS, "Cert parameter needs to be specified for secured WebSocket connection");
            set_fmt_errno(ERR_OTHER, "Cert parameter needs to be specified for secured WebSocket connection");
            return NULL;
        }
    }

    args = (ServerCreateInfo *)loc_alloc_zero(sizeof(ServerCreateInfo));
    args->port = port_str ? atoi(port_str) : 0;
    if (is_ssl) {
        args->certificate = certificate;
        args->key = key;
        args->ca_filepath = ca_filepath;
        args->cipher_list = cipher_list;
        args->options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        if (client_cert
                && (strcmp(client_cert, "true") == 0
                        || strcmp(client_cert, "1") == 0)) {
            args->options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
        }
    }
    server = channel_server_create(ps);
    args->si = server2ws(server);
    args->si->is_ssl = is_ssl;
    pthread_mutex_lock(&lws_list_mutex);
    list_add_last(&args->link, &server_create_list);
#if ENABLE_Epoll
    channel_lws_abort_epoll();
#else
    lws_cancel_service(lws_ctx);
#endif
    pthread_mutex_unlock(&lws_list_mutex);
    return server;
}

static void server_lws_connect_done(void * x) {
    SessionData * data = (SessionData *)x;
    ServerWS * si = data->si;
    ChannelWS * c;
    assert (si != NULL);
    pthread_mutex_lock(&data->mutex);
    if (data->wsi == NULL) {
        pthread_mutex_unlock(&data->mutex);
        return;
    }
    c= create_channel(si->is_ssl, 1);
    data->c = c;
    c->data = data;
    lws_lock(c->chan);
    pthread_mutex_unlock(&data->mutex);
    set_peer_addr(c, data->addr_buf, data->addr_len);
    si->serv.new_conn(&si->serv, c->chan);
}

static void channel_lws_connect_done(void * x) {
    ChannelConnectInfo * args = (ChannelConnectInfo *)x;
    pthread_mutex_lock(&lws_list_mutex);
    pending_connections--;
    pthread_mutex_unlock(&lws_list_mutex);

    if (args->error) {
        if (args->error == EPERM) {
            args->error = set_fmt_errno(ERR_OTHER, "Failed to handshake the connection h:%s p:%d", args->host, args->port);
        }
        else if (args->error == ECONNREFUSED) {
            args->error = set_fmt_errno(ERR_OTHER, "Failed to establish connection h:%s p:%d", args->host, args->port);
        }
        args->callback(args->callback_args, args->error, NULL);
        loc_free(args->data);
    }
    else {
        ChannelWS * c = create_channel(args->is_ssl, 0);
        if (c == NULL) {
            args->callback(args->callback_args, errno, NULL);
            loc_free(args->data);
        }
        else {
            args->data->c = c;
            c->data = args->data;
            lws_lock(c->chan);
            set_peer_addr(c, args->data->addr_buf, args->data->addr_len);
            args->callback(args->callback_args, 0, c->chan);
        }
    }
    loc_free(args->host);
    loc_free(args->get_url);
    loc_free(args->ca_filepath);
    loc_free(args->certificate);
    loc_free(args->cipher_list);
    loc_free(args->key);
    loc_free(args);
}

static void channel_lws_connect(PeerServer * ps, ChannelConnectCallBack callback, void * callback_args) {
    const char * host = peer_server_getprop(ps, "Host", NULL);
    const char * port_str = peer_server_getprop(ps, "Port", NULL);
    const char * get_url = peer_server_getprop(ps, "GetUrl", NULL);
    const char * self_signed = peer_server_getprop(ps, "SelfSigned", NULL);
    const char * ca_filepath = peer_server_getprop(ps, "CAfile", NULL);
    const char * cipher_list = peer_server_getprop(ps, "CipherList", NULL);

    const char * certificate = peer_server_getprop(ps, "Cert", NULL);
    const char * key = peer_server_getprop(ps, "Key", NULL);
    ChannelConnectInfo * args;

    args = (ChannelConnectInfo *)loc_alloc_zero(sizeof(ChannelConnectInfo));
    args->callback = callback;
    args->callback_args = callback_args;
    args->is_ssl = strcmp(peer_server_getprop(ps, "TransportName", ""), "WSS") == 0;
    if (port_str != NULL) args->port = atoi(port_str);
    args->ca_filepath = (ca_filepath != NULL ? loc_strdup(ca_filepath) : NULL);
    args->certificate = (certificate != NULL ? loc_strdup(certificate) : NULL);
    args->cipher_list = (cipher_list != NULL ? loc_strdup(cipher_list) : NULL);
    args->key = (key != NULL ? loc_strdup(key) : NULL);
    args->host = loc_strdup(host == NULL ? "127.0.0.1" : host);
    args->get_url = loc_strdup(get_url == NULL ? "/" : get_url);
    args->self_signed = self_signed ? (strcmp(self_signed, "true") == 0 || strcmp(self_signed, "1") == 0) : 0;
    pthread_mutex_lock(&lws_list_mutex);
    list_add_last(&args->link, &client_connect_list);
#if ENABLE_Epoll
    channel_lws_abort_epoll();
#else
    lws_cancel_service(lws_ctx);
#endif
    pthread_mutex_unlock(&lws_list_mutex);
}

static void trace_lws(int level,  const char *line) {
    trace(LOG_PROTOCOL, line);
}

void channel_lws_get_properties(Channel * channel, char *** prop_names, char *** prop_values, unsigned * prop_cnt) {
    ChannelWS * c = channel2ws(channel);
    assert(is_dispatch_thread());
    if(c->magic != CHANNEL_MAGIC) {
        *prop_cnt = 0;
        return;
    }
    assert(c->lock_cnt > 0);
    *prop_names = c->data->prop_names;
    *prop_values = c->data->prop_values;
    *prop_cnt = c->data->prop_cnt;
}

void ini_channel_lws(void) {
    static int initialized = 0;
    pthread_t thread;
#if ENABLE_Epoll
    struct epoll_event event;
    assert (POLLIN == EPOLLIN);
    assert (POLLPRI == EPOLLPRI);
    assert (POLLOUT == EPOLLOUT );
    assert (POLLRDHUP ==EPOLLRDHUP);
    assert (POLLERR == EPOLLERR);
    assert (POLLHUP == EPOLLHUP);
#endif

    if (initialized) return;
    channel_lws_extension_offset = channel_extension(sizeof(ChannelWS *));
#if ENABLE_Epoll
    epoll_fd = epoll_create1(0);
    epoll_events = (uint32_t *)loc_alloc_zero(getdtablesize() * sizeof(uint32_t));
    if (pipe(dummy_pipe_fds) < 0) check_error(errno);
    memset(&event, 0, sizeof(struct epoll_event));
    event.data.fd = dummy_pipe_fds[0];
    event.events = EPOLLIN;
    epoll_ctl (epoll_fd, EPOLL_CTL_ADD, event.data.fd, &event);
#endif
    if ((log_mode & LOG_PROTOCOL) == 0) lws_set_log_level (0, NULL);
    else lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO, trace_lws);
    add_channel_transport("WS", channel_lws_server, channel_lws_connect);
    add_channel_transport("WSS", channel_lws_server, channel_lws_connect);

    dummy_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    pthread_mutex_init(&lws_list_mutex, NULL);
    pthread_create(&thread, NULL, lws_service_thread, NULL);
}
#endif /* ENABLE_LibWebSockets */
