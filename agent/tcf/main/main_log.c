/*******************************************************************************
 * Copyright (c) 2007, 2012 Wind River Systems, Inc. and others.
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
 * TCF Logger main module.
 *
 * TCF Logger is a simple TCF agent that des not provide any services itself,
 * instead it forward all TCF traffic to another agent.
 * Logger prints all messages it forwards.
 * It can be used as diagnostic and debugging tool.
 */

#include <tcf/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <tcf/framework/asyncreq.h>
#include <tcf/framework/events.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/channel.h>
#include <tcf/framework/protocol.h>
#include <tcf/framework/proxy.h>
#include <tcf/framework/errors.h>
#include <tcf/services/discovery.h>

static const char * progname;
static const char * dest_url = "TCP::1534";

typedef struct ConnectInfo {
    PeerServer * ps;
    Channel * c1;
} ConnectInfo;

static void connect_done(void * args, int error, Channel * c2) {
    ConnectInfo * info = (ConnectInfo *)args;
    Channel * c1 = info->c1;

    if (!is_channel_closed(c1)) {
        assert(c1->state == ChannelStateRedirectReceived);
        if (error) {
            fprintf(stderr, "cannot connect to peer: %s\n", dest_url);
            channel_close(c1);
        }
        else {
            proxy_create(c1, c2);
        }
    }
    else if (!error) {
        channel_close(c2);
    }
    channel_unlock(c1);
    peer_server_free(info->ps);
    loc_free(info);
}

static void connect_dest(void * x) {
    Channel * c1 = (Channel *)x;
    PeerServer * ps;
    ConnectInfo * info;

    ps = channel_peer_from_url(dest_url);
    if (ps == NULL) {
        trace(LOG_ALWAYS, "cannot parse peer url: %s", dest_url);
        channel_close(c1);
        return;
    }
    channel_lock(c1);
    c1->state = ChannelStateRedirectReceived;
    info = (ConnectInfo *)loc_alloc_zero(sizeof(ConnectInfo));
    info->ps = ps;
    info->c1 = c1;
    channel_connect(ps, connect_done, info);
}

static void channel_server_connecting(Channel * c1) {
    trace(LOG_ALWAYS, "channel server connecting");

    assert(c1->state == ChannelStateStarted);
    c1->state = ChannelStateHelloSent;  /* Fake that we sent hello message. */
}

static void channel_server_connected(Channel * c1) {
    trace(LOG_ALWAYS, "channel server connected");

    assert(c1->state == ChannelStateConnected);

    /* Connect to destination on next dispatch since we are limited in
     * what we can do in a callback, e.g. cannot close channel. */
    post_event(connect_dest, c1);
}

static void channel_server_disconnected(Channel * c1) {
    trace(LOG_ALWAYS, "channel server disconnected");
    protocol_release(c1->protocol);
}

static void channel_new_connection(ChannelServer * serv, Channel * c) {
    c->protocol = protocol_alloc();
    c->connecting = channel_server_connecting;
    c->connected = channel_server_connected;
    c->disconnected = channel_server_disconnected;
    channel_start(c);
}

#define FILTER_IN 1
#define FILTER_OUT 2
#define FILTER_MODE (FILTER_IN | FILTER_OUT)

typedef struct MessageFilter {
    LINK all;
    int flags;
    int argc;
    /* Dynamic array, must be last member in struct */
    char * argv[1];
} MessageFilter;

typedef struct TokenFilter {
    LINK all;
    Channel * chan;
    char token[1];
} TokenFilter;

#define all2mf(A)   ((MessageFilter *)((char *)(A) - offsetof(MessageFilter, all)))
#define all2tf(A)   ((TokenFilter *)((char *)(A) - offsetof(TokenFilter, all)))

static LINK message_filters = TCF_LIST_INIT(message_filters);
static LINK token_filters = TCF_LIST_INIT(token_filters);

static int add_message_filter(const char * filter) {
    MessageFilter * mf;
    const char * s;
    int max = 1;
    int c;

    mf = (MessageFilter *)loc_alloc(sizeof *mf + (max - 1) * sizeof *mf->argv);
    mf->flags = 0;
    mf->argc = 0;

    s = filter;
    while ((c = *s) != '\0' && c != ',') {
        switch (c) {
        case 'i':
            mf->flags |= FILTER_IN;
            break;
        case 'o':
            mf->flags |= FILTER_OUT;
            break;
        default:
            return 1;
        }
        s++;
    }
    while (c == ',') {
        const char * start = ++s;
        while ((c = *s) != '\0' && c != ',')
            s++;
        if (mf->argc >= max) {
            max *= 2;
            mf = (MessageFilter *)loc_realloc(mf, sizeof *mf + (max - 1) * sizeof *mf->argv);
        }
        if (mf->argc == 1 && !strcmp(mf->argv[0], "C")) {
            /* Match any entry for command token */
            mf->argv[mf->argc++] = NULL;
            s = start - 1;
            c = *s;
        } else {
            mf->argv[mf->argc++] = loc_strndup(start, s - start);
        }
    }
    assert(c == '\0');

    if ((mf->flags & FILTER_MODE) != FILTER_IN && (mf->flags & FILTER_MODE) != FILTER_OUT)
        return 1;

    list_add_last(&mf->all, &message_filters);
    return 0;
}

static MessageFilter * find_message_filter(int argc, char ** argv) {
    LINK * l = message_filters.next;
    while (l != &message_filters) {
        MessageFilter *mf = all2mf(l);
        if (mf != NULL && mf->argc <= argc) {
            int i;
            for (i = 0; i < mf->argc; i++) {
                if (mf->argv[i] != NULL && strcmp(mf->argv[i], argv[i]) != 0)
                    break;
            }
            if (i >= mf->argc)
                return mf;
        }
        l = l->next;
    }
    return NULL;
}

static TokenFilter * find_token_filter(Channel * c, char * token) {
    LINK * l = token_filters.next;
    while (l != &token_filters) {
        TokenFilter *tf = all2tf(l);

        if (tf->chan == c && !strcmp(tf->token, token))
            return tf;
        l = l->next;
    }
    return NULL;
}

static int is_log_filtered(Channel * src, Channel * dst, int argc, char ** argv) {
    MessageFilter * mf;

    if (argc >= 2 && (argv[0][0] == 'P' || argv[0][0] == 'R') && argv[0][1] == '\0') {
        TokenFilter * tf = find_token_filter(dst, argv[1]);
        if (tf != NULL) {
            if (argv[0][0] == 'R') {
                list_remove(&tf->all);
                loc_free(tf);
            }
            return 1;
        }
    }

    mf = find_message_filter(argc, argv);
    if (mf && mf->flags & FILTER_OUT) {
        if (argc >= 2 && argv[0][0] == 'C' && argv[0][1] == '\0') {
            TokenFilter * tf = (TokenFilter *)loc_alloc_zero(sizeof(TokenFilter) + strlen(argv[1]));
            tf->chan = src;
            strcpy(tf->token, argv[1]);
            list_add_last(&tf->all, &token_filters);
        }
        return 1;
    }
    return 0;
}

#if !defined(_WRS_KERNEL)
static const char * help_text[] = {
    "Usage: tcflog [OPTION]...",
    "Start Target Communication Framework logger.",
    "The TCF logger can be used to capture traffic between two TCF peers and "
    "redirect it to either stderr or a file.",
    "For instance:",
    "    tcflog -s TCP::1437 TCP:128.224.218.33:4576",
    "This starts the TCF logger on port 1437 on the local machine and "
    "connects to target IP 128.224.218.33 on port 4576.",
    "  -L<file>         log file name, use -L- to send log to stderr",
#if ENABLE_Trace
    "  -l<level>        set log level, the level is comma separated list of:",
    "@",
#endif
    "  -s<url>          set agent listening port and protocol, default is TCP::1534",
    "  -f<t>,<m>,...    set proxy log filter, <t> is filter type, <m> is message type",
    "                   matching messages will be filtered out the when <t> is 'i' and",
    "                   will be filter in and <t> is 'o'. <m> is message type, example",
    "                   'C' for command, 'E' for event.  Additional fields are message",
    "                   specific.  Multiple -f options can be specified.  Examples:",
    "                      -fo,E                filter out all event messages",
    "                      -fi,C,Memory -fo     filter in Memory service command and",
    "                                           filter out all other messages",
    "                   Default filters (use -fi to disable):",
    "                      -fo,E,Locator,peerHeartBeat",
    "                      -fo,E,Locator,peerAdded",
    "                      -fo,E,Locator,peerRemoved",
    "                      -fo,E,Locator,peerChanged",
    "                      -fo,C,Locator,getPeers",
    NULL
};

static void show_help(void) {
    const char ** p = help_text;
    while (*p != NULL) {
        if (**p == '@') {
#if ENABLE_Trace
            struct trace_mode * tm = trace_mode_table;
            while (tm->mode != 0) {
                fprintf(stderr,
                    "      %-12s %s (%#x)\n", tm->name,
                    tm->description, tm->mode);
                tm++;
            }
#endif
            p++;
        }
        else {
            fprintf(stderr, "%s\n", *p++);
        }
    }
}
#endif

#if defined(_WRS_KERNEL)
int tcf_log(void);
int tcf_log(void) {
#else
int main(int argc, char ** argv) {
    int c;
    int ind;
    const char * log_name = "-";
#endif
    const char * url = "TCP:";
    PeerServer * ps;
    ChannelServer * serv;

    ini_mdep();
    ini_trace();
    ini_events_queue();
    ini_asyncreq();

    log_mode = LOG_TCFLOG;

#if defined(_WRS_KERNEL)

    progname = "tcf";
    open_log_file("-");

#else

    progname = argv[0];

    /* Parse arguments */
    for (ind = 1; ind < argc; ind++) {
        const char * s = argv[ind];
        if (*s != '-') {
            break;
        }
        s++;
        while ((c = *s++) != '\0') {
            switch (c) {
            case 'h':
                show_help();
                exit (0);

#if ENABLE_Trace
            case 'l':
#endif
            case 'L':
            case 's':
            case 'f':
                if (*s == '\0') {
                    if (++ind >= argc) {
                        fprintf(stderr, "%s: error: no argument given to option '%c'\n", progname, c);
                        exit(1);
                    }
                    s = argv[ind];
                }
                switch (c) {
#if ENABLE_Trace
                case 'l':
                    if (parse_trace_mode(s, &log_mode) != 0) {
                        fprintf(stderr, "Cannot parse log level: %s\n", s);
                        exit(1);
                    }
                    break;
#endif

                case 'L':
                    log_name = s;
                    break;

                case 's':
                    url = s;
                    break;

                case 'f':
                    if (add_message_filter(s) != 0) {
                        fprintf(stderr, "Cannot parse filter level: %s\n", s);
                        exit(1);
                    }
                    break;

                default:
                    fprintf(stderr, "%s: error: illegal option '%c'\n", progname, c);
                    show_help();
                    exit(1);
                }
                s = "";
                break;

            default:
                fprintf(stderr, "%s: error: illegal option '%c'\n", progname, c);
                show_help();
                exit(1);
            }
        }
    }
    open_log_file(log_name);
    if (ind < argc) {
        dest_url = argv[ind++];
    }

#endif

    /* Default filters (use "-fi" to disable). */
    add_message_filter("o,E,Locator,peerHeartBeat");
    add_message_filter("o,E,Locator,peerAdded");
    add_message_filter("o,E,Locator,peerRemoved");
    add_message_filter("o,E,Locator,peerChanged");
    add_message_filter("o,C,Locator,getPeers");

    set_proxy_log_filter_listener(is_log_filtered);

    ps = channel_peer_from_url(url);
    if (ps == NULL) {
        fprintf(stderr, "%s: invalid server URL (-s option value): %s\n", progname, url);
        exit(1);
    }
    peer_server_addprop(ps, loc_strdup("Name"), loc_strdup("TCF Protocol Logger"));
    peer_server_addprop(ps, loc_strdup("Proxy"), loc_strdup(""));
    serv = channel_server(ps);
    if (serv == NULL) {
        fprintf(stderr, "%s: cannot create TCF server: %s\n", progname, errno_to_str(errno));
        exit(1);
    }
    serv->new_conn = channel_new_connection;

    discovery_start();

    /* Process events - must run on the initial thread since ptrace()
     * returns ECHILD otherwise, thinking we are not the owner. */
    run_event_loop();
    return 0;
}
