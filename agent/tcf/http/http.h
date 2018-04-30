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

#ifndef D_http
#define D_http

#include <tcf/config.h>

extern int start_http_server(const char * host, const char * port);

typedef struct HttpParam {
    char * name;
    char * value;
    struct HttpParam * next;
} HttpParam;

extern OutputStream * get_http_stream(void);
extern HttpParam * get_http_headers(void);
extern HttpParam * get_http_params(void);

extern void http_send(char ch);
extern void http_send_block(const char * buf, size_t size);
extern void http_printf(const char * fmt, ...);

typedef struct HttpListener {
    int (*get_page)(const char * uri);
} HttpListener;

extern void add_http_listener(HttpListener * l);

extern void ini_http(void);

#endif /* D_http */
