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
 * Target service implementation: file system access (TCF name FileSystem)
 */

#ifndef D_filesystem
#define D_filesystem

#include <tcf/framework/protocol.h>

/*
 * Open modes
 */
static const int
    TCF_O_READ              = 0x00000001,
    TCF_O_WRITE             = 0x00000002,
    TCF_O_APPEND            = 0x00000004,
    TCF_O_CREAT             = 0x00000008,
    TCF_O_TRUNC             = 0x00000010,
    TCF_O_EXCL              = 0x00000020;

/*
 * Error codes
 */
static const int
    FSERR_EOF               = 0x10001,
    FSERR_NO_SUCH_FILE      = 0x10002,
    FSERR_PERMISSION_DENIED = 0x10003;

/*
 * Initialize file system service.
 */
extern void ini_file_system_service(Protocol *);

#endif
