/*******************************************************************************
 * Copyright (c) 2016 Wind River Systems, Inc. and others.
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
 * Framework initialization code.
 */

#include <tcf/config.h>

#include <tcf/framework/mdep.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/events.h>
#include <tcf/framework/asyncreq.h>
#include <tcf/main/framework.h>

#include <tcf/main/framework-ext.h>

void ini_framework(void) {
    ini_mdep();
    ini_trace();
    ini_events_queue();
    ini_asyncreq();
    ini_ext_framework();
}
