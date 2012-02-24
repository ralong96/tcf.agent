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
 * This module provides CPU specific definitions for X86.
 */

#ifdef _WRS_KERNEL
#  if CPU_FAMILY == SIMNT || CPU_FAMILY == I80X86
#    define __i386__ 1
#    define eip pc
#    undef BREAK_INST
#  endif
#  include <system/VxWorks/tcf/context-vxworks.h>
#endif

#if defined(_AMD64_) && !defined(__x86_64__)
#define __x86_64__ 1
#endif

#if defined(__i386__) || defined(__x86_64__)

#include <tcf/regset.h>

#if !defined(ENABLE_HardwareBreakpoints)
#  define ENABLE_HardwareBreakpoints 1
#endif

extern RegisterDefinition regs_index[];
extern unsigned char BREAK_INST[1];

#if ENABLE_HardwareBreakpoints
#define ENABLE_ini_cpudefs_mdep 1
extern void ini_cpudefs_mdep(void);
#endif

#else

#  error "Unknown CPU"

#endif
