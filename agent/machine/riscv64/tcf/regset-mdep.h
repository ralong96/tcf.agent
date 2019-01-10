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
 *
 *******************************************************************************/

#if defined(__linux__)

#define MDEP_UseREGSET
#define REGSET_GP NT_PRSTATUS
#define REGSET_FP NT_FPREGSET

struct regset_gp {
    uint64_t pc;
    uint64_t regs[31];
};

struct regset_fp {
    uint64_t _unused_;
};

#endif

/* Offset to be applied to the PC after a software trap */
#define TRAP_OFFSET 0
