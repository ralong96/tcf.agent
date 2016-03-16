/*******************************************************************************
 * Copyright (c) 2013, 2014 Stanislav Yakovlev and others.
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
 *     Stanislav Yakovlev - initial API and implementation
 *     Stanislav Yakovlev - [417363] add support for PowerPC floating point registers
 *******************************************************************************/

#include <tcf/config.h>

#if ENABLE_DebugContext && !ENABLE_ContextProxy

#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/trace.h>
#include <tcf/services/symbols.h>
#include <machine/powerpc/tcf/disassembler-powerpc.h>
#if ENABLE_ContextMux
#include <tcf/framework/cpudefs-mdep-mux.h>
#endif
#include <tcf/cpudefs-mdep.h>

#define REG_OFFSET(name) offsetof(REG_SET, name)

#ifdef __powerpc64__
#  define RSZ 8
#else
#  define RSZ 4
#endif

RegisterDefinition regs_def[] = {
#   define REG_PC user.regs.gpr[32]
    { "gpr0",      REG_OFFSET(user.regs.gpr[0]),      RSZ, 0, 0, 1},
    { "gpr1",      REG_OFFSET(user.regs.gpr[1]),      RSZ, 1, 1, 1},
    { "gpr2",      REG_OFFSET(user.regs.gpr[2]),      RSZ, 2, 2, 1},
    { "gpr3",      REG_OFFSET(user.regs.gpr[3]),      RSZ, 3, 3, 1},
    { "gpr4",      REG_OFFSET(user.regs.gpr[4]),      RSZ, 4, 4, 1},
    { "gpr5",      REG_OFFSET(user.regs.gpr[5]),      RSZ, 5, 5, 1},
    { "gpr6",      REG_OFFSET(user.regs.gpr[6]),      RSZ, 6, 6, 1},
    { "gpr7",      REG_OFFSET(user.regs.gpr[7]),      RSZ, 7, 7, 1},
    { "gpr8",      REG_OFFSET(user.regs.gpr[8]),      RSZ, 8, 8, 1},
    { "gpr9",      REG_OFFSET(user.regs.gpr[9]),      RSZ, 9, 9, 1},
    { "gpr10",     REG_OFFSET(user.regs.gpr[10]),     RSZ, 10, 10, 1},
    { "gpr11",     REG_OFFSET(user.regs.gpr[11]),     RSZ, 11, 11, 1},
    { "gpr12",     REG_OFFSET(user.regs.gpr[12]),     RSZ, 12, 12, 1},
    { "gpr13",     REG_OFFSET(user.regs.gpr[13]),     RSZ, 13, 13, 1},
    { "gpr14",     REG_OFFSET(user.regs.gpr[14]),     RSZ, 14, 14, 1},
    { "gpr15",     REG_OFFSET(user.regs.gpr[15]),     RSZ, 15, 15, 1},
    { "gpr16",     REG_OFFSET(user.regs.gpr[16]),     RSZ, 16, 16, 1},
    { "gpr17",     REG_OFFSET(user.regs.gpr[17]),     RSZ, 17, 17, 1},
    { "gpr18",     REG_OFFSET(user.regs.gpr[18]),     RSZ, 18, 18, 1},
    { "gpr19",     REG_OFFSET(user.regs.gpr[19]),     RSZ, 19, 19, 1},
    { "gpr20",     REG_OFFSET(user.regs.gpr[20]),     RSZ, 20, 20, 1},
    { "gpr21",     REG_OFFSET(user.regs.gpr[21]),     RSZ, 21, 21, 1},
    { "gpr22",     REG_OFFSET(user.regs.gpr[22]),     RSZ, 22, 22, 1},
    { "gpr23",     REG_OFFSET(user.regs.gpr[23]),     RSZ, 23, 23, 1},
    { "gpr24",     REG_OFFSET(user.regs.gpr[24]),     RSZ, 24, 24, 1},
    { "gpr25",     REG_OFFSET(user.regs.gpr[25]),     RSZ, 25, 25, 1},
    { "gpr26",     REG_OFFSET(user.regs.gpr[26]),     RSZ, 26, 26, 1},
    { "gpr27",     REG_OFFSET(user.regs.gpr[27]),     RSZ, 27, 27, 1},
    { "gpr28",     REG_OFFSET(user.regs.gpr[28]),     RSZ, 28, 28, 1},
    { "gpr29",     REG_OFFSET(user.regs.gpr[29]),     RSZ, 29, 29, 1},
    { "gpr30",     REG_OFFSET(user.regs.gpr[30]),     RSZ, 30, 30, 1},
    { "gpr31",     REG_OFFSET(user.regs.gpr[31]),     RSZ, 31, 31, 1},

    { "nip",       REG_OFFSET(user.regs.nip),         RSZ, -1, -1, 1},
    { "msr",       REG_OFFSET(user.regs.msr),         RSZ, 66, -1, 1},
    { "orig_gpr3", REG_OFFSET(user.regs.orig_gpr3),   RSZ, -1, -1, 1},
    { "ctr",       REG_OFFSET(user.regs.ctr),         RSZ, 109, -1, 1},
    { "link",      REG_OFFSET(user.regs.link),        RSZ, 108, -1, 1},
    { "xer",       REG_OFFSET(user.regs.xer),         RSZ, 101, -1, 1},
    { "ccr",       REG_OFFSET(user.regs.ccr),         RSZ, -1, -1, 1},
#ifdef __powerpc64__
    { "softe",     REG_OFFSET(user.regs.softe),       RSZ, -1, -1, 1},
#else
    { "mq",        REG_OFFSET(user.regs.mq),          4, 100, -1, 1},
#endif
    { "trap",      REG_OFFSET(user.regs.trap),        RSZ, -1, -1, 1},
    { "dar",       REG_OFFSET(user.regs.dar),         RSZ, 119, -1, 1},
    { "dsisr",     REG_OFFSET(user.regs.dsisr),       RSZ, 118, -1, 1},
    { "result",    REG_OFFSET(user.regs.result),      RSZ, -1, -1, 1},

    { "f0",        REG_OFFSET(fp.fpregs[0]),          8, 32, 32, 1},
    { "f1",        REG_OFFSET(fp.fpregs[1]),          8, 33, 33, 1},
    { "f2",        REG_OFFSET(fp.fpregs[2]),          8, 34, 34, 1},
    { "f3",        REG_OFFSET(fp.fpregs[3]),          8, 35, 35, 1},
    { "f4",        REG_OFFSET(fp.fpregs[4]),          8, 36, 36, 1},
    { "f5",        REG_OFFSET(fp.fpregs[5]),          8, 37, 37, 1},
    { "f6",        REG_OFFSET(fp.fpregs[6]),          8, 38, 38, 1},
    { "f7",        REG_OFFSET(fp.fpregs[7]),          8, 39, 39, 1},
    { "f8",        REG_OFFSET(fp.fpregs[8]),          8, 40, 40, 1},
    { "f9",        REG_OFFSET(fp.fpregs[9]),          8, 41, 41, 1},
    { "f10",       REG_OFFSET(fp.fpregs[10]),         8, 42, 42, 1},
    { "f11",       REG_OFFSET(fp.fpregs[11]),         8, 43, 43, 1},
    { "f12",       REG_OFFSET(fp.fpregs[12]),         8, 44, 44, 1},
    { "f13",       REG_OFFSET(fp.fpregs[13]),         8, 45, 45, 1},
    { "f14",       REG_OFFSET(fp.fpregs[14]),         8, 46, 46, 1},
    { "f15",       REG_OFFSET(fp.fpregs[15]),         8, 47, 47, 1},
    { "f16",       REG_OFFSET(fp.fpregs[16]),         8, 48, 48, 1},
    { "f17",       REG_OFFSET(fp.fpregs[17]),         8, 49, 49, 1},
    { "f18",       REG_OFFSET(fp.fpregs[18]),         8, 50, 50, 1},
    { "f19",       REG_OFFSET(fp.fpregs[19]),         8, 51, 51, 1},
    { "f20",       REG_OFFSET(fp.fpregs[20]),         8, 52, 52, 1},
    { "f21",       REG_OFFSET(fp.fpregs[21]),         8, 53, 53, 1},
    { "f22",       REG_OFFSET(fp.fpregs[22]),         8, 54, 54, 1},
    { "f23",       REG_OFFSET(fp.fpregs[23]),         8, 55, 55, 1},
    { "f24",       REG_OFFSET(fp.fpregs[24]),         8, 56, 56, 1},
    { "f25",       REG_OFFSET(fp.fpregs[25]),         8, 57, 57, 1},
    { "f26",       REG_OFFSET(fp.fpregs[26]),         8, 58, 58, 1},
    { "f27",       REG_OFFSET(fp.fpregs[27]),         8, 59, 59, 1},
    { "f28",       REG_OFFSET(fp.fpregs[28]),         8, 60, 60, 1},
    { "f29",       REG_OFFSET(fp.fpregs[29]),         8, 61, 61, 1},
    { "f30",       REG_OFFSET(fp.fpregs[30]),         8, 62, 62, 1},
    { "f31",       REG_OFFSET(fp.fpregs[31]),         8, 63, 63, 1},
    { "fpscr",     REG_OFFSET(fp.fpscr),              4, 65, 65, 1},

    { NULL,     0,                    0,  0,  0},
};

RegisterDefinition * regs_index = NULL;

unsigned char BREAK_INST[] = { 0x7f, 0xe0, 0x00, 0x08 };

static RegisterDefinition * pc_def = NULL;

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return pc_def;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {
    return 0;
}

#if ENABLE_add_cpudefs_disassembler
void add_cpudefs_disassembler(Context * cpu_ctx) {
#ifdef __powerpc64__
    add_disassembler(cpu_ctx, "PPC64", disassemble_powerpc);
#endif
    add_disassembler(cpu_ctx, "PPC", disassemble_powerpc);
}
#endif

#if ENABLE_ini_cpudefs_mdep
void ini_cpudefs_mdep(void) {
    RegisterDefinition * r;
    for (r = regs_def; r->name != NULL; r++) {
        if (r->offset == offsetof(REG_SET, REG_PC)) {
            r->role = "PC";
            pc_def = r;
        }
    }
    regs_index = regs_def;
}
#endif
#endif
