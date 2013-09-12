/*******************************************************************************
 * Copyright (c) 2013 Stanislav Yakovlev.
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
#include <tcf/cpudefs-mdep.h>

#define REG_OFFSET(name) offsetof(REG_SET, name)

RegisterDefinition regs_def[] = {
#   define REG_PC user.regs.gpr[32]
    { "gpr0",      REG_OFFSET(user.regs.gpr[0]),      4, 0, 0, 1},
    { "gpr1",      REG_OFFSET(user.regs.gpr[1]),      4, 1, 1, 1},
    { "gpr2",      REG_OFFSET(user.regs.gpr[2]),      4, 2, 2, 1},
    { "gpr3",      REG_OFFSET(user.regs.gpr[3]),      4, 3, 3, 1},
    { "gpr4",      REG_OFFSET(user.regs.gpr[4]),      4, 4, 4, 1},
    { "gpr5",      REG_OFFSET(user.regs.gpr[5]),      4, 5, 5, 1},
    { "gpr6",      REG_OFFSET(user.regs.gpr[6]),      4, 6, 6, 1},
    { "gpr7",      REG_OFFSET(user.regs.gpr[7]),      4, 7, 7, 1},
    { "gpr8",      REG_OFFSET(user.regs.gpr[8]),      4, 8, 8, 1},
    { "gpr9",      REG_OFFSET(user.regs.gpr[9]),      4, 9, 9, 1},
    { "gpr10",     REG_OFFSET(user.regs.gpr[10]),     4, 10, 10, 1},
    { "gpr11",     REG_OFFSET(user.regs.gpr[11]),     4, 11, 11, 1},
    { "gpr12",     REG_OFFSET(user.regs.gpr[12]),     4, 12, 12, 1},
    { "gpr13",     REG_OFFSET(user.regs.gpr[13]),     4, 13, 13, 1},
    { "gpr14",     REG_OFFSET(user.regs.gpr[14]),     4, 14, 14, 1},
    { "gpr15",     REG_OFFSET(user.regs.gpr[15]),     4, 15, 15, 1},
    { "gpr16",     REG_OFFSET(user.regs.gpr[16]),     4, 16, 16, 1},
    { "gpr17",     REG_OFFSET(user.regs.gpr[17]),     4, 17, 17, 1},
    { "gpr18",     REG_OFFSET(user.regs.gpr[18]),     4, 18, 18, 1},
    { "gpr19",     REG_OFFSET(user.regs.gpr[19]),     4, 19, 19, 1},
    { "gpr20",     REG_OFFSET(user.regs.gpr[20]),     4, 20, 20, 1},
    { "gpr21",     REG_OFFSET(user.regs.gpr[21]),     4, 21, 21, 1},
    { "gpr22",     REG_OFFSET(user.regs.gpr[22]),     4, 22, 22, 1},
    { "gpr23",     REG_OFFSET(user.regs.gpr[23]),     4, 23, 23, 1},
    { "gpr24",     REG_OFFSET(user.regs.gpr[24]),     4, 24, 24, 1},
    { "gpr25",     REG_OFFSET(user.regs.gpr[25]),     4, 25, 25, 1},
    { "gpr26",     REG_OFFSET(user.regs.gpr[26]),     4, 26, 26, 1},
    { "gpr27",     REG_OFFSET(user.regs.gpr[27]),     4, 27, 27, 1},
    { "gpr28",     REG_OFFSET(user.regs.gpr[28]),     4, 28, 28, 1},
    { "gpr29",     REG_OFFSET(user.regs.gpr[29]),     4, 29, 29, 1},
    { "gpr30",     REG_OFFSET(user.regs.gpr[30]),     4, 30, 30, 1},
    { "gpr31",     REG_OFFSET(user.regs.gpr[31]),     4, 31, 31, 1},

    { "nip",       REG_OFFSET(user.regs.nip),         4, -1, -1, 1},
    { "msr",       REG_OFFSET(user.regs.msr),         4, 66, -1, 1},
    { "orig_gpr3", REG_OFFSET(user.regs.orig_gpr3),   4, -1, -1, 1},
    { "ctr",       REG_OFFSET(user.regs.ctr),         4, 109, -1, 1},
    { "link",      REG_OFFSET(user.regs.link),        4, 108, -1, 1},
    { "xer",       REG_OFFSET(user.regs.xer),         4, 101, -1, 1},
    { "ccr",       REG_OFFSET(user.regs.ccr),         4, -1, -1, 1},
    { "mq",        REG_OFFSET(user.regs.mq),          4, 100, -1, 1},
    { "trap",      REG_OFFSET(user.regs.trap),        4, -1, -1, 1},
    { "dar",       REG_OFFSET(user.regs.dar),         4, 119, -1, 1},
    { "dsisr",     REG_OFFSET(user.regs.dsisr),       4, 118, -1, 1},
    { "result",    REG_OFFSET(user.regs.result),      4, -1, -1, 1},

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
    return -1;
}

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
