/*******************************************************************************
 * Copyright (c) 2015 Xilinx, Inc. and others.
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

#include <tcf/config.h>

#if ENABLE_DebugContext && !ENABLE_ContextProxy

#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/trace.h>
#include <tcf/services/symbols.h>
#include <tcf/services/runctrl.h>
#include <machine/a64/tcf/disassembler-a64.h>
#include <machine/a64/tcf/stack-crawl-a64.h>
#include <tcf/cpudefs-mdep.h>

#define REG_OFFSET(name) offsetof(REG_SET, name)

RegisterDefinition regs_def[] = {
    { "r0",      REG_OFFSET(gp.regs[0]),              8, 0, 0},
    { "sp",      REG_OFFSET(gp.sp),                   8, 31, 31},
    { "pc",      REG_OFFSET(gp.pc),                   8, 33, 33},
    { NULL,      0, 0,  0,  0},
};

RegisterDefinition * regs_index = NULL;
static unsigned regs_cnt = 0;
static unsigned regs_max = 0;

unsigned char BREAK_INST[] = { 0x00, 0x00, 0x20, 0xd4 };

static RegisterDefinition * pc_def = NULL;

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return pc_def;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {
    return crawl_stack_frame_a64(frame, down);
}

#if defined(ENABLE_add_cpudefs_disassembler) && ENABLE_add_cpudefs_disassembler
void add_cpudefs_disassembler(Context * cpu_ctx) {
    add_disassembler(cpu_ctx, "A64", disassemble_a64);
}
#endif

static RegisterDefinition * alloc_reg(void) {
    RegisterDefinition * r = regs_index + regs_cnt++;
    assert(regs_cnt <= regs_max);
    r->dwarf_id = -1;
    r->eh_frame_id = -1;
    r->big_endian = big_endian_host();
    return r;
}

static void ini_reg_defs(void) {
    RegisterDefinition * d;
    regs_cnt = 0;
    regs_max = 800;
    regs_index = (RegisterDefinition *)loc_alloc_zero(sizeof(RegisterDefinition) * regs_max);
    for (d = regs_def; d->name != NULL; d++) {
        RegisterDefinition * r = alloc_reg();
        assert(d->parent == NULL);
        *r = *d;
        if (strcmp(r->name, "sp") == 0) {
            r->role = "SP";
        }
        else if (strcmp(r->name, "pc") == 0) {
            r->role = "PC";
            pc_def = r;
        }
        else if (strcmp(r->name, "r0") == 0) {
            unsigned i;
            for (i = 1; i < 31; i++) {
                char name[64];
                r = alloc_reg();
                *r = *d;
                snprintf(name, sizeof(name), "r%d", i);
                r->name = loc_strdup(name);
                r->offset = d->offset + i * 8;
                r->dwarf_id = d->dwarf_id + i;
                r->eh_frame_id = d->eh_frame_id + i;
            }
        }
    }
}

void ini_cpudefs_mdep(void) {
    ini_reg_defs();
}

#endif
