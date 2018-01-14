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

#include <tcf/config.h>

#if ENABLE_DebugContext && !ENABLE_ContextProxy

#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#include <machine/microblaze/tcf/stack-crawl-microblaze.h>
#include <machine/microblaze/tcf/disassembler-microblaze.h>
#if ENABLE_ContextMux
#include <tcf/framework/cpudefs-mdep-mux.h>
#endif
#include <tcf/cpudefs-mdep.h>

RegisterDefinition * regs_index = NULL;
unsigned char BREAK_INST[] = { 0, 0, 0, 0 };

static RegisterDefinition * reg_pc = NULL;
static unsigned regs_cnt = 0;
static unsigned regs_max = 0;
static size_t regs_offs = 0;

static RegisterDefinition * alloc_reg(size_t size) {
    assert(regs_cnt < regs_max - 1);
    regs_index[regs_cnt].offset = regs_offs;
    regs_index[regs_cnt].size = size;
    regs_index[regs_cnt].dwarf_id = -1;
    regs_index[regs_cnt].eh_frame_id = -1;
    regs_offs += size;
    return regs_index + regs_cnt++;
}

static RegisterDefinition * alloc_group(const char * name) {
    RegisterDefinition * grp = alloc_reg(0);
    grp->name = loc_strdup(name);
    grp->no_read = 1;
    grp->no_write = 1;
    return grp;
}

static RegisterDefinition * alloc_spr(RegisterDefinition * grp, const char * name, size_t size, int id, const char * desc) {
    RegisterDefinition * reg = alloc_reg(size);
    reg->parent = grp;
    reg->name = loc_strdup(name);
    reg->description = loc_strdup(desc);
    reg->dwarf_id = (int16_t)id;
    reg->eh_frame_id = (int16_t)id;
    return reg;
}

static void microblaze_create_reg_definitions(void) {
    unsigned i = 0;

    regs_offs = 0;
    regs_cnt = 0;
    regs_max = 128;
    regs_index = (RegisterDefinition *)loc_alloc_zero(sizeof(RegisterDefinition) * regs_max);

    for (i = 0; i < 32; i++) {
        char name[32];
        RegisterDefinition * r = alloc_reg(4);
        snprintf(name, sizeof(name), "r%d", i);
        r->name = loc_strdup(name);
        r->dwarf_id = r->eh_frame_id = (int16_t)i;
        switch (i) {
        case 0: r->no_write = 1; break;
        case 1: r->role = "SP"; break;
        case 15: r->role = "RET"; break;
        }
    }

    reg_pc = alloc_spr(NULL, "pc", 4, 32, "Program Control Register");
    reg_pc->role = "PC";

    alloc_spr(NULL, "msr", 4, 33, "Machine Status Register");
    alloc_spr(NULL, "ear", 4, 34, "Exception Address Register");
    alloc_spr(NULL, "esr", 4, 35, "Exception Status Register");
    alloc_spr(NULL, "fsr", 4, 36, "Floating Point Unit Status Register");
    alloc_spr(NULL, "btr", 4, 37, "Exception Branch Taken Register");

    /* TODO: check if CPU configured with MMU */
    {
        RegisterDefinition * grp = alloc_group("mmu");
        alloc_spr(grp, "pid", 4, 51, "Process Identifier Register");
        alloc_spr(grp, "zpr", 4, 52, "Zone Protection Register");
        alloc_spr(grp, "tlbx", 4, 53, "Translation Look-Aside Buffer Index Register");
        alloc_spr(grp, "tlbsx", 4, 54, "Translation Look-Aside Buffer Search Index Register");
        alloc_spr(grp, "tlblo", 4, 55, "Translation Look-Aside Buffer Low Register");
        alloc_spr(grp, "tlbhi", 4, 56, "Translation Look-Aside Buffer High Register");
    }
    alloc_spr(NULL, "slr", 4, 57, "Stack protection - Low pointer");
    alloc_spr(NULL, "shr", 4, 58, "Stack protection - High pointer");
}

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return reg_pc;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {
    return crawl_stack_frame_microblaze(frame, down);
}

#if ENABLE_add_cpudefs_disassembler
void add_cpudefs_disassembler(Context * cpu_ctx) {
    add_disassembler(cpu_ctx, "MicroBlaze", disassemble_microblaze);
}
#endif

void ini_cpudefs_mdep(void) {
    static uint8_t bkpt_le[4] = { 0x18, 0x00, 0x0c, 0xba };
    static uint8_t bkpt_be[4] = { 0xba, 0x0c, 0x00, 0x18 };
    memcpy(BREAK_INST, big_endian_host() ? bkpt_be : bkpt_le, 4);
    microblaze_create_reg_definitions();
}

#endif /* ENABLE_DebugContext && !ENABLE_ContextProxy */
