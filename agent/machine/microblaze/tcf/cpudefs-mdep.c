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
#include <tcf/services/runctrl.h>
#include <machine/microblaze/tcf/stack-crawl-microblaze.h>
#include <machine/microblaze/tcf/disassembler-microblaze.h>
#if ENABLE_ContextMux
#include <tcf/framework/cpudefs-mdep-mux.h>
#endif
#include <tcf/cpudefs-mdep.h>

typedef struct ContextExtensionMicroBlaze {
    int sw_stepping;
    char opcode[sizeof(BREAK_INST)];
    ContextAddress addr;
} ContextExtensionMicroBlaze;

static size_t context_extension_offset = 0;

#define EXT(ctx) ((ContextExtensionMicroBlaze *)((char *)(ctx) + context_extension_offset))

RegisterDefinition * regs_index = NULL;
unsigned char BREAK_INST[] = { 0, 0, 0, 0 };

static RegisterDefinition * reg_pc = NULL;
static unsigned regs_cnt = 0;
static unsigned regs_max = 0;

#define REG_OFFSET(name) offsetof(REG_SET, name)

static RegisterDefinition * alloc_reg(size_t size) {
    assert(regs_cnt < regs_max - 1);
    regs_index[regs_cnt].size = size;
    regs_index[regs_cnt].dwarf_id = -1;
    regs_index[regs_cnt].eh_frame_id = -1;
    return regs_index + regs_cnt++;
}

static RegisterDefinition * alloc_group(const char * name) {
    RegisterDefinition * grp = alloc_reg(0);
    grp->name = loc_strdup(name);
    grp->no_read = 1;
    grp->no_write = 1;
    return grp;
}

static RegisterDefinition * alloc_spr(RegisterDefinition * grp, const char * name, size_t offset, size_t size, int id, const char * desc) {
    RegisterDefinition * reg = alloc_reg(size);
    reg->parent = grp;
    reg->name = loc_strdup(name);
    reg->description = loc_strdup(desc);
    reg->dwarf_id = (int16_t)id;
    reg->eh_frame_id = (int16_t)id;
    reg->offset = offset;
    return reg;
}

static void microblaze_create_reg_definitions(void) {
    unsigned i = 0;
    RegisterDefinition * pvr = NULL;

    regs_cnt = 0;
    regs_max = 128;
    regs_index = (RegisterDefinition *)loc_alloc_zero(sizeof(RegisterDefinition) * regs_max);

    for (i = 0; i < 32; i++) {
        RegisterDefinition * r = alloc_reg(4);
        r->name = loc_printf("r%d", i);
        r->dwarf_id = r->eh_frame_id = (int16_t)i;
        r->offset = REG_OFFSET(user.regs.gpr) + i * 4;
        switch (i) {
        case 0: r->no_write = 1; break;
        case 1: r->role = "SP"; break;
        case 15: r->role = "RET"; break;
        }
    }

    reg_pc = alloc_spr(NULL, "pc", REG_OFFSET(user.regs.pc), 4, 32, "Program Control Register");
    reg_pc->role = "PC";

    alloc_spr(NULL, "msr", REG_OFFSET(user.regs.msr), 4, 33, "Machine Status Register");
    alloc_spr(NULL, "ear", REG_OFFSET(user.regs.ear), 4, 34, "Exception Address Register");
    alloc_spr(NULL, "esr", REG_OFFSET(user.regs.esr), 4, 35, "Exception Status Register");
    alloc_spr(NULL, "fsr", REG_OFFSET(user.regs.fsr), 4, 36, "Floating Point Unit Status Register");
    alloc_spr(NULL, "btr", REG_OFFSET(user.regs.btr), 4, 37, "Exception Branch Taken Register");

    pvr = alloc_group("pvr");
    for (i = 0; i < 12; i++) {
        RegisterDefinition * r = alloc_reg(4);
        r->name = loc_printf("pvr%d", i);
        r->offset = REG_OFFSET(user.regs.pvr) + i * 4;
        r->parent = pvr;
    }
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

#if ENABLE_external_stepping_mode
static int read_reg(Context * ctx, RegisterDefinition * def, size_t size, ContextAddress * addr) {
    size_t i;
    uint8_t buf[8];
    uint64_t n = 0;
    *addr = 0;
    if (def->dwarf_id == 0) return 0;
    assert(!def->big_endian);
    assert(size <= def->size);
    assert(size <= sizeof(buf));
    if (context_read_reg(ctx, def, 0, size, buf) < 0) return -1;
    for (i = 0; i < size; i++) n |= (uint64_t)buf[i] << (i * 8);
    *addr = (ContextAddress)n;
    return 0;
}

static int read_mem(Context * ctx, ContextAddress addr, uint32_t * data) {
    size_t i;
    uint8_t buf[4];
    uint32_t v = 0;
    if (context_read_mem(ctx, addr, &buf, 4) < 0) return -1;
    for (i = 0; i < 4; i++) v |= (uint32_t)buf[i] << (big_endian_host() ? 3 - i : i) * 8;
    *data = v;
    return 0;
}

static int br_condition(uint32_t instr, ContextAddress data) {
    int32_t ra32 = (int32_t)data;
    int64_t ra64 = (int64_t)data;
    switch ((instr >> 21) & 0xf) {
    case  0: return ra32 == 0;
    case  1: return ra32 != 0;
    case  2: return ra32 < 0;
    case  3: return ra32 <= 0;
    case  4: return ra32 > 0;
    case  5: return ra32 >= 0;
    case  8: return ra64 == 0;
    case  9: return ra64 != 0;
    case 10: return ra64 < 0;
    case 11: return ra64 <= 0;
    case 12: return ra64 > 0;
    case 13: return ra64 >= 0;
    }
    return 0;
}

static int get_next_address(Context * ctx, ContextAddress * next_addr) {
    uint32_t instr = 0;
    uint64_t imm = 0;
    unsigned imm_bits = 0;
    ContextAddress addr = 0;
    ContextAddress instr_addr = 0;

    /* Read opcode at PC */
    if (read_reg(ctx, reg_pc, reg_pc->size, &addr) < 0) return -1;
    if (read_mem(ctx, addr, &instr) < 0) return -1;
    instr_addr = addr;
    addr += 4;

    /* Check for IMM and IMML instructions */
    if ((instr & 0xffff0000) == 0xb0000000) {
        imm_bits = 16;
        imm = instr & 0xffff;
        if (read_mem(ctx, addr, &instr) < 0) return -1;
        instr_addr = addr;
        addr += 4;
    }
    else if ((instr & 0xff000000) == 0xb2000000) {
        imm_bits = 24;
        imm = instr & 0xffffff;
        if (read_mem(ctx, addr, &instr) < 0) return -1;
        instr_addr = addr;
        addr += 4;
    }

    /* Check for branch and return instructions */
    if ((instr & 0xfc0007ff) == 0x98000000) {
        /* BR .. BRK */
        ContextAddress rb_data = 0;
        RegisterDefinition * rb_def = regs_index + ((instr >> 11) & 0x1f);
        if (read_reg(ctx, rb_def, rb_def->size, &rb_data) < 0) return -1;
        if (instr & (1 << 19)) {
            addr = rb_data;
        }
        else {
            addr = instr_addr + rb_data;
        }
    }
    else if ((instr & 0xfc0007ff) == 0x9c000000) {
        /* BEQ .. BGED */
        ContextAddress ra_data = 0;
        RegisterDefinition * ra_def = regs_index + ((instr >> 16) & 0x1f);
        if (read_reg(ctx, ra_def, ra_def->size, &ra_data) < 0) return -1;
        if (br_condition(instr, ra_data)) {
            ContextAddress rb_data = 0;
            RegisterDefinition * rb_def = regs_index + ((instr >> 11) & 0x1f);
            if (read_reg(ctx, rb_def, rb_def->size, &rb_data) < 0) return -1;
            addr = instr_addr + rb_data;
        }
        else if (instr & (1 << 25)) {
            addr += 4;
        }
    }
    else if ((instr & 0xfc000000) == 0xb4000000) {
        /* RTSD .. RTED */
        ContextAddress ra_data = 0;
        RegisterDefinition * ra_def = regs_index + ((instr >> 16) & 0x1f);
        if (read_reg(ctx, ra_def, ra_def->size, &ra_data) < 0) return -1;
        imm = (imm << 16) | (instr & 0xffff);
        imm_bits += 16;
        if (imm & ((uint64_t)1 << (imm_bits - 1))) {
            imm |= ~(((uint64_t)1 << imm_bits) - 1);
        }
        addr = ra_data + imm;
    }
    else if ((instr & 0xfc000000) == 0xb8000000) {
        /* BRI .. BRKI */
        imm = (imm << 16) | (instr & 0xffff);
        imm_bits += 16;
        if (imm & ((uint64_t)1 << (imm_bits - 1))) {
            imm |= ~(((uint64_t)1 << imm_bits) - 1);
        }
        if (instr & (1 << 19)) {
            addr = imm;
        }
        else {
            addr = instr_addr + imm;
        }
    }
    else if ((instr & 0xfc000000) == 0xbc000000) {
        /* BEQI .. BGEID */
        ContextAddress ra_data = 0;
        RegisterDefinition * ra_def = regs_index + ((instr >> 16) & 0x1f);
        if (read_reg(ctx, ra_def, ra_def->size, &ra_data) < 0) return -1;
        if (br_condition(instr, ra_data)) {
            imm = (imm << 16) | (instr & 0xffff);
            imm_bits += 16;
            if (imm & ((uint64_t)1 << (imm_bits - 1))) {
                imm |= ~(((uint64_t)1 << imm_bits) - 1);
            }
            addr = instr_addr + imm;
        }
        else if (instr & (1 << 25)) {
            addr += 4;
        }
    }

    *next_addr = addr;
    return 0;
}

int cpu_enable_stepping_mode(Context * ctx, uint32_t * is_cont) {
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    ContextExtensionMicroBlaze * ext = EXT(grp);
    assert(!grp->exited);
    assert(!ext->sw_stepping);
    if (get_next_address(ctx, &ext->addr) < 0) return -1;
    if (context_read_mem(grp, ext->addr, ext->opcode, sizeof(BREAK_INST)) < 0) return -1;
    if (context_write_mem(grp, ext->addr, BREAK_INST, sizeof(BREAK_INST)) < 0) return -1;
    ext->sw_stepping = 1;
    run_ctrl_lock();
    *is_cont = 1;
    return 0;
}

int cpu_disable_stepping_mode(Context * ctx) {
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    ContextExtensionMicroBlaze * ext = EXT(grp);
    if (ext->sw_stepping) {
        run_ctrl_unlock();
        ext->sw_stepping = 0;
        if (grp->exited) return 0;
        return context_write_mem(grp, ext->addr, ext->opcode, sizeof(BREAK_INST));
    }
    return 0;
}
#endif

void ini_cpudefs_mdep(void) {
    static uint8_t bkpt_le[4] = { 0x18, 0x00, 0x0c, 0xba };
    static uint8_t bkpt_be[4] = { 0xba, 0x0c, 0x00, 0x18 };
    context_extension_offset = context_extension(sizeof(ContextExtensionMicroBlaze));
    memcpy(BREAK_INST, big_endian_host() ? bkpt_be : bkpt_le, 4);
    microblaze_create_reg_definitions();
}

#endif /* ENABLE_DebugContext && !ENABLE_ContextProxy */
