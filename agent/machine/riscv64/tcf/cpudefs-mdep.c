/*******************************************************************************
* Copyright (c) 2019-2020 Xilinx, Inc. and others.
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
#include <tcf/config.h>

#if ENABLE_DebugContext && !ENABLE_ContextProxy

#include <assert.h>
#include <tcf/framework/cpudefs.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/trace.h>
#include <tcf/services/runctrl.h>
#if ENABLE_ContextMux
#include <tcf/framework/cpudefs-mdep-mux.h>
#endif
#include <tcf/disassembler-riscv64.h>
#include <tcf/stack-crawl-riscv64.h>
#include <tcf/cpudefs-mdep.h>

typedef struct ContextExtensionRISCV {
    int sw_stepping;
    char opcode[sizeof(BREAK_INST)];
    unsigned opcode_size;
    ContextAddress step_addr;
} ContextExtensionRISCV;

static size_t context_extension_offset = 0;

#define EXT(ctx) ((ContextExtensionRISCV *)((char *)(ctx) + context_extension_offset))

unsigned char BREAK_INST[] = {0x02, 0x90};
RegisterDefinition * regs_index;

static RegisterDefinition * reg_pc;
static unsigned regs_cnt;
static unsigned regs_max;

#define REG_OFFSET(name) offsetof(REG_SET, name)

static const RegisterDefinition rv_regs[] = {
    {.name="zero", .description="Zero register", .offset=REG_OFFSET(other), .no_write = 1},
    {.name="ra", .description="Return address", .role="RET"},
    {.name="sp", .description="Stack pointer", .role="SP"},
    {.name="gp", .description="Global pointer"},
    {.name="tp", .description="Thread pointer"},
    {.name="t0", .description="Temporary register"},
    {.name="t1", .description="Temporary register"},
    {.name="t2", .description="Temporary register"},
    {.name="s0", .description="Saved register / frame pointer"},
    {.name="s1", .description="Saved register"},
    {.name="a0", .description="Function argument / return value"},
    {.name="a1", .description="Function argument"},
    {.name="a2", .description="Function argument"},
    {.name="a3", .description="Function argument"},
    {.name="a4", .description="Function argument"},
    {.name="a5", .description="Function argument"},
    {.name="a6", .description="Function argument"},
    {.name="a7", .description="Function argument"},
    {.name="s2", .description="Saved register"},
    {.name="s3", .description="Saved register"},
    {.name="s4", .description="Saved register"},
    {.name="s5", .description="Saved register"},
    {.name="s6", .description="Saved register"},
    {.name="s7", .description="Saved register"},
    {.name="s8", .description="Saved register"},
    {.name="s9", .description="Saved register"},
    {.name="s10", .description="Saved register"},
    {.name="s11", .description="Saved register"},
    {.name="t3", .description="Temporary register"},
    {.name="t4", .description="Temporary register"},
    {.name="t5", .description="Temporary register"},
    {.name="t6", .description="Temporary register"},
    {NULL}
};

static RegisterDefinition * alloc_reg(void) {
    RegisterDefinition * r = regs_index + regs_cnt++;
    assert(regs_cnt <= regs_max);
    return r;
}

static RegisterDefinition * alloc_spr(const char * name, size_t offset, size_t size, int16_t id, const char * desc) {
    RegisterDefinition * reg = alloc_reg();
    reg->name = loc_strdup(name);
    reg->description = loc_strdup(desc);
    reg->dwarf_id = id;
    reg->eh_frame_id = id;
    reg->offset = offset;
    reg->size = size;
    return reg;
}

int mdep_get_other_regs(pid_t pid, REG_SET * data, size_t data_offs, size_t data_size,
        size_t * done_offs, size_t * done_size) {
    assert(data_offs >= REG_OFFSET(other));
    assert(data_offs + data_size <= REG_OFFSET(other) + sizeof(data->other));
    (void)pid;
    data->other = 0;
    *done_offs = REG_OFFSET(other);
    *done_size = sizeof(data->other);
    return 0;
}

int mdep_set_other_regs(pid_t pid, REG_SET * data, size_t data_offs, size_t data_size,
        size_t * done_offs, size_t * done_size) {
    assert(data_offs >= REG_OFFSET(other));
    assert(data_offs + data_size <= REG_OFFSET(other) + sizeof(data->other));
    (void)pid;
    *done_offs = REG_OFFSET(other);
    *done_size = sizeof(data->other);
    return 0;
}

RegisterDefinition * get_PC_definition(Context * ctx) {
    if (!context_has_state(ctx)) return NULL;
    return reg_pc;
}

int crawl_stack_frame(StackFrame * frame, StackFrame * down) {
    return crawl_stack_frame_riscv64(frame, down);
}

#if defined(ENABLE_add_cpudefs_disassembler) && ENABLE_add_cpudefs_disassembler
void add_cpudefs_disassembler(Context * cpu_ctx) {
    add_disassembler(cpu_ctx, "Riscv64", disassemble_riscv64);
}
#endif

#if ENABLE_external_stepping_mode

static Context * riscv_ctx;
static uint64_t riscv_pc;
static uint32_t riscv_instr;

static int riscv_read_reg(RegisterDefinition * r, uint64_t * res) {
    unsigned i;
    uint8_t buf[8];
    *res = 0;
    assert(r->size <= sizeof(buf));
    assert(!r->big_endian);
    if (context_read_reg(riscv_ctx, r, 0, r->size, buf) < 0) return -1;
    for (i = 0; i < r->size; i++) *res |= (uint64_t)buf[i] << (i * 8);
    return 0;
}

static int riscv_read_mem(uint64_t addr, uint32_t * res, unsigned size) {
    unsigned i;
    uint8_t buf[4];
    *res = 0;
    assert(size <= sizeof(buf));
    if (context_read_mem(riscv_ctx, (ContextAddress)addr, buf, size) < 0) return -1;
    for (i = 0; i < size; i++) *res |= (uint32_t)buf[i] << (i * 8);
    return 0;
}

static int32_t get_imm_se(const int * bits) {
    unsigned i;
    uint32_t v = 0;
    for (i = 0; i < 32 && bits[i]; i++) {
        if (riscv_instr & (1u << bits[i])) v |= 1u << i;
    }
    if (v & (1u << (i - 1))) v |= ~((1u << i) - 1);
    return v;
}

static int riscv_get_next_address(Context * ctx, ContextExtensionRISCV * ext) {
    static const int imm_bits_j[32] = { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 20, 12, 13, 14, 15, 16, 17, 18, 19, 31 };
    static const int imm_bits_jc[32] = { 3, 4, 5, 11, 2, 7, 6, 9, 10, 8, 12 };
    static const int imm_bits_b[32] = { 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 7, 31 };

    riscv_ctx = ctx;

    /* read opcode at PC */
    if (riscv_read_reg(reg_pc, &riscv_pc) < 0) return -1;
    if (riscv_read_mem(riscv_pc, &riscv_instr, 4) < 0) return -1;

    if ((riscv_instr & 3) == 3) {
        ext->step_addr = riscv_pc + 4;
    }
    else {
        riscv_instr &= 0xffff;
        ext->step_addr = riscv_pc + 2;
    }

    trace(LOG_CONTEXT, "pc 0x%016" PRIx64 ", opcode 0x%08x", riscv_pc, riscv_instr);

    if ((riscv_instr & 0x0000007f) == 0x0000006f) { /* j, jal */
        int32_t imm = get_imm_se(imm_bits_j);
        ext->step_addr = riscv_pc + ((int64_t)imm << 1);
        return 0;
    }
    if ((riscv_instr & 0xe003) == 0x2001) { /* addiw (replaces jal in RV64c) */
        return 0;
    }
    if ((riscv_instr & 0x6003) == 0x2001) { /* j, jal */
        int32_t imm = get_imm_se(imm_bits_jc);
        ext->step_addr = riscv_pc + ((int64_t)imm << 1);
        return 0;
    }
    if ((riscv_instr & 0x0000707f) == 0x00000067) { /* jalr */
        unsigned rs1 = (riscv_instr >> 15) & 0x1f;
        int32_t imm = riscv_instr >> 20;
        uint64_t addr = 0;
        if (riscv_read_reg(regs_index + rs1, &addr) < 0) return -1;
        ext->step_addr = (addr + ((int64_t)imm << 1)) & ~(uint64_t)1;
        return 0;
    }
    if ((riscv_instr & 0xe003) == 0x8002) { /* jr, jalr */
        unsigned rd = (riscv_instr >> 7) & 0x1f;
        unsigned rs = (riscv_instr >> 2) & 0x1f;
        uint64_t addr = 0;
        if (rd == 0) return 0;
        if (rs != 0) return 0;
        if (riscv_read_reg(regs_index + rd, &addr) < 0) return -1;
        ext->step_addr = addr & ~(uint64_t)1;
        return 0;
    }
    if ((riscv_instr & 0x0000007f) == 0x00000063) { /* beq, bne, blt, bge, bltu, bgeu */
        int32_t imm = get_imm_se(imm_bits_b);
        unsigned rs2 = (riscv_instr >> 20) & 0x1f;
        unsigned rs1 = (riscv_instr >> 15) & 0x1f;
        uint64_t x = 0, y = 0;
        int ok = 0;
        if (riscv_read_reg(regs_index + rs1, &x) < 0) return -1;
        if (riscv_read_reg(regs_index + rs2, &y) < 0) return -1;
        switch ((riscv_instr >> 12) & 7) {
        case 0: ok = x == y; break;
        case 1: ok = x != y; break;
        case 4: ok = (int64_t)x < (int64_t)y; break;
        case 5: ok = (int64_t)x >= (int64_t)y; break;
        case 6: ok = x < y; break;
        case 7: ok = x >= y; break;
        }
        if (ok) ext->step_addr = riscv_pc + ((int64_t)imm << 1);
        return 0;
    }

    return 0;
}

int cpu_enable_stepping_mode(Context * ctx, uint32_t * is_cont) {
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    ContextExtensionRISCV * ext = EXT(grp);
    assert(!grp->exited);
    assert(!ext->sw_stepping);
    if (riscv_get_next_address(ctx, ext) < 0) return -1;
    trace(LOG_CONTEXT, "enable_sw_stepping_mode %s 0x%08x", ctx->id, (unsigned)ext->step_addr);
    ext->opcode_size = sizeof(BREAK_INST);
    if (context_read_mem(grp, ext->step_addr, ext->opcode, ext->opcode_size) < 0) return -1;
    if (context_write_mem(grp, ext->step_addr, BREAK_INST, ext->opcode_size) < 0) return -1;
    ext->sw_stepping = 1;
    run_ctrl_lock();
    *is_cont = 1;
    return 0;
}

int cpu_disable_stepping_mode(Context * ctx) {
    Context * grp = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    ContextExtensionRISCV * ext = EXT(grp);
    if (ext->sw_stepping) {
        trace(LOG_CONTEXT, "disable_sw_stepping_mode %s", ctx->id);
        run_ctrl_unlock();
        ext->sw_stepping = 0;
        if (grp->exited) return 0;
        return context_write_mem(grp, ext->step_addr, ext->opcode, ext->opcode_size);
    }
    return 0;
}
#endif

void ini_cpudefs_mdep(void) {
    int i;

    context_extension_offset = context_extension(sizeof(ContextExtensionRISCV));

    regs_cnt = 0;
    regs_max = 128;
    regs_index = (RegisterDefinition *)loc_alloc_zero(sizeof(RegisterDefinition) * regs_max);

    for (i = 0; rv_regs[i].name != NULL; ++i) {
        RegisterDefinition * r = alloc_reg();
        *r = rv_regs[i];
        r->size = 8;
        r->dwarf_id = i;
        r->eh_frame_id = i;
        if (r->offset == 0) r->offset = i * 8;
    }
    reg_pc = alloc_spr("pc", REG_OFFSET(gp.pc), 8, -1, "Program counter");
    reg_pc->dwarf_id = reg_pc->eh_frame_id = 0x17b1;
    reg_pc->role = "PC";
}

#endif /* ENABLE_DebugContext && !ENABLE_ContextProxy */
