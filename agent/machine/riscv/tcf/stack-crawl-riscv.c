/*******************************************************************************
* Copyright (c) 2019 Xilinx, Inc. and others.
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

/*
* This module implements stack crawl for RISC-V processor.
*/

#include <tcf/config.h>

#if ENABLE_DebugContext

#include <assert.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/context.h>
#include <tcf/framework/myalloc.h>
#include <machine/riscv/tcf/stack-crawl-riscv.h>

#define MEM_HASH_SIZE       61
#define REG_DATA_SIZE       32
#define BRANCH_LIST_SIZE    12

#define REG_VAL_FRAME        1
#define REG_VAL_ADDR         2
#define REG_VAL_STACK        3
#define REG_VAL_OTHER        4

#define REG_ID_RA   1
#define REG_ID_SP   2

#define MAX_INST 200

typedef struct {
    uint64_t v[MEM_HASH_SIZE]; /* Value bits 0..63 */
    uint64_t h[MEM_HASH_SIZE]; /* Value bits 64..127 */
    uint64_t a[MEM_HASH_SIZE]; /* Address */
    uint8_t  size[MEM_HASH_SIZE];
    uint8_t  valid[MEM_HASH_SIZE];
} MemData;

typedef struct {
    uint64_t v;
    uint64_t h;
    unsigned o;
} RegData;

typedef struct {
    uint64_t addr;
    RegData reg_data[REG_DATA_SIZE];
    RegData pc_data;
    MemData mem_data;
} BranchData;

static unsigned xlen = 0;

static Context * stk_ctx = NULL;
static StackFrame * stk_frame = NULL;
static MemData mem_data;
static RegData reg_data[REG_DATA_SIZE];
static RegData pc_data;

static uint32_t instr;

static unsigned branch_pos = 0;
static unsigned branch_cnt = 0;
static BranchData branch_data[BRANCH_LIST_SIZE];

static int trace_return = 0;
static int trace_branch = 0;

typedef struct {
    uint64_t addr;
    uint32_t size;
    uint8_t data[64];
} MemCache;

#define MEM_CACHE_SIZE       8
static MemCache mem_cache[MEM_CACHE_SIZE];
static unsigned mem_cache_idx = 0;

static const int imm_bits_w[32] = { 6, 10, 11, 12, 5 };
#if 0
static const int imm_bits_d[32] = { 10, 11, 12, 5, 6 };
static const int imm_bits_q[32] = { 11, 12, 5, 6, 10 };

static const int imm_bits_lw_sp[32] = { 4, 5, 6, 12, 2, 3 };
static const int imm_bits_ld_sp[32] = { 5, 6, 12, 2, 3, 4 };
static const int imm_bits_lq_sp[32] = { 6, 12, 2, 3, 4, 5 };
static const int imm_bits_sw_sp[32] = { 9, 10, 11, 12, 7, 8 };
static const int imm_bits_sd_sp[32] = { 10, 11, 12, 7, 8, 9 };
static const int imm_bits_sq_sp[32] = { 11, 12, 7, 8, 9, 10 };

static const int imm_bits_s[32] = { 7, 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 31 };
static const int imm_bits_j[32] = { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 20, 12, 13, 14, 15, 16, 17, 18, 19, 31 };
static const int imm_bits_b[32] = { 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 7, 31 };
static const int imm_bits_jc[32] = { 3, 4, 5, 11, 2, 7, 6, 9, 10, 8, 12 };
static const int imm_bits_bc[32] = { 3, 4, 10, 11, 2, 5, 6, 12 };

static const int imm_bits_addi_sp[32] = { 6, 2, 5, 3, 4, 12 };
#endif
static const int imm_bits_addi_spn[32] = { 6, 5, 11, 12, 7, 8, 9, 10 };
#if 0
static const int imm_bits_shift[32] = { 2, 3, 4, 5, 6, 12 };
#endif

static int read_reg128(StackFrame * frame, RegisterDefinition * reg_def, uint64_t * v, uint64_t * h);

static int read_byte(uint64_t addr, uint8_t * bt) {
    unsigned i = 0;
    MemCache * c = NULL;

    if (addr == 0) {
        errno = ERR_INV_ADDRESS;
        return -1;
    }
    for (i = 0; i < MEM_CACHE_SIZE; i++) {
        c = mem_cache + mem_cache_idx;
        if (c->addr <= addr && (c->addr + c->size < c->addr || c->addr + c->size > addr)) {
            *bt = c->data[addr - c->addr];
            return 0;
        }
        mem_cache_idx = (mem_cache_idx + 1) % MEM_CACHE_SIZE;
    }
    mem_cache_idx = (mem_cache_idx + 1) % MEM_CACHE_SIZE;
    c = mem_cache + mem_cache_idx;
    c->addr = addr;
    c->size = sizeof(c->data);
    if (context_read_mem(stk_ctx, (ContextAddress)addr, c->data, c->size) < 0) {
#if ENABLE_ExtendedMemoryErrorReports
        int error = errno;
        MemoryErrorInfo info;
        if (context_get_mem_error_info(&info) < 0 || info.size_valid == 0) {
            c->size = 0;
            errno = error;
            return -1;
        }
        c->size = info.size_valid;
#else
        c->size = 0;
        return -1;
#endif
    }
    *bt = c->data[0];
    return 0;
}

#if 0
static int read_u16(uint64_t addr, uint16_t * w) {
    unsigned i;
    uint16_t n = 0;
    for (i = 0; i < 2; i++) {
        uint8_t bt = 0;
        if (read_byte(addr + i, &bt) < 0) return -1;
        n |= (uint32_t)bt << (i * 8);
    }
    *w = n;
    return 0;
}
#endif

static int read_u32(uint64_t addr, uint32_t * w) {
    unsigned i;
    uint32_t n = 0;
    for (i = 0; i < 4; i++) {
        uint8_t bt = 0;
        if (read_byte(addr + i, &bt) < 0) return -1;
        n |= (uint32_t)bt << (i * 8);
    }
    *w = n;
    return 0;
}

static int read_u64(uint64_t addr, uint64_t * w) {
    unsigned i;
    uint64_t n = 0;
    for (i = 0; i < 8; i++) {
        uint8_t bt = 0;
        if (read_byte(addr + i, &bt) < 0) return -1;
        n |= (uint64_t)bt << (i * 8);
    }
    *w = n;
    return 0;
}

static int read_u128(uint64_t addr, uint64_t * w, uint64_t * h) {
    if (read_u64(addr, w) < 0) return -1;
    if (read_u64(addr + 8, h) < 0) return -1;
    return 0;
}

static int mem_hash_index(const uint64_t addr) {
    int v = (int)(addr % MEM_HASH_SIZE);
    int s = v;

    do {
        /* Check if the element is occupied */
        if (mem_data.size[s]) {
            /* Check if it is occupied with the sought data */
            if (mem_data.a[s] == addr)  return s;
        }
        else {
            /* Item is free, this is where the item should be stored */
            return s;
        }

        /* Search the next entry */
        s++;
        if (s >= MEM_HASH_SIZE) s = 0;
    } while (s != v);

    /* Search failed, hash is full and the address not stored */
    errno = ERR_OTHER;
    return -1;
}

static int mem_hash_read(uint64_t addr, uint64_t * v, uint64_t * h, unsigned bytes, int * valid) {
    int i = mem_hash_index(addr);

    if (i >= 0 && mem_data.size[i] && mem_data.a[i] == addr) {
        *v = mem_data.v[i];
        *h = mem_data.h[i];
        *valid = mem_data.valid[i] && mem_data.size[i] >= bytes;
        return 0;
    }

    /* Address not found in the hash */
    errno = ERR_OTHER;
    return -1;
}

static int load_reg(uint64_t addr, RegData * r) {
    int valid = 0;

    /* Check if the value can be found in the hash */
    if (mem_hash_read(addr, &r->v, &r->h, xlen >> 3, &valid) == 0) {
        r->o = valid ? REG_VAL_OTHER : 0;
    }
    else {
        /* Not in the hash, so read from real memory */
        uint32_t v = 0;
        r->o = 0;
        r->v = 0;
        r->h = 0;
        switch (xlen) {
        case 32:
            if (read_u32(addr, &v) < 0) return -1;
            r->v = v;
            break;
        case 64:
            if (read_u64(addr, &r->v) < 0) return -1;
            break;
        case 128:
            if (read_u128(addr, &r->v, &r->h) < 0) return -1;
            break;
        }
        r->o = REG_VAL_OTHER;
    }
    return 0;
}

static int load_reg_lazy(uint64_t addr, int r) {
    int valid = 0;
    if (mem_hash_read(addr, &reg_data[r].v, &reg_data[r].h, xlen >> 3, &valid) == 0) {
        if (valid) {
            reg_data[r].o = REG_VAL_OTHER;
            return 0;
        }
        reg_data[r].o = 0;
        reg_data[r].v = 0;
        reg_data[r].h = 0;
        return 0;
    }
    reg_data[r].o = REG_VAL_ADDR;
    reg_data[r].v = addr;
    return 0;
}

static int chk_reg_loaded(RegData * r) {
    if (r->o == 0) return 0;
    if (r->o == REG_VAL_OTHER) return 0;
    if (r->o == REG_VAL_FRAME) {
        RegisterDefinition * def = get_reg_definitions(stk_ctx) + r->v;
        if (read_reg128(stk_frame, def, &r->v, &r->h) < 0) {
            if (stk_frame->is_top_frame) return -1;
            r->o = 0;
            return 0;
        }
        r->o = REG_VAL_OTHER;
        return 0;
    }
    return load_reg(r->v, r);
}

static int chk_loaded(int r) {
    return chk_reg_loaded(reg_data + r);
}

static int mem_hash_write(uint64_t addr, uint64_t v, uint64_t h, unsigned bytes, int valid) {
    int n = mem_hash_index(addr);
    unsigned i;

    if (n < 0) {
        set_errno(ERR_OTHER, "Memory hash overflow");
        return -1;
    }

    /* Fix lazy loaded registers */
    for (i = 0; i < REG_DATA_SIZE; i++) {
        if (reg_data[i].o != REG_VAL_ADDR && reg_data[i].o != REG_VAL_STACK) continue;
        if (reg_data[i].v >= addr + 8) continue;
        if (reg_data[i].v + 8 <= addr) continue;
        if (load_reg(reg_data[i].v, reg_data + i) < 0) return -1;
    }

    /* Store the item */
    mem_data.a[n] = addr;
    mem_data.v[n] = valid ? v : 0;
    mem_data.h[n] = valid && bytes > 8 ? h : 0;
    mem_data.size[n] = bytes;
    mem_data.valid[n] = (uint8_t)valid;
    return 0;
}

static int store_reg(uint64_t addr, int r) {
    if (chk_loaded(r) < 0) return -1;
    assert(reg_data[r].o == 0 || reg_data[r].o == REG_VAL_OTHER);
    return mem_hash_write(addr, reg_data[r].v, reg_data[r].h, xlen >> 3, reg_data[r].o != 0);
}

static uint32_t get_imm(const int * bits) {
    unsigned i;
    uint32_t v = 0;
    for (i = 0; i < 32 && bits[i]; i++) {
        if (instr & (1u << bits[i])) v |= 1u << i;
    }
    return v;
}

#if 0
static int32_t get_imm_se(const int * bits) {
    unsigned i;
    uint32_t v = 0;
    for (i = 0; i < 32 && bits[i]; i++) {
        if (instr & (1u << bits[i])) v |= 1u << i;
    }
    if (v & (1u << (i - 1))) v |= ~((1u << i) - 1);
    return v;
}

static int32_t get_imm_rse(unsigned pos, unsigned bits) {
    uint32_t v = (instr >> pos) & ((1u << bits) - 1);
    if (v & (1u << (bits - 1))) v |= ~((1u << bits) - 1);
    return v;
}
#endif

static int trace_rv32(void) {
    /* Quadrant 0 */
    if ((instr & 0xffff) == 0x0000) {
        set_errno(ERR_OTHER, "Illegal instruction");
        return -1;
    }
    if ((instr & 0xe003) == 0x0000) {
        uint32_t imm = get_imm(imm_bits_addi_spn);
        if (imm != 0) {
            unsigned rd = ((instr >> 2) & 0x7) + 8;
            if (chk_loaded(2) < 0) return -1;
            reg_data[rd].v = reg_data[2].v + imm * 4;
            reg_data[rd].o = reg_data[2].o;
            return 0;
        }
    }
    if ((instr & 0x6003) == 0x2000) {
        /* FP registers are not traced */
        return 0;
    }
    if ((instr & 0x6003) == 0x4000) {
        unsigned rd = ((instr >> 2) & 0x7) + 8;
        unsigned rs = ((instr >> 7) & 0x7) + 8;
        int ld = (instr & 0x8000) == 0;
        if (chk_loaded(rs) < 0) return -1;
        if (!reg_data[rs].o) {
            if (ld) reg_data[rd].o = 0;
        }
        else {
            uint32_t imm = get_imm(imm_bits_w);
            uint64_t addr = reg_data[rs].v + imm * 4;
            if (ld) {
                load_reg_lazy(addr, rd);
            }
            else {
                if (store_reg(addr, rd) < 0) return -1;
            }
        }
        return 0;
    }
    if ((instr & 0x6003) == 0x6000) {
        /* FP registers are not traced */
        return 0;
    }

    return 0;
}

static int trace_rv64(void) {
    return 0;
}

static int trace_rv128(void) {
    return 0;
}

static int trace_rv32c(void) {
    return 0;
}

static int trace_rv64c(void) {
    return 0;
}

static int trace_rv128c(void) {
    return 0;
}

static int trace_riscv(void) {
    assert(pc_data.o != REG_VAL_ADDR);
    assert(pc_data.o != REG_VAL_STACK);

    /* Check PC alignment */
    if (pc_data.v & 0x3) {
        set_errno(ERR_OTHER, "PC misalignment");
        return -1;
    }

    /* Read the instruction */
    if (read_u32(pc_data.v, &instr) < 0) return -1;

    if ((instr & 3) == 3) {
        if (xlen == 32 && trace_rv32() < 0) return -1;
        if (xlen == 64 && trace_rv64() < 0) return -1;
        if (xlen == 128 && trace_rv128() < 0) return -1;
        if (!trace_return && !trace_branch) pc_data.v += 4;
    }
    else {
        instr &= 0xffff;
        if (xlen == 32 && trace_rv32c() < 0) return -1;
        if (xlen == 64 && trace_rv64c() < 0) return -1;
        if (xlen == 128 && trace_rv128c() < 0) return -1;
        if (!trace_return && !trace_branch) pc_data.v += 2;
    }

    return 0;
}

static int trace_instructions(void) {
    unsigned i;
    RegData org_pc = pc_data;
    RegData org_regs[REG_DATA_SIZE];
    memcpy(org_regs, reg_data, sizeof(org_regs));
    for (;;) {
        unsigned t;
        BranchData * b = NULL;
        if (chk_loaded(REG_ID_SP) < 0) return -1;
        trace(LOG_STACK, "Stack crawl: pc %#" PRIx64 ", sp %#" PRIx64,
            pc_data.o ? pc_data.v : (uint64_t)0,
            reg_data[REG_ID_SP].o ? reg_data[REG_ID_SP].v : (uint64_t)0);
        for (t = 0; t < MAX_INST; t++) {
            int error = 0;
            trace_return = 0;
            trace_branch = 0;
            if (pc_data.o != REG_VAL_OTHER) {
                error = set_errno(ERR_OTHER, "PC value not available");
            }
            else if (pc_data.v == 0) {
                error = set_errno(ERR_OTHER, "PC == 0");
            }
            else if (trace_riscv() < 0) {
                error = errno;
            }
            if (!error && trace_return) {
                if (chk_loaded(REG_ID_SP) < 0 || !reg_data[REG_ID_SP].o) {
                    error = set_errno(ERR_OTHER, "Stack crawl: invalid SP value");
                }
            }
            if (error) {
                trace(LOG_STACK, "Stack crawl: %s", errno_to_str(error));
                break;
            }
            if (trace_return) return 0;
            if (trace_branch) break;
        }
        if (branch_pos >= branch_cnt) break;
        b = branch_data + branch_pos++;
        memcpy(reg_data, b->reg_data, sizeof(reg_data));
        mem_data = b->mem_data;
        pc_data = b->pc_data;
    }
    trace(LOG_STACK, "Stack crawl: Function epilogue not found");
    for (i = 0; i < REG_DATA_SIZE; i++) reg_data[i].o = 0;
    pc_data.o = 0;

    if (pc_data.o == 0) {
        if (chk_reg_loaded(&org_pc) < 0) return -1;
        if (chk_reg_loaded(org_regs + REG_ID_RA) < 0) return -1;
        if (chk_reg_loaded(org_regs + REG_ID_SP) < 0) return -1;
        if (org_regs[REG_ID_SP].v != 0 && org_regs[REG_ID_RA].v != 0 && org_pc.v != org_regs[REG_ID_RA].v) {
            pc_data = org_regs[REG_ID_RA];
        }
    }
    return 0;
}

static int read_reg128(StackFrame * frame, RegisterDefinition * reg_def, uint64_t * v, uint64_t * h) {
    uint8_t buf[16];
    if (reg_def == NULL) {
        set_errno(ERR_INV_CONTEXT, "Invalid register");
        return -1;
    }
    if (frame == NULL) {
        set_errno(ERR_INV_CONTEXT, "Invalid stack frame");
        return -1;
    }
    if (reg_def->size > sizeof(buf)) {
        errno = ERR_INV_DATA_SIZE;
        return -1;
    }
    if (read_reg_bytes(frame, reg_def, 0, reg_def->size, buf) < 0) return -1;
    if (v != NULL) {
        size_t i;
        uint64_t n = 0;
        for (i = 0; i < 8 && i < reg_def->size; i++) {
            n = n << 8;
            n |= buf[reg_def->big_endian ? i : reg_def->size - i - 1];
        }
        *v = n;
    }
    if (h != NULL) {
        size_t i;
        uint64_t n = 0;
        for (i = 8; i < reg_def->size; i++) {
            n = n << 8;
            n |= buf[reg_def->big_endian ? i : reg_def->size - i - 1];
        }
        *h = n;
    }
    return 0;
}

static int write_reg128(StackFrame * frame, RegisterDefinition * reg_def, uint64_t v, uint64_t h) {
    size_t i;
    uint8_t buf[16];
    if (reg_def == NULL) {
        set_errno(ERR_INV_CONTEXT, "Invalid register");
        return -1;
    }
    if (frame == NULL) {
        set_errno(ERR_INV_CONTEXT, "Invalid stack frame");
        return -1;
    }
    if (reg_def->size > sizeof(buf)) {
        errno = ERR_INV_DATA_SIZE;
        return -1;
    }
    for (i = 0; i < 8 && i < reg_def->size; i++) {
        buf[reg_def->big_endian ? reg_def->size - i - 1 : i] = (uint8_t)v;
        v = v >> 8;
    }
    for (i = 8; i < reg_def->size; i++) {
        buf[reg_def->big_endian ? reg_def->size - i - 1 : i] = (uint8_t)h;
        h = h >> 8;
    }
    if (write_reg_bytes(frame, reg_def, 0, reg_def->size, buf) < 0) return -1;
    if (!frame->is_top_frame) frame->has_reg_data = 1;
    return 0;
}

static int crawl_stack_frame_riscv(StackFrame * frame, StackFrame * down) {
    RegisterDefinition * defs = get_reg_definitions(frame->ctx);
    RegisterDefinition * def = NULL;
    unsigned i;

    stk_ctx = frame->ctx;
    stk_frame = frame;
    memset(&mem_data, 0, sizeof(mem_data));
    memset(&reg_data, 0, sizeof(reg_data));
    memset(&pc_data, 0, sizeof(pc_data));
    branch_pos = 0;
    branch_cnt = 0;

    for (i = 0; i < MEM_CACHE_SIZE; i++) mem_cache[i].size = 0;

    for (def = defs; def->name; def++) {
        if (def->dwarf_id == REG_ID_SP) {
            if (read_reg128(frame, def, &reg_data[REG_ID_SP].v, &reg_data[REG_ID_SP].h) < 0) continue;
            if (reg_data[REG_ID_SP].v == 0) return 0;
            reg_data[REG_ID_SP].o = REG_VAL_OTHER;
        }
        else if (def->dwarf_id >= 0 && def->dwarf_id < REG_DATA_SIZE) {
            reg_data[def->dwarf_id].v = (uint32_t)(def - defs);
            reg_data[def->dwarf_id].o = REG_VAL_FRAME;
        }
        else if (strcmp(def->name, "pc") == 0) {
            if (read_reg128(frame, def, &pc_data.v, &pc_data.h) < 0) continue;
            pc_data.o = REG_VAL_OTHER;
        }
    }

    if (trace_instructions() < 0) return -1;

    for (def = defs; def->name; def++) {
        if (def->dwarf_id >= 0 && def->dwarf_id < REG_DATA_SIZE) {
            int r = def->dwarf_id;
#if ENABLE_StackRegisterLocations
            if (r == REG_ID_SP) {
                /* Skip */
            }
            else if (reg_data[r].o == REG_VAL_ADDR || reg_data[r].o == REG_VAL_STACK) {
                int valid = 0;
                uint64_t v = 0;
                uint64_t h = 0;
                uint64_t addr = reg_data[r].v;
                LocationExpressionCommand * cmds = NULL;
                if (mem_hash_read(addr, &v, &h, xlen >> 3, &valid) == 0) {
                    if (valid && write_reg128(down, def, v, h) < 0) return -1;
                    continue;
                }
                cmds = (LocationExpressionCommand *)tmp_alloc_zero(sizeof(LocationExpressionCommand) * 2);
                cmds[0].cmd = SFT_CMD_NUMBER;
                cmds[0].args.num = reg_data[r].v;
                cmds[1].cmd = SFT_CMD_RD_MEM;
                cmds[1].args.mem.size = 8;
                if (write_reg_location(down, def, cmds, 2) == 0) {
                    down->has_reg_data = 1;
                    continue;
                }
            }
            else if (reg_data[r].o == REG_VAL_FRAME) {
                LocationExpressionCommand * cmds = (LocationExpressionCommand *)tmp_alloc_zero(sizeof(LocationExpressionCommand));
                cmds[0].cmd = SFT_CMD_RD_REG;
                cmds[0].args.reg = defs + reg_data[r].v;
                if (write_reg_location(down, def, cmds, 1) == 0) {
                    down->has_reg_data = 1;
                    continue;
                }
            }
#endif
            if (chk_loaded(r) < 0) continue;
            if (!reg_data[r].o) continue;
            if (r == REG_ID_SP) frame->fp = (ContextAddress)reg_data[r].v;
            if (write_reg128(down, def, reg_data[r].v, reg_data[r].h) < 0) return -1;
        }
        else if (strcmp(def->name, "pc") == 0) {
            if (chk_reg_loaded(&pc_data) < 0) continue;
            if (!pc_data.o) continue;
            if (write_reg128(down, def, pc_data.v, pc_data.h) < 0) return -1;
        }
    }

    stk_frame = NULL;
    stk_ctx = NULL;
    return 0;
}

int crawl_stack_frame_riscv32(StackFrame * frame, StackFrame * down) {
    xlen = 32;
    return crawl_stack_frame_riscv(frame, down);
}

int crawl_stack_frame_riscv64(StackFrame * frame, StackFrame * down) {
    xlen = 32;
    return crawl_stack_frame_riscv(frame, down);
}

int crawl_stack_frame_riscv128(StackFrame * frame, StackFrame * down) {
    xlen = 32;
    return crawl_stack_frame_riscv(frame, down);
}

#endif /* ENABLE_DebugContext */
