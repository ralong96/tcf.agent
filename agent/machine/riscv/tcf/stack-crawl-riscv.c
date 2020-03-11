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
#include <machine/riscv/tcf/uxlen.h>
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
    int_xlen_t  v[MEM_HASH_SIZE]; /* Value */
    int_xlen_t  a[MEM_HASH_SIZE]; /* Address */
    uint8_t  size[MEM_HASH_SIZE];
    uint8_t  valid[MEM_HASH_SIZE];
} MemData;

typedef struct {
    int_xlen_t v;
    unsigned o;
} RegData;

typedef struct {
    int_xlen_t addr;
    RegData reg_data[REG_DATA_SIZE];
    RegData pc_data;
    MemData mem_data;
} BranchData;

static Context * stk_ctx = NULL;
static StackFrame * stk_frame = NULL;
static MemData mem_data;
static RegData reg_data[REG_DATA_SIZE];
static RegData pc_data;
static RegData mepc_data;
static RegData sepc_data;
static RegData uepc_data;

static uint32_t instr;

static unsigned branch_pos = 0;
static unsigned branch_cnt = 0;
static BranchData branch_data[BRANCH_LIST_SIZE];

static int trace_return = 0;
static int trace_branch = 0;

typedef struct {
    ContextAddress addr;
    size_t size;
    uint8_t data[64];
} MemCache;

#define MEM_CACHE_SIZE       8
static MemCache mem_cache[MEM_CACHE_SIZE];
static unsigned mem_cache_idx = 0;

static const int imm_bits_w[32] = { 6, 10, 11, 12, 5 };
static const int imm_bits_d[32] = { 10, 11, 12, 5, 6 };
static const int imm_bits_q[32] = { 11, 12, 5, 6, 10 };

static const int imm_bits_lw_sp[32] = { 4, 5, 6, 12, 2, 3 };
static const int imm_bits_ld_sp[32] = { 5, 6, 12, 2, 3, 4 };
static const int imm_bits_lq_sp[32] = { 6, 12, 2, 3, 4, 5 };
static const int imm_bits_sw_sp[32] = { 9, 10, 11, 12, 7, 8 };
static const int imm_bits_sd_sp[32] = { 10, 11, 12, 7, 8, 9 };
static const int imm_bits_sq_sp[32] = { 11, 12, 7, 8, 9, 10 };

static const int imm_bits_s[32] = { 7, 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 31 };
static const int imm_bits_b[32] = { 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 7, 31 };
static const int imm_bits_j[32] = { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 20, 12, 13, 14, 15, 16, 17, 18, 19, 31 };
static const int imm_bits_jc[32] = { 3, 4, 5, 11, 2, 7, 6, 9, 10, 8, 12 };
static const int imm_bits_bc[32] = { 3, 4, 10, 11, 2, 5, 6, 12 };

static const int imm_bits_addi_sp[32] = { 6, 2, 5, 3, 4, 12 };
static const int imm_bits_addi_spn[32] = { 6, 5, 11, 12, 7, 8, 9, 10 };
static const int imm_bits_shift[32] = { 2, 3, 4, 5, 6, 12 };

static int read_reg128(StackFrame * frame, RegisterDefinition * reg_def, int_xlen_t * v);

static int read_mem(ContextAddress address, void * buf, size_t size) {
#if ENABLE_MemoryAccessModes
    static MemoryAccessMode mem_access_mode = { 0, 0, 0, 0, 0, 0, 1 };
    return context_read_mem_ext(stk_ctx, &mem_access_mode, address, buf, size);
#else
    return context_read_mem(stk_ctx, address, buf, size);
#endif
}

static int read_byte(int_xlen_t addr, uint8_t * bt) {
    unsigned i = 0;
    MemCache * c = NULL;
    ContextAddress ca = 0;

    addr = fix_sign(addr, xlen, 0);
    if (int_xlen_to_h(addr) != 0) {
        /* TODO: 128-bit memory address */
        errno = ERR_INV_ADDRESS;
        return -1;
    }
    ca = (ContextAddress)int_xlen_to_l(addr);
    if (ca == 0) {
        errno = ERR_INV_ADDRESS;
        return -1;
    }
    for (i = 0; i < MEM_CACHE_SIZE; i++) {
        c = mem_cache + mem_cache_idx;
        if (c->addr <= ca && (c->addr + c->size < c->addr || c->addr + c->size > ca)) {
            *bt = c->data[ca - c->addr];
            return 0;
        }
        mem_cache_idx = (mem_cache_idx + 1) % MEM_CACHE_SIZE;
    }
    mem_cache_idx = (mem_cache_idx + 1) % MEM_CACHE_SIZE;
    c = mem_cache + mem_cache_idx;
    c->addr = ca;
    c->size = sizeof(c->data);
    if (read_mem(ca, c->data, c->size) < 0) {
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

static int read_u16(int_xlen_t addr, uint16_t * w) {
    unsigned i;
    uint16_t n = 0;
    for (i = 0; i < 2; i++) {
        uint8_t bt = 0;
        if (read_byte(int_xlen_add_u(addr, i), &bt) < 0) return -1;
        n |= (uint32_t)bt << (i * 8);
    }
    *w = n;
    return 0;
}

static int read_u32(int_xlen_t addr, uint32_t * w) {
    unsigned i;
    uint32_t n = 0;
    for (i = 0; i < 4; i++) {
        uint8_t bt = 0;
        if (read_byte(int_xlen_add_u(addr, i), &bt) < 0) return -1;
        n |= (uint32_t)bt << (i * 8);
    }
    *w = n;
    return 0;
}

static int read_u64(int_xlen_t addr, uint64_t * w) {
    unsigned i;
    uint64_t n = 0;
    for (i = 0; i < 8; i++) {
        uint8_t bt = 0;
        if (read_byte(int_xlen_add_u(addr, i), &bt) < 0) return -1;
        n |= (uint64_t)bt << (i * 8);
    }
    *w = n;
    return 0;
}

static int read_u128(int_xlen_t addr, int_xlen_t * v) {
    uint64_t l = 0;
    uint64_t h = 0;
    if (read_u64(addr, &l) < 0) return -1;
    if (read_u64(int_xlen_add_u(addr, 8), &h) < 0) return -1;
    *v = int_xlen_from_u2(l, h);
    return 0;
}

static int mem_hash_index(const int_xlen_t addr) {
    int v = (int)(int_xlen_to_l(addr) % MEM_HASH_SIZE);
    int s = v;

    do {
        /* Check if the element is occupied */
        if (mem_data.size[s]) {
            /* Check if it is occupied with the sought data */
            if (int_xlen_cmpu(mem_data.a[s], addr) == 0)  return s;
        }
        else {
            /* Item is free, this is where the item should be stored */
            return s;
        }

        /* Search the next entry */
        s++;
        if (s >= MEM_HASH_SIZE) s = 0;
    }
    while (s != v);

    /* Search failed, hash is full and the address not stored */
    errno = ERR_OTHER;
    return -1;
}

static int mem_hash_read(const int_xlen_t addr, int_xlen_t * v, unsigned bytes, int * valid) {
    int i = mem_hash_index(addr);

    if (i >= 0 && mem_data.size[i] && int_xlen_cmpu(mem_data.a[i], addr) == 0) {
        *valid = mem_data.valid[i] && mem_data.size[i] >= bytes;
        *v = mem_data.v[i];
        return 0;
    }

    /* Address not found in the hash */
    errno = ERR_OTHER;
    return -1;
}

static int load_reg_from_mem(const int_xlen_t addr, RegData * r, unsigned bits) {
    uint8_t v8 = 0;
    uint16_t v16 = 0;
    uint32_t v32 = 0;
    uint64_t v64 = 0;
    memset(r, 0, sizeof(RegData));
    switch (bits) {
    case 8:
        if (read_byte(addr, &v8) < 0) return -1;
        r->v = int_xlen_from_u(v8);
        break;
    case 16:
        if (read_u16(addr, &v16) < 0) return -1;
        r->v = int_xlen_from_u(v16);
        break;
    case 32:
        if (read_u32(addr, &v32) < 0) return -1;
        r->v = int_xlen_from_u(v32);
        break;
    case 64:
        if (read_u64(addr, &v64) < 0) return -1;
        r->v = int_xlen_from_u(v64);
        break;
    case 128:
        if (read_u128(addr, &r->v) < 0) return -1;
        break;
    default:
        errno = ERR_UNSUPPORTED;
        return -1;
    }
    r->o = REG_VAL_OTHER;
    return 0;
}

static int load_reg(const int_xlen_t addr, RegData * r, unsigned bits) {
    int valid = 0;

    /* Check if the value can be found in the hash */
    if (mem_hash_read(addr, &r->v, bits >> 3, &valid) == 0) {
        if (valid) {
            r->v = fix_sign(r->v, bits, 1);
            r->o = REG_VAL_OTHER;
            return 0;
        }
        memset(r, 0, sizeof(RegData));
    }
    else {
        /* Not in the hash, so read from real memory */
        if (load_reg_from_mem(addr, r, bits) < 0) return -1;
        r->v = fix_sign(r->v, bits, 1);
    }
    return 0;
}

static int load_reg_lazy(int_xlen_t addr, unsigned r, unsigned bits, int sign) {
    int valid = 0;
    if (mem_hash_read(addr, &reg_data[r].v, bits >> 3, &valid) == 0) {
        if (valid) {
            reg_data[r].v = fix_sign(reg_data[r].v, bits, sign);
            reg_data[r].o = REG_VAL_OTHER;
            return 0;
        }
        memset(reg_data + r, 0, sizeof(RegData));
        return 0;
    }
    if (bits == xlen) {
        reg_data[r].o = REG_VAL_ADDR;
        reg_data[r].v = addr;
        return 0;
    }
    if (load_reg_from_mem(addr, reg_data + r, bits) < 0) return -1;
    reg_data[r].v = fix_sign(reg_data[r].v, bits, sign);
    return 0;
}

static int chk_reg_loaded(RegData * r) {
    if (r->o == 0) return 0;
    if (r->o == REG_VAL_OTHER) return 0;
    if (r->o == REG_VAL_FRAME) {
        RegisterDefinition * def = get_reg_definitions(stk_ctx) + int_xlen_to_l(r->v);
        if (read_reg128(stk_frame, def, &r->v) < 0) {
            if (stk_frame->is_top_frame) return -1;
            r->o = 0;
            return 0;
        }
        r->o = REG_VAL_OTHER;
        return 0;
    }
    return load_reg(r->v, r, xlen);
}

static int chk_loaded(unsigned r) {
    return chk_reg_loaded(reg_data + r);
}

static int mem_hash_write(int_xlen_t addr, int_xlen_t v, unsigned bytes, int valid) {
    int n = mem_hash_index(addr);
    unsigned i;

    if (n < 0) {
        set_errno(ERR_OTHER, "Memory hash overflow");
        return -1;
    }

    /* Fix lazy loaded registers */
    for (i = 0; i < REG_DATA_SIZE; i++) {
        if (reg_data[i].o != REG_VAL_ADDR && reg_data[i].o != REG_VAL_STACK) continue;
        if (int_xlen_cmpu(reg_data[i].v, int_xlen_add_u(addr, xlen >> 3)) >= 0) continue;
        if (int_xlen_cmpu(int_xlen_add_u(reg_data[i].v, xlen >> 3), addr) <= 0) continue;
        if (load_reg(reg_data[i].v, reg_data + i, xlen) < 0) return -1;
    }

    /* Store the item */
    mem_data.a[n] = addr;
    mem_data.v[n] = v;
    mem_data.size[n] = (uint8_t)bytes;
    mem_data.valid[n] = (uint8_t)valid;
    return 0;
}

static int store_reg(int_xlen_t addr, unsigned r, unsigned bits) {
    if (chk_loaded(r) < 0) return -1;
    assert(reg_data[r].o == 0 || reg_data[r].o == REG_VAL_OTHER);
    return mem_hash_write(addr, reg_data[r].v, bits >> 3, reg_data[r].o != 0);
}

static uint32_t get_imm(const int * bits) {
    unsigned i;
    uint32_t v = 0;
    for (i = 0; i < 32 && bits[i]; i++) {
        if (instr & (1u << bits[i])) v |= 1u << i;
    }
    return v;
}

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

static void add_branch(int_xlen_t addr) {
    if (branch_cnt < BRANCH_LIST_SIZE) {
        int add = 1;
        unsigned i = 0;
        addr = fix_sign(addr, xlen, 1);
        for (i = 0; i < branch_cnt; i++) {
            BranchData * b = branch_data + i;
            if (int_xlen_cmpu(b->addr, addr) == 0) {
                add = 0;
                break;
            }
        }
        if (add) {
            BranchData * b = branch_data + branch_cnt++;
            b->addr = addr;
            b->mem_data = mem_data;
            memcpy(b->reg_data, reg_data, sizeof(reg_data));
            b->pc_data.o = REG_VAL_OTHER;
            b->pc_data.v = addr;
        }
    }
}

static int trace_rv32i(void) {
    unsigned func = (instr >> 12) & 7;
    unsigned rs2 = (instr >> 20) & 0x1f;
    unsigned rs1 = (instr >> 15) & 0x1f;
    unsigned rd = (instr >> 7) & 0x1f;
    if ((instr & 0x0000007f) == 0x00000037) { /* lui */
        if (rd != 0) {
            int64_t imm = (int32_t)(instr & 0xfffff000);
            reg_data[rd].v = int_xlen_from_i(imm);
            reg_data[rd].o = REG_VAL_OTHER;
        }
        return 0;
    }
    if ((instr & 0x0000007f) == 0x00000017) { /* auipc */
        if (rd != 0) {
            int64_t imm = (int32_t)(instr & 0xfffff000);
            reg_data[rd].v = int_xlen_add(pc_data.v, int_xlen_from_i(imm));
            reg_data[rd].o = REG_VAL_OTHER;
        }
        return 0;
    }
    if ((instr & 0x0000007f) == 0x0000006f) { /* j, jal */
        int32_t imm = get_imm_se(imm_bits_j);
        if (rd == 0) {
            add_branch(int_xlen_add_i(pc_data.v, (int64_t)imm << 1));
            trace_branch = 1;
        }
        else {
            reg_data[rd].v = int_xlen_add_u(pc_data.v, 4);
            reg_data[rd].o = pc_data.o;
        }
        return 0;
    }
    if ((instr & 0x0000707f) == 0x00000067) { /* jalr */
        int32_t imm = instr >> 20;
        if (rd == 0) {
            if (imm == 0 && rs1 == 1) { /* ret */
                pc_data = reg_data[1];
                trace_return = 1;
                return 0;
            }
            if (reg_data[rs1].o) add_branch(reg_data[rs1].v);
            trace_branch = 1;
            return 0;
        }
        reg_data[rd].v = int_xlen_add_u(pc_data.v, 4);
        reg_data[rd].o = pc_data.o;
        return 0;
    }
    if ((instr & 0x0000007f) == 0x00000063) { /* conditional branch */
        int32_t imm = get_imm_se(imm_bits_b);
        add_branch(int_xlen_add_i(pc_data.v, (int64_t)imm << 1));
        return 0;
    }
    if ((instr & 0x0000007f) == 0x00000003) {
        if (func <= 2 || func == 4 || func == 5) {
            if (rd != 0) {
                int32_t imm = get_imm_rse(20, 12);
                if (chk_loaded(rs1) < 0) return -1;
                if (reg_data[rs1].o) {
                    int_xlen_t addr = int_xlen_add_i(reg_data[rs1].v, imm);
                    switch (func) {
                    case 0:
                        /* lb */
                        return load_reg_lazy(addr, rd, 8, 1);
                    case 1:
                        /* lh */
                        return load_reg_lazy(addr, rd, 16, 1);
                    case 2:
                        /* lw */
                        return load_reg_lazy(addr, rd, 32, 1);
                    case 4:
                        /* lbu */
                        return load_reg_lazy(addr, rd, 8, 0);
                    case 5:
                        /* lhu */
                        return load_reg_lazy(addr, rd, 16, 0);
                    }
                }
                reg_data[rd].o = 0;
            }
            return 0;
        }
    }
    if ((instr & 0x0000007f) == 0x00000023) {
        if (func <= 2) {
            int32_t imm = get_imm_se(imm_bits_s);
            if (chk_loaded(rs1) < 0) return -1;
            if (reg_data[rs1].o) {
                int_xlen_t addr = int_xlen_add_i(reg_data[rs1].v, imm);
                switch (func) {
                case 0:
                    /* sb */
                    return store_reg(addr, rs2, 8);
                case 1:
                    /* sh */
                    return store_reg(addr, rs2, 16);
                case 2:
                    /* sw */
                    return store_reg(addr, rs2, 32);
                }
            }
            return 0;
        }
    }
    if ((instr & 0x0000007f) == 0x00000013) {
        if (func != 1 && func != 5) {
            if (rd != 0) {
                int32_t imm = get_imm_rse(20, 12);
                if (chk_loaded(rs1) < 0) return -1;
                if (reg_data[rs1].o) {
                    switch (func) {
                    case 0: /* addi */
                        reg_data[rd].v = int_xlen_add(reg_data[rs1].v, int_xlen_from_i(imm));
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 2: /* slti */
                        reg_data[rd].v = int_xlen_from_u(int_xlen_cmpi(reg_data[rs1].v, int_xlen_from_i(imm)) < 0 ? 1 : 0);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 3: /* sltiu */
                        reg_data[rd].v = int_xlen_from_u(int_xlen_cmpu(reg_data[rs1].v, int_xlen_from_i(imm)) < 0 ? 1 : 0);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 4: /* xori */
                        reg_data[rd].v = int_xlen_xor(reg_data[rs1].v, int_xlen_from_i(imm));
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 6: /* ori */
                        reg_data[rd].v = int_xlen_or(reg_data[rs1].v, int_xlen_from_i(imm));
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 7: /* andi */
                        reg_data[rd].v = int_xlen_and(reg_data[rs1].v, int_xlen_from_i(imm));
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    }
                }
                reg_data[rd].o = 0;
            }
            return 0;
        }
    }
    if ((instr & 0xbe00007f) == 0x00000013) {
        if (func == 1 || func == 5) {
            if (rd != 0) {
                uint32_t imm = (instr >> 20) & 0x1f;
                if (chk_loaded(rs1) < 0) return -1;
                if (reg_data[rs1].o) {
                    switch (func) {
                    case 1:
                        reg_data[rd].v = int_xlen_sll(reg_data[rs1].v, imm);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 5:
                        reg_data[rd].v = instr & (1 << 30) ?
                            int_xlen_sra(reg_data[rs1].v, imm) :
                            int_xlen_srl(reg_data[rs1].v, imm);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    }
                }
                reg_data[rd].o = 0;
            }
            return 0;
        }
    }
    if ((instr & 0xfe00007f) == 0x00000033) {
        if (rd != 0) {
            if (chk_loaded(rs1) < 0) return -1;
            if (chk_loaded(rs2) < 0) return -1;
            if (reg_data[rs1].o && reg_data[rs2].o) {
                switch (func) {
                case 0: /* add */
                    reg_data[rd].v = int_xlen_add(reg_data[rs1].v, reg_data[rs2].v);
                    reg_data[rd].o = REG_VAL_OTHER;
                    return 0;
                case 1: /* sll */
                    reg_data[rd].v = int_xlen_sll(reg_data[rs1].v, int_xlen_to_l(reg_data[rs2].v) & (xlen - 1));
                    reg_data[rd].o = REG_VAL_OTHER;
                    return 0;
                case 2: /* slt */
                    reg_data[rd].v = int_xlen_from_u(int_xlen_cmpi(reg_data[rs1].v, reg_data[rs2].v) < 0 ? 1 : 0);
                    reg_data[rd].o = REG_VAL_OTHER;
                    return 0;
                case 3: /* sltu */
                    reg_data[rd].v = int_xlen_from_u(int_xlen_cmpu(reg_data[rs1].v, reg_data[rs2].v) < 0 ? 1 : 0);
                    reg_data[rd].o = REG_VAL_OTHER;
                    return 0;
                case 4: /* xor */
                    reg_data[rd].v = int_xlen_xor(reg_data[rs1].v, reg_data[rs2].v);
                    reg_data[rd].o = REG_VAL_OTHER;
                    return 0;
                case 5: /* srl */
                    reg_data[rd].v = int_xlen_srl(reg_data[rs1].v, int_xlen_to_l(reg_data[rs2].v) & (xlen - 1));
                    reg_data[rd].o = REG_VAL_OTHER;
                    return 0;
                case 6: /* or */
                    reg_data[rd].v = int_xlen_or(reg_data[rs1].v, reg_data[rs2].v);
                    reg_data[rd].o = REG_VAL_OTHER;
                    return 0;
                case 7: /* and */
                    reg_data[rd].v = int_xlen_and(reg_data[rs1].v, reg_data[rs2].v);
                    reg_data[rd].o = REG_VAL_OTHER;
                    return 0;
                }
            }
            reg_data[rd].o = 0;
        }
        return 0;
    }
    if ((instr & 0xfe00007f) == 0x40000033) {
        if (func == 0 || func == 5) {
            if (rd != 0) {
                if (chk_loaded(rs1) < 0) return -1;
                if (chk_loaded(rs2) < 0) return -1;
                switch (func) {
                case 0:
                    reg_data[rd].v = int_xlen_sub(reg_data[rs1].v, reg_data[rs2].v);
                    reg_data[rd].o = reg_data[rs1].o && reg_data[rs2].o ? REG_VAL_OTHER : 0;
                    return 0;
                case 5:
                    reg_data[rd].v = int_xlen_sra(reg_data[rs1].v, int_xlen_to_l(reg_data[rs2].v));
                    reg_data[rd].o = reg_data[rs1].o && reg_data[rs2].o ? REG_VAL_OTHER : 0;
                    return 0;
                }
            }
            return 0;
        }
    }
    if ((instr & 0x0000707f) == 0x0000000f) {
        unsigned p = (instr >> 24) & 0xf;
        unsigned s = (instr >> 20) & 0xf;
        if (p != 0 && s != 0) {
            /* fence - no register changes */
            return 0;
        }
    }
    if (instr == 0x00000073) {
        /* ecall */
        return 0;
    }
    if (instr == 0x00100073) {
        /* ebreak - no register changes */
        return 0;
    }
    if ((instr & 0x0fffffff) == 0x00200073) {
        switch (instr >> 28) {
        case 0: /* uret */
            pc_data = uepc_data;
            trace_return = 1;
            return 0;
        case 1: /* sret */
            pc_data = sepc_data;
            trace_return = 1;
            return 0;
        case 3: /* mret */
            pc_data = mepc_data;
            trace_return = 1;
            return 0;
        }
    }
    if (instr == 0x10500073) {
        /* wfi - no register changes */
        return 0;
    }
    if ((instr & 0xfe007fff) == 0x12000073) {
        /* sfence.vma - no register changes */
        return 0;
    }
    return 0;
}

static int trace_rv32(void) {
    if (trace_rv32i() < 0) return -1;
    return 0;
}

static int trace_rv64i(void) {
    unsigned func = (instr >> 12) & 7;
    unsigned rs2 = (instr >> 20) & 0x1f;
    unsigned rs1 = (instr >> 15) & 0x1f;
    unsigned rd = (instr >> 7) & 0x1f;
    if ((instr & 0x0000007f) == 0x00000003) {
        if (func == 3 || func == 6) {
            if (rd != 0) {
                int32_t imm = get_imm_rse(20, 12);
                if (chk_loaded(rs1) < 0) return -1;
                if (reg_data[rs1].o) {
                    int_xlen_t addr = int_xlen_add_i(reg_data[rs1].v, imm);
                    switch (func) {
                    case 3:
                        /* ld */
                        return load_reg_lazy(addr, rd, 64, 1);
                    case 6:
                        /* lwu */
                        return load_reg_lazy(addr, rd, 32, 0);
                    }
                }
                reg_data[rd].o = 0;
            }
            return 0;
        }
    }
    if ((instr & 0x0000007f) == 0x00000023) {
        if (func == 3) { /* sd */
            int32_t imm = get_imm_se(imm_bits_s);
            if (chk_loaded(rs1) < 0) return -1;
            if (reg_data[rs1].o) {
                int_xlen_t addr = int_xlen_add_i(reg_data[rs1].v, imm);
                return store_reg(addr, rs2, 64);
            }
            return 0;
        }
    }
    if ((instr & 0xbc00007f) == 0x00000013) {
        if (func == 1 || func == 5) {
            if (rd != 0) {
                uint32_t imm = (instr >> 20) & 0x3f;
                if (chk_loaded(rs1) < 0) return -1;
                if (reg_data[rs1].o) {
                    switch (func) {
                    case 1:
                        reg_data[rd].v = int_xlen_sll(reg_data[rs1].v, imm);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 5:
                        reg_data[rd].v = instr & (1 << 30) ?
                            int_xlen_sra(reg_data[rs1].v, imm) :
                            int_xlen_srl(reg_data[rs1].v, imm);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    }
                }
                reg_data[rd].o = 0;
            }
            return 0;
        }
    }
    if ((instr & 0x0000707f) == 0x0000001b) { /* addiw */
        if (rd != 0) {
            int32_t imm = get_imm_rse(20, 12);
            if (chk_loaded(rs1) < 0) return -1;
            if (reg_data[rs1].o) {
                reg_data[rd].v = fix_sign(int_xlen_add_i(reg_data[rs1].v, imm), 32, 1);
                reg_data[rd].o = REG_VAL_OTHER;
                return 0;
            }
            reg_data[rd].o = 0;
        }
        return 0;
    }
    if ((instr & 0xbe00007f) == 0x0000001b) {
        if (func == 1 || func == 5) {
            if (rd != 0) {
                uint32_t imm = (instr >> 20) & 0x1f;
                if (chk_loaded(rs1) < 0) return -1;
                if (reg_data[rs1].o) {
                    switch (func) {
                    case 1:
                        reg_data[rd].v = fix_sign(int_xlen_sll(reg_data[rs1].v, imm), 32, 1);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 5:
                        if (instr & (1 << 30)) {
                            reg_data[rd].v = int_xlen_sra(fix_sign(reg_data[rs1].v, 32, 1), imm);
                        }
                        else {
                            reg_data[rd].v = int_xlen_srl(fix_sign(reg_data[rs1].v, 32, 0), imm);
                        }
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    }
                }
                reg_data[rd].o = 0;
            }
            return 0;
        }
    }
    if ((instr & 0xfe00007f) == 0x0000003b) {
        if (func == 0 || func == 1 || func == 5) {
            if (rd != 0) {
                if (chk_loaded(rs1) < 0) return -1;
                if (chk_loaded(rs2) < 0) return -1;
                if (reg_data[rs1].o && reg_data[rs2].o) {
                    switch (func) {
                    case 0: /* addw */
                        reg_data[rd].v = fix_sign(int_xlen_add(reg_data[rs1].v, reg_data[rs2].v), 32, 1);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 1: /* sllw */
                        reg_data[rd].v = fix_sign(int_xlen_sll(reg_data[rs1].v, int_xlen_to_l(reg_data[rs2].v) & (xlen - 1)), 32, 1);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 5: /* srlw */
                        reg_data[rd].v = int_xlen_srl(fix_sign(reg_data[rs1].v, 32, 0), int_xlen_to_l(reg_data[rs2].v) & (xlen - 1));
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    }
                }
                reg_data[rd].o = 0;
            }
            return 0;
        }
    }
    if ((instr & 0xfe00007f) == 0x4000003b) {
        if (func == 0 || func == 5) {
            if (rd != 0) {
                if (chk_loaded(rs1) < 0) return -1;
                if (chk_loaded(rs2) < 0) return -1;
                if (reg_data[rs1].o && reg_data[rs2].o) {
                    switch (func) {
                    case 0: /* subw */
                        reg_data[rd].v = fix_sign(int_xlen_sub(reg_data[rs1].v, reg_data[rs2].v), 32, 1);
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    case 5: /* sraw */
                        reg_data[rd].v = int_xlen_sra(fix_sign(reg_data[rs1].v, 32, 1), int_xlen_to_l(reg_data[rs2].v) & (xlen - 1));
                        reg_data[rd].o = REG_VAL_OTHER;
                        return 0;
                    }
                }
                reg_data[rd].o = 0;
            }
            return 0;
        }
    }
    if (trace_rv32i() < 0) return -1;
    return 0;
}



static int trace_rv64(void) {
    if (trace_rv64i() < 0) return -1;
    return 0;
}

static int trace_rv128(void) {
    if (trace_rv64i() < 0) return -1;
    return 0;
}

static int trace_rv32c(void) {
    /* Quadrant 0 */
    if ((instr & 0xffff) == 0x0000) {
        set_errno(ERR_OTHER, "Illegal instruction");
        return -1;
    }
    if ((instr & 0xe003) == 0x0000) {
        uint32_t imm = get_imm(imm_bits_addi_spn);
        if (imm != 0) {
            unsigned rd = ((instr >> 2) & 0x7) + 8;
            if (chk_loaded(REG_ID_SP) < 0) return -1;
            reg_data[rd].v = int_xlen_add_u(reg_data[REG_ID_SP].v, imm * 4);
            reg_data[rd].o = reg_data[REG_ID_SP].o;
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
        if (reg_data[rs].o) {
            uint32_t imm = get_imm(imm_bits_w);
            int_xlen_t addr = int_xlen_add_u(reg_data[rs].v, imm * 4);
            if (ld) {
                if (load_reg_lazy(addr, rd, 32, 1) < 0) return -1;
            }
            else {
                if (store_reg(addr, rd, 32) < 0) return -1;
            }
            return 0;
        }
        if (ld) reg_data[rd].o = 0;
        return 0;
    }
    if ((instr & 0x6003) == 0x6000) {
        /* FP registers are not traced */
        return 0;
    }

    /* Quadrant 1 */
    if ((instr & 0xef83) == 0x0001) {
        /* nop */
        return 0;
    }
    if ((instr & 0xe003) == 0x0001) { /* addi */
        int32_t imm = get_imm_se(imm_bits_shift);
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            if (chk_loaded(rd) < 0) return -1;
            reg_data[rd].v = int_xlen_add_i(reg_data[rd].v, imm);
            return 0;
        }
    }
    if ((instr & 0x6003) == 0x2001) { /* j, jal */
        int32_t imm = get_imm_se(imm_bits_jc);
        if (instr & 0x8000) {
            add_branch(int_xlen_add_i(pc_data.v, (int64_t)imm << 1));
            trace_branch = 1;
        }
        else {
            reg_data[REG_ID_RA].v = int_xlen_add_u(pc_data.v, 2);
            reg_data[REG_ID_RA].o = pc_data.o;
        }
        return 0;
    }
    if ((instr & 0xe003) == 0x4001) {
        int32_t imm = get_imm_se(imm_bits_shift);
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            reg_data[rd].v = int_xlen_from_i(imm);
            reg_data[rd].o = REG_VAL_OTHER;
            return 0;
        }
    }
    if ((instr & 0xe003) == 0x6001) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd == 2) {
            int32_t imm = get_imm_se(imm_bits_addi_sp);
            if (imm != 0) {
                reg_data[REG_ID_SP].v = int_xlen_add_i(reg_data[REG_ID_SP].v, imm << 4);
                return 0;
            }
        }
        if (rd != 0) {
            int32_t imm = get_imm_se(imm_bits_shift);
            if (imm != 0) {
                reg_data[rd].v = int_xlen_from_i(imm << 12);
                reg_data[rd].o = REG_VAL_OTHER;
                return 0;
            }
        }
    }
    if ((instr & 0xe003) == 0x8001) {
        unsigned rd = ((instr >> 7) & 0x7) + 8;
        unsigned func = (instr >> 10) & 3;
        if (func < 2) {
            uint32_t imm = get_imm(imm_bits_shift);
            if (xlen == 32 && imm >= 32) return 0;
            if (imm == 0) {
                if (xlen == 128) imm = 64;
                else return 0;
            }
            if (chk_loaded(rd) < 0) return -1;
            reg_data[rd].v = func ? int_xlen_sra(reg_data[rd].v, imm) : int_xlen_srl(reg_data[rd].v, imm);
        }
        else if (func == 2) {
            int32_t imm = get_imm_se(imm_bits_shift);
            if (chk_loaded(rd) < 0) return -1;
            reg_data[rd].v = int_xlen_and(reg_data[rd].v, int_xlen_from_i(imm));
        }
        else if ((instr & (1 << 12)) == 0) {
            unsigned rs = ((instr >> 2) & 0x7) + 8;
            if (chk_loaded(rd) < 0) return -1;
            if (chk_loaded(rs) < 0) return -1;
            switch ((instr >> 5) & 3) {
            case 0:
                reg_data[rd].v = int_xlen_sub(reg_data[rd].v, reg_data[rs].v);
                break;
            case 1:
                reg_data[rd].v = int_xlen_xor(reg_data[rd].v, reg_data[rs].v);
                break;
            case 2:
                reg_data[rd].v = int_xlen_or(reg_data[rd].v, reg_data[rs].v);
                break;
            case 3:
                reg_data[rd].v = int_xlen_and(reg_data[rd].v, reg_data[rs].v);
                break;
            }
            reg_data[rd].o = reg_data[rd].o && reg_data[rs].o ? REG_VAL_OTHER : 0;
        }
        return 0;
    }
    if ((instr & 0xc003) == 0xc001) {
        int32_t imm = get_imm_se(imm_bits_bc);
        add_branch(int_xlen_add_i(pc_data.v, imm << 1));
        return 0;
    }

    /* Quadrant 2 */
    if ((instr & 0xe003) == 0x4002) { /* lw */
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            if (chk_loaded(REG_ID_SP) < 0) return -1;
            if (reg_data[REG_ID_SP].o) {
                uint32_t imm = get_imm(imm_bits_lw_sp);
                return load_reg_lazy(int_xlen_add_u(reg_data[REG_ID_SP].v, imm * 4), rd, 32, 1);
            }
            reg_data[rd].o = 0;
            return 0;
        }
    }
    if ((instr & 0xe003) == 0x6002) {
        /* FP registers are not traced */
        return 0;
    }
    if ((instr & 0xe003) == 0x2002) {
        /* FP registers are not traced */
        return 0;
    }
    if ((instr & 0xe003) == 0xc002) {
        unsigned rd = (instr >> 2) & 0x1f;
        if (chk_loaded(REG_ID_SP) < 0) return -1;
        if (reg_data[REG_ID_SP].o) {
            uint32_t imm = get_imm(imm_bits_sw_sp);
            if (store_reg(int_xlen_add_u(reg_data[REG_ID_SP].v, imm * 4), rd, 32) < 0) return -1;
        }
        return 0;
    }
    if ((instr & 0xe003) == 0xe002) {
        /* FP registers are not traced */
        return 0;
    }
    if ((instr & 0xe003) == 0xa002) {
        /* FP registers are not traced */
        return 0;
    }
    if ((instr & 0xe003) == 0x0002) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            uint32_t imm = get_imm(imm_bits_shift);
            if (xlen == 32 && imm >= 32) return 0;
            if (imm == 0) {
                if (xlen == 128) imm = 64;
                else return 0;
            }
            if (chk_loaded(rd) < 0) return -1;
            reg_data[rd].v = int_xlen_sll(reg_data[rd].v, imm);
            return 0;
        }
    }
    if ((instr & 0xe003) == 0x8002) {
        unsigned rd = (instr >> 7) & 0x1f;
        unsigned rs = (instr >> 2) & 0x1f;
        if ((instr & (1 << 12)) == 0) {
            if (rd == 0) return 0;
            if (rs == 0) {
                if (chk_loaded(rd) < 0) return -1;
                if (rd == REG_ID_RA) {
                    pc_data = reg_data[rd];
                    trace_return = 1;
                    return 0;
                }
                if (reg_data[rd].o) add_branch(reg_data[rd].v);
                trace_branch = 1;
                return 0;
            }
            if (chk_loaded(rs) < 0) return -1;
            reg_data[rd] = reg_data[rs];
            return 0;
        }
        if (rd == 0 && rs == 0) {
            /* ebreak */
            return 0;
        }
        if (rd == 0) return 0;
        if (rs == 0) {
            reg_data[REG_ID_RA].v = int_xlen_add_u(pc_data.v, 2);
            reg_data[REG_ID_RA].o = pc_data.o;
            return 0;
        }
        if (chk_loaded(rd) < 0) return -1;
        if (chk_loaded(rs) < 0) return -1;
        reg_data[rd].v = int_xlen_add(reg_data[rd].v, reg_data[rs].v);
        reg_data[rd].o = reg_data[rd].o && reg_data[rs].o ? REG_VAL_OTHER : 0;
        return 0;
    }

    return 0;
}

static int trace_rv64c(void) {
    if ((instr & 0xe003) == 0x2001) {
        int32_t imm = get_imm_se(imm_bits_shift);
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            if (chk_loaded(rd) < 0) return -1;
            reg_data[rd].v = int_xlen_add_i(reg_data[rd].v, imm);
            return 0;
        }
    }
    if ((instr & 0xe003) == 0x6002) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            if (chk_loaded(REG_ID_SP) < 0) return -1;
            if (reg_data[REG_ID_SP].o) {
                uint32_t imm = get_imm(imm_bits_ld_sp);
                return load_reg_lazy(int_xlen_add_u(reg_data[REG_ID_SP].v, imm * 8), rd, 64, 1);
            }
            reg_data[rd].o = 0;
            return 0;
        }
    }
    if ((instr & 0xe003) == 0xe002) {
        unsigned rd = (instr >> 2) & 0x1f;
        if (chk_loaded(REG_ID_SP) < 0) return -1;
        if (reg_data[REG_ID_SP].o) {
            uint32_t imm = get_imm(imm_bits_sd_sp);
            if (store_reg(int_xlen_add_u(reg_data[REG_ID_SP].v, imm * 8), rd, 64) < 0) return -1;
        }
        return 0;
    }
    if ((instr & 0x6003) == 0x6000) {
        unsigned rd = ((instr >> 2) & 0x7) + 8;
        unsigned rs = ((instr >> 7) & 0x7) + 8;
        int ld = (instr & 0x8000) == 0;
        if (chk_loaded(rs) < 0) return -1;
        if (reg_data[rs].o) {
            uint32_t imm = get_imm(imm_bits_d);
            int_xlen_t addr = int_xlen_add_u(reg_data[rs].v, imm * 8);
            if (ld) {
                if (load_reg_lazy(addr, rd, 64, 1) < 0) return -1;
            }
            else {
                if (store_reg(addr, rd, 64) < 0) return -1;
            }
            return 0;
        }
        if (ld) reg_data[rd].o = 0;
        return 0;
    }
    if ((instr & 0xfc03) == 0x9c01) {
        unsigned rd = ((instr >> 7) & 0x7) + 8;
        unsigned rs = ((instr >> 2) & 0x7) + 8;
        if (chk_loaded(rd) < 0) return -1;
        if (chk_loaded(rs) < 0) return -1;
        switch ((instr >> 5) & 3) {
        case 0:
            reg_data[rd].v = int_xlen_sub(reg_data[rd].v, reg_data[rs].v);
            break;
        case 1:
            reg_data[rd].v = int_xlen_add(reg_data[rd].v, reg_data[rs].v);
            break;
        default:
            return 0;
        }
        reg_data[rd].o = reg_data[rd].o && reg_data[rs].o ? REG_VAL_OTHER : 0;
        return 0;
    }
    return trace_rv32c();
}

static int trace_rv128c(void) {
    if ((instr & 0xe003) == 0x2002) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            if (chk_loaded(REG_ID_SP) < 0) return -1;
            if (reg_data[REG_ID_SP].o) {
                uint32_t imm = get_imm(imm_bits_lq_sp);
                return load_reg_lazy(int_xlen_add_u(reg_data[REG_ID_SP].v, imm * 16), rd, 128, 1);
            }
            reg_data[rd].o = 0;
            return 0;
        }
    }
    if ((instr & 0xe003) == 0xa002) {
        unsigned rd = (instr >> 2) & 0x1f;
        if (chk_loaded(REG_ID_SP) < 0) return -1;
        if (reg_data[REG_ID_SP].o) {
            uint32_t imm = get_imm(imm_bits_sq_sp);
            if (store_reg(int_xlen_add_u(reg_data[REG_ID_SP].v, imm * 16), rd, 128) < 0) return -1;
        }
        return 0;
    }
    if ((instr & 0x6003) == 0x2000) {
        unsigned rd = ((instr >> 2) & 0x7) + 8;
        unsigned rs = ((instr >> 7) & 0x7) + 8;
        int ld = (instr & 0x8000) == 0;
        if (chk_loaded(rs) < 0) return -1;
        if (reg_data[rs].o) {
            uint32_t imm = get_imm(imm_bits_q);
            int_xlen_t addr = int_xlen_add_u(reg_data[rs].v, imm * 16);
            if (ld) {
                if (load_reg_lazy(addr, rd, 128, 1) < 0) return -1;
            }
            else {
                if (store_reg(addr, rd, 128) < 0) return -1;
            }
            return 0;
        }
        if (ld) reg_data[rd].o = 0;
        return 0;
    }
    return trace_rv64c();
}

static int trace_riscv(void) {
    assert(pc_data.o != REG_VAL_ADDR);
    assert(pc_data.o != REG_VAL_STACK);

    /* Check PC alignment */
    if (int_xlen_to_l(pc_data.v) & 0x1) {
        set_errno(ERR_OTHER, "PC misalignment");
        return -1;
    }

    /* Read the instruction */
    if (read_u32(pc_data.v, &instr) < 0) return -1;

    if ((instr & 3) == 3) {
        if (xlen == 32 && trace_rv32() < 0) return -1;
        if (xlen == 64 && trace_rv64() < 0) return -1;
        if (xlen == 128 && trace_rv128() < 0) return -1;
        if (!trace_return && !trace_branch) pc_data.v = int_xlen_add_u(pc_data.v, 4);
    }
    else {
        instr &= 0xffff;
        if (xlen == 32 && trace_rv32c() < 0) return -1;
        if (xlen == 64 && trace_rv64c() < 0) return -1;
        if (xlen == 128 && trace_rv128c() < 0) return -1;
        if (!trace_return && !trace_branch) pc_data.v = int_xlen_add_u(pc_data.v, 2);
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
            pc_data.o ? int_xlen_to_l(pc_data.v) : (uint64_t)0,
            reg_data[REG_ID_SP].o ? int_xlen_to_l(reg_data[REG_ID_SP].v) : (uint64_t)0);
        for (t = 0; t < MAX_INST; t++) {
            int error = 0;
            trace_return = 0;
            trace_branch = 0;
            if (pc_data.o != REG_VAL_OTHER) {
                error = set_errno(ERR_OTHER, "PC value not available");
            }
            else if (int_xlen_cmpu(pc_data.v, int_xlen_from_u(0)) == 0) {
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
        if (int_xlen_cmpu(org_regs[REG_ID_SP].v, int_xlen_from_u(0)) != 0 &&
            int_xlen_cmpu(org_regs[REG_ID_RA].v, int_xlen_from_u(0)) != 0 &&
            int_xlen_cmpu(org_pc.v, org_regs[REG_ID_RA].v) != 0) {
            pc_data = org_regs[REG_ID_RA];
        }
    }
    return 0;
}

static int read_reg128(StackFrame * frame, RegisterDefinition * reg_def, int_xlen_t * v) {
    uint8_t buf[16];
    uint64_t l = 0;
    uint64_t h = 0;
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
        for (i = 0; i < 8 && i < reg_def->size; i++) {
            l = l << 8;
            l |= buf[reg_def->big_endian ? i : reg_def->size - i - 1];
        }
    }
    if (v != NULL) {
        size_t i;
        for (i = 8; i < reg_def->size; i++) {
            h = h << 8;
            h |= buf[reg_def->big_endian ? i : reg_def->size - i - 1];
        }
    }
    *v = int_xlen_from_u2(l, h);
    return 0;
}

static int write_reg128(StackFrame * frame, RegisterDefinition * reg_def, int_xlen_t v) {
    size_t i;
    uint8_t buf[16];
    uint64_t l = int_xlen_to_l(v);
    uint64_t h = int_xlen_to_h(v);
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
        buf[reg_def->big_endian ? reg_def->size - i - 1 : i] = (uint8_t)l;
        l = l >> 8;
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

    if (defs == NULL) {
        set_errno(ERR_OTHER, "Context has no registers");
        return -1;
    }

    stk_ctx = frame->ctx;
    stk_frame = frame;
    memset(&mem_data, 0, sizeof(mem_data));
    memset(&reg_data, 0, sizeof(reg_data));
    memset(&pc_data, 0, sizeof(pc_data));
    memset(&mepc_data, 0, sizeof(mepc_data));
    memset(&sepc_data, 0, sizeof(sepc_data));
    memset(&uepc_data, 0, sizeof(uepc_data));
    branch_pos = 0;
    branch_cnt = 0;

    for (i = 0; i < MEM_CACHE_SIZE; i++) mem_cache[i].size = 0;

    for (def = defs; def->name; def++) {
        if (def->dwarf_id == 0) {
            assert(xlen == def->size * 8);
            reg_data[def->dwarf_id].v = int_xlen_from_u(0);
            reg_data[def->dwarf_id].o = REG_VAL_OTHER;
        }
        else if (def->dwarf_id == REG_ID_SP) {
            if (read_reg128(frame, def, &reg_data[REG_ID_SP].v) < 0) continue;
            if (int_xlen_cmpu(reg_data[REG_ID_SP].v, int_xlen_from_u(0)) == 0) return 0;
            reg_data[REG_ID_SP].o = REG_VAL_OTHER;
        }
        else if (def->dwarf_id >= 0 && def->dwarf_id < REG_DATA_SIZE) {
            reg_data[def->dwarf_id].v = int_xlen_from_u(def - defs);
            reg_data[def->dwarf_id].o = REG_VAL_FRAME;
        }
        else if (strcmp(def->name, "pc") == 0) {
            if (read_reg128(frame, def, &pc_data.v) < 0) continue;
            pc_data.o = REG_VAL_OTHER;
        }
        else if (strcmp(def->name, "mepc") == 0) {
            if (read_reg128(frame, def, &mepc_data.v) < 0) continue;
            mepc_data.o = REG_VAL_OTHER;
        }
        else if (strcmp(def->name, "sepc") == 0) {
            if (read_reg128(frame, def, &sepc_data.v) < 0) continue;
            sepc_data.o = REG_VAL_OTHER;
        }
        else if (strcmp(def->name, "uepc") == 0) {
            if (read_reg128(frame, def, &uepc_data.v) < 0) continue;
            uepc_data.o = REG_VAL_OTHER;
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
                int_xlen_t v;
                int valid = 0;
                LocationExpressionCommand * cmds = NULL;
                if (mem_hash_read(reg_data[r].v, &v, xlen >> 3, &valid) == 0) {
                    if (valid && write_reg128(down, def, v) < 0) return -1;
                    continue;
                }
                cmds = (LocationExpressionCommand *)tmp_alloc_zero(sizeof(LocationExpressionCommand) * 2);
                cmds[0].cmd = SFT_CMD_NUMBER;
                cmds[0].args.num = int_xlen_to_l(reg_data[r].v);
                cmds[1].cmd = SFT_CMD_RD_MEM;
                cmds[1].args.mem.size = xlen >> 3;
                if (write_reg_location(down, def, cmds, 2) == 0) {
                    down->has_reg_data = 1;
                    continue;
                }
            }
            else if (reg_data[r].o == REG_VAL_FRAME) {
                LocationExpressionCommand * cmds = (LocationExpressionCommand *)tmp_alloc_zero(sizeof(LocationExpressionCommand));
                cmds[0].cmd = SFT_CMD_RD_REG;
                cmds[0].args.reg = defs + int_xlen_to_l(reg_data[r].v);
                if (write_reg_location(down, def, cmds, 1) == 0) {
                    down->has_reg_data = 1;
                    continue;
                }
            }
#endif
            assert(r != 0 || reg_data[r].o == REG_VAL_OTHER || reg_data[r].o == 0);
            assert(r != 0 || int_xlen_to_l(reg_data[r].v) == 0);
            if (chk_loaded(r) < 0) continue;
            if (!reg_data[r].o) continue;
            if (r == REG_ID_SP) frame->fp = (ContextAddress)int_xlen_to_l(reg_data[r].v);
            if (write_reg128(down, def, reg_data[r].v) < 0) return -1;
        }
        else if (strcmp(def->name, "pc") == 0) {
            if (chk_reg_loaded(&pc_data) < 0) continue;
            if (!pc_data.o) continue;
            if (write_reg128(down, def, pc_data.v) < 0) return -1;
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
    xlen = 64;
    return crawl_stack_frame_riscv(frame, down);
}

int crawl_stack_frame_riscv128(StackFrame * frame, StackFrame * down) {
    xlen = 128;
    return crawl_stack_frame_riscv(frame, down);
}

#endif /* ENABLE_DebugContext */
