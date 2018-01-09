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


/*
 * This module implements stack crawl for MicroBlaze.
 */

#include <tcf/config.h>

#if ENABLE_DebugContext

#include <assert.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/context.h>
#include <machine/microblaze/tcf/stack-crawl-microblaze.h>

#define USE_MEM_CACHE        1
#define MEM_HASH_SIZE       61
#define MEM_CACHE_SIZE       8
#define BRANCH_LIST_SIZE    12
#define REG_DATA_SIZE       34

#define REG_VAL_ADDR         1
#define REG_VAL_STACK        2
#define REG_VAL_OTHER        3

#define REG_SP_INDEX         1
#define REG_LR_INDEX        15
#define REG_PC_INDEX        32
#define REG_MSR_INDEX       33

typedef struct {
    uint32_t v;
    uint32_t o;
} RegData;

typedef struct {
    uint32_t v[MEM_HASH_SIZE]; /* Value */
    uint32_t a[MEM_HASH_SIZE]; /* Address */
    uint8_t  used[MEM_HASH_SIZE];
    uint8_t  valid[MEM_HASH_SIZE];
} MemData;

typedef struct {
    uint32_t addr;
    RegData reg_data[REG_DATA_SIZE];
    MemData mem_data;
} BranchData;

static Context * stk_ctx = NULL;
static RegData reg_data[REG_DATA_SIZE];
static MemData mem_data;
static unsigned mem_cache_idx = 0;

static int trace_return = 0;
static int trace_return_next = 0;
static uint32_t trace_return_addr = 0;
static int trace_branch = 0;
static int trace_branch_next = 0;
static int trace_branch_conditional = 0;
static int trace_branch_exit = 0;
static uint32_t trace_branch_addr = 0;
static uint32_t trace_imm = 0;

static unsigned branch_pos = 0;
static unsigned branch_cnt = 0;
static BranchData branch_data[BRANCH_LIST_SIZE];

typedef struct {
    uint64_t addr;
    uint32_t size;
    uint8_t data[64];
} MemCache;

static MemCache mem_cache[MEM_CACHE_SIZE];

static int read_byte(uint64_t addr, uint8_t * bt) {
    unsigned i = 0;
    MemCache * c = NULL;

    for (i = 0; i < MEM_CACHE_SIZE; i++) {
        c = mem_cache + mem_cache_idx;
        if (c->size > 0 && c->addr <= addr && (c->addr + c->size < c->addr || c->addr + c->size > addr)) {
            *bt = c->data[addr - c->addr];
            return 0;
        }
        mem_cache_idx = (mem_cache_idx + 1) % MEM_CACHE_SIZE;
    }
    mem_cache_idx = (mem_cache_idx + 1) % MEM_CACHE_SIZE;
    c = mem_cache + mem_cache_idx;
    c->addr = addr;
    c->size = sizeof(c->data);
    if (context_read_mem(stk_ctx, addr, c->data, c->size) < 0) {
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

static int read_word(uint64_t addr, uint32_t * w) {
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

static int mem_hash_index(const uint32_t addr) {
    int v = addr % MEM_HASH_SIZE;
    int s = v;

    do {
        /* Check if the element is occupied */
        if (mem_data.used[s]) {
            /* Check if it is occupied with the sought data */
            if (mem_data.a[s] == addr)  return s;
        }
        else {
            /* Item is free, this is where the item should be stored */
            return s;
        }

        /* Search the next entry */
        if (++s >= MEM_HASH_SIZE) s = 0;
    }
    while(s != v);

    /* Search failed, hash is full and the address not stored */
    return -1;
}

static int mem_hash_read(uint32_t addr, uint32_t * data, int * valid) {
    int i = mem_hash_index(addr);

    if (i >= 0 && mem_data.used[i] && mem_data.a[i] == addr) {
        *data  = mem_data.v[i];
        *valid = mem_data.valid[i];
        return 0;
    }

    /* Address not found in the hash */
    errno = ERR_OTHER;
    return -1;
}

static int load_reg(uint64_t addr, int r) {
    int valid = 0;

    /* Check if the value can be found in the hash */
    if (addr < 0x100000000 && mem_hash_read((uint32_t)addr, &reg_data[r].v, &valid) == 0) {
        reg_data[r].o = valid ? REG_VAL_OTHER : 0;
    }
    else {
        /* Not in the hash, so read from real memory */
        reg_data[r].o = 0;
        if (read_word(addr, &reg_data[r].v) < 0) return -1;
        reg_data[r].o = REG_VAL_OTHER;
    }
    return 0;
}

static int load_reg_lazy(uint32_t addr, int r) {
    int valid = 0;
    if (mem_hash_read(addr, &reg_data[r].v, &valid) == 0) {
        if (valid) {
            reg_data[r].o = REG_VAL_OTHER;
            return 0;
        }
        reg_data[r].o = 0;
        reg_data[r].v = 0;
        return 0;
    }
    reg_data[r].o = REG_VAL_ADDR;
    reg_data[r].v = addr;
    return 0;
}

static int chk_loaded(int r) {
    if (reg_data[r].o != REG_VAL_ADDR && reg_data[r].o != REG_VAL_STACK) return 0;
    return load_reg(reg_data[r].v, r);
}

static int mem_hash_write(uint32_t addr, uint32_t value, int valid) {
    int h = mem_hash_index(addr);
    unsigned i;

    if (h < 0) {
        set_errno(ERR_OTHER, "Memory hash overflow");
        return -1;
    }

    /* Fix lazy loaded registers */
    for (i = 0; i < REG_DATA_SIZE; i++) {
        if (reg_data[i].o != REG_VAL_ADDR && reg_data[i].o != REG_VAL_STACK) continue;
        if (reg_data[i].v >= addr + 4) continue;
        if (reg_data[i].v + 4 <= addr) continue;
        if (load_reg(reg_data[i].v, i) < 0) return -1;
    }

    /* Store the item */
    mem_data.used[h] = 1;
    mem_data.a[h] = addr;
    mem_data.v[h] = valid ? value : 0;
    mem_data.valid[h] = (uint8_t)valid;
    return 0;
}

static int store_reg(uint32_t addr, int r) {
    if (chk_loaded(r) < 0) return -1;
    assert(reg_data[r].o != REG_VAL_ADDR);
    assert(reg_data[r].o != REG_VAL_STACK);
    return mem_hash_write(addr, reg_data[r].v, reg_data[r].o != 0);
}

static void add_branch(uint32_t addr) {
    if (branch_cnt < BRANCH_LIST_SIZE) {
        int add = 1;
        unsigned i = 0;
        for (i = 0; i < branch_cnt; i++) {
            BranchData * b = branch_data + i;
            if (b->addr == addr) {
                add = 0;
                break;
            }
        }
        if (add) {
            BranchData * b = branch_data + branch_cnt++;
            b->addr = addr;
            b->mem_data = mem_data;
            memcpy(b->reg_data, reg_data, sizeof(reg_data));
            b->reg_data[32].v = addr;
        }
    }
}

static uint32_t sext(uint32_t val) {
    /* Sign extend value, treated as a 16-bit signed integer */
    return ((val >> 15) & 1) ? 0xffff0000 | val : 0x0000ffff & val;
}

static void set_msr_c(uint32_t to) {
    /* Set Machine Status Register carry bit, C */
    reg_data[REG_MSR_INDEX].v = (reg_data[REG_MSR_INDEX].v & 0xfffffffb) | (to << 2);
}

static void update_msr_c(uint32_t a, uint32_t b, uint32_t carry_in, uint32_t K) {
    int32_t sa  = (int32_t)a;
    int32_t sb  = (int32_t)b;

    /* Update Machine Status Register carry bit, C, unless K is set to keep its value */
    if (K)
        return;

    if (carry_in) {
        if ((sb > 0 && sa >= INT_MAX - sb) || (sb < 0 && sa <= INT_MIN - sb))
            set_msr_c(1);
    }
    else {
        if ((sb > 0 && sa > INT_MAX - sb) || (sb < 0 && sa < INT_MIN - sb))
            set_msr_c(1);
    }
}

static uint32_t arithmetic_right_shift(uint32_t val, uint32_t shift) {
    /* Compute the arithmetic right shift of the value, shifted according to shift */
    shift = shift & 0x1f;
    if (shift == 0)
      return val;
    if (val & 0x80000000)
      return val >> shift | ~(0U >> shift);
    return val >> shift;
}

static void add_branch_delayslot(uint32_t addr, uint32_t D, int conditional) {
    if (D) {
        /* Branch with delay slot, defer handling */
        trace_branch_addr = addr;
        trace_branch_next = 1;
        trace_branch_conditional = conditional;
    }
    else {
        /* Trace both directions for conditional branch */
        add_branch(addr);
        trace_branch = ! conditional;
    }
}

#ifdef DEBUG_STACK_CRAWL
#define DEBUG_TRACE(format, ...) trace(LOG_STACK, "Stack crawl: " #format, __VA_ARGS__)
#else
#define DEBUG_TRACE(format, ...)
#endif

static int trace_microblaze(void) {
    uint32_t pc, instr;
    uint32_t rd, ra, rb, imm;
    uint32_t msr_c;

    int return_delayslot = trace_return_next;
    int branch_delayslot = trace_branch_next;

    assert(reg_data[REG_PC_INDEX].o != REG_VAL_ADDR);

    /* Check that the PC is still on MicroBlaze alignment */
    if (reg_data[REG_PC_INDEX].v & 0x3) {
        set_errno(ERR_OTHER, "PC misalignment");
        return -1;
    }

    /* Read the instruction */
    pc = reg_data[REG_PC_INDEX].v;
    if (read_word(pc, &instr) < 0) return -1;

    /* Extract MSR carry flag, registers and immediate value */
    msr_c = (reg_data[REG_MSR_INDEX].v >> 2) & 1;
    rd = (instr & 0x03e00000) >> 21;
    ra = (instr & 0x001f0000) >> 16;
    rb = (instr & 0x0000f800) >> 11;
    imm = trace_imm + sext(instr & 0xffff);
    trace_imm = 0;

    /* Handle delay slot. Trace both directions for conditional branch */
    trace_branch = trace_branch_next && ! trace_branch_conditional;
    trace_branch_next = 0;
    trace_return = trace_return_next;
    trace_return_next = 0;

    if ((instr & 0xe4000000) == 0x00000000) { /* add */
        uint32_t K = (instr & 0x10000000) != 0;
        uint32_t C = (instr & 0x08000000) != 0;
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v + reg_data[rb].v + (msr_c & C);
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        update_msr_c(reg_data[ra].v, reg_data[rb].v, msr_c & C, K);
        DEBUG_TRACE("%08x: %08x    add     r%d, r%d, r%d ; = 0x%08x", pc, instr, rd, ra, rb, reg_data[rd].v);
    }
    else if ((instr & 0xe4000000) == 0x20000000) { /* addi */
        uint32_t K = (instr & 0x10000000) != 0;
        uint32_t C = (instr & 0x08000000) != 0;
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v + imm + (msr_c & C);
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        update_msr_c(reg_data[ra].v, imm, msr_c & C, K);
        DEBUG_TRACE("%08x: %08x    addi    r%d, r%d, %d ; = 0x%08x", pc, instr, rd, ra, imm, reg_data[rd].v);
    }
    else if ((instr & 0xfc000000) == 0x84000000) { /* and */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v & reg_data[rb].v;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    and     r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000000) == 0xa4000000) { /* andi */
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v & imm;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    andi    r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc000000) == 0x8c000000) { /* andn */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v & ~reg_data[rb].v;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    andn    r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000000) == 0xac000000) { /* andni */
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v & ~imm;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    andni   r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc000000) == 0x9c000000) { /* Conditional branch */
        uint32_t D = (instr & 0x02000000) != 0;
        uint32_t addr = reg_data[REG_PC_INDEX].v;
        chk_loaded(rb);
        addr += reg_data[rb].v;
        add_branch_delayslot(addr, D, 1);
        DEBUG_TRACE("%08x: %08x    bxx     r%d", pc, instr, rb);
    }
    else if ((instr & 0xfc000000) == 0xbc000000) { /* Conditional immediate branch */
        uint32_t D = (instr & 0x02000000) != 0;
        uint32_t addr = reg_data[REG_PC_INDEX].v;
        addr += imm;
        add_branch_delayslot(addr, D, 1);
        DEBUG_TRACE("%08x: %08x    bxxi    0x%x", pc, instr, imm);
    }
    else if ((instr & 0xfc0c0000) == 0x98080000) { /* Unconditional absolute branch */
        uint32_t D = (instr & 0x00100000) != 0;
        chk_loaded(rb);
        add_branch_delayslot(reg_data[rb].v, D, 0);
        DEBUG_TRACE("%08x: %08x    bra     r%d", pc, instr, rb);
    }
    else if ((instr & 0xfc0c0000) == 0x98000000) { /* Unconditional relative branch */
        uint32_t D = (instr & 0x00100000) != 0;
        uint32_t addr = reg_data[REG_PC_INDEX].v;
        chk_loaded(rb);
        addr += reg_data[rb].v;
        add_branch_delayslot(addr, D, 0);
        DEBUG_TRACE("%08x: %08x    br      r%d", pc, instr, rb);
    }
    else if ((instr & 0xfc0c0000) == 0xb8080000) { /* Unconditional immediate absolute branch */
        uint32_t D = (instr & 0x00100000) != 0;
        add_branch_delayslot(imm, D, 0);
        DEBUG_TRACE("%08x: %08x    brai    0x%x", pc, instr, imm);
    }
    else if ((instr & 0xfc0c0000) == 0xb8000000) { /* Unconditional immediate relative branch */
        uint32_t D = (instr & 0x00100000) != 0;
        uint32_t addr = reg_data[REG_PC_INDEX].v;
        addr += imm;
        if (!D && imm == 0)
            /* Found "bri 0".  Exit stack crawl */
            trace_branch_exit = 1;
        else
            add_branch_delayslot(addr, D, 0);
        DEBUG_TRACE("%08x: %08x    bri     0x%x", pc, instr, imm);
    }
    else if ((instr & 0xdc040000) == 0x98040000) { /* Branch and link */
        /* Subroutines are expected to preserve the contents of r1, r2, r13, r14 and r19 to r31 */
        unsigned i;
        for (i = 3; i <= 18; i++) {
            if (i != 13 && i != 14) reg_data[i].o = 0;
        }
        DEBUG_TRACE("%08x: %08x    brl", pc, instr);
    }
    else if ((instr & 0xfc000400) == 0x44000400) { /* bsll */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v << (reg_data[rb].v & 0x1f);
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    bsll    r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000600) == 0x44000000) { /* bsrl */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v >> (reg_data[rb].v & 0x1f);
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    bsrl    r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000600) == 0x44000200) { /* bsra */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = arithmetic_right_shift(reg_data[ra].v, reg_data[rb].v);
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    bsra    r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000400) == 0x64000400) { /* bslli */
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v << (imm & 0x1f);
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    bslli   r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc000600) == 0x64000000) { /* bsrli */
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v >> (imm & 0x1f);
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    bsrli   r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc000600) == 0x64000200) { /* bsrai */
        chk_loaded(ra);
        reg_data[rd].v = arithmetic_right_shift(reg_data[ra].v, imm);
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    bsrai   r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc00ffff) == 0x900000e0) { /* clz */
        uint32_t val;
        uint32_t n = 0;
        uint32_t mask = 0x80000000;
        chk_loaded(ra);
        val = reg_data[ra].v;
        while ((val & mask) == 0 && n < 32) {
            n++; mask >>= 1;
        }
        reg_data[rd].v = n;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    clz     r%d, r%d", pc, instr, rd, ra);
    }
    else if ((instr & 0xfc0007ff) == 0x14000001) { /* cmp */
        uint32_t vala, valb;
        chk_loaded(ra); chk_loaded(rb);
        vala = reg_data[ra].v;
        valb = reg_data[rb].v;
        if ((int32_t)vala > (int32_t)valb)
           reg_data[rd].v = (valb - vala) | 0x80000000;
        else
           reg_data[rd].v = (valb - vala) & 0x7fffffff;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    cmp     r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc0007ff) == 0x14000003) { /* cmpu */
        uint32_t vala, valb;
        chk_loaded(ra); chk_loaded(rb);
        vala = reg_data[ra].v;
        valb = reg_data[rb].v;
        if (vala > valb)
           reg_data[rd].v = (valb - vala) | 0x80000000;
        else
           reg_data[rd].v = (valb - vala) & 0x7fffffff;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    cmpu    r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000000) == 0x58000000) { /* Floating point instructions */
        reg_data[rd].o = 0; /* Not traced */
        DEBUG_TRACE("%08x: %08x    fxxx    r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xdc000000) == 0x4c000000) { /* get, getd */
        reg_data[rd].o = 0; /* Not traced */
        DEBUG_TRACE("%08x: %08x    getx    r%d", pc, instr, rd);
    }
    else if ((instr & 0xfc0007ff) == 0x48000000) { /* idiv */
        chk_loaded(ra); chk_loaded(rb);
        if (reg_data[ra].v == 0) {
            reg_data[rd].v = 0;
            reg_data[rd].o = REG_VAL_OTHER;
        }
        else {
            reg_data[rd].v = (uint32_t)((int32_t)reg_data[rb].v / (int32_t)reg_data[ra].v);
            reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        }
        DEBUG_TRACE("%08x: %08x    idiv    r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc0007ff) == 0x48000002) { /* idivu */
        chk_loaded(ra); chk_loaded(rb);
        if (reg_data[ra].v == 0) {
            reg_data[rd].v = 0;
            reg_data[rd].o = REG_VAL_OTHER;
        }
        else {
            reg_data[rd].v = reg_data[rb].v / reg_data[ra].v;
            reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        }
        DEBUG_TRACE("%08x: %08x    idivu   r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xffff0000) == 0xb0000000) { /* imm */
        trace_imm = instr << 16;
        DEBUG_TRACE("%08x: %08x    imm     0x%x", pc, instr, instr & 0xffff);
    }
    else if ((instr & 0xf8000000) == 0xc0000000) { /* lbu, lhu, lbuea, lhuea */
        reg_data[rd].o = 0; /* Not traced */
        DEBUG_TRACE("%08x: %08x    lb/lhu/lbuea/lhuea  r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xf8000000) == 0xe0000000) { /* lbui, lhui */
        reg_data[rd].o = 0; /* Not traced */
        DEBUG_TRACE("%08x: %08x    lb/lhui r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xf0000000) == 0xc0000000) { /* Load word */
        chk_loaded(ra); chk_loaded(rb);
        if (reg_data[ra].o && reg_data[rb].o) {
            if (instr & 0x80) {
                load_reg(((uint64_t)reg_data[ra].v << 32) + reg_data[rb].v, rd);
            }
            else {
                load_reg_lazy(reg_data[ra].v + reg_data[rb].v, rd);
            }
            if (instr & 0x200) {
                chk_loaded(rd);
                swap_bytes(&reg_data[rd].v, 4);
            }
        }
        else {
            reg_data[rd].o = 0;
        }
        DEBUG_TRACE("%08x: %08x    lw/lwr/lwx/lwea r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xf0000000) == 0xe0000000) { /* Load word immediate */
        uint32_t addr;
        chk_loaded(ra);
        if (reg_data[ra].o) {
            addr = reg_data[ra].v + imm;
            load_reg_lazy(addr, rd);
        }
        else {
            reg_data[rd].o = 0;
        }
        DEBUG_TRACE("%08x: %08x    lwi     r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc1fc000) == 0x94008000) { /* mfs */
        if ((instr & 0xffff) == 0x0000) { /* PC */
            reg_data[rd].v = reg_data[REG_PC_INDEX].v;
            reg_data[rd].o = REG_VAL_OTHER;
        }
        else if ((instr & 0xffff) == 0x0001) { /* MSR */
            reg_data[rd].v = reg_data[REG_MSR_INDEX].v;
            reg_data[rd].o = REG_VAL_OTHER;
        }
        else {
            reg_data[rd].o = 0; /* Not traced */
        }
        DEBUG_TRACE("%08x: %08x    mfs     r%d, 0x%x", pc, instr, rd, instr & 0x3fff);
    }
    else if ((instr & 0xfc1fc000) == 0x94088000) { /* mfse */
        reg_data[rd].o = 0; /* Not traced */
        DEBUG_TRACE("%08x: %08x    mfse    r%d, 0x%x", pc, instr, rd, instr & 0x3fff);
    }
    else if ((instr & 0xfc1f8000) == 0x94110000) { /* msrclr */
        reg_data[rd].v = reg_data[REG_MSR_INDEX].v;
        reg_data[rd].o = REG_VAL_OTHER;
        reg_data[REG_MSR_INDEX].v = reg_data[REG_MSR_INDEX].v & ~(instr & 0x3fff);
        DEBUG_TRACE("%08x: %08x    msrclr  r%d, 0x%x", pc, instr, rd, instr & 0x3fff);
    }
    else if ((instr & 0xfc1f8000) == 0x94100000) { /* msrset */
        reg_data[rd].v = reg_data[REG_MSR_INDEX].v;
        reg_data[rd].o = REG_VAL_OTHER;
        reg_data[REG_MSR_INDEX].v = reg_data[REG_MSR_INDEX].v | (instr & 0x3fff);
        DEBUG_TRACE("%08x: %08x    msrset  r%d, 0x%x", pc, instr, rd, instr & 0x3fff);
    }
    else if ((instr & 0xffe0c000) == 0x9400c000) { /* mts */
        if ((instr & 0xffff) == 0x0001) { /* MSR */
            chk_loaded(ra);
            reg_data[REG_MSR_INDEX].v = reg_data[ra].v;
        }
        /* Other registers not traced */
        DEBUG_TRACE("%08x: %08x    mts     0x%x, r%d", pc, instr, instr & 0xffff, ra);
    }
    else if ((instr & 0xfc0007ff) == 0x40000000) { /* mul */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v * reg_data[rb].v;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    mul     r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc0007ff) == 0x40000001) { /* mulh */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = (uint32_t)(((int64_t) reg_data[ra].v * (int64_t) reg_data[rb].v) >> 32LL);
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    mulh    r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc0007ff) == 0x40000003) { /* mulhu */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = (uint32_t)(((uint64_t) reg_data[ra].v * (uint64_t) reg_data[rb].v) >> 32LL);
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    mulhu   r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc0007ff) == 0x40000002) { /* mulhsu */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = (uint32_t)(((int64_t) reg_data[ra].v * (uint64_t) reg_data[rb].v) >> 32LL);
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    mulhsu  r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000000) == 0x60000000) { /* muli */
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v * imm;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    muli    r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc0007ff) == 0x80000000) { /* or */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v | reg_data[rb].v;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    or      r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000000) == 0xa0000000) { /* ori */
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v | imm;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    ori     r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc0007ff) == 0x80000400) { /* pcmpbf */
        uint32_t vala, valb;
        chk_loaded(ra); chk_loaded(rb);
        vala = reg_data[ra].v;
        valb = reg_data[rb].v;
        if ((vala & 0xff) == (valb & 0xff))
            reg_data[rd].v = 1;
        else if ((vala & 0xff00) == (valb & 0xff00))
            reg_data[rd].v = 2;
        else if ((vala & 0xff0000) == (valb & 0xff0000))
            reg_data[rd].v = 3;
        else if ((vala & 0xff000000) == (valb & 0xff000000))
            reg_data[rd].v = 4;
        else
            reg_data[rd].v = 0;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    pcmpbf  r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc0007ff) == 0x88000400) { /* pcmpeq */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v == reg_data[rb].v;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    pcmpeq  r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc0007ff) == 0x8c000400) { /* pcmpne */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v != reg_data[rb].v;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    pcmpne  r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xdfe08000) == 0x4c008000) { /* put, putd */
        /* NULL */
        DEBUG_TRACE("%08x: %08x    pcmpne  r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xe4000000) == 0x04000000) { /* rsub */
        uint32_t K = (instr & 0x10000000) != 0;
        uint32_t C = (instr & 0x08000000) != 0;
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[rb].v + ~reg_data[ra].v + (msr_c & C);
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        update_msr_c(reg_data[rb].v, ~reg_data[ra].v, msr_c & C, K);
        DEBUG_TRACE("%08x: %08x    putx    r%d", pc, instr, rd);
    }
    else if ((instr & 0xe4000000) == 0x24000000) { /* rsubi */
        uint32_t K = (instr & 0x10000000) != 0;
        uint32_t C = (instr & 0x08000000) != 0;
        chk_loaded(ra);
        reg_data[rd].v = imm + ~reg_data[ra].v + (msr_c & C);
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        update_msr_c(imm, ~reg_data[ra].v, msr_c & C, K);
        DEBUG_TRACE("%08x: %08x    rsubi   r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xff000000) == 0xb6000000) { /* rtbd, rted, rtid, rtsd */
        chk_loaded(ra);
        if (!reg_data[ra].o) {
            /* Return address is not valid */
            set_errno(ERR_OTHER, "Return instruction with invalid address");
            return -1;
        }
        /* Found the return address */
        trace_return_next = 1;
        trace_return_addr = reg_data[ra].v + imm;
        DEBUG_TRACE("%08x: %08x    rtxd    r%d, %d ; = 0x%08x", pc, instr, ra, imm, trace_return_addr);
    }
    else if ((instr & 0xf8000000) == 0xd0000000) { /* sb, sh, sbea, shea */
        /* Not traced */
        DEBUG_TRACE("%08x: %08x    sb/sh/sbea/shea r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xf8000000) == 0xf0000000) { /* sbi, shi */
        /* Not traced */
        DEBUG_TRACE("%08x: %08x    sbi/shi r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xf0000000) == 0xd0000000) { /* Store word */
        chk_loaded(ra); chk_loaded(rb);
        if (reg_data[ra].o && reg_data[rb].o) {
            chk_loaded(rd);
            if (instr & 0x80) {
                /* swea: Not traced */
            }
            else {
                uint32_t addr = reg_data[ra].v + reg_data[rb].v;
                if (!reg_data[rd].o) {
                    mem_hash_write(addr, 0, 0);
                }
                else if (instr & 0x200) {
                    uint32_t v = reg_data[rd].v;
                    swap_bytes(&v, 4);
                    mem_hash_write(addr, v, 1);
                }
                else {
                    store_reg(addr, rd);
                }
            }
        }
        DEBUG_TRACE("%08x: %08x    sw/swr/swx/swea r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xf0000000) == 0xf0000000) { /* Store word immediate */
        uint32_t addr;
        chk_loaded(ra);
        if (reg_data[ra].o) {
            addr = reg_data[ra].v + imm;
            store_reg(addr, rd);
        }
        DEBUG_TRACE("%08x: %08x    swi     r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else if ((instr & 0xfc00ffff) == 0x90000061) { /* sext16 */
        chk_loaded(ra);
        reg_data[rd].v = sext(reg_data[ra].v);
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    sext16  r%d, r%d", pc, instr, rd, ra);
    }
    else if ((instr & 0xfc00ffff) == 0x90000060) { /* sext8 */
        uint32_t val;
        chk_loaded(ra);
        val = reg_data[ra].v;
        reg_data[rd].v = ((val >> 7) & 1) ? 0xffffff00 | val : 0x000000ff & val;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    sext8   r%d, r%d", pc, instr, rd, ra);
    }
    else if ((instr & 0xfc00ffff) == 0x90000000) { /* sra */
        chk_loaded(ra);
        reg_data[rd].v = arithmetic_right_shift(reg_data[ra].v, 1);
        set_msr_c(reg_data[ra].v & 1);
        DEBUG_TRACE("%08x: %08x    sra     r%d, r%d", pc, instr, rd, ra);
    }
    else if ((instr & 0xfc00ffff) == 0x90000021) { /* src */
        chk_loaded(ra);
        reg_data[rd].v = arithmetic_right_shift(reg_data[ra].v, 1) | (msr_c << 31);
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    src     r%d, r%d", pc, instr, rd, ra);
    }
    else if ((instr & 0xfc00ffff) == 0x90000041) { /* srl */
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v >> 1;
        set_msr_c(reg_data[ra].v & 1);
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    srl     r%d, r%d", pc, instr, rd, ra);
    }
    else if ((instr & 0xfc00ffff) == 0x900001e0) { /* swapb */
        uint32_t val;
        chk_loaded(ra);
        val = reg_data[ra].v;
        reg_data[rd].v = (val & 0xff) << 24 | (val & 0xff00) << 8 | (val & 0xff0000) >> 8 | (val & 0xff000000) >> 24;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    swapb   r%d, r%d", pc, instr, rd, ra);
    }
    else if ((instr & 0xfc00ffff) == 0x900001e2) { /* swaph */
        uint32_t val;
        chk_loaded(ra);
        val = reg_data[ra].v;
        reg_data[rd].v = (val & 0xffff) << 16 | (val & 0xffff0000) >> 16;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    swaph   r%d, r%d", pc, instr, rd, ra);
    }
    else if ((instr & 0xffe003e1) == 0x90000060) { /* wdc, wic */
        /* NULL */
        DEBUG_TRACE("%08x: %08x    wic/wdc r%d, r%d", pc, instr, ra, rb);
    }
    else if ((instr & 0xfc0007ff) == 0x88000000) { /* xor */
        chk_loaded(ra); chk_loaded(rb);
        reg_data[rd].v = reg_data[ra].v ^ reg_data[rb].v;
        reg_data[rd].o = reg_data[ra].o && reg_data[rb].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    xor     r%d, r%d, r%d", pc, instr, rd, ra, rb);
    }
    else if ((instr & 0xfc000000) == 0xa8000000) { /* xori */
        chk_loaded(ra);
        reg_data[rd].v = reg_data[ra].v ^ imm;
        reg_data[rd].o = reg_data[ra].o ? REG_VAL_OTHER : 0;
        DEBUG_TRACE("%08x: %08x    xori    r%d, r%d, %d", pc, instr, rd, ra, imm);
    }
    else {
        unsigned i;
        /* Unknown/undecoded.  May alter some register, so invalidate file */
        for (i = 2;  i < 15; i++) reg_data[i].o = 0;
        for (i = 16; i < 32; i++) reg_data[i].o = 0;
        DEBUG_TRACE("%08x: %08x    unknown", pc, instr);
    }

    /* Ensure register 0 is always 0 */
    reg_data[0].v = 0;
    reg_data[0].o = REG_VAL_OTHER;

    /* Finalize delay slot */
    if (return_delayslot) {
        reg_data[REG_PC_INDEX].v = trace_return_addr;
        reg_data[REG_PC_INDEX].o = REG_VAL_OTHER;
    }
    if (branch_delayslot) {
        add_branch(trace_branch_addr);
    }

    if (!trace_return && !trace_branch) {
        /* Check next address */
        reg_data[REG_PC_INDEX].v += 4;
    }
    return 0;
}

static int trace_instructions(void) {
    unsigned i;
    RegData org_regs[REG_DATA_SIZE];

    memcpy(org_regs, reg_data, sizeof(org_regs));

    for (;;) {
        unsigned t = 0;
        BranchData * b = NULL;
        uint32_t sp = 0;
        if (chk_loaded(REG_SP_INDEX)  < 0) return -1;
        if (chk_loaded(REG_PC_INDEX)  < 0) return -1;
        if (chk_loaded(REG_MSR_INDEX) < 0) return -1;
        trace_return_next = 0;
        trace_branch_next = 0;
        trace_branch_conditional = 0;
        trace_branch_exit = 0;
        trace_imm = 0;
        sp = reg_data[REG_SP_INDEX].v;
        trace(LOG_STACK, "Stack crawl: pc 0x%08" PRIx32 ", sp 0x%08" PRIx32,
            reg_data[REG_PC_INDEX].o ? reg_data[REG_PC_INDEX].v : 0,
            reg_data[REG_SP_INDEX].o ? reg_data[REG_SP_INDEX].v : 0);
        for (t = 0; t < 200; t++) {
            int error = 0;
            trace_return = 0;
            trace_branch = 0;
            if (chk_loaded(REG_PC_INDEX) < 0) {
                error = errno;
            }
            else if (!reg_data[REG_PC_INDEX].o) {
                error = set_errno(ERR_OTHER, "PC value not available");
            }
            else if (!reg_data[REG_PC_INDEX].v) {
                error = set_errno(ERR_OTHER, "PC == 0");
            }
            else if (trace_microblaze() < 0) {
                error = errno;
            }
            if (!error && trace_return) {
                if (chk_loaded(REG_SP_INDEX) < 0 || !reg_data[REG_SP_INDEX].o || reg_data[REG_SP_INDEX].v < sp) {
                    error = set_errno(ERR_OTHER, "Stack crawl: invalid SP value");
                }
            }
            if (error) {
                trace(LOG_STACK, "Stack crawl: %s", errno_to_str(error));
                break;
            }
            if (trace_return) return 0;
            if (trace_branch) break;
            if (trace_branch_exit) break;
        }
        if (branch_pos >= branch_cnt) break;
        b = branch_data + branch_pos++;
        mem_data = b->mem_data;
        memcpy(reg_data, b->reg_data, sizeof(reg_data));
    }
    trace(LOG_STACK, "Stack crawl: Function epilogue not found");
    for (i = 0; i < REG_DATA_SIZE; i++) reg_data[i].o = 0;
    if (org_regs[REG_PC_INDEX].o && org_regs[REG_PC_INDEX].v >= 0x08 && org_regs[REG_SP_INDEX].v != 0) {
        unsigned lr = REG_LR_INDEX;
        uint32_t pc = org_regs[REG_PC_INDEX].v;
        if (pc >= 0x10 && pc < 0x18) lr = 14;
        else if (pc >= 0x18 && pc < 0x20) lr = 16;
        else if (pc >= 0x20 && pc < 0x28) lr = 17;
        if (org_regs[lr].v != 0 && pc != org_regs[lr].v + 8) {
            reg_data[REG_SP_INDEX]  = org_regs[REG_SP_INDEX];
            reg_data[REG_PC_INDEX]  = org_regs[lr];
            reg_data[REG_MSR_INDEX] = org_regs[REG_MSR_INDEX];
            reg_data[REG_PC_INDEX].v += 8;
        }
    }
    return 0;
}

int crawl_stack_frame_microblaze(StackFrame * frame, StackFrame * down) {
    RegisterDefinition * def = NULL;
    uint32_t pc = 0;

#if USE_MEM_CACHE
    unsigned i;
    for (i = 0; i < MEM_CACHE_SIZE; i++) mem_cache[i].size = 0;
#endif

    stk_ctx = frame->ctx;
    memset(&reg_data, 0, sizeof(reg_data));
    memset(&mem_data, 0, sizeof(mem_data));
    branch_pos = 0;
    branch_cnt = 0;

    for (def = get_reg_definitions(stk_ctx); def->name; def++) {
        uint64_t v = 0;
        if (def->dwarf_id < 0 || def->dwarf_id >= REG_DATA_SIZE) continue;
        if (read_reg_value(frame, def, &v) < 0) continue;
        reg_data[def->dwarf_id].v = (uint32_t)v;
        reg_data[def->dwarf_id].o = REG_VAL_OTHER;
        if (def->dwarf_id == REG_PC_INDEX) pc = (uint32_t)v;
    }

    if (trace_instructions() < 0) return -1;

    for (def = get_reg_definitions(stk_ctx); def->name; def++) {
        if (def->dwarf_id < 0 || def->dwarf_id >= REG_DATA_SIZE) continue;
        if (chk_loaded(def->dwarf_id) < 0) continue;
        if (!reg_data[def->dwarf_id].o) continue;
        if (write_reg_value(down, def, reg_data[def->dwarf_id].v) < 0) return -1;
        if (def->dwarf_id == REG_SP_INDEX) {
            frame->fp = reg_data[def->dwarf_id].v;
            if (pc < 0x50 && frame->fp > 4) frame->fp -= 4;
        }
    }

    stk_ctx = NULL;
    return 0;
}

#endif /* ENABLE_DebugContext */
