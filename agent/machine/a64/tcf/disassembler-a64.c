/*******************************************************************************
 * Copyright (c) 2014 Xilinx, Inc. and others.
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

#if SERVICE_Disassembly

#include <assert.h>
#include <stdio.h>
#include <tcf/framework/context.h>
#include <tcf/services/symbols.h>
#include <machine/a64/tcf/disassembler-a64.h>

static char buf[128];
static size_t buf_pos = 0;
static DisassemblerParams * params = NULL;
static uint64_t instr_addr = 0;
static uint32_t instr = 0;

static void add_char(char ch) {
    if (buf_pos >= sizeof(buf) - 1) return;
    buf[buf_pos++] = ch;
    if (ch == ' ') while (buf_pos < 8) buf[buf_pos++] = ch;
}

static void add_str(const char * s) {
    while (*s) add_char(*s++);
}

static void add_dec_uint32(uint32_t n) {
    char s[32];
    size_t i = 0;
    do {
        s[i++] = (char)('0' + n % 10);
        n = n / 10;
    }
    while (n != 0);
    while (i > 0) add_char(s[--i]);
}

static void add_dec_uint64(uint64_t n) {
    char s[64];
    size_t i = 0;
    do {
        s[i++] = (char)('0' + (int)(n % 10));
        n = n / 10;
    }
    while (n != 0);
    while (i > 0) add_char(s[--i]);
}

static void add_hex_uint32(uint32_t n) {
    char s[32];
    size_t i = 0;
    while (i < 8) {
        uint32_t d = n & 0xf;
        s[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        n = n >> 4;
    }
    while (i > 0) add_char(s[--i]);
}

static void add_hex_uint64(uint64_t n) {
    char s[64];
    size_t i = 0;
    while (i < 16) {
        uint32_t d = n & 0xf;
        s[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        n = n >> 4;
    }
    while (i > 0) add_char(s[--i]);
}

static void add_flt_uint32(uint32_t n) {
    char buf[32];
    union {
        uint32_t n;
        float f;
    } u;
    u.n = n;
    snprintf(buf, sizeof(buf), "%g", u.f);
    add_str(buf);
}

static void add_flt_uint64(uint64_t n) {
    char buf[32];
    union {
        uint64_t n;
        double d;
    } u;
    u.n = n;
    snprintf(buf, sizeof(buf), "%g", u.d);
    add_str(buf);
}

static void add_reg_name(uint32_t n, int x) {
    add_char(x ? 'x' : 'w');
    add_dec_uint32(n);
}

static void add_addr(uint64_t addr) {
    while (buf_pos < 16) add_char(' ');
    add_str("; addr=0x");
    add_hex_uint64(addr);
#if ENABLE_Symbols
    if (params->ctx != NULL) {
        Symbol * sym = NULL;
        char * name = NULL;
        ContextAddress sym_addr = 0;
        if (find_symbol_by_addr(params->ctx, STACK_NO_FRAME, (ContextAddress)addr, &sym) < 0) return;
        if (get_symbol_name(sym, &name) < 0 || name == NULL) return;
        if (get_symbol_address(sym, &sym_addr) < 0) return;
        if (sym_addr <= addr) {
            add_str(": ");
            add_str(name);
            if (sym_addr < addr) {
                add_str(" + 0x");
                add_hex_uint64(addr - (uint64_t)sym_addr);
            }
        }
    }
#endif
}

static void data_processing_immediate(void) {
    if ((instr & 0x1f000000) == 0x10000000) {
        /* PC-rel. addressing */
        uint64_t base = instr_addr;
        uint64_t imm = 0;
        add_str(instr & (1u << 31) ? "adrp" : "adr");
        add_char(' ');
        add_reg_name(instr & 0x1f, 1);
        add_str(", ");
        imm |= ((instr >> 29) & 0x3);
        imm |= ((instr >> 5) & 0x7ffff) << 2;
        if (imm & (1u << 20)) imm |= ~((uint64_t)(1u << 20) - 1);
        if (instr & (1u << 31)) {
            imm = imm << 12;
            base &= ~((uint64_t)0xfff);
        }
        if (imm & ((uint64_t)1u << 63)) {
            add_char('-');
            add_dec_uint64(~imm + 1);
        }
        else {
            add_char('+');
            add_dec_uint64(imm);
        }
        add_addr(base + imm);
        return;
    }

    if ((instr & 0x1f000000) == 0x11000000) {
        /* Add/subtract (immediate) */
        int x = (instr & (1u << 31)) != 0;
        switch ((instr >> 29) & 3) {
        case 0: add_str("add"); break;
        case 1: add_str("adds"); break;
        case 2: add_str("sub"); break;
        case 3: add_str("subs"); break;
        }
        add_char(' ');
        add_reg_name(instr & 0x1f, x);
        add_str(", ");
        add_reg_name((instr >> 5) & 0x1f, x);
        add_str(", #");
        add_hex_uint32((instr >> 10) & 0xfff);
        switch ((instr >> 22) & 3) {
        case 1: add_str(", lsl #12"); break;
        }
        return;
    }

    if ((instr & 0x1f800000) == 0x12000000) {
        /* Logical (immediate) */
        uint32_t imm = 0;
        int x = (instr & (1u << 31)) != 0;
        switch ((instr >> 29) & 3) {
        case 0: add_str("and"); break;
        case 1: add_str("orr"); break;
        case 2: add_str("eor"); break;
        case 3: add_str("ands"); break;
        }
        add_char(' ');
        add_reg_name(instr & 0x1f, x);
        add_str(", ");
        add_reg_name((instr >> 5) & 0x1f, x);
        add_str(", #");
        imm |= ((instr >> 22) & 0x1) << 12;
        imm |= ((instr >> 10) & 0x3f) << 6;
        imm |= (instr >> 16) & 0x3f;
        add_hex_uint32(imm);
        return;
    }

    if ((instr & 0x1f800000) == 0x12800000) {
        /* Move wide (immediate) */
        int x = (instr & (1u << 31)) != 0;
        switch ((instr >> 29) & 3) {
        case 0: add_str("movn"); break;
        case 1: return;
        case 2: add_str("movz"); break;
        case 3: add_str("movk"); break;
        }
        add_char(' ');
        add_reg_name(instr & 0x1f, x);
        add_str(", #");
        add_hex_uint32((instr >> 5) & 0xffff);
        switch ((instr >> 21) & 3) {
        case 1: add_str(", lsl #16"); break;
        case 2: add_str(", lsl #32"); break;
        case 3: add_str(", lsl #48"); break;
        }
        return;
    }

    if ((instr & 0x1f800000) == 0x13000000) {
        /* Bitfield */
        int x = (instr & (1u << 31)) != 0;
        switch ((instr >> 29) & 3) {
        case 0: add_str("sbfm"); break;
        case 1: add_str("bfm"); break;
        case 2: add_str("ubfm"); break;
        case 3: return;
        }
        add_char(' ');
        add_reg_name(instr & 0x1f, x);
        add_str(", ");
        add_reg_name((instr >> 5) & 0x1f, x);
        add_str(", #");
        add_hex_uint32((instr >> 16) & 0x3f);
        add_str(", #");
        add_hex_uint32((instr >> 10) & 0x3f);
        return;
    }

    if ((instr & 0x1f800000) == 0x13800000) {
        /* Extract */
        int x = (instr & (1u << 31)) != 0;
        switch ((instr >> 29) & 3) {
        case 0: add_str("extr"); break;
        case 1: return;
        case 2: return;
        case 3: return;
        }
        add_char(' ');
        add_reg_name(instr & 0x1f, x);
        add_str(", ");
        add_reg_name((instr >> 5) & 0x1f, x);
        add_str(", ");
        add_reg_name((instr >> 16) & 0x1f, x);
        add_str(", #");
        add_hex_uint32((instr >> 10) & 0x3f);
        return;
    }
}

static void branch_exception_system() {
    if ((instr & 0x7c000000) == 0x14000000) {
        /* Unconditional branch (immediate) */
        int32_t imm = instr & 0x3ffffff;
        add_str(instr & (1u << 31) ? "bl" : "b");
        add_char(' ');
        if (imm & 0x02000000) {
            imm |= 0xfc000000;
            add_char('-');
            add_dec_uint32(~imm + 1);
        }
        else {
            add_char('+');
            add_dec_uint32(imm);
        }
        add_addr(instr_addr + ((int64_t)imm << 2));
        return;
    }

    if ((instr & 0x7e000000) == 0x34000000) {
        /* Compare & branch (immediate) */
    }

    if ((instr & 0x7e000000) == 0x36000000) {
        /* Test & branch (immediate) */
    }

    if ((instr & 0xfe000000) == 0x54000000) {
        /* Conditional branch (immediate) */
    }

    if ((instr & 0xff000000) == 0xd4000000) {
        /* Exception generation */
    }

    if ((instr & 0xffc00000) == 0xd5000000) {
        /* System */
    }

    if ((instr & 0xfe000000) == 0xd6000000) {
        /* Unconditional branch (register) */
    }
}

static void loads_and_stores() {
}

static void data_processing_register() {
}

static void data_processing_simd_and_fp() {
}

DisassemblyResult * disassemble_a64(uint8_t * code,
        ContextAddress addr, ContextAddress size,
        DisassemblerParams * disass_params) {
    unsigned i;
    static DisassemblyResult dr;

    if (size < 4) return NULL;
    memset(&dr, 0, sizeof(dr));
    dr.size = 4;
    buf_pos = 0;
    params = disass_params;
    instr_addr = addr;
    for (i = 0; i < 4; i++) instr |= (uint32_t)*code++ << (i * 8);

    if ((instr & 0x1c000000) == 0x10000000) data_processing_immediate();
    else if ((instr & 0x1c000000) == 0x10000000) branch_exception_system();
    else if ((instr & 0x0a000000) == 0x08000000) loads_and_stores();
    else if ((instr & 0x0e000000) == 0x0a000000) data_processing_register();
    else if ((instr & 0x0e000000) == 0x0e000000) data_processing_simd_and_fp();

    dr.text = buf;
    if (buf_pos == 0) {
        snprintf(buf, sizeof(buf), ".word 0x%08x", instr);
    }
    else {
        buf[buf_pos] = 0;
    }
    return &dr;
}

#endif /* SERVICE_Disassembly */
