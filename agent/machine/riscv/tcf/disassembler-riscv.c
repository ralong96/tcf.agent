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

#include <tcf/config.h>

#if SERVICE_Disassembly

#include <assert.h>
#include <stdio.h>
#include <tcf/framework/context.h>
#include <tcf/services/symbols.h>
#include <machine/riscv/tcf/disassembler-riscv.h>

static char buf[128];
static size_t buf_pos = 0;
static unsigned xlen = 0;
static DisassemblerParams * params = NULL;
static uint64_t instr_addr = 0;
static uint32_t instr = 0;

static const int imm_bits_w[32] = { 6, 10, 11, 12, 5 };
static const int imm_bits_d[32] = { 10, 11, 12, 5, 6 };
static const int imm_bits_q[32] = { 11, 12, 5, 6, 10 };

static const int imm_bits_lw_sp[32] = { 4, 5, 6, 12, 2, 3 };
static const int imm_bits_ld_sp[32] = { 5, 6, 12, 2, 3, 4 };
static const int imm_bits_lq_sp[32] = { 6, 12, 2, 3, 4, 5 };
static const int imm_bits_sw_sp[32] = { 9, 10, 11, 12, 7, 8 };
static const int imm_bits_sd_sp[32] = { 10, 11, 12, 7, 8, 9 };
static const int imm_bits_sq_sp[32] = { 11, 12, 7, 8, 9, 10 };

static const int imm_bits_addi_spn[32] = { 6, 5, 11, 12, 7, 8, 9, 10 };
static const int imm_bits_shift[32] = { 2, 3, 4, 5, 6, 12 };

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

#if 0
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
#endif

static void add_hex_uint32(uint32_t n) {
    char s[32];
    size_t i = 0;
    while (i < 8) {
        uint32_t d = n & 0xf;
        if (i > 0 && n == 0) break;
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
        if (i > 0 && n == 0) break;
        s[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        n = n >> 4;
    }
    while (i > 0) add_char(s[--i]);
}

#if 0
static void add_flt_uint32(uint32_t n) {
    char str[32];
    union {
        uint32_t n;
        float f;
    } u;
    u.n = n;
    snprintf(str, sizeof(str), "%#g", u.f);
    add_str(str);
}

static void add_flt_uint64(uint64_t n) {
    char str[32];
    union {
        uint64_t n;
        double d;
    } u;
    u.n = n;
    snprintf(str, sizeof(str), "%#g", u.d);
    add_str(str);
}
#endif

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

static void add_reg(unsigned n) {
    static const char * names[] = {
        "zero", "ra",
        "sp",   "gp",
        "tp",   "t0",
        "t1",   "t2",
        "s0",   "s1",
        "a0",   "a1",
        "a2",   "a3",
        "a4",   "a5",
        "a6",   "a7",
        "s2",   "s3",
        "s4",   "s5",
        "s6",   "s7",
        "s8",   "s9",
        "s10",  "s11",
        "t3",   "t4",
        "t5",   "t6"
    };
    add_str(names[n & 0x1f]);
}

static void add_rvc_reg(unsigned n) {
    static const char * names[] = {
        "s0",   "s1",
        "a0",   "a1",
        "a2",   "a3",
        "a4",   "a5",
    };
    add_str(names[n & 0x7]);
}

static void add_freg(unsigned n) {
    add_char('f');
    add_dec_uint32(n);
}

static uint32_t get_imm(const int * bits) {
    unsigned i;
    uint32_t v = 0;
    for (i = 0; i < 32 && bits[i]; i++) {
        if (instr & (1u << bits[i])) v |= 1u << i;
    }
    return v;
}

static void disassemble_rv32i(void) {
    if ((instr & 0x0000007f) == 0x00000037) {
        unsigned imm = instr >> 12;
        add_str("lui ");
        add_reg((instr >> 7) & 0x1f);
        add_str(", ");
        add_dec_uint32(imm);
        return;
    }
    if ((instr & 0x0000007f) == 0x00000017) {
        unsigned imm = instr >> 12;
        add_str("auipc ");
        add_reg((instr >> 7) & 0x1f);
        add_str(", 0x");
        add_hex_uint32(imm);
        return;
    }
    if ((instr & 0x0000007f) == 0x0000006f) {
        static const int imm_bits[32] = { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 20, 12, 13, 14, 15, 16, 17, 18, 19, 31 };
        int32_t imm = get_imm(imm_bits);
        add_str("jal ");
        add_reg((instr >> 7) & 0x1f);
        add_str(", ");
        if (imm & 0x00080000) {
            imm |= 0xfff80000;
            add_char('-');
            add_dec_uint32(~imm + 1);
        }
        else {
            add_char('+');
            add_dec_uint32(imm);
        }
        add_addr(instr_addr + ((int64_t)imm << 1));
        return;
    }
    if ((instr & 0x0000707f) == 0x00000067) {
        int32_t imm = instr >> 20;
        add_str("jalr ");
        add_reg((instr >> 7) & 0x1f);
        add_str(", ");
        if (imm == 0) {
            add_reg((instr >> 15) & 0x1f);
            return;
        }
        add_dec_uint32(imm);
        add_char('(');
        add_reg((instr >> 15) & 0x1f);
        add_char(')');
        return;
    }
    if ((instr & 0x0000007f) == 0x00000013) {
        unsigned func = (instr >> 12) & 7;
        unsigned rs = (instr >> 15) & 0x1f;
        unsigned rd = (instr >> 7) & 0x1f;
        int32_t imm = instr >> 20;
        switch (func) {
        case 0:
            if (rs == 0 && rd == 0 && imm == 0) {
                add_str("nop");
                return;
            }
            add_str("addi ");
            break;
        case 2:
            add_str("slti ");
            break;
        case 3:
            add_str("sltiu ");
            break;
        case 4:
            add_str("xori ");
            break;
        case 6:
            add_str("ori ");
            break;
        case 7:
            add_str("andi ");
            break;
        }
        if (buf_pos > 0) {
            add_reg((instr >> 7) & 0x1f);
            add_str(", ");
            add_reg((instr >> 15) & 0x1f);
            add_str(", ");
            add_dec_uint32(imm);
            return;
        }
    }
}

static void disassemble_rv64i(void) {
    if ((instr & 0x0000307f) == 0x00003003) {
        int32_t imm = instr >> 20;
        add_str(instr & (1 << 14) ? "lwu " : "ld ");
        add_reg((instr >> 7) & 0x1f);
        add_str(", ");
        if (imm & 0x00000800) {
            imm |= 0xfffff800;
            add_char('-');
            add_dec_uint32(~imm + 1);
        }
        else {
            add_char('+');
            add_dec_uint32(imm);
        }
        add_char('(');
        add_reg((instr >> 15) & 0x1f);
        add_char(')');
        return;
    }
    disassemble_rv32i();
}

static void disassemble_rv128i(void) {
    disassemble_rv64i();
}

static void disassemble_rv32c(void) {
    if ((instr & 0xffff) == 0x0000) {
        add_str("illegal instruction");
        return;
    }
    if ((instr & 0xe003) == 0x0000) {
        uint32_t imm = get_imm(imm_bits_addi_spn);
        if (imm != 0) {
            add_str("addi ");
            add_rvc_reg((instr >> 2) & 0x7);
            add_str(", ");
            add_reg(2);
            add_str(", ");
            add_dec_uint32(imm * 4);
            return;
        }
    }
    if ((instr & 0xe003) == 0x4002) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            add_str("lw ");
            add_reg(rd);
            add_str(", ");
            add_dec_uint32(get_imm(imm_bits_lw_sp) * 4);
            add_str("(sp)");
            return;
        }
    }
    if ((instr & 0xe003) == 0x6002) {
        unsigned rd = (instr >> 7) & 0x1f;
        add_str("flw ");
        add_freg(rd);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_lw_sp) * 4);
        add_str("(sp)");
        return;
    }
    if ((instr & 0xe003) == 0x2002) {
        unsigned rd = (instr >> 7) & 0x1f;
        add_str("fld ");
        add_freg(rd);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_ld_sp) * 4);
        add_str("(sp)");
        return;
    }
    if ((instr & 0xe003) == 0xc002) {
        add_str("sw ");
        add_reg((instr >> 2) & 0x1f);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_sw_sp) * 4);
        add_str("(sp)");
        return;
    }
    if ((instr & 0xe003) == 0xe002) {
        add_str("fsw ");
        add_freg((instr >> 2) & 0x1f);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_sw_sp) * 4);
        add_str("(sp)");
        return;
    }
    if ((instr & 0xe003) == 0xa002) {
        add_str("fsd ");
        add_freg((instr >> 2) & 0x1f);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_sd_sp) * 8);
        add_str("(sp)");
        return;
    }
    if ((instr & 0x6003) == 0x4000) {
        add_str(instr & 0x8000 ? "sw " : "lw ");
        add_rvc_reg((instr >> 2) & 0x7);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_w) * 4);
        add_str("(");
        add_rvc_reg((instr >> 7) & 0x7);
        add_str(")");
        return;
    }
    if ((instr & 0x6003) == 0x6000) {
        add_str(instr & 0x8000 ? "fsw " : "flw ");
        add_freg((instr >> 2) & 0x7);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_w) * 4);
        add_str("(");
        add_rvc_reg((instr >> 7) & 0x7);
        add_str(")");
        return;
    }
    if ((instr & 0x6003) == 0x2000) {
        add_str(instr & 0x8000 ? "fsd " : "fld ");
        add_freg((instr >> 2) & 0x7);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_d) * 8);
        add_str("(");
        add_rvc_reg((instr >> 7) & 0x7);
        add_str(")");
        return;
    }
    if ((instr & 0xe003) == 0x0002) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            unsigned imm = get_imm(imm_bits_shift);
            if (xlen == 32 && imm >= 32) return;
            if (imm == 0) {
                if (xlen == 128) imm = 64;
                else return;
            }
            add_str("slli ");
            add_reg(rd);
            add_str(", ");
            add_reg(rd);
            add_str(", ");
            add_dec_uint32(imm);
            return;
        }
    }
    if ((instr & 0x6003) == 0x2001) {
        static const int imm_bits[32] = { 3, 4, 5, 11, 2, 7, 6, 9, 10, 8, 12 };
        int32_t imm = get_imm(imm_bits);
        add_str("jal ");
        add_reg(instr & 0x8000 ? 0 : 1);
        add_str(", ");
        if (imm & 0x0400) {
            imm |= 0xffffc000;
            add_char('-');
            add_dec_uint32(~imm + 1);
        }
        else {
            add_char('+');
            add_dec_uint32(imm);
        }
        add_addr(instr_addr + ((int64_t)imm << 1));
        return;
    }
    if ((instr & 0xc003) == 0xc001) {
        static const int imm_bits[32] = { 3, 4, 7, 8, 2, 5, 6, 9 };
        int32_t imm = get_imm(imm_bits);
        add_str(instr & 0x2000 ? "bne " : "beq ");
        add_rvc_reg((instr >> 7) & 7);
        add_str(", ");
        add_reg(0);
        add_str(", ");
        if (imm & 0x0080) {
            imm |= 0xffffff80;
            add_char('-');
            add_dec_uint32(~imm + 1);
        }
        else {
            add_char('+');
            add_dec_uint32(imm);
        }
        add_addr(instr_addr + ((int64_t)imm << 1));
        return;
    }
    if ((instr & 0xe003) == 0x8001) {
        unsigned rd = (instr >> 7) & 0x7;
        unsigned func = (instr >> 10) & 3;
        if (func <= 2) {
            unsigned imm = get_imm(imm_bits_shift);
            if (func < 2) {
                if (xlen == 32 && imm >= 32) return;
                if (imm == 0) {
                    if (xlen == 128) imm = 64;
                    else return;
                }
            }
            switch (func) {
            case 0:
                add_str("srli ");
                break;
            case 1:
                add_str("srai ");
                break;
            case 2:
                add_str("andi ");
                break;
            }
            add_rvc_reg(rd);
            add_str(", ");
            add_rvc_reg(rd);
            add_str(", ");
            add_dec_uint32(imm);
        }
        else if ((instr & (1 << 12)) == 0) {
            switch ((instr >> 5) & 3) {
            case 0:
                add_str("sub ");
                break;
            case 1:
                add_str("xor ");
                break;
            case 2:
                add_str("or ");
                break;
            case 3:
                add_str("and ");
                break;
            }
            add_rvc_reg(rd);
            add_str(", ");
            add_rvc_reg(rd);
            add_str(", ");
            add_rvc_reg((instr >> 2) & 7);
        }
        return;
    }
    if ((instr & 0xe003) == 0x8002) {
        unsigned rd = (instr >> 7) & 0x1f;
        unsigned rs = (instr >> 2) & 0x1f;
        if ((instr & (1 << 12)) == 0) {
            if (rd == 0) return;
            if (rs == 0) {
                add_str("jalr ");
                add_reg(0);
                add_str(", 0(");
                add_reg(rd);
                add_str(")");
                return;
            }
            add_str("mv ");
        }
        else {
            if (rd == 0 && rs == 0) {
                add_str("ebreak");
                return;
            }
            if (rd == 0) return;
            if (rs == 0) {
                add_str("jalr ");
                add_reg(1);
                add_str(", 0(");
                add_reg(rd);
                add_str(")");
                return;
            }
            add_str("add ");
        }
        add_reg(rd);
        add_str(", ");
        add_reg(rs);
        return;
    }
}

static void disassemble_rv64c(void) {
    if ((instr & 0xe003) == 0x6002) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            add_str("ld ");
            add_reg(rd);
            add_str(", ");
            add_dec_uint32(get_imm(imm_bits_ld_sp) * 8);
            add_str("(sp)");
            return;
        }
    }
    if ((instr & 0xe003) == 0xe002) {
        add_str("sd ");
        add_reg((instr >> 2) & 0x1f);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_sd_sp) * 8);
        add_str("(sp)");
        return;
    }
    if ((instr & 0x6003) == 0x6000) {
        add_str(instr & 0x8000 ? "sd " : "ld ");
        add_rvc_reg((instr >> 2) & 0x7);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_d) * 8);
        add_str("(");
        add_rvc_reg((instr >> 7) & 0x7);
        add_str(")");
        return;
    }
    if ((instr & 0xfc03) == 0x9c01) {
        unsigned rd = (instr >> 7) & 0x7;
        switch ((instr >> 5) & 3) {
        case 0:
            add_str("subw ");
            break;
        case 1:
            add_str("addw ");
            break;
        default:
            return;
        }
        add_rvc_reg(rd);
        add_str(", ");
        add_rvc_reg(rd);
        add_str(", ");
        add_rvc_reg((instr >> 2) & 7);
        return;
    }
    disassemble_rv32c();
}

static void disassemble_rv128c(void) {
    if ((instr & 0xe003) == 0x2002) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            add_str("lq ");
            add_reg(rd);
            add_str(", ");
            add_dec_uint32(get_imm(imm_bits_lq_sp) * 16);
            add_str("(sp)");
            return;
        }
    }
    if ((instr & 0xe003) == 0xa002) {
        add_str("sq ");
        add_reg((instr >> 2) & 0x1f);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_sq_sp) * 16);
        add_str("(sp)");
        return;
    }
    if ((instr & 0x6003) == 0x2000) {
        add_str(instr & 0x8000 ? "sq " : "lq ");
        add_rvc_reg((instr >> 2) & 0x7);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_q) * 16);
        add_str("(");
        add_rvc_reg((instr >> 7) & 0x7);
        add_str(")");
        return;
    }
    disassemble_rv64c();
}

static DisassemblyResult * disassemble_riscv(uint8_t * code,
        ContextAddress addr, ContextAddress size,
        DisassemblerParams * disass_params) {
    static DisassemblyResult dr;

    if (size == 0) return NULL;
    memset(&dr, 0, sizeof(dr));
    buf_pos = 0;
    instr = 0;
    instr_addr = addr;
    params = disass_params;

    if ((*code & 3) == 3) {
        if (size < 4) return NULL;
        instr = (uint32_t)code[0] + ((uint32_t)code[1] << 8) + ((uint32_t)code[2] << 16) + ((uint32_t)code[3] << 24);
        dr.size = 4;
        if (xlen == 32) disassemble_rv32i();
        if (xlen == 64) disassemble_rv64i();
        if (xlen == 128) disassemble_rv128i();
    }
    else {
        if (size < 2) return NULL;
        instr = (uint32_t)code[0] + ((uint32_t)code[1] << 8);
        dr.size = 2;
        if (xlen == 32) disassemble_rv32c();
        if (xlen == 64) disassemble_rv64c();
        if (xlen == 128) disassemble_rv128c();
    }

    dr.text = buf;
    if (buf_pos == 0) {
        if (dr.size == 2) {
            snprintf(buf, sizeof(buf), ".half 0x%04x", (unsigned)instr);
        }
        else {
            snprintf(buf, sizeof(buf), ".word 0x%08x", (unsigned)instr);
        }
    }
    else {
        buf[buf_pos] = 0;
    }
    return &dr;
}

DisassemblyResult * disassemble_riscv32(uint8_t * code,
    ContextAddress addr, ContextAddress size,
    DisassemblerParams * disass_params) {
    xlen = 32;
    return disassemble_riscv(code, addr, size, disass_params);
}

DisassemblyResult * disassemble_riscv64(uint8_t * code,
    ContextAddress addr, ContextAddress size,
    DisassemblerParams * disass_params) {
    xlen = 64;
    return disassemble_riscv(code, addr, size, disass_params);
}

DisassemblyResult * disassemble_riscv128(uint8_t * code,
    ContextAddress addr, ContextAddress size,
    DisassemblerParams * disass_params) {
    xlen = 128;
    return disassemble_riscv(code, addr, size, disass_params);
}

#endif /* SERVICE_Disassembly */
