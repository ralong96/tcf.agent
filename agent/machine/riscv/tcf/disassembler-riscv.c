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

static void add_reg_csr(unsigned csr) {
    switch (csr) {
    case 1: add_str("fflags"); return;
    }
    add_str("csr");
    add_dec_uint32(csr);
}

static void add_freg(unsigned n) {
    static const char * names[] = {
        "ft0",  "ft1",
        "ft2",  "ft3",
        "ft4",  "ft5",
        "ft6",  "ft7",
        "fs0",  "fs1",
        "fa0",  "fa1",
        "fa2",  "fa3",
        "fa4",  "fa5",
        "fa6",  "fa7",
        "fs2",  "fs3",
        "fs4",  "fs5",
        "fs6",  "fs7",
        "fs8",  "fs9",
        "fs10", "fs11",
        "ft8",  "ft9",
        "ft10", "ft11"
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

static void add_rvc_freg(unsigned n) {
    static const char * names[] = {
        "fs0",  "fs1",
        "fa0",  "fa1",
        "fa2",  "fa3",
        "fa4",  "fa5",
    };
    add_str(names[n & 0x7]);
}

static void add_rm(unsigned rm) {
    static const char * names[] = {
        "rne",  "rtz",
        "rdn",  "rup",
        "rmm",  "5",
        "6",    "dyn",
    };
    if ((rm & 0x7) == 7) return;
    add_str(", ");
    add_str(names[rm & 0x7]);
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

static void disassemble_rv32i(void) {
    unsigned rs2 = (instr >> 20) & 0x1f;
    unsigned rs1 = (instr >> 15) & 0x1f;
    unsigned rd = (instr >> 7) & 0x1f;
    if ((instr & 0x0000007f) == 0x00000037) {
        unsigned imm = instr >> 12;
        add_str("lui ");
        add_reg(rd);
        add_str(", 0x");
        add_hex_uint32(imm);
        return;
    }
    if ((instr & 0x0000007f) == 0x00000017) {
        unsigned imm = instr >> 12;
        add_str("auipc ");
        add_reg(rd);
        add_str(", 0x");
        add_hex_uint32(imm);
        return;
    }
    if ((instr & 0x0000007f) == 0x0000006f) {
        static const int imm_bits[32] = { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 20, 12, 13, 14, 15, 16, 17, 18, 19, 31 };
        int32_t imm = get_imm_se(imm_bits);
        if (rd == 0) {
            add_str("j ");
        }
        else {
            add_str("jal ");
            add_reg(rd);
            add_str(", ");
        }
        if (imm < 0) {
            add_char('-');
            add_dec_uint32(-imm);
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
        add_reg(rd);
        add_str(", ");
        if (imm == 0) {
            add_reg(rs1);
            return;
        }
        add_dec_uint32(imm);
        add_char('(');
        add_reg(rs1);
        add_char(')');
        return;
    }
    if ((instr & 0x0000007f) == 0x00000063) {
        static const int imm_bits[32] = { 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 7, 31 };
        int32_t imm = get_imm_se(imm_bits);
        if (rs2 == 0) {
            switch ((instr >> 12) & 7) {
            case 0:
                add_str("beqz ");
                break;
            case 1:
                add_str("bnez ");
                break;
            case 4:
                add_str("bltz ");
                break;
            case 5:
                add_str("bgez ");
                break;
            case 6:
                add_str("bltuz ");
                break;
            case 7:
                add_str("bgeuz ");
                break;
            }
        }
        else if (rs1 == 0) {
            switch ((instr >> 12) & 7) {
            case 4:
                add_str("bgtz ");
                break;
            case 5:
                add_str("blez ");
                break;
            case 6:
                add_str("bgtuz ");
                break;
            case 7:
                add_str("bteuz ");
                break;
            }
        }
        else {
            switch ((instr >> 12) & 7) {
            case 0:
                add_str("beq ");
                break;
            case 1:
                add_str("bne ");
                break;
            case 4:
                add_str("blt ");
                break;
            case 5:
                add_str("bge ");
                break;
            case 6:
                add_str("bltu ");
                break;
            case 7:
                add_str("bgeu ");
                break;
            }
        }
        if (buf_pos > 0) {
            if (rs1 != 0) {
                add_reg(rs1);
                add_str(", ");
            }
            if (rs2 != 0) {
                add_reg(rs2);
                add_str(", ");
            }
            if (imm < 0) {
                add_char('-');
                add_dec_uint32(-imm);
            }
            else {
                add_char('+');
                add_dec_uint32(imm);
            }
            add_addr(instr_addr + ((int64_t)imm << 1));
            return;
        }
    }
    if ((instr & 0x0000007f) == 0x00000003) {
        int32_t imm = get_imm_rse(20, 12);
        switch ((instr >> 12) & 7) {
        case 0:
            add_str("lb ");
            break;
        case 1:
            add_str("lh ");
            break;
        case 2:
            add_str("lw ");
            break;
        case 4:
            add_str("lbu ");
            break;
        case 5:
            add_str("lhu ");
            break;
        }
        if (buf_pos > 0) {
            add_reg(rd);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                add_dec_uint32(-imm);
            }
            else {
                add_dec_uint32(imm);
            }
            add_str("(");
            add_reg(rs1);
            add_str(")");
            return;
        }
    }
    if ((instr & 0x0000007f) == 0x00000023) {
        static const int imm_bits[32] = { 7, 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 31 };
        int32_t imm = get_imm_se(imm_bits);
        switch ((instr >> 12) & 7) {
        case 0:
            add_str("sb ");
            break;
        case 1:
            add_str("sh ");
            break;
        case 2:
            add_str("sw ");
            break;
        }
        if (buf_pos > 0) {
            add_reg(rs2);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                add_dec_uint32(-imm);
            }
            else {
                add_dec_uint32(imm);
            }
            add_str("(");
            add_reg(rs1);
            add_str(")");
            return;
        }
    }
    if ((instr & 0x0000007f) == 0x00000013) {
        unsigned func = (instr >> 12) & 7;
        int32_t imm = get_imm_rse(20, 12);
        switch (func) {
        case 0:
            if (rs1 == 0) {
                if (rd == 0 && imm == 0) {
                    add_str("nop");
                    return;
                }
                add_str("li ");
                add_reg(rd);
                add_str(", ");
                if (imm < 0) {
                    add_char('-');
                    imm = -imm;
                }
                add_dec_uint32(imm);
                return;
            }
            if (imm == 0) {
                add_str("mv ");
                add_reg(rd);
                add_str(", ");
                add_reg(rs1);
                return;
            }
            add_str("addi ");
            break;
        case 2:
            add_str("slti ");
            break;
        case 3:
            if (imm == 1) {
                add_str("seqz ");
                add_reg(rd);
                add_str(", ");
                add_reg(rs1);
                return;
            }
            add_str("sltiu ");
            break;
        case 4:
            if (imm == -1) {
                add_str("not ");
                add_reg(rd);
                add_str(", ");
                add_reg(rs1);
                return;
            }
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
            add_reg(rd);
            add_str(", ");
            add_reg(rs1);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                imm = -imm;
            }
            add_dec_uint32(imm);
            return;
        }
    }
    if ((instr & 0xbe00007f) == 0x00000013) {
        unsigned func = (instr >> 12) & 7;
        uint32_t imm = rs2;
        switch (func) {
        case 1:
            add_str("slli ");
            break;
        case 5:
            add_str(instr & (1 << 30) ? "srai " : "srli ");
            break;
        }
        if (buf_pos > 0) {
            add_reg(rd);
            add_str(", ");
            add_reg(rs1);
            add_str(", 0x");
            add_hex_uint32(imm);
            return;
        }
    }
    if ((instr & 0xfe00007f) == 0x00000033) {
        unsigned func = (instr >> 12) & 7;
        static const char * nm[8] = { "add", "sll", "slt", "sltu", "xor", "srl", "or", "and" };
        if (func == 2 && rs1 == 0) add_str("sgtz ");
        if (func == 3 && rs1 == 0) add_str("snez ");
        if (func == 2 && rs2 == 0) add_str("sltz ");
        if (buf_pos > 0) {
            add_reg(rd);
            add_str(", ");
            add_reg(rs1 ? rs1 : rs2);
            return;
        }
        add_str(nm[func]);
        add_char(' ');
        add_reg(rd);
        add_str(", ");
        add_reg(rs1);
        add_str(", ");
        add_reg(rs2);
        return;
    }
    if ((instr & 0xfe00007f) == 0x40000033) {
        unsigned func = (instr >> 12) & 7;
        switch (func) {
        case 0:
            if (rs1 == 0) {
                add_str("neg ");
                add_reg(rd);
                add_str(", ");
                add_reg(rs2);
                return;
            }
            add_str("sub ");
            break;
        case 5:
            add_str("sra ");
            break;
        }
        if (buf_pos > 0) {
            add_reg(rd);
            add_str(", ");
            add_reg(rs1);
            add_str(", ");
            add_reg(rs2);
            return;
        }
    }
}

static void disassemble_rv_z(void) {
    unsigned rs1 = (instr >> 15) & 0x1f;
    unsigned rd = (instr >> 7) & 0x1f;
    unsigned func = (instr >> 12) & 7;
    if ((instr & 0x0000007f) == 0x0000000f && func == 1) {
        unsigned imm = instr >> 20;
        add_str("fence.i ");
        add_reg(rd);
        add_str(", ");
        add_reg(rs1);
        add_str(", 0x");
        add_hex_uint32(imm);
        return;
    }
    if ((instr & 0x0000007f) == 0x00000073) {
        const char * nms[4] = { NULL, "csrrw", "csrrs", "csrrc" };
        const char * nm = nms[func & 3];
        unsigned csr = instr >> 20;
        if (nm != NULL) {
            if (csr == 1) {
                if (rs1 == 0 && func == 2) {
                    add_str("frflags ");
                    add_reg(rd);
                    return;
                }
                if (func == 1) {
                    add_str("fsflags ");
                    if (rd != 0) {
                        add_reg(rd);
                        add_str(", ");
                    }
                    add_reg(rs1);
                    return;
                }
            }
            if (csr == 2) {
                if (rs1 == 0 && func == 2) {
                    add_str("frrm ");
                    add_reg(rd);
                    return;
                }
                if (func == 1) {
                    add_str("fsrm ");
                    if (rd != 0) {
                        add_reg(rd);
                        add_str(", ");
                    }
                    add_reg(rs1);
                    return;
                }
            }
            if (func == 2 && rs1 == 0) {
                add_str("csrr ");
                add_reg(rd);
                add_str(", ");
                add_reg_csr(csr);
                return;
            }
            if (rd == 0) {
                const char * nms[4] = { NULL, "csrw", "csrs", "csrc" };
                add_str(nms[func & 3]);
                if (func >= 4) add_char('i');
                add_char(' ');
            }
            else {
                add_str(nm);
                if (func >= 4) add_char('i');
                add_char(' ');
                add_reg(rd);
                add_str(", ");
            }
            add_reg_csr(csr);
            add_str(", ");
            if (func < 4) add_reg(rs1);
            else add_dec_uint32(rs1);
            return;
        }
    }
}

static void disassemble_rv32m(void) {
    unsigned rs2 = (instr >> 20) & 0x1f;
    unsigned rs1 = (instr >> 15) & 0x1f;
    unsigned rd = (instr >> 7) & 0x1f;
    unsigned func = (instr >> 12) & 7;
    if ((instr & 0xfe00007f) == 0x02000033) {
        switch (func) {
        case 0:
            add_str("mul ");
            break;
        case 1:
            add_str("mulh ");
            break;
        case 2:
            add_str("mulhsu ");
            break;
        case 3:
            add_str("mulhu ");
            break;
        case 4:
            add_str("div ");
            break;
        case 5:
            add_str("divu ");
            break;
        case 6:
            add_str("rem ");
            break;
        case 7:
            add_str("remu ");
            break;
        }
        add_reg(rd);
        add_str(", ");
        add_reg(rs1);
        add_str(", ");
        add_reg(rs2);
        return;
    }
}

static void disassemble_rv32f(void) {
    unsigned rs2 = (instr >> 20) & 0x1f;
    unsigned rs1 = (instr >> 15) & 0x1f;
    unsigned rd = (instr >> 7) & 0x1f;
    unsigned rm = (instr >> 12) & 0x7;
    if ((instr & 0x0000007f) == 0x00000007) {
        unsigned size = (instr >> 12) & 7;
        char sz_char = 0;
        switch (size) {
        case 2: sz_char = 'w'; break;
        case 3: sz_char = 'd'; break;
        case 4: sz_char = 'q'; break;
        }
        if (sz_char) {
            int32_t imm = get_imm_rse(20, 12);
            add_str("fl");
            add_char(sz_char);
            add_char(' ');
            add_freg(rd);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                add_dec_uint32(-imm);
            }
            else {
                add_dec_uint32(imm);
            }
            add_char('(');
            add_reg(rs1);
            add_char(')');
            return;
        }
    }
    if ((instr & 0x0000007f) == 0x00000027) {
        unsigned size = (instr >> 12) & 7;
        char sz_char = 0;
        switch (size) {
        case 2: sz_char = 'w'; break;
        case 3: sz_char = 'd'; break;
        case 4: sz_char = 'q'; break;
        }
        if (sz_char) {
            static const int imm_bits[32] = { 7, 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 31 };
            int32_t imm = get_imm_se(imm_bits);
            add_str("fs");
            add_char(sz_char);
            add_char(' ');
            add_freg(rs2);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                add_dec_uint32(-imm);
            }
            else {
                add_dec_uint32(imm);
            }
            add_char('(');
            add_reg(rs1);
            add_char(')');
            return;
        }
    }
    if ((instr & 0x00000073) == 0x00000043) {
        unsigned size = (instr >> 25) & 3;
        char sz_char = 0;
        switch (size) {
        case 0: sz_char = 's'; break;
        case 1: sz_char = 'd'; break;
        case 3: sz_char = 'q'; break;
        }
        if (sz_char) {
            const char * nm[4] = { "fmadd.", "fmsub.", "fnmsub.", "fnmadd." };
            add_str(nm[(instr >> 2) & 3]);
            add_char(sz_char);
            add_char(' ');
            add_freg(rd);
            add_str(", ");
            add_freg(rs1);
            add_str(", ");
            add_freg(rs2);
            add_str(", ");
            add_freg((instr >> 27) & 0x1f);
            add_str(", ");
            add_dec_uint32(rm);
            return;
        }
    }
    if ((instr & 0x0000007f) == 0x00000053) {
        unsigned size = (instr >> 25) & 3;
        char sz_char = 0;
        switch (size) {
        case 0: sz_char = 's'; break;
        case 1: sz_char = 'd'; break;
        case 3: sz_char = 'q'; break;
        }
        if (sz_char) {
            int no_rs2 = 0;
            int no_rm = 0;
            switch ((instr >> 27) & 0x1f) {
            case 0:
                add_str("fadd.");
                add_char(sz_char);
                break;
            case 1:
                add_str("fsub.");
                add_char(sz_char);
                break;
            case 2:
                add_str("fmul.");
                add_char(sz_char);
                break;
            case 3:
                add_str("fdiv.");
                add_char(sz_char);
                break;
            case 4:
                if (rs1 == rs2) {
                    if (rm == 0) add_str("fmv.");
                    if (rm == 1) add_str("fneg.");
                    if (rm == 2) add_str("fabs.");
                    if (buf_pos > 0) {
                        add_char(sz_char);
                        add_char(' ');
                        add_freg(rd);
                        add_str(", ");
                        add_freg(rs1);
                        return;
                    }
                }
                no_rm = 1;
                if (rm == 0) add_str("fsgnj.");
                if (rm == 1) add_str("fsgnjn.");
                if (rm == 2) add_str("fsgnjx.");
                if (buf_pos > 0) add_char(sz_char);
                break;
            case 5:
                no_rm = 1;
                if (rm == 0) add_str("fmin.");
                if (rm == 1) add_str("fmax.");
                if (buf_pos > 0) add_char(sz_char);
                break;
            case 8:
                no_rs2 = 1;
                if (rs2 == 0 && size == 1) add_str("fcvt.d.s");
                if (rs2 == 1 && size == 0) add_str("fcvt.s.d");
                if (buf_pos > 0) {
                    add_char(' ');
                    add_freg(rd);
                    add_str(", ");
                    add_freg(rs1);
                    if (rs2 == 0 && size == 1) return;
                    add_rm(rm);
                    return;
                }
                break;
            case 11:
                no_rs2 = 1;
                if (rs2 == 0) add_str("fsqrt.");
                if (buf_pos > 0) add_char(sz_char);
                break;
            case 20:
                no_rm = 1;
                if (rm == 0) add_str("fle.");
                if (rm == 1) add_str("flt.");
                if (rm == 2) add_str("feq.");
                if (buf_pos > 0) {
                    add_char(sz_char);
                    add_char(' ');
                    add_reg(rd);
                    add_str(", ");
                    add_freg(rs1);
                    add_str(", ");
                    add_freg(rs2);
                    return;
                }
                break;
            case 24:
                no_rs2 = 1;
                if (rs2 == 0) add_str("fcvt.w.");
                if (rs2 == 1) add_str("fcvt.wu.");
                if (buf_pos > 0) {
                    add_char(sz_char);
                    add_char(' ');
                    add_freg(rd);
                    add_str(", ");
                    add_reg(rs1);
                    add_rm(rm);
                    return;
                }
                break;
            case 26:
                no_rs2 = 1;
                if (rs2 == 0 || rs2 == 1) {
                    add_str("fcvt.");
                    add_char(sz_char);
                    add_char('.');
                    add_char('w');
                    if (rs2 == 1) add_char('u');
                    add_reg(rd);
                    add_str(", ");
                    add_freg(rs1);
                    add_rm(rm);
                    return;
                }
                break;
            case 28:
                no_rm = 1;
                no_rs2 = 1;
                if (rs2 == 0) {
                    if (rm == 0) {
                        add_str("fmv.x.");
                        add_char(sz_char);
                        add_char(' ');
                        add_reg(rd);
                        add_str(", ");
                        add_freg(rs1);
                        return;
                    }
                    if (rm == 1) add_str("fclass.");
                    if (buf_pos > 0) add_char(sz_char);
                }
                break;
            case 30:
                no_rm = 1;
                no_rs2 = 1;
                if (rs2 == 0 && rm == 0 && size == 0) {
                    add_str("fmv.w.x ");
                    add_freg(rd);
                    add_str(", ");
                    add_reg(rs1);
                    return;
                }
                break;
            }
            if (buf_pos > 0) {
                add_char(' ');
                add_freg(rd);
                add_str(", ");
                add_freg(rs1);
                if (!no_rs2) {
                    add_str(", ");
                    add_freg(rs2);
                }
                if (!no_rm) {
                    add_rm(rm);
                }
                return;
            }
        }
    }
}

static void disassemble_rv64i(void) {
    unsigned rs2 = (instr >> 20) & 0x1f;
    unsigned rs1 = (instr >> 15) & 0x1f;
    unsigned rd = (instr >> 7) & 0x1f;
    unsigned func = (instr >> 12) & 7;
    if ((instr & 0x0000007f) == 0x00000003) {
        int32_t imm = get_imm_rse(20, 12);
        switch (func) {
        case 6:
            add_str("lwu ");
            break;
        case 3:
            add_str("ld ");
            break;
        }
        if (buf_pos > 0) {
            add_reg((instr >> 7) & 0x1f);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                add_dec_uint32(-imm);
            }
            else {
                add_dec_uint32(imm);
            }
            add_char('(');
            add_reg(rs1);
            add_char(')');
            return;
        }
    }
    if ((instr & 0x0000307f) == 0x00003023) {
        static const int imm_bits[32] = { 7, 8, 9, 10, 11, 25, 26, 27, 28, 29, 30, 31 };
        int32_t imm = get_imm_se(imm_bits);
        add_str("sd ");
        add_reg((instr >> 20) & 0x1f);
        add_str(", ");
        if (imm < 0) {
            add_char('-');
            add_dec_uint32(-imm);
        }
        else {
            add_dec_uint32(imm);
        }
        add_char('(');
        add_reg(rs1);
        add_char(')');
        return;
    }
    if ((instr & 0xbc00007f) == 0x00000013) {
        unsigned rs = rs1;
        unsigned rd = (instr >> 7) & 0x1f;
        uint32_t imm = (instr >> 20) & 0x3f;
        switch (func) {
        case 1:
            add_str("slli ");
            break;
        case 5:
            add_str(instr & (1 << 30) ? "srai " : "srli ");
            break;
        }
        if (buf_pos > 0) {
            add_reg(rd);
            add_str(", ");
            add_reg(rs);
            add_str(", 0x");
            add_hex_uint32(imm);
            return;
        }
    }
    if ((instr & 0x0000707f) == 0x0000001b) {
        unsigned rd = (instr >> 7) & 0x1f;
        int32_t imm = get_imm_rse(20, 12);
        if (imm == 0) {
            add_str("sext.w ");
            add_reg(rd);
            add_str(", ");
            add_reg(rs1);
            return;

        }
        add_str("addiw ");
        add_reg(rd);
        add_str(", ");
        add_reg(rs1);
        add_str(", ");
        if (imm < 0) {
            add_char('-');
            imm = -imm;
        }
        add_dec_uint32(imm);
        return;
    }
    if ((instr & 0xbe00007f) == 0x0000001b) {
        unsigned rd = (instr >> 7) & 0x1f;
        uint32_t imm = (instr >> 20) & 0x1f;
        switch (func) {
        case 1:
            add_str(instr & (1 << 30) ? "" : "slliw ");
            break;
        case 5:
            add_str(instr & (1 << 30) ? "sraiw " : "srliw ");
            break;
        }
        if (buf_pos > 0) {
            add_reg(rd);
            add_str(", ");
            add_reg(rs1);
            add_str(", 0x");
            add_hex_uint32(imm);
            return;
        }
    }
    if ((instr & 0xbe00007f) == 0x0000003b) {
        switch (func) {
        case 0:
            if (rs1 == 0 && (instr & (1 << 30)) != 0) {
                add_str("negw ");
                add_reg(rd);
                add_str(", ");
                add_reg(rs2);
                return;
            }
            add_str(instr & (1 << 30) ? "subw " : "addw ");
            break;
        case 1:
            add_str(instr & (1 << 30) ? "" : "sllw ");
            break;
        case 5:
            add_str(instr & (1 << 30) ? "sraw " : "srlw ");
            break;
        }
        if (buf_pos > 0) {
            add_reg(rd);
            add_str(", ");
            add_reg(rs1);
            add_str(", ");
            add_reg(rs2);
            return;
        }
    }
    disassemble_rv32i();
}

static void disassemble_rv64m(void) {
    unsigned func = (instr >> 12) & 7;
    if ((instr & 0xfe00007f) == 0x0200003b) {
        unsigned rs2 = (instr >> 20) & 0x1f;
        unsigned rs1 = (instr >> 15) & 0x1f;
        unsigned rd = (instr >> 7) & 0x1f;
        switch (func) {
        case 0:
            add_str("mulw ");
            break;
        case 4:
            add_str("divw ");
            break;
        case 5:
            add_str("divuw ");
            break;
        case 6:
            add_str("remw ");
            break;
        case 7:
            add_str("remuw ");
            break;
        }
        if (buf_pos > 0) {
            add_reg(rd);
            add_str(", ");
            add_reg(rs1);
            add_str(", ");
            add_reg(rs2);
            return;
        }
    }
    disassemble_rv32m();
}

static void disassemble_rv64f(void) {
    if ((instr & 0x0000007f) == 0x00000053) {
        unsigned size = (instr >> 25) & 3;
        char sz_char = 0;
        switch (size) {
        case 0: sz_char = 's'; break;
        case 1: sz_char = 'd'; break;
        case 3: sz_char = 'q'; break;
        }
        if (sz_char) {
            unsigned rs2 = (instr >> 20) & 0x1f;
            unsigned rs1 = (instr >> 15) & 0x1f;
            unsigned rd = (instr >> 7) & 0x1f;
            unsigned rm = (instr >> 12) & 0x7;
            switch ((instr >> 27) & 0x1f) {
            case 24:
                if (rs2 == 2) add_str("fcvt.l.");
                if (rs2 == 3) add_str("fcvt.lu.");
                if (buf_pos > 0) {
                    add_char(sz_char);
                    add_char(' ');
                    add_reg(rd);
                    add_str(", ");
                    add_freg(rs1);
                    add_rm(rm);
                    return;
                }
                break;
            case 26:
                if (rs2 == 2 || rs2 == 3) {
                    add_str("fcvt.");
                    add_char(sz_char);
                    add_char('.');
                    add_char('l');
                    if (rs2 == 3) add_char('u');
                    add_char(' ');
                    add_freg(rd);
                    add_str(", ");
                    add_reg(rs1);
                    add_rm(rm);
                    return;
                }
                break;
            case 30:
                if (rs2 == 0 && rm == 0 && size == 1) {
                    add_str("fmv.d.x ");
                    add_freg(rd);
                    add_str(", ");
                    add_reg(rs1);
                    return;
                }
                break;
            }
        }
    }
    disassemble_rv32f();
}

static void disassemble_rv32c(void) {
    // Quadrant 0
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
    if ((instr & 0x6003) == 0x2000) {
        add_str(instr & 0x8000 ? "fsd " : "fld ");
        add_rvc_freg((instr >> 2) & 0x7);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_d) * 8);
        add_str("(");
        add_rvc_reg((instr >> 7) & 0x7);
        add_str(")");
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
        add_rvc_freg((instr >> 2) & 0x7);
        add_str(", ");
        add_dec_uint32(get_imm(imm_bits_w) * 4);
        add_str("(");
        add_rvc_reg((instr >> 7) & 0x7);
        add_str(")");
        return;
    }

    // Quadrant 1
    if ((instr & 0xef83) == 0x0001) {
        add_str("nop");
        return;
    }
    if ((instr & 0xe003) == 0x0001) {
        int32_t imm = get_imm_se(imm_bits_shift);
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            add_str("addi ");
            add_reg(rd);
            add_str(", ");
            add_reg(rd);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                imm = -imm;
            }
            add_dec_uint32(imm);
            return;
        }
    }
    if ((instr & 0x6003) == 0x2001) {
        static const int imm_bits[32] = { 3, 4, 5, 11, 2, 7, 6, 9, 10, 8, 12 };
        int32_t imm = get_imm_se(imm_bits);
        if (instr & 0x8000) {
            add_str("j ");
        }
        else {
            add_str("jal ");
            add_reg(1);
            add_str(", ");
        }
        if (imm < 0) {
            add_char('-');
            add_dec_uint32(-imm);
        }
        else {
            add_char('+');
            add_dec_uint32(imm);
        }
        add_addr(instr_addr + ((int64_t)imm << 1));
        return;
    }
    if ((instr & 0xe003) == 0x4001) {
        int32_t imm = get_imm_se(imm_bits_shift);
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            add_str("li ");
            add_reg(rd);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                imm = -imm;
            }
            add_dec_uint32(imm);
            return;
        }
    }
    if ((instr & 0xe003) == 0x6001) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd == 2) {
            static const int imm_bits[32] = { 6, 2, 5, 3, 4, 12 };
            int32_t imm = get_imm_se(imm_bits);
            if (imm != 0) {
                add_str("addi sp, sp, ");
                if (imm < 0) {
                    add_char('-');
                    imm = -imm;
                }
                add_dec_uint32(imm << 4);
                return;
            }
        }
        if (rd != 0) {
            int32_t imm = get_imm_se(imm_bits_shift);
            if (imm != 0) {
                add_str("lui ");
                add_reg(rd);
                add_str(", 0x");
                add_hex_uint32(imm & 0xfffff);
                return;
            }
        }
    }
    if ((instr & 0xe003) == 0x8001) {
        unsigned rd = (instr >> 7) & 0x7;
        unsigned func = (instr >> 10) & 3;
        if (func < 2) {
            uint32_t imm = get_imm(imm_bits_shift);
            if (xlen == 32 && imm >= 32) return;
            if (imm == 0) {
                if (xlen == 128) imm = 64;
                else return;
            }
            switch (func) {
            case 0:
                add_str("srli ");
                break;
            case 1:
                add_str("srai ");
                break;
            }
            add_rvc_reg(rd);
            add_str(", ");
            add_rvc_reg(rd);
            add_str(", 0x");
            add_hex_uint32(imm);
        }
        else if (func == 2) {
            int32_t imm = get_imm_se(imm_bits_shift);
            add_str("andi ");
            add_rvc_reg(rd);
            add_str(", ");
            add_rvc_reg(rd);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                imm = -imm;
            }
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
    if ((instr & 0xc003) == 0xc001) {
        static const int imm_bits[32] = { 3, 4, 10, 11, 2, 5, 6, 12 };
        int32_t imm = get_imm_se(imm_bits);
        add_str(instr & 0x2000 ? "bnez " : "beqz ");
        add_rvc_reg((instr >> 7) & 7);
        add_str(", ");
        if (imm < 0) {
            add_char('-');
            add_dec_uint32(-imm);
        }
        else {
            add_char('+');
            add_dec_uint32(imm);
        }
        add_addr(instr_addr + ((int64_t)imm << 1));
        return;
    }

    // Quadrant 2
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
        add_dec_uint32(get_imm(imm_bits_ld_sp) * 8);
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
    if ((instr & 0xe003) == 0x0002) {
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            uint32_t imm = get_imm(imm_bits_shift);
            if (xlen == 32 && imm >= 32) return;
            if (imm == 0) {
                if (xlen == 128) imm = 64;
                else return;
            }
            add_str("slli ");
            add_reg(rd);
            add_str(", ");
            add_reg(rd);
            add_str(", 0x");
            add_hex_uint32(imm);
            return;
        }
    }
    if ((instr & 0xe003) == 0x8002) {
        unsigned rd = (instr >> 7) & 0x1f;
        unsigned rs = (instr >> 2) & 0x1f;
        if ((instr & (1 << 12)) == 0) {
            if (rd == 0) return;
            if (rs == 0) {
                if (rd == 1) {
                    add_str("ret");
                    return;
                }
                add_str("jr ");
                add_reg(rd);
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
                add_reg(rd);
                return;
            }
            add_str("add ");
            add_reg(rd);
            add_str(", ");
        }
        add_reg(rd);
        add_str(", ");
        add_reg(rs);
        return;
    }
}

static void disassemble_rv64c(void) {
    if ((instr & 0xe003) == 0x2001) {
        int32_t imm = get_imm_se(imm_bits_shift);
        unsigned rd = (instr >> 7) & 0x1f;
        if (rd != 0) {
            if (imm == 0) {
                add_str("sext.w ");
                add_reg(rd);
                add_str(", ");
                add_reg(rd);
                return;
            }
            add_str("addiw ");
            add_reg(rd);
            add_str(", ");
            add_reg(rd);
            add_str(", ");
            if (imm < 0) {
                add_char('-');
                imm = -imm;
            }
            add_dec_uint32(imm);
            return;
        }
    }
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

static void disassemble_rv32(void) {
    disassemble_rv32i();
    disassemble_rv32m();
    disassemble_rv32f();
    disassemble_rv_z();
}

static void disassemble_rv64(void) {
    disassemble_rv64i();
    disassemble_rv64m();
    disassemble_rv64f();
    disassemble_rv_z();
}

static void disassemble_rv128(void) {
    disassemble_rv64();
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
        if (xlen == 32) disassemble_rv32();
        if (xlen == 64) disassemble_rv64();
        if (xlen == 128) disassemble_rv128();
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
