/*******************************************************************************
 * Copyright (c) 2015-2020 Xilinx, Inc. and others.
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
#include <machine/x86_64/tcf/disassembler-x86_64.h>

#define MODE_16     0
#define MODE_32     1
#define MODE_64     2

#define PREFIX_LOCK         0x0001
#define PREFIX_REPNZ        0x0002
#define PREFIX_REPZ         0x0004
#define PREFIX_CS           0x0008 /* Also "Branch not taken" hint */
#define PREFIX_SS           0x0010
#define PREFIX_DS           0x0020 /* Also "Branch taken" hint */
#define PREFIX_ES           0x0040
#define PREFIX_FS           0x0080
#define PREFIX_GS           0x0100
#define PREFIX_DATA_SIZE    0x0200
#define PREFIX_ADDR_SIZE    0x0400

#define REX_W               0x08
#define REX_R               0x04
#define REX_X               0x02
#define REX_B               0x01

#define REG_SIZE_ST         10
#define REG_SIZE_MMX        11
#define REG_SIZE_XMM        12
#define REG_SIZE_YMM        13
#define REG_SIZE_SEG        14
#define REG_SIZE_CR         15
#define REG_SIZE_DR         16

static char buf[128];
static size_t buf_pos = 0;
static DisassemblerParams * params = NULL;
static uint64_t instr_addr = 0;
static uint8_t * code_buf = NULL;
static size_t code_pos = 0;
static size_t code_len = 0;
static uint32_t prefix = 0;
static uint32_t vex = 0;
static uint8_t rex = 0;
static unsigned data_size = 0;
static unsigned addr_size = 0;
static int x86_mode = 0;

static uint8_t get_code(void) {
    uint8_t c = 0;
    if (code_pos < code_len) c = code_buf[code_pos];
    code_pos++;
    return c;
}

static void add_char(char ch) {
    if (buf_pos >= sizeof(buf) - 1) return;
    buf[buf_pos++] = ch;
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

#if 0 /* Not used yet */
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

#if 0 /* Not used yet */
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

static void add_reg(unsigned reg, unsigned size) {
    switch (size) {
    case REG_SIZE_ST:
        add_str("st");
        add_dec_uint32(reg & 7);
        return;
    case REG_SIZE_MMX:
        add_str("mmx");
        add_dec_uint32(reg & 7);
        return;
    case REG_SIZE_XMM:
        add_str("xmm");
        add_dec_uint32(reg);
        return;
    case REG_SIZE_YMM:
        add_str("ymm");
        add_dec_uint32(reg);
        return;
    case REG_SIZE_SEG:
        switch (reg & 7) {
        case 0: add_str("es"); break;
        case 1: add_str("cs"); break;
        case 2: add_str("ss"); break;
        case 3: add_str("ds"); break;
        case 4: add_str("fs"); break;
        case 5: add_str("gs"); break;
        case 6: add_str("s6"); break;
        case 7: add_str("s7"); break;
        }
        return;
    case REG_SIZE_CR:
        add_str("cr");
        add_dec_uint32(reg);
        return;
    case REG_SIZE_DR:
        add_str("dr");
        add_dec_uint32(reg);
        return;
    }
    assert(size <= 8);
    if (reg >= 8) {
        add_char('r');
        add_dec_uint32(reg);
        switch (size) {
        case 1: add_char('l'); break;
        case 2: add_char('w'); break;
        case 4: add_char('d'); break;
        }
        return;
    }
    if (rex && size == 1 && reg >= 4 && reg <= 7) {
        switch (reg) {
        case 4: add_str("spl"); break;
        case 5: add_str("bpl"); break;
        case 6: add_str("sil"); break;
        case 7: add_str("dil"); break;
        }
        return;
    }
    if (size == 1) {
        switch (reg) {
        case 0: add_str("al"); break;
        case 1: add_str("cl"); break;
        case 2: add_str("dl"); break;
        case 3: add_str("bl"); break;
        case 4: add_str("ah"); break;
        case 5: add_str("ch"); break;
        case 6: add_str("dh"); break;
        case 7: add_str("bh"); break;
        }
    }
    else {
        switch (size) {
        case 4: add_char('e'); break;
        case 8: add_char('r'); break;
        }
        switch (reg) {
        case 0: add_str("ax"); break;
        case 1: add_str("cx"); break;
        case 2: add_str("dx"); break;
        case 3: add_str("bx"); break;
        case 4: add_str("sp"); break;
        case 5: add_str("bp"); break;
        case 6: add_str("si"); break;
        case 7: add_str("di"); break;
        }
    }
}

static void add_ttt(unsigned ttt) {
    switch (ttt) {
    case  0: add_str("o"); break;
    case  1: add_str("no"); break;
    case  2: add_str("b"); break;
    case  3: add_str("ae"); break;
    case  4: add_str("e"); break;
    case  5: add_str("ne"); break;
    case  6: add_str("be"); break;
    case  7: add_str("a"); break;
    case  8: add_str("s"); break;
    case  9: add_str("ns"); break;
    case 10: add_str("pe"); break;
    case 11: add_str("po"); break;
    case 12: add_str("l"); break;
    case 13: add_str("ge"); break;
    case 14: add_str("le"); break;
    case 15: add_str("g"); break;
    }
}

static void add_disp8(void) {
    uint32_t disp = get_code();
    if (disp < 0x80) {
        add_char('+');
    }
    else {
        add_char('-');
        disp = (disp ^ 0xff) + 1;
    }
    add_str("0x");
    add_hex_uint32(disp);
}

static void add_disp16(void) {
    uint32_t disp = get_code();
    disp |= (uint32_t)get_code() << 8;
    add_str("0x");
    add_hex_uint32(disp);
}

static void add_disp32(void) {
    uint32_t disp = get_code();
    disp |= (uint32_t)get_code() << 8;
    disp |= (uint32_t)get_code() << 16;
    disp |= (uint32_t)get_code() << 24;
    add_str("0x");
    add_hex_uint32(disp);
}

static void add_imm8(void) {
    uint32_t imm = get_code();
    add_str("0x");
    add_hex_uint32(imm);
}

static void add_imm16(void) {
    uint32_t imm = get_code();
    imm |= (uint32_t)get_code() << 8;
    add_str("0x");
    add_hex_uint32(imm);
}

static void add_imm32(void) {
    uint32_t imm = get_code();
    imm |= (uint32_t)get_code() << 8;
    imm |= (uint32_t)get_code() << 16;
    imm |= (uint32_t)get_code() << 24;
    add_str("0x");
    add_hex_uint32(imm);
}

#if 0 /* Not used yet */
static void add_imm64(void) {
    uint64_t imm = get_code();
    imm |= (uint64_t)get_code() << 8;
    imm |= (uint64_t)get_code() << 16;
    imm |= (uint64_t)get_code() << 24;
    imm |= (uint64_t)get_code() << 32;
    imm |= (uint64_t)get_code() << 40;
    imm |= (uint64_t)get_code() << 48;
    imm |= (uint64_t)get_code() << 56;
    add_str("0x");
    add_hex_uint64(imm);
}
#endif

static void add_moffs(int wide) {
    uint64_t addr = 0;
    unsigned i = 0;

    while (i < addr_size) {
        addr |= (uint64_t)get_code() << (i * 8);
        i++;
    }

    add_str("[0x");
    add_hex_uint64(addr);
    add_char(']');
}

static void add_rel(unsigned size) {
    uint64_t offs = 0;
    uint64_t sign = (uint64_t)1 << (size * 8 - 1);
    uint64_t mask = sign - 1;
    unsigned i = 0;

    while (i < size) {
        offs |= (uint64_t)get_code() << (i * 8);
        i++;
    }

    if (offs & sign) {
        offs = (offs ^ (sign | mask)) + 1;
        add_str("-0x");
        add_hex_uint64(offs);
        add_addr(instr_addr + code_pos - offs);
    }
    else {
        add_str("+0x");
        add_hex_uint64(offs);
        add_addr(instr_addr + code_pos + offs);
    }
}

static void add_modrm_reg(unsigned modrm, unsigned size) {
    unsigned rm = (modrm >> 3) & 7;
    if (rex & REX_R) rm += 8;
    add_reg(rm, size);
}

static void add_modrm_mem(unsigned modrm, unsigned size) {
    unsigned mod = (modrm >> 6) & 3;
    unsigned rm = modrm & 7;
    if (mod == 3) {
        if (rex & REX_B) rm += 8;
        add_reg(rm, size);
    }
    else {
        switch (size) {
        case 1: add_str("byte"); break;
        case 2: add_str("word"); break;
        case 4: add_str("dword"); break;
        case 8: add_str("qword"); break;
        case REG_SIZE_MMX: add_str("qword"); break;
        case REG_SIZE_XMM: add_str("dqword"); break;
        case REG_SIZE_YMM: add_str("qqword"); break;
        }
        add_char('[');
        if (prefix & PREFIX_CS) add_str("cs:");
        if (prefix & PREFIX_SS) add_str("ss:");
        if (prefix & PREFIX_DS) add_str("ds:");
        if (prefix & PREFIX_ES) add_str("es:");
        if (prefix & PREFIX_FS) add_str("fs:");
        if (prefix & PREFIX_GS) add_str("gs:");
        if (addr_size < 4) {
            switch (rm) {
            case 0: add_str("bx+si"); break;
            case 1: add_str("bx+di"); break;
            case 2: add_str("bp+si"); break;
            case 3: add_str("bp+di"); break;
            case 4: add_str("si"); break;
            case 5: add_str("di"); break;
            case 6: if (mod != 0) add_str("bp"); break;
            case 7: add_str("bx"); break;
            }
        }
        else {
            if (rm == 5 && mod == 0) {
                if (x86_mode == MODE_64) {
                    add_str(addr_size > 4 ? "rip" : "eip");
                    add_char('+');
                }
            }
            else if (rm == 4) {
                uint8_t sib = get_code();
                unsigned base = sib & 7;
                unsigned index = (sib >> 3) & 7;
                unsigned scale = (sib >> 6) & 3;
                int bs = 0;
                if (base != 5 || mod == 1 || mod == 2) {
                    if (rex & REX_B) add_reg(base + 8, addr_size);
                    else add_reg(base, addr_size);
                    bs = 1;
                }
                if (index != 4 || (rex & REX_X) != 0) {
                    if (bs) add_char('+');
                    if (rex & REX_X) add_reg(index + 8, addr_size);
                    else add_reg(index, addr_size);
                    switch (scale) {
                    case 1: add_str("*2"); break;
                    case 2: add_str("*4"); break;
                    case 3: add_str("*8"); break;
                    }
                    bs = 1;
                }
                if (base == 5) {
                    if (mod == 0 || mod == 2) {
                        if (bs) add_char('+');
                        add_disp32();
                    }
                    else if (mod == 1) {
                        add_disp8();
                    }
                }
            }
            else {
                if (rex & REX_B) rm += 8;
                add_reg(rm, addr_size);
            }
        }
        switch (mod) {
        case 0:
            if (addr_size == 2 && rm == 6) add_disp16();
            if (addr_size == 4 && rm == 5) add_disp32();
            if (addr_size == 8 && rm == 5) add_disp32();
            break;
        case 1:
            add_disp8();
            break;
        case 2:
            add_char('+');
            if (addr_size <= 2) add_disp16();
            else add_disp32();
            break;
        }
        add_char(']');
    }
}

static void add_modrm(unsigned reg_size, unsigned mem_size, int swap) {
    unsigned modrm = get_code();
    if (swap) {
        add_modrm_mem(modrm, mem_size);
        add_char(',');
        add_modrm_reg(modrm, reg_size);
    }
    else {
        add_modrm_reg(modrm, reg_size);
        add_char(',');
        add_modrm_mem(modrm, mem_size);
    }
}

static void add_a_op(unsigned op) {
    switch (op) {
    case 0: add_str("add "); break;
    case 1: add_str("or "); break;
    case 2: add_str("adc "); break;
    case 3: add_str("sbb "); break;
    case 4: add_str("and "); break;
    case 5: add_str("sub "); break;
    case 6: add_str("xor "); break;
    case 7: add_str("cmp "); break;
    }
}

static int shift_op(unsigned op) {
    switch (op) {
    case 0: add_str("rol "); return 1;
    case 1: add_str("ror "); return 1;
    case 2: add_str("rcl "); return 1;
    case 3: add_str("rcr "); return 1;
    case 4: add_str("shl "); return 1;
    case 5: add_str("shr "); return 1;
    case 7: add_str("sar "); return 1;
    }
    return 0;
}

static void disassemble_0f(void) {
    uint8_t opcode = get_code();
    uint8_t modrm = 0;

    switch (opcode) {
    case 0x1f:
        modrm = get_code();
        add_str("nop ");
        add_modrm_mem(modrm, data_size);
        return;
    case 0x28:
    case 0x29:
        add_str("mov");
        if (prefix & PREFIX_DATA_SIZE) {
            add_str("apd ");
            add_modrm(REG_SIZE_YMM, REG_SIZE_YMM, (opcode & 1) != 0);
            return;
        }
        add_str("aps ");
        add_modrm(REG_SIZE_XMM, REG_SIZE_XMM, 0);
        return;
    case 0x2a:
        add_str("cvtsi2");
        if (prefix & PREFIX_DATA_SIZE) {
            add_str("pd ");
            add_modrm(REG_SIZE_YMM, 4, 0);
            return;
        }
        if (prefix & PREFIX_REPNZ) {
            add_str("sd ");
            add_modrm(REG_SIZE_YMM, 8, 0);
            return;
        }
        if (prefix & PREFIX_REPZ) {
            add_str("ss ");
            add_modrm(REG_SIZE_XMM, 8, 0);
            return;
        }
        add_str("ps ");
        add_modrm(REG_SIZE_MMX, 4, 0);
        return;
    case 0x2e:
    case 0x2f:
        switch (opcode) {
        case 0x2e: add_str("ucomi"); break;
        case 0x2f: add_str("comi"); break;
        }
        if (prefix & PREFIX_DATA_SIZE) {
            add_str("sd ");
            add_modrm(REG_SIZE_XMM, REG_SIZE_XMM, 0);
            return;
        }
        add_str("ss ");
        add_modrm(REG_SIZE_MMX, REG_SIZE_MMX, 0);
        return;
    case 0x38:
        switch (get_code()) {
        case 0xf6:
            if (prefix & PREFIX_DATA_SIZE) {
                add_str("adcx ");
                add_modrm(data_size, 1, 0);
                return;
            }
            break;
        }
        break;
    case 0x51:
    case 0x58:
    case 0x59:
    case 0x5c:
    case 0x5d:
    case 0x5e:
    case 0x5f:
        switch (opcode) {
        case 0x51: add_str("sqrt"); break;
        case 0x58: add_str("add"); break;
        case 0x59: add_str("mul"); break;
        case 0x5c: add_str("sub"); break;
        case 0x5d: add_str("min"); break;
        case 0x5e: add_str("div"); break;
        case 0x5f: add_str("max"); break;
        }
        if (prefix & PREFIX_DATA_SIZE) {
            add_str("pd ");
            add_modrm(REG_SIZE_YMM, 4, 0);
            return;
        }
        if (prefix & PREFIX_REPNZ) {
            add_str("sd ");
            add_modrm(REG_SIZE_YMM, 8, 0);
            return;
        }
        if (prefix & PREFIX_REPZ) {
            add_str("ss ");
            add_modrm(REG_SIZE_XMM, 8, 0);
            return;
        }
        add_str("ps ");
        add_modrm(REG_SIZE_MMX, 4, 0);
        return;
    case 0x6f:
    case 0x7f:
        add_str("mov");
        if (prefix & PREFIX_DATA_SIZE) {
            add_str("dqa ");
            add_modrm(REG_SIZE_XMM, REG_SIZE_XMM, (opcode & 0x10) != 0);
            return;
        }
        if (prefix & PREFIX_REPZ) {
            add_str("dqu ");
            add_modrm(REG_SIZE_XMM, REG_SIZE_XMM, (opcode & 0x10) != 0);
            return;
        }
        add_str("q ");
        add_modrm(REG_SIZE_MMX, REG_SIZE_MMX, (opcode & 0x10) != 0);
        return;
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
    case 0x88:
    case 0x89:
    case 0x8a:
    case 0x8b:
    case 0x8c:
    case 0x8d:
    case 0x8e:
    case 0x8f:
        add_char('j');
        add_ttt(opcode & 0xf);
        add_char(' ');
        add_rel(4);
        return;
    case 0x90:
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97:
    case 0x98:
    case 0x99:
    case 0x9a:
    case 0x9b:
    case 0x9c:
    case 0x9d:
    case 0x9e:
    case 0x9f:
        modrm = get_code();
        add_str("set");
        add_ttt(opcode  & 0xf);
        add_char(' ');
        add_modrm_mem(modrm, 1);
        return;
    case 0xa0:
        add_str("push fs");
        return;
    case 0xa1:
        add_str("pop fs");
        return;
    case 0xa4:
        add_str("shld ");
        add_modrm(data_size, data_size, 1);
        add_char(',');
        add_imm8();
        return;
    case 0xa5:
        add_str("shld ");
        add_modrm(data_size, data_size, 1);
        add_str(",cl");
        return;
    case 0xa8:
        add_str("push gs");
        return;
    case 0xa9:
        add_str("pop gs");
        return;
    case 0xb6:
        add_str("movzx ");
        add_modrm(data_size, 1, 0);
        return;
    case 0xb7:
        add_str("movzx ");
        add_modrm(data_size, 2, 0);
        return;
    case 0xbe:
        add_str("movsx ");
        add_modrm(data_size, 1, 0);
        return;
    case 0xbf:
        add_str("movsx ");
        add_modrm(data_size, 2, 0);
        return;
    case 0xef:
        add_str("pxor ");
        if (prefix & PREFIX_DATA_SIZE) {
            add_modrm(REG_SIZE_XMM, REG_SIZE_XMM, 0);
            return;
        }
        add_modrm(REG_SIZE_MMX, REG_SIZE_MMX, 0);
        return;
    }

    buf_pos = 0;
}

static void disassemble_cmps(unsigned reg_size, unsigned mem_size) {
    if (prefix & PREFIX_REPNZ) add_str("repnz ");
    if (prefix & PREFIX_REPZ) add_str("repz ");
    add_str("cmps ");
    switch (mem_size) {
    case 1: add_str("byte"); break;
    case 2: add_str("word"); break;
    case 4: add_str("dword"); break;
    case 8: add_str("qword"); break;
    }
    add_char('[');
    if (prefix & PREFIX_CS) add_str("cs:");
    else if (prefix & PREFIX_SS) add_str("ss:");
    else if (prefix & PREFIX_DS) add_str("ds:");
    else if (prefix & PREFIX_ES) add_str("es:");
    else if (prefix & PREFIX_FS) add_str("fs:");
    else if (prefix & PREFIX_GS) add_str("gs:");
    else add_str("ds:");
    add_reg(6, reg_size);
    add_str("],");
    switch (mem_size) {
    case 1: add_str("byte"); break;
    case 2: add_str("word"); break;
    case 4: add_str("dword"); break;
    case 8: add_str("qword"); break;
    }
    add_str("[es:");
    add_reg(7, reg_size);
    add_char(']');
}

static void disassemble_instr(void) {
    uint8_t opcode = 0;
    uint8_t modrm = 0;
    uint8_t imm = 0;

    opcode = get_code();
    switch (opcode) {
    case 0x00:
    case 0x08:
    case 0x10:
    case 0x18:
    case 0x20:
    case 0x28:
    case 0x30:
    case 0x38:
        add_a_op((opcode >> 3) & 7);
        add_modrm(1, 1, 1);
        return;
    case 0x01:
    case 0x09:
    case 0x11:
    case 0x19:
    case 0x21:
    case 0x29:
    case 0x31:
    case 0x39:
        add_a_op((opcode >> 3) & 7);
        add_modrm(data_size, data_size, 1);
        return;
    case 0x02:
    case 0x0a:
    case 0x12:
    case 0x1a:
    case 0x22:
    case 0x2a:
    case 0x32:
    case 0x3a:
        add_a_op((opcode >> 3) & 7);
        add_modrm(1, 1, 0);
        return;
    case 0x03:
    case 0x0b:
    case 0x13:
    case 0x1b:
    case 0x23:
    case 0x2b:
    case 0x33:
    case 0x3b:
        add_a_op((opcode >> 3) & 7);
        add_modrm(data_size, data_size, 0);
        return;
    case 0x04:
    case 0x0c:
    case 0x14:
    case 0x1c:
    case 0x24:
    case 0x2c:
    case 0x34:
    case 0x3c:
        add_a_op((opcode >> 3) & 7);
        add_str("al,");
        add_imm8();
        return;
    case 0x05:
    case 0x0d:
    case 0x15:
    case 0x1d:
    case 0x25:
    case 0x2d:
    case 0x35:
    case 0x3d:
        add_a_op((opcode >> 3) & 7);
        add_reg(0, data_size);
        add_char(',');
        if (data_size <= 2) add_imm16();
        else add_imm32();
        return;
    case 0x06:
        add_str("push es");
        return;
    case 0x07:
        add_str("pop es");
        return;
    case 0x0e:
        add_str("push cs");
        return;
    case 0x0f:
        disassemble_0f();
        return;
    case 0x16:
        add_str("push ss");
        return;
    case 0x17:
        add_str("pop ss");
        return;
    case 0x1e:
        add_str("push ds");
        return;
    case 0x1f:
        add_str("pop ds");
        return;
    case 0x37:
        add_str("aaa");
        return;
    case 0x3f:
        add_str("aas");
        return;
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
        add_str("inc ");
        add_reg(opcode & 7, data_size);
        return;
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
    case 0x4e:
    case 0x4f:
        add_str("dec ");
        add_reg(opcode & 7, data_size);
        return;
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57:
        add_str("push ");
        if (rex & REX_B) add_reg((opcode & 7) + 8, addr_size);
        else add_reg(opcode & 7, addr_size);
        return;
    case 0x58:
    case 0x59:
    case 0x5a:
    case 0x5b:
    case 0x5c:
    case 0x5d:
    case 0x5e:
    case 0x5f:
        add_str("pop ");
        if (rex & REX_B) add_reg((opcode & 7) + 8, addr_size);
        else add_reg(opcode & 7, addr_size);
        return;
    case 0x63:
        add_str("movsxd ");
        add_modrm(data_size, x86_mode == MODE_64 ? 4 : 2, 0);
        return;
    case 0x68:
        add_str("push ");
        if (data_size == 2) add_imm16();
        else add_imm32();
        return;
    case 0x6a:
        add_str("push ");
        add_imm8();
        return;
    case 0x70:
    case 0x71:
    case 0x72:
    case 0x73:
    case 0x74:
    case 0x75:
    case 0x76:
    case 0x77:
    case 0x78:
    case 0x79:
    case 0x7a:
    case 0x7b:
    case 0x7c:
    case 0x7d:
    case 0x7e:
    case 0x7f:
        add_char('j');
        add_ttt(opcode & 0xf);
        add_char(' ');
        add_rel(1);
        return;
    case 0x80:
        modrm = get_code();
        add_a_op((modrm >> 3) & 7);
        add_modrm_mem(modrm, data_size);
        add_char(',');
        add_imm8();
        return;
    case 0x81:
        modrm = get_code();
        add_a_op((modrm >> 3) & 7);
        add_modrm_mem(modrm, data_size);
        add_char(',');
        if (data_size == 2) add_imm16();
        else add_imm32();
        return;
    case 0x83:
        modrm = get_code();
        add_a_op((modrm >> 3) & 7);
        add_modrm_mem(modrm, data_size);
        add_char(',');
        add_imm8();
        return;
    case 0x84:
        add_str("test ");
        add_modrm(1, 1, 1);
        return;
    case 0x85:
        add_str("test ");
        add_modrm(data_size, data_size, 1);
        return;
    case 0x88:
        add_str("mov ");
        add_modrm(1, 1, 1);
        return;
    case 0x89:
        add_str("mov ");
        add_modrm(data_size, data_size, 1);
        return;
    case 0x8a:
        add_str("mov ");
        add_modrm(1, 1, 0);
        return;
    case 0x8b:
        add_str("mov ");
        add_modrm(data_size, data_size, 0);
        return;
    case 0x8c:
        add_str("mov ");
        add_modrm(REG_SIZE_SEG, data_size, 1);
        return;
    case 0x8d:
        add_str("lea ");
        add_modrm(data_size, 0, 0);
        return;
    case 0x8e:
        add_str("mov ");
        add_modrm(REG_SIZE_SEG, data_size, 0);
        return;
    case 0x8f:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0:
            add_str("pop ");
            add_modrm_mem(modrm, data_size);
            return;
        }
        break;
    case 0x90:
        add_str("nop");
        return;
    case 0x98:
        switch (data_size) {
        case 2: add_str("cbw"); return;
        case 4: add_str("cwde"); return;
        case 8: add_str("cdqe"); return;
        }
        break;
    case 0x99:
        switch (data_size) {
        case 2: add_str("cwd"); return;
        case 4: add_str("cdq"); return;
        case 8: add_str("cqo"); return;
        }
        break;
    case 0x9a:
        add_str("call ");
        add_imm16();
        add_char(':');
        if (addr_size <= 2) add_imm16();
        else add_imm32();
        return;
    case 0xa0:
        add_str("mov al,");
        add_moffs(0);
        return;
    case 0xa1:
        add_str("mov ");
        add_reg(0, data_size);
        add_char(',');
        add_moffs(1);
        return;
    case 0xa2:
        add_str("mov ");
        add_moffs(0);
        add_char(',');
        add_reg(0, 1);
        return;
    case 0xa3:
        add_str("mov ");
        add_moffs(1);
        add_char(',');
        add_reg(0, data_size);
        return;
    case 0xa6:
        disassemble_cmps(addr_size, 1);
        return;
    case 0xa7:
        disassemble_cmps(addr_size, data_size);
        return;
    case 0xa8:
        add_str("test al,");
        add_imm8();
        return;
    case 0xa9:
        add_str("test ");
        add_reg(0, data_size);
        add_char(',');
        if (data_size <= 2) add_imm16();
        else add_imm32();
        return;
    case 0xb0:
    case 0xb1:
    case 0xb2:
    case 0xb3:
    case 0xb4:
    case 0xb5:
    case 0xb6:
    case 0xb7:
        add_str("mov ");
        add_reg(opcode & 7, 1);
        add_char(',');
        add_imm8();
        return;
    case 0xb8:
    case 0xb9:
    case 0xba:
    case 0xbb:
    case 0xbc:
    case 0xbd:
    case 0xbe:
    case 0xbf:
        add_str("mov ");
        add_reg(opcode & 7, data_size);
        add_char(',');
        if (addr_size <= 2) add_imm16();
        else add_imm32();
        return;
    case 0xc0:
    case 0xc1:
        modrm = get_code();
        if (!shift_op((modrm >> 3) & 7)) break;
        add_modrm_mem(modrm, data_size);
        add_char(',');
        add_imm8();
        return;
    case 0xc2:
        add_str("ret ");
        add_imm16();
        return;
    case 0xc3:
        add_str("ret");
        return;
    case 0xc6:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0:
            add_str("mov ");
            add_modrm_mem(modrm, 1);
            add_char(',');
            add_imm8();
            return;
        }
        break;
    case 0xc7:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0:
            add_str("mov ");
            add_modrm_mem(modrm, data_size);
            add_char(',');
            if (addr_size <= 2) add_imm16();
            else add_imm32();
            return;
        }
        break;
    case 0xc8:
        add_str("enter ");
        add_imm16();
        add_char(',');
        add_imm8();
        return;
    case 0xc9:
        add_str("leave");
        return;
    case 0xca:
        add_str("ret ");
        add_imm16();
        return;
    case 0xcb:
        add_str("ret");
        return;
    case 0xd0:
    case 0xd1:
        modrm = get_code();
        if (!shift_op((modrm >> 3) & 7)) break;
        add_modrm_mem(modrm, data_size);
        add_str(",1");
        return;
    case 0xd2:
    case 0xd3:
        modrm = get_code();
        if (!shift_op((modrm >> 3) & 7)) break;
        add_modrm_mem(modrm, data_size);
        add_str(",cl");
        return;
    case 0xe3:
        switch (data_size) {
        case 2:
            add_str("jcxz ");
            add_rel(1);
            return;
        case 4:
            add_str("jecxz ");
            add_rel(1);
            return;
        case 8:
            add_str("jrcxz ");
            add_rel(1);
            return;
        }
        break;
    case 0xe8:
        add_str("call ");
        add_rel(addr_size <= 2 ? 2: 4);
        return;
    case 0xd4:
        add_str("aam");
        imm = get_code();
        if (imm != 0x0a) {
            add_str(" 0x");
            add_hex_uint32(imm);
        }
        return;
    case 0xd5:
        add_str("aad");
        imm = get_code();
        if (imm != 0x0a) {
            add_str(" 0x");
            add_hex_uint32(imm);
        }
        return;
    case 0xe9:
        add_str("jmp ");
        add_rel(4);
        return;
    case 0xeb:
        add_str("jmp ");
        add_rel(1);
        return;
    case 0xf6:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0:
            add_str("test ");
            add_modrm_mem(modrm, 1);
            add_char(',');
            add_imm8();
            return;
        }
        break;
    case 0xf7:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0:
            add_str("test ");
            add_modrm_mem(modrm, data_size);
            add_char(',');
            if (data_size <= 2) add_imm16();
            else add_imm32();
            return;
        }
        break;
    case 0xfe:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0:
            add_str("inc ");
            add_modrm_mem(modrm, 1);
            return;
        case 1:
            add_str("dec ");
            add_modrm_mem(modrm, 1);
            return;
        }
        break;
    case 0xff:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0:
            add_str("inc ");
            add_modrm_mem(modrm, data_size);
            return;
        case 1:
            add_str("dec ");
            add_modrm_mem(modrm, data_size);
            return;
        case 2:
            add_str("call ");
            add_modrm_mem(modrm, addr_size);
            return;
        case 4:
            add_str("jmp ");
            add_modrm_mem(modrm, addr_size);
            return;
        case 6:
            add_str("push ");
            add_modrm_mem(modrm, data_size);
            return;
        }
        break;
    }

    buf_pos = 0;
}

static DisassemblyResult * disassemble_x86(uint8_t * code,
        ContextAddress addr, ContextAddress size, int mode,
        DisassemblerParams * disass_params) {

    static DisassemblyResult dr;

    memset(&dr, 0, sizeof(dr));
    buf_pos = 0;
    code_buf = code;
    code_len = (size_t)size;
    code_pos = 0;

    instr_addr = addr;
    params = disass_params;
    x86_mode = mode;
    prefix = 0;
    vex = 0;
    rex = 0;

    /* Instruction Prefixes */
    while (code_pos < code_len) {
        switch (code_buf[code_pos]) {
        case 0xf0:
            prefix |= PREFIX_LOCK;
            add_str("lock ");
            code_pos++;
            continue;
        case 0xf2:
            prefix |= PREFIX_REPNZ;
            code_pos++;
            continue;
        case 0xf3:
            prefix |= PREFIX_REPZ;
            code_pos++;
            continue;
        case 0x2e:
            prefix |= PREFIX_CS;
            code_pos++;
            continue;
        case 0x36:
            prefix |= PREFIX_SS;
            code_pos++;
            continue;
        case 0x3e:
            prefix |= PREFIX_DS;
            code_pos++;
            continue;
        case 0x26:
            prefix |= PREFIX_ES;
            code_pos++;
            continue;
        case 0x64:
            prefix |= PREFIX_FS;
            code_pos++;
            continue;
        case 0x65:
            prefix |= PREFIX_GS;
            code_pos++;
            continue;
        case 0x66:
            prefix |= PREFIX_DATA_SIZE;
            code_pos++;
            continue;
        case 0x67:
            prefix |= PREFIX_ADDR_SIZE;
            code_pos++;
            continue;
        }
        break;
    }

    if (x86_mode == MODE_64) {
        if (code_pos + 1 < code_len && code_buf[code_pos] == 0xc5) { /* Two byte VEX */
            vex = code_buf[code_pos++];
            vex |= (uint32_t)code_buf[code_pos++] << 8;
        }
        else if (code_pos + 2 < code_len && code_buf[code_pos] == 0xc4) { /* Three byte VEX */
            vex = code_buf[code_pos++];
            vex |= (uint32_t)code_buf[code_pos++] << 8;
            vex |= (uint32_t)code_buf[code_pos++] << 16;
        }
        else if (code_pos < code_len && code_buf[code_pos] >= 0x40 && code_buf[code_pos] <= 0x4f) {
            rex = code_buf[code_pos++];
        }
    }

    switch (x86_mode) {
    case MODE_16:
        data_size = prefix & PREFIX_DATA_SIZE ? 4 : 2;
        addr_size = prefix & PREFIX_ADDR_SIZE ? 4 : 2;
        break;
    case MODE_32:
        data_size = prefix & PREFIX_DATA_SIZE ? 2 : 4;
        addr_size = prefix & PREFIX_ADDR_SIZE ? 2 : 4;
        break;
    case MODE_64:
        if ((rex & REX_W) == 0) {
            data_size = prefix & PREFIX_DATA_SIZE ? 2 : 4;
        }
        else {
            data_size = 8;
        }
        addr_size = prefix & PREFIX_ADDR_SIZE ? 4 : 8;
        break;
    }

    disassemble_instr();

    dr.text = buf;
    if (buf_pos == 0 || code_pos > code_len) {
        snprintf(buf, sizeof(buf), ".byte 0x%02x", code_buf[0]);
        dr.size = 1;
    }
    else {
        buf[buf_pos] = 0;
        dr.size = code_pos;
    }
    return &dr;
}

DisassemblyResult * disassemble_x86_16(uint8_t * code,
    ContextAddress addr, ContextAddress size,
    DisassemblerParams * disass_params) {
    return disassemble_x86(code, addr, size, MODE_16, disass_params);
}

DisassemblyResult * disassemble_x86_32(uint8_t * code,
        ContextAddress addr, ContextAddress size,
        DisassemblerParams * disass_params) {
    return disassemble_x86(code, addr, size, MODE_32, disass_params);
}

DisassemblyResult * disassemble_x86_64(uint8_t * code,
        ContextAddress addr, ContextAddress size,
        DisassemblerParams * disass_params) {
    return disassemble_x86(code, addr, size, MODE_64, disass_params);
}

#endif /* SERVICE_Disassembly */
