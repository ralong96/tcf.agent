/*******************************************************************************
 * Copyright (c) 2015 Xilinx, Inc. and others.
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

#define PREFIX_LOCK         0x0001
#define PREFIX_REPNZ        0x0002
#define PREFIX_REPZ         0x0004
#define PREFIX_CS           0x0008
#define PREFIX_SS           0x0010
#define PREFIX_DS           0x0020
#define PREFIX_ES           0x0040
#define PREFIX_FS           0x0080
#define PREFIX_GS           0x0100
#define PREFIX_DATA_SIZE    0x0200
#define PREFIX_ADDR_SIZE    0x0400

#define REX_W               0x08
#define REX_R               0x04
#define REX_X               0x02
#define REX_B               0x01

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
static int x86_64 = 0;

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

#if 0 /* Not used yet */
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
#endif

static void add_reg(unsigned reg, unsigned size) {
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
    if (x86_64 && size == 1 && reg >= 4 && reg <= 7) {
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

#if 0 /* Not used yet */
static void add_seg_reg(unsigned reg) {
    switch (reg) {
    case 0: add_str("es"); break;
    case 1: add_str("cs"); break;
    case 2: add_str("ss"); break;
    case 3: add_str("ds"); break;
    case 4: add_str("fs"); break;
    case 5: add_str("gs"); break;
    case 6: add_str("s6"); break;
    case 7: add_str("s7"); break;
    }
}

static void add_ctrl_reg(unsigned reg) {
    add_str("cr");
    add_dec_uint32(reg);
}

static void add_dbg_reg(unsigned reg) {
    add_str("dr");
    add_dec_uint32(reg);
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
#endif

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

static void add_modrm(unsigned modrm, int w) {
    unsigned mod = (modrm >> 6) & 3;
    unsigned rm = modrm & 7;
    if (mod == 3) {
        add_reg(rm, w ? data_size : 1);
    }
    else {
        add_char('[');
        if (addr_size == 4) {
            switch (rm) {
            case 0: add_str("eax"); break;
            case 1: add_str("acx"); break;
            case 2: add_str("edx"); break;
            case 3: add_str("ebx"); break;
            case 4:
                {
                    uint8_t sib = get_code();
                    unsigned base = sib & 7;
                    unsigned index = (sib >> 3) & 7;
                    unsigned scale = (sib >> 6) & 3;
                    int bs = 0;
                    if ((mod == 0 && base != 5) || mod == 1 || mod == 2) {
                        add_reg(base, 4);
                        bs = 1;
                    }
                    if (index != 4) {
                        if (bs) add_char('+');
                        add_reg(index, 4);
                        switch (scale) {
                        case 1: add_str("*2"); break;
                        case 2: add_str("*4"); break;
                        case 3: add_str("*8"); break;
                        }
                        bs = 1;
                    }
                    if ((mod == 0 && base == 5) || mod == 2) {
                        if (bs) add_char('+');
                        add_disp32();
                    }
                    else if (mod == 1) {
                        add_disp8();
                    }
                    add_char(']');
                }
                return;
            case 5: if (mod != 0) add_str("ebp"); break;
            case 6: add_str("esi"); break;
            case 7: add_str("edi"); break;
            }
        }
        else {
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
        switch (mod) {
        case 0:
            if (rm == 6) {
                add_char('+');
                if (addr_size == 4) add_disp32();
                else add_disp16();
            }
            break;
        case 1:
            add_disp8();
            break;
        case 2:
            add_char('+');
            if (addr_size == 4) add_disp32();
            else add_disp16();
            break;
        }
        add_char(']');
    }
}

static void disassemble_instr(void) {
    uint8_t opcode = 0;
    uint8_t modrm = 0;
    uint8_t imm = 0;

    opcode = get_code();
    switch (opcode) {
    case 0x00:
        modrm = get_code();
        add_str("add ");
        add_modrm(modrm, 0);
        add_char(',');
        add_reg((modrm >> 3) & 7, 1);
        return;
    case 0x01:
        modrm = get_code();
        add_str("add ");
        add_modrm(modrm, 1);
        add_char(',');
        add_reg((modrm >> 3) & 7, data_size);
        return;
    case 0x02:
        modrm = get_code();
        add_str("add ");
        add_reg((modrm >> 3) & 7, 1);
        add_char(',');
        add_modrm(modrm, 0);
        return;
    case 0x03:
        modrm = get_code();
        add_str("add ");
        add_reg((modrm >> 3) & 7, data_size);
        add_char(',');
        add_modrm(modrm, 1);
        return;
    case 0x04:
        add_str("add al,");
        add_imm8();
        return;
    case 0x05:
        add_str("add ");
        add_reg(0, data_size);
        add_char(',');
        if (data_size <= 2) add_imm16();
        else add_imm32();
        return;
    case 0x0f:
        if (prefix & PREFIX_DATA_SIZE) {
            switch (get_code()) {
            case 0x38:
                switch (get_code()) {
                case 0xf6:
                    modrm = get_code();
                    add_str("adcx ");
                    add_reg((modrm >> 3) & 7, data_size);
                    add_char(',');
                    add_modrm(modrm, 0);
                    return;
                }
                break;
            }
        }
        break;
    case 0x10:
        modrm = get_code();
        add_str("adc ");
        add_modrm(modrm, 0);
        add_char(',');
        add_reg((modrm >> 3) & 7, 1);
        return;
    case 0x11:
        modrm = get_code();
        add_str("adc ");
        add_modrm(modrm, 1);
        add_char(',');
        add_reg((modrm >> 3) & 7, data_size);
        return;
    case 0x12:
        modrm = get_code();
        add_str("adc ");
        add_reg((modrm >> 3) & 7, 1);
        add_char(',');
        add_modrm(modrm, 0);
        return;
    case 0x13:
        modrm = get_code();
        add_str("adc ");
        add_reg((modrm >> 3) & 7, data_size);
        add_char(',');
        add_modrm(modrm, 1);
        return;
    case 0x14:
        add_str("adc al,");
        add_imm8();
        return;
    case 0x15:
        add_str("adc ");
        add_reg(0, data_size);
        add_char(',');
        if (data_size <= 2) add_imm16();
        else add_imm32();
        return;
    case 0x20:
        modrm = get_code();
        add_str("and ");
        add_modrm(modrm, 0);
        add_char(',');
        add_reg((modrm >> 3) & 7, 1);
        return;
    case 0x21:
        modrm = get_code();
        add_str("and ");
        add_modrm(modrm, 1);
        add_char(',');
        add_reg((modrm >> 3) & 7, data_size);
        return;
    case 0x22:
        modrm = get_code();
        add_str("and ");
        add_reg((modrm >> 3) & 7, 1);
        add_char(',');
        add_modrm(modrm, 0);
        return;
    case 0x23:
        modrm = get_code();
        add_str("and ");
        add_reg((modrm >> 3) & 7, data_size);
        add_char(',');
        add_modrm(modrm, 1);
        return;
    case 0x24:
        add_str("and al,");
        add_imm8();
        return;
    case 0x25:
        add_str("and ");
        add_reg(0, data_size);
        add_char(',');
        if (data_size <= 2) add_imm16();
        else add_imm32();
        return;
    case 0x37:
        add_str("aaa");
        return;
    case 0x3f:
        add_str("aas");
        return;
    case 0x80:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0: add_str("add "); break;
        case 2: add_str("adc "); break;
        case 4: add_str("and "); break;
        }
        add_modrm(modrm, 1);
        add_char(',');
        add_imm8();
        return;
    case 0x81:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0: add_str("add "); break;
        case 2: add_str("adc "); break;
        case 4: add_str("and "); break;
        }
        add_modrm(modrm, 1);
        add_char(',');
        if (data_size == 2) add_imm16();
        else add_imm32();
        return;
    case 0x83:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 0: add_str("add "); break;
        case 2: add_str("adc "); break;
        case 4: add_str("and "); break;
        }
        add_modrm(modrm, 1);
        add_char(',');
        add_imm8();
        return;
    case 0x9a:
        add_str("call ");
        add_imm16();
        add_char(':');
        if (addr_size <= 2) add_imm16();
        else add_imm32();
        return;
        return;
    case 0xe8:
        add_str("call ");
        if (addr_size <= 2) add_imm16();
        else add_imm32();
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
    case 0xff:
        modrm = get_code();
        switch ((modrm >> 3) & 7) {
        case 2:
            add_str("call ");
            add_modrm(modrm, 1);
            return;
        }
        break;;
    }

    buf_pos = 0;
}

static DisassemblyResult * disassemble_x86(uint8_t * code,
        ContextAddress addr, ContextAddress size, int i64,
        DisassemblerParams * disass_params) {

    static DisassemblyResult dr;

    memset(&dr, 0, sizeof(dr));
    buf_pos = 0;
    code_buf = code;
    code_len = (size_t)size;
    code_pos = 0;

    instr_addr = addr;
    params = disass_params;
    x86_64 = i64;
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
            add_str("repnz ");
            code_pos++;
            continue;
        case 0xf3:
            prefix |= PREFIX_REPZ;
            add_str("repz ");
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

    if (i64) {
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

    data_size = rex & REX_W ? 8 : 4;
    addr_size = x86_64 ? 8 : 4;

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

DisassemblyResult * disassemble_x86_32(uint8_t * code,
        ContextAddress addr, ContextAddress size,
        DisassemblerParams * disass_params) {
    return disassemble_x86(code, addr, size, 0, disass_params);
}

DisassemblyResult * disassemble_x86_64(uint8_t * code,
        ContextAddress addr, ContextAddress size,
        DisassemblerParams * disass_params) {
    return disassemble_x86(code, addr, size, 1, disass_params);
}

#endif /* SERVICE_Disassembly */
