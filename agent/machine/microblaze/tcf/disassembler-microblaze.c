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
 * This module implements disassembler for MicroBlaze.
 */

#include <tcf/config.h>

#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <tcf/framework/context.h>
#include <tcf/services/symbols.h>
#include <machine/microblaze/tcf/disassembler-microblaze.h>

enum InstructionType {
    INST_TYPE_RD_RA_RB,
    INST_TYPE_RD_RA_IMM,
    INST_TYPE_RD_RA_IMM5,
    INST_TYPE_RD_RA_IMM5_IMM5,
    INST_TYPE_RD_RA,
    INST_TYPE_RD_RB,
    INST_TYPE_RD_IMM,
    INST_TYPE_RD_IMM15,
    INST_TYPE_RD_IMM4,
    INST_TYPE_RA_RB,
    INST_TYPE_RA_IMM,
    INST_TYPE_RA_IMM4,
    INST_TYPE_RD_SA,
    INST_TYPE_SA_RA,
    INST_TYPE_RA,
    INST_TYPE_RB,
    INST_TYPE_RD,
    INST_TYPE_IMM,
    INST_TYPE_IMM4,
    INST_TYPE_RDIMM,
    INST_TYPE_NULL
};

enum InstructionFlags {
    F_CTRL       = 0x00000001,
    F_DIRECT     = 0x00000002,
    F_INDIRJMP   = 0x00000004,
    F_IMM        = 0x00000008,
};

enum Instructions {
    i_add,            i_addc,           i_addi,           i_addic,
    i_addik,          i_addikc,         i_addk,           i_addkc,
    i_aget,           i_agetd,          i_and,            i_andi,
    i_andn,           i_andni,          i_aput,           i_aputd,
    i_beq,            i_beqd,           i_beqi,           i_beqid,
    i_bge,            i_bged,           i_bgei,           i_bgeid,
    i_bgt,            i_bgtd,           i_bgti,           i_bgtid,
    i_ble,            i_bled,           i_blei,           i_bleid,
    i_blt,            i_bltd,           i_blti,           i_bltid,
    i_bne,            i_bned,           i_bnei,           i_bneid,
    i_br,             i_bra,            i_brad,           i_brai,
    i_braid,          i_brald,          i_bralid,         i_brd,
    i_bri,            i_brid,           i_brk,            i_brki,
    i_brld,           i_brlid,          i_bsefi,          i_bsifi,
    i_bsll,           i_bslli,          i_bsra,           i_bsrai,
    i_bsrl,           i_bsrli,          i_caget,          i_cagetd,
    i_caput,          i_caputd,         i_cget,           i_cgetd,
    i_clz,            i_cmp,            i_cmpu,           i_cput,
    i_cputd,          i_eaget,          i_eagetd,         i_ecaget,
    i_ecagetd,        i_ecget,          i_ecgetd,         i_eget,
    i_egetd,          i_fadd,           i_fcmp_eq,        i_fcmp_ge,
    i_fcmp_gt,        i_fcmp_le,        i_fcmp_lt,        i_fcmp_ne,
    i_fcmp_un,        i_fdiv,           i_fint,           i_flt,
    i_fmul,           i_frsub,          i_fsqrt,          i_get,
    i_getd,           i_idiv,           i_idivu,          i_imm,
    i_lbu,            i_lbuea,          i_lbui,           i_lbur,
    i_lhu,            i_lhuea,          i_lhui,           i_lhur,
    i_lw,             i_lwea,           i_lwi,            i_lwr,
    i_lwx,            i_mbar,           i_mfs,            i_mfse,
    i_msrclr,         i_msrset,         i_mts,            i_mul,
    i_mulh,           i_mulhsu,         i_mulhu,          i_muli,
    i_naget,          i_nagetd,         i_naput,          i_naputd,
    i_ncaget,         i_ncagetd,        i_ncaput,         i_ncaputd,
    i_ncget,          i_ncgetd,         i_ncput,          i_ncputd,
    i_neaget,         i_neagetd,        i_necaget,        i_necagetd,
    i_necget,         i_necgetd,        i_neget,          i_negetd,
    i_nget,           i_ngetd,          i_nput,           i_nputd,
    i_or,             i_ori,            i_pcmpbf,         i_pcmpeq,
    i_pcmpne,         i_put,            i_putd,           i_rsub,
    i_rsubc,          i_rsubi,          i_rsubic,         i_rsubik,
    i_rsubikc,        i_rsubk,          i_rsubkc,         i_rtbd,
    i_rted,           i_rtid,           i_rtsd,           i_sb,
    i_sbea,           i_sbi,            i_sbr,            i_sext16,
    i_sext8,          i_sh,             i_shea,           i_shi,
    i_shr,            i_sleep,          i_sra,            i_src,
    i_srl,            i_sw,             i_swapb,          i_swaph,
    i_swea,           i_swi,            i_swr,            i_swx,
    i_taget,          i_tagetd,         i_taput,          i_taputd,
    i_tcaget,         i_tcagetd,        i_tcaput,         i_tcaputd,
    i_tcget,          i_tcgetd,         i_tcput,          i_tcputd,
    i_teaget,         i_teagetd,        i_tecaget,        i_tecagetd,
    i_tecget,         i_tecgetd,        i_teget,          i_tegetd,
    i_tget,           i_tgetd,          i_tnaget,         i_tnagetd,
    i_tnaput,         i_tnaputd,        i_tncaget,        i_tncagetd,
    i_tncaput,        i_tncaputd,       i_tncget,         i_tncgetd,
    i_tncput,         i_tncputd,        i_tneaget,        i_tneagetd,
    i_tnecaget,       i_tnecagetd,      i_tnecget,        i_tnecgetd,
    i_tneget,         i_tnegetd,        i_tnget,          i_tngetd,
    i_tnput,          i_tnputd,         i_tput,           i_tputd,
    i_wdc,            i_wdc_clear,      i_wdc_clear_ea,   i_wdc_ext_clear,
    i_wdc_ext_flush,  i_wdc_flush,      i_wic,            i_xor,
    i_xori
};

typedef struct InstructionInfo {
    unsigned hash;
    const char * name;
    unsigned type;
    unsigned flags;
} InstructionInfo;

static InstructionInfo instruction_info[] = {
    { 0x00, "add",            INST_TYPE_RD_RA_RB, 0 },
    { 0x02, "addc",           INST_TYPE_RD_RA_RB, 0 },
    { 0x08, "addi",           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0a, "addic",          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0c, "addik",          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0e, "addikc",         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x04, "addk",           INST_TYPE_RD_RA_RB, 0 },
    { 0x06, "addkc",          INST_TYPE_RD_RA_RB, 0 },
    { 0x1b, "aget",           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "agetd",          INST_TYPE_RD_RB, 0 },
    { 0x21, "and",            INST_TYPE_RD_RA_RB, 0 },
    { 0x29, "andi",           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x23, "andn",           INST_TYPE_RD_RA_RB, 0 },
    { 0x2b, "andni",          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x1b, "aput",           INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, "aputd",          INST_TYPE_RA_RB, 0 },
    { 0x27, "beq",            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, "beqd",           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, "beqi",           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, "beqid",          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, "bge",            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, "bged",           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, "bgei",           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, "bgeid",          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, "bgt",            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, "bgtd",           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, "bgti",           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, "bgtid",          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, "ble",            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, "bled",           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, "blei",           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, "bleid",          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, "blt",            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, "bltd",           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, "blti",           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, "bltid",          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, "bne",            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, "bned",           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, "bnei",           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, "bneid",          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x26, "br",             INST_TYPE_RB, F_CTRL },
    { 0x26, "bra",            INST_TYPE_RB, F_CTRL|F_DIRECT },
    { 0x26, "brad",           INST_TYPE_RB, F_CTRL|F_DIRECT },
    { 0x2e, "brai",           INST_TYPE_IMM, F_CTRL|F_DIRECT|F_IMM },
    { 0x2e, "braid",          INST_TYPE_IMM, F_CTRL|F_DIRECT|F_IMM },
    { 0x26, "brald",          INST_TYPE_RD_RB, F_CTRL|F_DIRECT },
    { 0x2e, "bralid",         INST_TYPE_RD_IMM, F_CTRL|F_DIRECT|F_IMM },
    { 0x26, "brd",            INST_TYPE_RB, F_CTRL },
    { 0x2e, "bri",            INST_TYPE_IMM, F_CTRL|F_IMM },
    { 0x2e, "brid",           INST_TYPE_IMM, F_CTRL|F_IMM },
    { 0x26, "brk",            INST_TYPE_RD_RB, F_CTRL|F_DIRECT },
    { 0x2e, "brki",           INST_TYPE_RD_IMM, F_CTRL|F_DIRECT|F_IMM },
    { 0x26, "brld",           INST_TYPE_RD_RB, F_CTRL },
    { 0x2e, "brlid",          INST_TYPE_RD_IMM, F_CTRL|F_IMM },
    { 0x19, "bsefi",          INST_TYPE_RD_RA_IMM5_IMM5, F_IMM },
    { 0x19, "bsifi",          INST_TYPE_RD_RA_IMM5_IMM5, F_IMM },
    { 0x11, "bsll",           INST_TYPE_RD_RA_RB, 0 },
    { 0x19, "bslli",          INST_TYPE_RD_RA_IMM5, F_IMM },
    { 0x11, "bsra",           INST_TYPE_RD_RA_RB, 0 },
    { 0x19, "bsrai",          INST_TYPE_RD_RA_IMM5, F_IMM },
    { 0x11, "bsrl",           INST_TYPE_RD_RA_RB, 0 },
    { 0x19, "bsrli",          INST_TYPE_RD_RA_IMM5, F_IMM },
    { 0x1b, "caget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "cagetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "caput",          INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, "caputd",         INST_TYPE_RA_RB, 0 },
    { 0x1b, "cget",           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "cgetd",          INST_TYPE_RD_RB, 0 },
    { 0x24, "clz",            INST_TYPE_RD_RA, 0 },
    { 0x05, "cmp",            INST_TYPE_RD_RA_RB, 0 },
    { 0x05, "cmpu",           INST_TYPE_RD_RA_RB, 0 },
    { 0x1b, "cput",           INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, "cputd",          INST_TYPE_RA_RB, 0 },
    { 0x1b, "eaget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "eagetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "ecaget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "ecagetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "ecget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "ecgetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "eget",           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "egetd",          INST_TYPE_RD_RB, 0 },
    { 0x16, "fadd",           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fcmp.eq",        INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fcmp.ge",        INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fcmp.gt",        INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fcmp.le",        INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fcmp.lt",        INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fcmp.ne",        INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fcmp.un",        INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fdiv",           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fint",           INST_TYPE_RD_RA, 0 },
    { 0x16, "flt",            INST_TYPE_RD_RA, 0 },
    { 0x16, "fmul",           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "frsub",          INST_TYPE_RD_RA_RB, 0 },
    { 0x16, "fsqrt",          INST_TYPE_RD_RA, 0 },
    { 0x1b, "get",            INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "getd",           INST_TYPE_RD_RB, 0 },
    { 0x12, "idiv",           INST_TYPE_RD_RA_RB, 0 },
    { 0x12, "idivu",          INST_TYPE_RD_RA_RB, 0 },
    { 0x2c, "imm",            INST_TYPE_IMM, F_IMM },
    { 0x30, "lbu",            INST_TYPE_RD_RA_RB, 0 },
    { 0x30, "lbuea",          INST_TYPE_RD_RA_RB, 0 },
    { 0x38, "lbui",           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x30, "lbur",           INST_TYPE_RD_RA_RB, 0 },
    { 0x31, "lhu",            INST_TYPE_RD_RA_RB, 0 },
    { 0x31, "lhuea",          INST_TYPE_RD_RA_RB, 0 },
    { 0x39, "lhui",           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x31, "lhur",           INST_TYPE_RD_RA_RB, 0 },
    { 0x32, "lw",             INST_TYPE_RD_RA_RB, 0 },
    { 0x32, "lwea",           INST_TYPE_RD_RA_RB, 0 },
    { 0x3a, "lwi",            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x32, "lwr",            INST_TYPE_RD_RA_RB, 0 },
    { 0x32, "lwx",            INST_TYPE_RD_RA_RB, 0 },
    { 0x2e, "mbar",           INST_TYPE_RDIMM, F_CTRL|F_DIRECT|F_IMM },
    { 0x25, "mfs",            INST_TYPE_RD_SA, 0 },
    { 0x25, "mfse",           INST_TYPE_RD_SA, 0 },
    { 0x25, "msrclr",         INST_TYPE_RD_IMM15, 0 },
    { 0x25, "msrset",         INST_TYPE_RD_IMM15, 0 },
    { 0x25, "mts",            INST_TYPE_SA_RA, 0 },
    { 0x10, "mul",            INST_TYPE_RD_RA_RB, 0 },
    { 0x10, "mulh",           INST_TYPE_RD_RA_RB, 0 },
    { 0x10, "mulhsu",         INST_TYPE_RD_RA_RB, 0 },
    { 0x10, "mulhu",          INST_TYPE_RD_RA_RB, 0 },
    { 0x18, "muli",           INST_TYPE_RD_RA_IMM, 0 },
    { 0x1b, "naget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "nagetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "naput",          INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, "naputd",         INST_TYPE_RA_RB, 0 },
    { 0x1b, "ncaget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "ncagetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "ncaput",         INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, "ncaputd",        INST_TYPE_RA_RB, 0 },
    { 0x1b, "ncget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "ncgetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "ncput",          INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, "ncputd",         INST_TYPE_RA_RB, 0 },
    { 0x1b, "neaget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "neagetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "necaget",        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "necagetd",       INST_TYPE_RD_RB, 0 },
    { 0x1b, "necget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "necgetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "neget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "negetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "nget",           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "ngetd",          INST_TYPE_RD_RB, 0 },
    { 0x1b, "nput",           INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, "nputd",          INST_TYPE_RA_RB, 0 },
    { 0x20, "or",             INST_TYPE_RD_RA_RB, 0 },
    { 0x28, "ori",            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x20, "pcmpbf",         INST_TYPE_RD_RA_RB, 0 },
    { 0x22, "pcmpeq",         INST_TYPE_RD_RA_RB, 0 },
    { 0x23, "pcmpne",         INST_TYPE_RD_RA_RB, 0 },
    { 0x1b, "put",            INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, "putd",           INST_TYPE_RA_RB, 0 },
    { 0x01, "rsub",           INST_TYPE_RD_RA_RB, 0 },
    { 0x03, "rsubc",          INST_TYPE_RD_RA_RB, 0 },
    { 0x09, "rsubi",          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0b, "rsubic",         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0d, "rsubik",         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0f, "rsubikc",        INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x05, "rsubk",          INST_TYPE_RD_RA_RB, 0 },
    { 0x07, "rsubkc",         INST_TYPE_RD_RA_RB, 0 },
    { 0x2d, "rtbd",           INST_TYPE_RA_IMM, F_CTRL|F_INDIRJMP|F_IMM },
    { 0x2d, "rted",           INST_TYPE_RA_IMM, F_CTRL|F_INDIRJMP|F_IMM },
    { 0x2d, "rtid",           INST_TYPE_RA_IMM, F_CTRL|F_INDIRJMP|F_IMM },
    { 0x2d, "rtsd",           INST_TYPE_RA_IMM, F_CTRL|F_INDIRJMP|F_IMM },
    { 0x34, "sb",             INST_TYPE_RD_RA_RB, 0 },
    { 0x34, "sbea",           INST_TYPE_RD_RA_RB, 0 },
    { 0x3c, "sbi",            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x34, "sbr",            INST_TYPE_RD_RA_RB, 0 },
    { 0x24, "sext16",         INST_TYPE_RD_RA, 0 },
    { 0x24, "sext8",          INST_TYPE_RD_RA, 0 },
    { 0x35, "sh",             INST_TYPE_RD_RA_RB, 0 },
    { 0x35, "shea",           INST_TYPE_RD_RA_RB, 0 },
    { 0x3d, "shi",            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x35, "shr",            INST_TYPE_RD_RA_RB, 0 },
    { 0x2e, "sleep",          INST_TYPE_NULL, F_CTRL|F_DIRECT|F_IMM },
    { 0x24, "sra",            INST_TYPE_RD_RA, 0 },
    { 0x24, "src",            INST_TYPE_RD_RA, 0 },
    { 0x24, "srl",            INST_TYPE_RD_RA, 0 },
    { 0x36, "sw",             INST_TYPE_RD_RA_RB, 0 },
    { 0x24, "swapb",          INST_TYPE_RD_RA, 0 },
    { 0x24, "swaph",          INST_TYPE_RD_RA, 0 },
    { 0x36, "swea",           INST_TYPE_RD_RA_RB, 0 },
    { 0x3e, "swi",            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x36, "swr",            INST_TYPE_RD_RA_RB, 0 },
    { 0x36, "swx",            INST_TYPE_RD_RA_RB, 0 },
    { 0x1b, "taget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tagetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "taput",          INST_TYPE_IMM4, F_IMM },
    { 0x13, "taputd",         INST_TYPE_RB, 0 },
    { 0x1b, "tcaget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tcagetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "tcaput",         INST_TYPE_IMM4, F_IMM },
    { 0x13, "tcaputd",        INST_TYPE_RB, 0 },
    { 0x1b, "tcget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tcgetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "tcput",          INST_TYPE_IMM4, F_IMM },
    { 0x13, "tcputd",         INST_TYPE_RB, 0 },
    { 0x1b, "teaget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "teagetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "tecaget",        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tecagetd",       INST_TYPE_RD_RB, 0 },
    { 0x1b, "tecget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tecgetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "teget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tegetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "tget",           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tgetd",          INST_TYPE_RD_RB, 0 },
    { 0x1b, "tnaget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tnagetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "tnaput",         INST_TYPE_IMM4, F_IMM },
    { 0x13, "tnaputd",        INST_TYPE_RB, 0 },
    { 0x1b, "tncaget",        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tncagetd",       INST_TYPE_RD_RB, 0 },
    { 0x1b, "tncaput",        INST_TYPE_IMM4, F_IMM },
    { 0x13, "tncaputd",       INST_TYPE_RB, 0 },
    { 0x1b, "tncget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tncgetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "tncput",         INST_TYPE_IMM4, F_IMM },
    { 0x13, "tncputd",        INST_TYPE_RB, 0 },
    { 0x1b, "tneaget",        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tneagetd",       INST_TYPE_RD_RB, 0 },
    { 0x1b, "tnecaget",       INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tnecagetd",      INST_TYPE_RD_RB, 0 },
    { 0x1b, "tnecget",        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tnecgetd",       INST_TYPE_RD_RB, 0 },
    { 0x1b, "tneget",         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tnegetd",        INST_TYPE_RD_RB, 0 },
    { 0x1b, "tnget",          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, "tngetd",         INST_TYPE_RD_RB, 0 },
    { 0x1b, "tnput",          INST_TYPE_IMM4, F_IMM },
    { 0x13, "tnputd",         INST_TYPE_RB, 0 },
    { 0x1b, "tput",           INST_TYPE_IMM4, F_IMM },
    { 0x13, "tputd",          INST_TYPE_RB, 0 },
    { 0x24, "wdc",            INST_TYPE_RA_RB, 0 },
    { 0x24, "wdc.clear",      INST_TYPE_RA_RB, 0 },
    { 0x24, "wdc.clear.ea",   INST_TYPE_RA_RB, 0 },
    { 0x24, "wdc.ext.clear",  INST_TYPE_RA_RB, 0 },
    { 0x24, "wdc.ext.flush",  INST_TYPE_RA_RB, 0 },
    { 0x24, "wdc.flush",      INST_TYPE_RA_RB, 0 },
    { 0x24, "wic",            INST_TYPE_RA_RB, 0 },
    { 0x22, "xor",            INST_TYPE_RD_RA_RB, 0 },
    { 0x2a, "xori",           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0 }
};

#define UNKNOWN_OPCODE (sizeof(instruction_info) / sizeof(InstructionInfo) - 1)

/* opcode_hash[] maps 6 most significant bits of the instruction into enum Instructions.
 * This is done to speed up opcode lookup. Some instructions have the same 6 MSb,
 * so further decode will still be necessary (done in decode_instruction). */
static enum Instructions opcode_hash[64];

static uint32_t instr_bits = 0;

/* Decoded instruction */
static unsigned instr_op = UNKNOWN_OPCODE; /* index in instruction_info */
static short instr_r1 = 0;
static short instr_r2 = 0;
static short instr_rd = 0;
static short instr_imm = 0;
static short instr_imm2 = 0;

static int decode_instruction(void) {
    unsigned hash = instr_bits >> 26;
    enum Instructions op = opcode_hash[hash];

    instr_op = UNKNOWN_OPCODE;
    instr_r1 = 0;
    instr_r2 = 0;
    instr_rd = 0;
    instr_imm = 0;
    instr_imm2 = 0;

    /* If non-existent opcode */
    if (op == UNKNOWN_OPCODE) return 0;

    /* Further decode for certain instructions */
    switch (hash) {
    case 0x05:
        switch (instr_bits & 0x0003) {
        case 0x0:
            op = i_rsubk;
            break;
        case 0x1:
            op = i_cmp;
            break;
        case 0x3:
            op = i_cmpu;
            break;
        default:
            return 0;
        }
        break;

    case 0x10:
        switch (instr_bits & 0x3) {
        case 0x0:
            op = i_mul;
            break;
        case 0x1:
            op = i_mulh;
            break;
        case 0x2:
            op = i_mulhsu;
            break;
        case 0x3:
            op = i_mulhu;
            break;
        }
        break;

    case 0x11:
        switch (instr_bits & 0x0600) {
        case 0x0000:
            op = i_bsrl;
            break;
        case 0x0200:
            op = i_bsra;
            break;
        case 0x400:
            op = i_bsll;
            break;
        default:
            return 0;
        }
        break;

    case 0x12:
        switch (instr_bits & 0x0002) {
        case 0x0000:
            op = i_idiv;
            break;
        case 0x0002:
            op = i_idivu;
            break;
        default:
            return 0;
        }
        break;

    case 0x13:
        switch ((instr_bits >> 5) & 0x3F) {
        case 0x00: /* 000000 */ op = i_getd;      break;
        case 0x01: /* 000001 */ op = i_egetd;     break;
        case 0x02: /* 000010 */ op = i_agetd;     break;
        case 0x03: /* 000011 */ op = i_eagetd;    break;
        case 0x04: /* 000100 */ op = i_tgetd;     break;
        case 0x05: /* 000101 */ op = i_tegetd;    break;
        case 0x06: /* 000110 */ op = i_tagetd;    break;
        case 0x07: /* 000111 */ op = i_teagetd;   break;
        case 0x08: /* 001000 */ op = i_cgetd;     break;
        case 0x09: /* 001001 */ op = i_ecgetd;    break;
        case 0x0A: /* 001010 */ op = i_cagetd;    break;
        case 0x0B: /* 001011 */ op = i_ecagetd;   break;
        case 0x0C: /* 001100 */ op = i_tcgetd;    break;
        case 0x0D: /* 001101 */ op = i_tecgetd;   break;
        case 0x0E: /* 001110 */ op = i_tcagetd;   break;
        case 0x0F: /* 001111 */ op = i_tecagetd;  break;
        case 0x10: /* 010000 */ op = i_ngetd;     break;
        case 0x11: /* 010001 */ op = i_negetd;    break;
        case 0x12: /* 010010 */ op = i_nagetd;    break;
        case 0x13: /* 010011 */ op = i_neagetd;   break;
        case 0x14: /* 010100 */ op = i_tngetd;    break;
        case 0x15: /* 010101 */ op = i_tnegetd;   break;
        case 0x16: /* 010110 */ op = i_tnagetd;   break;
        case 0x17: /* 010111 */ op = i_tneagetd;  break;
        case 0x18: /* 011000 */ op = i_ncgetd;    break;
        case 0x19: /* 011001 */ op = i_necgetd;   break;
        case 0x1A: /* 011010 */ op = i_ncagetd;   break;
        case 0x1B: /* 011011 */ op = i_necagetd;  break;
        case 0x1C: /* 011100 */ op = i_tncgetd;   break;
        case 0x1D: /* 011101 */ op = i_tnecgetd;  break;
        case 0x1E: /* 011110 */ op = i_tncagetd;  break;
        case 0x1F: /* 011111 */ op = i_tnecagetd; break;

        case 0x20: /* 100000 */ op = i_putd;      break;
        case 0x22: /* 100010 */ op = i_aputd;     break;
        case 0x24: /* 100100 */ op = i_tputd;     break;
        case 0x26: /* 100110 */ op = i_taputd;    break;
        case 0x28: /* 101000 */ op = i_cputd;     break;
        case 0x2A: /* 101010 */ op = i_caputd;    break;
        case 0x2C: /* 101100 */ op = i_tcputd;    break;
        case 0x2E: /* 101110 */ op = i_tcaputd;   break;
        case 0x30: /* 110000 */ op = i_nputd;     break;
        case 0x32: /* 110010 */ op = i_naputd;    break;
        case 0x34: /* 110100 */ op = i_tnputd;    break;
        case 0x36: /* 110110 */ op = i_tnaputd;   break;
        case 0x38: /* 111000 */ op = i_ncputd;    break;
        case 0x3A: /* 111010 */ op = i_ncaputd;   break;
        case 0x3C: /* 111100 */ op = i_tncputd;   break;
        case 0x3E: /* 111110 */ op = i_tncaputd;  break;
        default:
            return 0;
        }
        break;

    case 0x19:
        switch (instr_bits & 0xC600) {
        case 0x0000:
            op = i_bsrli;
            break;
        case 0x0200:
            op = i_bsrai;
            break;
        case 0x0400:
            op = i_bslli;
            break;
        case 0x4000:
            op = i_bsefi;
            break;
        case 0x8000:
            op = i_bsifi;
            break;
        default:
            return 0;
        }
        break;

    case 0x1b:
        switch ((instr_bits >> 10) & 0x3F) {
        case 0x00: /* 000000 */ op = i_get;      break;
        case 0x01: /* 000001 */ op = i_eget;     break;
        case 0x02: /* 000010 */ op = i_aget;     break;
        case 0x03: /* 000011 */ op = i_eaget;    break;
        case 0x04: /* 000100 */ op = i_tget;     break;
        case 0x05: /* 000101 */ op = i_teget;    break;
        case 0x06: /* 000110 */ op = i_taget;    break;
        case 0x07: /* 000111 */ op = i_teaget;   break;
        case 0x08: /* 001000 */ op = i_cget;     break;
        case 0x09: /* 001001 */ op = i_ecget;    break;
        case 0x0A: /* 001010 */ op = i_caget;    break;
        case 0x0B: /* 001011 */ op = i_ecaget;   break;
        case 0x0C: /* 001100 */ op = i_tcget;    break;
        case 0x0D: /* 001101 */ op = i_tecget;   break;
        case 0x0E: /* 001110 */ op = i_tcaget;   break;
        case 0x0F: /* 001111 */ op = i_tecaget;  break;
        case 0x10: /* 010000 */ op = i_nget;     break;
        case 0x11: /* 010001 */ op = i_neget;    break;
        case 0x12: /* 010010 */ op = i_naget;    break;
        case 0x13: /* 010011 */ op = i_neaget;   break;
        case 0x14: /* 010100 */ op = i_tnget;    break;
        case 0x15: /* 010101 */ op = i_tneget;   break;
        case 0x16: /* 010110 */ op = i_tnaget;   break;
        case 0x17: /* 010111 */ op = i_tneaget;  break;
        case 0x18: /* 011000 */ op = i_ncget;    break;
        case 0x19: /* 011001 */ op = i_necget;   break;
        case 0x1A: /* 011010 */ op = i_ncaget;   break;
        case 0x1B: /* 011011 */ op = i_necaget;  break;
        case 0x1C: /* 011100 */ op = i_tncget;   break;
        case 0x1D: /* 011101 */ op = i_tnecget;  break;
        case 0x1E: /* 011110 */ op = i_tncaget;  break;
        case 0x1F: /* 011111 */ op = i_tnecaget; break;

        case 0x20: /* 100000 */ op = i_put;      break;
        case 0x22: /* 100010 */ op = i_aput;     break;
        case 0x24: /* 100100 */ op = i_tput;     break;
        case 0x26: /* 100110 */ op = i_taput;    break;
        case 0x28: /* 101000 */ op = i_cput;     break;
        case 0x2A: /* 101010 */ op = i_caput;    break;
        case 0x2C: /* 101100 */ op = i_tcput;    break;
        case 0x2E: /* 101110 */ op = i_tcaput;   break;
        case 0x30: /* 110000 */ op = i_nput;     break;
        case 0x32: /* 110010 */ op = i_naput;    break;
        case 0x34: /* 110100 */ op = i_tnput;    break;
        case 0x36: /* 110110 */ op = i_tnaput;   break;
        case 0x38: /* 111000 */ op = i_ncput;    break;
        case 0x3A: /* 111010 */ op = i_ncaput;   break;
        case 0x3C: /* 111100 */ op = i_tncput;   break;
        case 0x3E: /* 111110 */ op = i_tncaput;  break;
        default:
            return 0;
        }
        break;

    case 0x20:
        if (instr_bits & 0x400)
            op = i_pcmpbf;
        else
            op = i_or;
        break;

    case 0x22:
        if (instr_bits & 0x400)
            op = i_pcmpeq;
        else
            op = i_xor;
        break;
    case 0x23:
        if (instr_bits & 0x400)
            op = i_pcmpne;
        else
            op = i_andn;
        break;

    case 0x24:
        switch (instr_bits & 0xFFFF) {
        case 0x0001:
            op = i_sra;
            break;
        case 0x0021:
            op = i_src;
            break;
        case 0x0041:
            op = i_srl;
            break;
        case 0x0060:
            op = i_sext8;
            break;
        case 0x0061:
            op = i_sext16;
            break;
        default:

            switch (instr_bits & 0x1FFF) {
            case 0x0064:
                op = i_wdc;
                break;
            case 0x0068:
                op = i_wic;
                break;
            case 0x0074:
                op = i_wdc_flush;
                break;
            case 0x0066:
                op = i_wdc_clear;
                break;
            case 0x00e0:
                op = i_clz;
                break;
            case 0x00e6:
                op = i_wdc_clear_ea;
                break;
            case 0x01e0:
                op = i_swapb;
                break;
            case 0x01e2:
                op = i_swaph;
                break;
            case 0x0476:
                op = i_wdc_ext_flush;
                break;
            case 0x0466:
                op = i_wdc_ext_clear;
                break;
            default:
                return 0;
            }
            break;

        }
        break;

    case 0x25:
        switch (instr_bits & 0xC000) {
        case 0xC000:
            op = i_mts;
            break;
        case 0x8000:
            op = (instr_bits & 0x80000) ? i_mfse : i_mfs;
            break;
        case 0x4000:
        case 0x0000:
            if (instr_bits & 0x10000)
              op = i_msrclr;
            else
              op = i_msrset;
            break;
        default:
            return 0;
        }
        break;

    case 0x26:
        switch ((instr_bits >> 16) & 0x1F) {
        case 0x00:
            op = i_br;
            break;
        case 0x10:
            op = i_brd;
            break;
        case 0x14:
            op = i_brld;
            break;
        case 0x08:
            op = i_bra;
            break;
        case 0x18:
            op = i_brad;
            break;
        case 0x1C:
            op = i_brald;
            break;
        case 0x0C:
            op = i_brk;
            break;
        default:
            return 0;
        }
        break;

    case 0x27:
        switch ((instr_bits >> 21) & 0x1F) {
        case 0x00:
            op = i_beq;
            break;
        case 0x01:
            op = i_bne;
            break;
        case 0x02:
            op = i_blt;
            break;
        case 0x03:
            op = i_ble;
            break;
        case 0x04:
            op = i_bgt;
            break;
        case 0x05:
            op = i_bge;
            break;
        case 0x10:
            op = i_beqd;
            break;
        case 0x11:
            op = i_bned;
            break;
        case 0x12:
            op = i_bltd;
            break;
        case 0x13:
            op = i_bled;
            break;
        case 0x14:
            op = i_bgtd;
            break;
        case 0x15:
            op = i_bged;
            break;
        default:
            return 0;
        }
        break;

    case 0x2d:
        switch ((instr_bits >> 21) & 0x1F) {
        case 0x10:
            op = i_rtsd;
            break;
        case 0x11:
            op = i_rtid;
            break;
        case 0x12:
            op = i_rtbd;
            break;
        case 0x14:
            op = i_rted;
            break;
        default:
            return 0;
        }
        break;

    case 0x2e:
        switch ((instr_bits >> 16) & 0x1F) {
        case 0x00:
            op = i_bri;
            break;
        case 0x02:
            switch ((instr_bits >> 21) & 0x1F) {
            case 0x10:
                op = i_sleep;
                break;
            case 0x00:
            case 0x01:
            case 0x02:
                op = i_mbar;
                break;
            default:
                return 0;
            }
            break;
        case 0x10:
            op = i_brid;
            break;
        case 0x14:
            op = i_brlid;
            break;
        case 0x08:
            op = i_brai;
            break;
        case 0x18:
            op = i_braid;
            break;
        case 0x1C:
            op = i_bralid;
            break;
        case 0x0C:
            op = i_brki;
            break;
        default:
            return 0;
        }
        break;

    case 0x2f:
        switch ((instr_bits >> 21) & 0x1F) {
        case 0x00:
            op = i_beqi;
            break;
        case 0x01:
            op = i_bnei;
            break;
        case 0x02:
            op = i_blti;
            break;
        case 0x03:
            op = i_blei;
            break;
        case 0x04:
            op = i_bgti;
            break;
        case 0x05:
            op = i_bgei;
            break;
        case 0x10:
            op = i_beqid;
            break;
        case 0x11:
            op = i_bneid;
            break;
        case 0x12:
            op = i_bltid;
            break;
        case 0x13:
            op = i_bleid;
            break;
        case 0x14:
            op = i_bgtid;
            break;
        case 0x15:
            op = i_bgeid;
            break;
        default:
            return 0;
        }
        break;

    case 0x30:
        switch (instr_bits & 0x7FF) {
        case 0x000:
            op = i_lbu;
            break;
        case 0x200:
            op = i_lbur;
            break;
        case 0x080:
            op = i_lbuea;
            break;
        default:
            return 0;
        }
        break;

    case 0x31:
        switch (instr_bits & 0x7FF) {
        case 0x000:
            op = i_lhu;
            break;
        case 0x200:
            op = i_lhur;
            break;
        case 0x080:
            op = i_lhuea;
            break;
        default:
            return 0;
        }
        break;

    case 0x32:
        switch (instr_bits & 0x7FF) {
        case 0x000:
            op = i_lw;
            break;
        case 0x200:
            op = i_lwr;
            break;
        case 0x400:
            op = i_lwx;
            break;
        case 0x080:
            op = i_lwea;
            break;
        default:
            return 0;
        }
        break;

    case 0x34:
        switch (instr_bits & 0x7FF) {
        case 0x000:
            op = i_sb;
            break;
        case 0x200:
            op = i_sbr;
            break;
        case 0x080:
            op = i_sbea;
            break;
        default:
            return 0;
        }
        break;

    case 0x35:
        switch (instr_bits & 0x7FF) {
        case 0x000:
            op = i_sh;
            break;
        case 0x200:
            op = i_shr;
            break;
        case 0x080:
            op = i_shea;
            break;
        default:
            return 0;
        }
        break;

    case 0x36:
        switch (instr_bits & 0x7FF) {
        case 0x000:
            op = i_sw;
            break;
        case 0x200:
            op = i_swr;
            break;
        case 0x400:
            op = i_swx;
            break;
        case 0x080:
            op = i_swea;
            break;
        default:
            return 0;
        }
        break;

    case 0x16:  /* FP operation */
        switch((instr_bits >> 7) & 0x7) {
        case 0:
            op = i_fadd;
            break;
        case 1:
            op = i_frsub;
            break;
        case 2:
            op = i_fmul;
            break;
        case 3:
            op = i_fdiv;
            break;
        case 4: /* fp comparison */
            switch((instr_bits >> 4) & 0x7 ) {
            case 0:
                op = i_fcmp_un;
                break;
            case 1:
                op = i_fcmp_lt;
                break;
            case 2:
                op = i_fcmp_eq;
                break;
            case 3:
                op = i_fcmp_le;
                break;
            case 4:
                op = i_fcmp_gt;
                break;
            case 5:
                op = i_fcmp_ne;
                break;
            case 6:
                op = i_fcmp_ge;
                break;
            }
            break;
        case 5: /* int to fp conversion */
            op = i_flt;
            break;
        case 6: /* fp to int */
            op = i_fint;
            break;
        case 7:
            op = i_fsqrt;
            break;
        }
    }

    instr_op = op;
    instr_rd = (short) ((instr_bits >> 21) & 0x1F);
    instr_r1 = (short) ((instr_bits >> 16) & 0x1F);
    instr_r2 = (short) ((instr_bits >> 11) & 0x1F);

    switch (instruction_info[op].type) {
    case INST_TYPE_RD_IMM4:
    case INST_TYPE_RA_IMM4:
        instr_imm = (short) (instr_bits & 0xF);
        break;

    case INST_TYPE_RD_RA_IMM5:
        instr_imm = (short) (instr_bits & 0x1F);
        break;

    case INST_TYPE_RD_RA_IMM5_IMM5:
        if (instr_bits & 0x00004000)
            instr_imm = (short) ((instr_bits >> 6) & 0x1F);
        else
            instr_imm = (short) (((instr_bits >> 6) & 0x1F) - (instr_bits & 0x1F) + 1);
        instr_imm2 = (short) (instr_bits & 0x1F);
        break;

    case INST_TYPE_RD_IMM15:
        instr_imm = (short) (instr_bits & 0x7FFF);
        break;

    case INST_TYPE_RD_IMM:
    case INST_TYPE_RA_IMM:
    case INST_TYPE_RD_RA_IMM:
    case INST_TYPE_IMM:
        instr_imm = (short) (instr_bits & 0xFFFF);
        break;
    case INST_TYPE_IMM4:
        instr_imm = (short) (instr_bits & 0xF);
        break;
    case INST_TYPE_RDIMM:
        instr_imm = (short) ((instr_bits >> 21) & 0x1F);
        break;
    case INST_TYPE_RD_RA_RB:
    case INST_TYPE_RD_RA:
    case INST_TYPE_RD_RB:
    case INST_TYPE_RA_RB:
    case INST_TYPE_RD_SA:
    case INST_TYPE_SA_RA:
    case INST_TYPE_RA:
    case INST_TYPE_RB:
    case INST_TYPE_RD:
    case INST_TYPE_NULL:
        instr_imm = 0;
        break;
    }

    return 1;
}

static const char * SPREG_NAME_MFS[] = {
    "PC",  /* 0x0000 */
    "MSR", /* 0x0001 */
    "???",
    "EAR", /* 0x0003 */
    "???",
    "ESR", /* 0x0005 */
    "???",
    "FSR", /* 0x0007 */
    "???",
    "???",
    "???",
    "BTR", /* 0x000B */
    "???",
    "EDR", /* 0x000D */
    "???",
    "???",
};

static const char * SPREG_NAME_MTS[] = {
    "???",
    "MSR", /* 0x0001 */
    "???",
    "???",
    "???",
    "???",
    "???",
    "FSR", /* 0x0007 */
};

static const char * STACKREG_NAME[] = {
    "SLR", "???", "SHR", "???",
};

static const char * MMUREG_NAME_MFS[] = {
    "PID", "ZPR", "TLBX", "TLBLO", "TLBHI", "???", "???", "???"
};

static const char * MMUREG_NAME_MTS[] = {
    "PID", "ZPR", "TLBX", "TLBLO", "TLBHI", "TLBSX", "???", "???"
};

static const unsigned int MNEMONIC_FIELD_WIDTH = 14;

static char buf[128];
static size_t buf_pos = 0;
static Context * ctx = NULL;
static ContextAddress ctx_addr = 0;

static void add_char(char ch) {
    if (buf_pos >= sizeof(buf) - 1) return;
    buf[buf_pos++] = ch;
    if (ch == ' ') while (buf_pos < 8) buf[buf_pos++] = ch;
}

static void add_str(const char * s) {
    while (*s) add_char(*s++);
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

static void add_addr(uint32_t addr) {
    while (buf_pos < 16) add_char(' ');
    add_str("; addr=0x");
    add_hex_uint32(addr);
#if ENABLE_Symbols
    if (ctx != NULL) {
        Symbol * sym = NULL;
        char * name = NULL;
        ContextAddress sym_addr = 0;
        if (find_symbol_by_addr(ctx, STACK_NO_FRAME, addr, &sym) < 0) return;
        if (get_symbol_name(sym, &name) < 0 || name == NULL) return;
        if (get_symbol_address(sym, &sym_addr) < 0) return;
        if (sym_addr <= addr) {
            add_str(": ");
            add_str(name);
            if (sym_addr < addr) {
                add_str(" + 0x");
                add_hex_uint32(addr - (uint32_t)sym_addr);
            }
        }
    }
#endif
}

static int disassemble_instruction(void) {
    char tmp_buf[100];

    if (decode_instruction() == 0) {
        /* no such opcode */
        return -1;
    }

    add_str(instruction_info[instr_op].name);
    while (buf_pos < MNEMONIC_FIELD_WIDTH) buf[buf_pos++] = ' ';

    switch (instruction_info[instr_op].type) {
    case INST_TYPE_RD_RA_RB:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%-2d, r%-2d", instr_rd, instr_r1, instr_r2);
        break;
    case INST_TYPE_RD_RA_IMM:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%-2d, %d", instr_rd, instr_r1, instr_imm);
        break;
    case INST_TYPE_RD_RA_IMM5:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%-2d, %d", instr_rd, instr_r1, instr_imm);
        break;
    case INST_TYPE_RD_RA_IMM5_IMM5:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%-2d, %d, %d", instr_rd, instr_r1, instr_imm, instr_imm2);
        break;
    case INST_TYPE_RD_RA:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%-2d", instr_rd, instr_r1);
        break;
    case INST_TYPE_RD_RB:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%-2d", instr_rd, instr_r2);
        break;
    case INST_TYPE_RD_IMM:
    case INST_TYPE_RD_IMM15:
    case INST_TYPE_RD_IMM4:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, %d", instr_rd, instr_imm);
        break;
    case INST_TYPE_RA_RB:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%-2d", instr_r1, instr_r2);
        break;
    case INST_TYPE_RA_IMM:
    case INST_TYPE_RA_IMM4:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, %d", instr_r1, instr_imm);
        break;
    case INST_TYPE_RD_SA: /* mfs */
        if (instr_bits & 0x2000) { /* PVR */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, rPVR%d", instr_rd, (int)instr_bits & 0xf);
        }
        else if (instr_bits & 0x0800) { /* STACK REGs */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%s", instr_rd, STACKREG_NAME[instr_bits & 0x3]);
        }
        else if (instr_bits & 0x1000) { /* MMU REGs */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%s", instr_rd, MMUREG_NAME_MFS[instr_bits & 0x7]);
        }
        else {
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d, r%s", instr_rd, SPREG_NAME_MFS[instr_bits & 0xf]);
        }
        break;
    case INST_TYPE_SA_RA: /* mts */
        if (instr_bits & 0x0800) { /* STACK REGs */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%s, r%-2d", STACKREG_NAME[instr_bits & 0x3], instr_r1);
        }
        else if (instr_bits & 0x1000) { /* MMU REGs */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%s, r%-2d", MMUREG_NAME_MTS[instr_bits & 0x7], instr_r1);
        }
        else {
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-3s, r%-2d", SPREG_NAME_MTS[instr_bits & 0x7], instr_r1);
        }
        break;
    case INST_TYPE_RA:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d", instr_r1);
        break;
    case INST_TYPE_RB:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d", instr_r2);
        break;
    case INST_TYPE_RD:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2d", instr_rd);
        break;
    case INST_TYPE_IMM:
    case INST_TYPE_IMM4:
    case INST_TYPE_RDIMM:
        snprintf(tmp_buf, sizeof(tmp_buf), "%d", instr_imm);
        break;
    case INST_TYPE_NULL:
        tmp_buf[0] = 0;
        break;
    default:
        snprintf(tmp_buf, sizeof(tmp_buf), "invalid");
        break;
    }

    add_str(tmp_buf);

    if (ctx != NULL &&
            (instruction_info[instr_op].flags & F_CTRL) != 0 &&
            (instruction_info[instr_op].flags & F_IMM) != 0 &&
            (instruction_info[instr_op].flags & F_INDIRJMP) == 0 &&
            instruction_info[instr_op].type != INST_TYPE_NULL) {
        uint8_t mem[4];
        if (context_read_mem(ctx, ctx_addr - 4, mem, 4) == 0) {
            uint32_t addr = 0;
            if (mem[3] == 0xb0 && mem[2] == 0x00) {
                addr = (mem[1] << 24) | (mem[0] << 16) | instr_imm;
            }
            else if (instr_imm & (1 << 15)) {
                addr = 0xffff0000 | instr_imm;
            }
            else {
                addr = instr_imm;
            }
            if ((instruction_info[instr_op].flags & F_DIRECT) == 0) addr += (uint32_t)ctx_addr;
            while (buf_pos < 32) buf[buf_pos++] = ' ';
            add_addr(addr);
        }
    }

    return 0;
}

DisassemblyResult * disassemble_microblaze(uint8_t * code,
        ContextAddress addr, ContextAddress size, DisassemblerParams * params) {
    static DisassemblyResult dr;
    static int ini_done = 0;
    unsigned i;

    if (!ini_done) {
        unsigned l = sizeof(opcode_hash) / sizeof(opcode_hash[0]);
        for (i = 0; i < l; i++) {
            /* make all unknown by default */
            opcode_hash[i] = (enum Instructions)UNKNOWN_OPCODE;
        }
        for (i = 0; i < UNKNOWN_OPCODE; i++) {
            assert(instruction_info[i].hash < l);
            opcode_hash[instruction_info[i].hash] = (enum Instructions)i;
        }
        ini_done = 1;
    }

    if (size < 4) return NULL;
    buf_pos = 0;
    ctx = params->ctx;
    ctx_addr = addr;
    instr_bits = 0;
    for (i = 0; i < 4; i++) {
        instr_bits |= (uint32_t)code[i] << (params->big_endian ? 3 - i : i) * 8;
    }
    if (disassemble_instruction() < 0) return NULL;
    buf[buf_pos++] = 0;
    memset(&dr, 0, sizeof(dr));
    dr.size = 4;
    dr.text = buf;
    return &dr;
}
