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
#include <tcf/framework/myalloc.h>
#include <tcf/services/symbols.h>
#include <machine/microblaze/tcf/disassembler-microblaze.h>

enum InstructionType {
    INST_TYPE_RD_RA_RB,
    INST_TYPE_RD_RA_IMM,
    INST_TYPE_RD_RA_IMM5,
    INST_TYPE_RD_RA_IMM6,
    INST_TYPE_RD_RA_IMM5_IMM5,
    INST_TYPE_RD_RA_IMM6_IMM6,
    INST_TYPE_RD_RA,
    INST_TYPE_RD_RB,
    INST_TYPE_RD_IMM,
    INST_TYPE_RD_IMM15,
    INST_TYPE_RD_IMM4,
    INST_TYPE_RA_RB,
    INST_TYPE_RA_IMM,
    INST_TYPE_RA_IMML,
    INST_TYPE_RA_IMM4,
    INST_TYPE_RD_SA,
    INST_TYPE_SA_RA,
    INST_TYPE_RA,
    INST_TYPE_RB,
    INST_TYPE_RD,
    INST_TYPE_IMM,
    INST_TYPE_IMM4,
    INST_TYPE_IMML,
    INST_TYPE_RDIMM,
    INST_TYPE_NULL
};

enum InstructionFlags {
    F_CTRL       = 0x00000001,
    F_ABS        = 0x00000002,
    F_INDIRJMP   = 0x00000004,
    F_IMM        = 0x00000008,
};

enum Instructions {
    /* 32-bit instructions */
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
    i_xori,
    /* 64-bit instructions */
    i_addl,           i_rsubl,          i_addlc,          i_rsublc,
    i_addlk,          i_rsublk,         i_addlkc,         i_rsublkc,
    i_cmpl,           i_cmplu,          i_addli,          i_rsubli,
    i_addlic,         i_rsublic,        i_addlik,         i_rsublik,
    i_addlikc,        i_rsublikc,       i_mull,
    i_bslll,          i_bslra,          i_bslrl,          i_bsllli,
    i_bslrai,         i_bslrli,         i_bslefi,         i_bslifi,
    i_orl,            i_andl,           i_xorl,           i_andnl,
    i_pcmplbf,        i_pcmpleq,        i_pcmplne,
    i_srla,           i_srlc,           i_srll,
    i_sextl8,         i_sextl16,        i_sextl32,
    i_brea,           i_bread,          i_breald,         i_beaeq,
    i_bealeq,         i_beaeqd,         i_bealeqd,        i_beane,
    i_bealne,         i_beaned,         i_bealned,        i_bealt,
    i_beallt,         i_bealtd,         i_bealltd,        i_beale,
    i_bealle,         i_bealed,         i_bealled,        i_beagt,
    i_bealgt,         i_beagtd,         i_bealgtd,        i_beage,
    i_bealge,         i_beaged,         i_bealged,
    i_orli,           i_andli,          i_xorli,          i_andnli,
    i_imml,
    i_breai,          i_breaid,         i_brealid,        i_beaeqi,
    i_bealeqi,        i_beaeqid,        i_bealeqid,       i_beanei,
    i_bealnei,        i_beaneid,        i_bealneid,       i_bealti,
    i_beallti,        i_bealtid,        i_bealltid,       i_bealei,
    i_beallei,        i_bealeid,        i_bealleid,       i_beagti,
    i_bealgti,        i_beagtid,        i_bealgtid,       i_beagei,
    i_bealgei,        i_beageid,        i_bealgeid,
    i_ll,             i_llr,            i_sl,             i_slr,
    i_dadd,           i_drsub,          i_dmul,           i_ddiv,
    i_dcmp_lt,        i_dcmp_eq,        i_dcmp_le,        i_dcmp_gt,
    i_dcmp_ne,        i_dcmp_ge,        i_dcmp_un,        i_dbl,
    i_dlong,          i_dsqrt,
    i_lli,            i_sli,
};

typedef struct InstructionInfo {
    unsigned hash;
    enum Instructions op;
    const char * name;
    unsigned type;
    unsigned flags;
} InstructionInfo;

#define OP(x) i_##x, #x

static InstructionInfo instruction_info[] = {
    { 0x00, OP(add),            INST_TYPE_RD_RA_RB, 0 },
    { 0x02, OP(addc),           INST_TYPE_RD_RA_RB, 0 },
    { 0x08, OP(addi),           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0a, OP(addic),          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0c, OP(addik),          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0e, OP(addikc),         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x04, OP(addk),           INST_TYPE_RD_RA_RB, 0 },
    { 0x06, OP(addkc),          INST_TYPE_RD_RA_RB, 0 },
    { 0x1b, OP(aget),           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(agetd),          INST_TYPE_RD_RB, 0 },
    { 0x21, OP(and),            INST_TYPE_RD_RA_RB, 0 },
    { 0x29, OP(andi),           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x23, OP(andn),           INST_TYPE_RD_RA_RB, 0 },
    { 0x2b, OP(andni),          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x1b, OP(aput),           INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, OP(aputd),          INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beq),            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, OP(beqd),           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, OP(beqi),           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, OP(beqid),          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, OP(bge),            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, OP(bged),           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, OP(bgei),           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, OP(bgeid),          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, OP(bgt),            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, OP(bgtd),           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, OP(bgti),           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, OP(bgtid),          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, OP(ble),            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, OP(bled),           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, OP(blei),           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, OP(bleid),          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, OP(blt),            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, OP(bltd),           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, OP(blti),           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, OP(bltid),          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x27, OP(bne),            INST_TYPE_RA_RB, F_CTRL },
    { 0x27, OP(bned),           INST_TYPE_RA_RB, F_CTRL },
    { 0x2f, OP(bnei),           INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x2f, OP(bneid),          INST_TYPE_RA_IMM, F_CTRL|F_IMM },
    { 0x26, OP(br),             INST_TYPE_RB, F_CTRL },
    { 0x26, OP(bra),            INST_TYPE_RB, F_CTRL },
    { 0x26, OP(brad),           INST_TYPE_RB, F_CTRL },
    { 0x2e, OP(brai),           INST_TYPE_IMM, F_CTRL|F_ABS|F_IMM },
    { 0x2e, OP(braid),          INST_TYPE_IMM, F_CTRL|F_ABS|F_IMM },
    { 0x26, OP(brald),          INST_TYPE_RD_RB, F_CTRL },
    { 0x2e, OP(bralid),         INST_TYPE_RD_IMM, F_CTRL|F_ABS|F_IMM },
    { 0x26, OP(brd),            INST_TYPE_RB, F_CTRL },
    { 0x2e, OP(bri),            INST_TYPE_IMM, F_CTRL|F_IMM },
    { 0x2e, OP(brid),           INST_TYPE_IMM, F_CTRL|F_IMM },
    { 0x26, OP(brk),            INST_TYPE_RD_RB, F_CTRL },
    { 0x2e, OP(brki),           INST_TYPE_RD_IMM, F_CTRL|F_IMM },
    { 0x26, OP(brld),           INST_TYPE_RD_RB, F_CTRL },
    { 0x2e, OP(brlid),          INST_TYPE_RD_IMM, F_CTRL|F_IMM },
    { 0x19, OP(bsefi),          INST_TYPE_RD_RA_IMM5_IMM5, F_IMM },
    { 0x19, OP(bsifi),          INST_TYPE_RD_RA_IMM5_IMM5, F_IMM },
    { 0x11, OP(bsll),           INST_TYPE_RD_RA_RB, 0 },
    { 0x19, OP(bslli),          INST_TYPE_RD_RA_IMM5, F_IMM },
    { 0x11, OP(bsra),           INST_TYPE_RD_RA_RB, 0 },
    { 0x19, OP(bsrai),          INST_TYPE_RD_RA_IMM5, F_IMM },
    { 0x11, OP(bsrl),           INST_TYPE_RD_RA_RB, 0 },
    { 0x19, OP(bsrli),          INST_TYPE_RD_RA_IMM5, F_IMM },
    { 0x1b, OP(caget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(cagetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(caput),          INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, OP(caputd),         INST_TYPE_RA_RB, 0 },
    { 0x1b, OP(cget),           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(cgetd),          INST_TYPE_RD_RB, 0 },
    { 0x24, OP(clz),            INST_TYPE_RD_RA, 0 },
    { 0x05, OP(cmp),            INST_TYPE_RD_RA_RB, 0 },
    { 0x05, OP(cmpu),           INST_TYPE_RD_RA_RB, 0 },
    { 0x1b, OP(cput),           INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, OP(cputd),          INST_TYPE_RA_RB, 0 },
    { 0x1b, OP(eaget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(eagetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(ecaget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(ecagetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(ecget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(ecgetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(eget),           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(egetd),          INST_TYPE_RD_RB, 0 },
    { 0x16, OP(fadd),           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_fcmp_eq, "fcmp.eq", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_fcmp_ge, "fcmp.ge", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_fcmp_gt, "fcmp.gt", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_fcmp_le, "fcmp.le", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_fcmp_lt, "fcmp.lt", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_fcmp_ne, "fcmp.ne", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_fcmp_un, "fcmp.un", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(fdiv),           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(fint),           INST_TYPE_RD_RA, 0 },
    { 0x16, OP(flt),            INST_TYPE_RD_RA, 0 },
    { 0x16, OP(fmul),           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(frsub),          INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(fsqrt),          INST_TYPE_RD_RA, 0 },
    { 0x1b, OP(get),            INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(getd),           INST_TYPE_RD_RB, 0 },
    { 0x12, OP(idiv),           INST_TYPE_RD_RA_RB, 0 },
    { 0x12, OP(idivu),          INST_TYPE_RD_RA_RB, 0 },
    { 0x2c, OP(imm),            INST_TYPE_IMM, F_IMM },
    { 0x30, OP(lbu),            INST_TYPE_RD_RA_RB, 0 },
    { 0x30, OP(lbuea),          INST_TYPE_RD_RA_RB, 0 },
    { 0x38, OP(lbui),           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x30, OP(lbur),           INST_TYPE_RD_RA_RB, 0 },
    { 0x31, OP(lhu),            INST_TYPE_RD_RA_RB, 0 },
    { 0x31, OP(lhuea),          INST_TYPE_RD_RA_RB, 0 },
    { 0x39, OP(lhui),           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x31, OP(lhur),           INST_TYPE_RD_RA_RB, 0 },
    { 0x32, OP(lw),             INST_TYPE_RD_RA_RB, 0 },
    { 0x32, OP(lwea),           INST_TYPE_RD_RA_RB, 0 },
    { 0x3a, OP(lwi),            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x32, OP(lwr),            INST_TYPE_RD_RA_RB, 0 },
    { 0x32, OP(lwx),            INST_TYPE_RD_RA_RB, 0 },
    { 0x2e, OP(mbar),           INST_TYPE_RDIMM, F_CTRL|F_ABS|F_IMM },
    { 0x25, OP(mfs),            INST_TYPE_RD_SA, 0 },
    { 0x25, OP(mfse),           INST_TYPE_RD_SA, 0 },
    { 0x25, OP(msrclr),         INST_TYPE_RD_IMM15, 0 },
    { 0x25, OP(msrset),         INST_TYPE_RD_IMM15, 0 },
    { 0x25, OP(mts),            INST_TYPE_SA_RA, 0 },
    { 0x10, OP(mul),            INST_TYPE_RD_RA_RB, 0 },
    { 0x10, OP(mulh),           INST_TYPE_RD_RA_RB, 0 },
    { 0x10, OP(mulhsu),         INST_TYPE_RD_RA_RB, 0 },
    { 0x10, OP(mulhu),          INST_TYPE_RD_RA_RB, 0 },
    { 0x18, OP(muli),           INST_TYPE_RD_RA_IMM, 0 },
    { 0x1b, OP(naget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(nagetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(naput),          INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, OP(naputd),         INST_TYPE_RA_RB, 0 },
    { 0x1b, OP(ncaget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(ncagetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(ncaput),         INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, OP(ncaputd),        INST_TYPE_RA_RB, 0 },
    { 0x1b, OP(ncget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(ncgetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(ncput),          INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, OP(ncputd),         INST_TYPE_RA_RB, 0 },
    { 0x1b, OP(neaget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(neagetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(necaget),        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(necagetd),       INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(necget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(necgetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(neget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(negetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(nget),           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(ngetd),          INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(nput),           INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, OP(nputd),          INST_TYPE_RA_RB, 0 },
    { 0x20, OP(or),             INST_TYPE_RD_RA_RB, 0 },
    { 0x28, OP(ori),            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x20, OP(pcmpbf),         INST_TYPE_RD_RA_RB, 0 },
    { 0x22, OP(pcmpeq),         INST_TYPE_RD_RA_RB, 0 },
    { 0x23, OP(pcmpne),         INST_TYPE_RD_RA_RB, 0 },
    { 0x1b, OP(put),            INST_TYPE_RA_IMM4, F_IMM },
    { 0x13, OP(putd),           INST_TYPE_RA_RB, 0 },
    { 0x01, OP(rsub),           INST_TYPE_RD_RA_RB, 0 },
    { 0x03, OP(rsubc),          INST_TYPE_RD_RA_RB, 0 },
    { 0x09, OP(rsubi),          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0b, OP(rsubic),         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0d, OP(rsubik),         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0f, OP(rsubikc),        INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x05, OP(rsubk),          INST_TYPE_RD_RA_RB, 0 },
    { 0x07, OP(rsubkc),         INST_TYPE_RD_RA_RB, 0 },
    { 0x2d, OP(rtbd),           INST_TYPE_RA_IMM, F_CTRL|F_INDIRJMP|F_IMM },
    { 0x2d, OP(rted),           INST_TYPE_RA_IMM, F_CTRL|F_INDIRJMP|F_IMM },
    { 0x2d, OP(rtid),           INST_TYPE_RA_IMM, F_CTRL|F_INDIRJMP|F_IMM },
    { 0x2d, OP(rtsd),           INST_TYPE_RA_IMM, F_CTRL|F_INDIRJMP|F_IMM },
    { 0x34, OP(sb),             INST_TYPE_RD_RA_RB, 0 },
    { 0x34, OP(sbea),           INST_TYPE_RD_RA_RB, 0 },
    { 0x3c, OP(sbi),            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x34, OP(sbr),            INST_TYPE_RD_RA_RB, 0 },
    { 0x24, OP(sext16),         INST_TYPE_RD_RA, 0 },
    { 0x24, OP(sext8),          INST_TYPE_RD_RA, 0 },
    { 0x35, OP(sh),             INST_TYPE_RD_RA_RB, 0 },
    { 0x35, OP(shea),           INST_TYPE_RD_RA_RB, 0 },
    { 0x3d, OP(shi),            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x35, OP(shr),            INST_TYPE_RD_RA_RB, 0 },
    { 0x2e, OP(sleep),          INST_TYPE_NULL, F_CTRL|F_ABS|F_IMM },
    { 0x24, OP(sra),            INST_TYPE_RD_RA, 0 },
    { 0x24, OP(src),            INST_TYPE_RD_RA, 0 },
    { 0x24, OP(srl),            INST_TYPE_RD_RA, 0 },
    { 0x36, OP(sw),             INST_TYPE_RD_RA_RB, 0 },
    { 0x24, OP(swapb),          INST_TYPE_RD_RA, 0 },
    { 0x24, OP(swaph),          INST_TYPE_RD_RA, 0 },
    { 0x36, OP(swea),           INST_TYPE_RD_RA_RB, 0 },
    { 0x3e, OP(swi),            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x36, OP(swr),            INST_TYPE_RD_RA_RB, 0 },
    { 0x36, OP(swx),            INST_TYPE_RD_RA_RB, 0 },
    { 0x1b, OP(taget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tagetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(taput),          INST_TYPE_IMM4, F_IMM },
    { 0x13, OP(taputd),         INST_TYPE_RB, 0 },
    { 0x1b, OP(tcaget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tcagetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tcaput),         INST_TYPE_IMM4, F_IMM },
    { 0x13, OP(tcaputd),        INST_TYPE_RB, 0 },
    { 0x1b, OP(tcget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tcgetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tcput),          INST_TYPE_IMM4, F_IMM },
    { 0x13, OP(tcputd),         INST_TYPE_RB, 0 },
    { 0x1b, OP(teaget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(teagetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tecaget),        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tecagetd),       INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tecget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tecgetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(teget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tegetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tget),           INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tgetd),          INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tnaget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tnagetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tnaput),         INST_TYPE_IMM4, F_IMM },
    { 0x13, OP(tnaputd),        INST_TYPE_RB, 0 },
    { 0x1b, OP(tncaget),        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tncagetd),       INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tncaput),        INST_TYPE_IMM4, F_IMM },
    { 0x13, OP(tncaputd),       INST_TYPE_RB, 0 },
    { 0x1b, OP(tncget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tncgetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tncput),         INST_TYPE_IMM4, F_IMM },
    { 0x13, OP(tncputd),        INST_TYPE_RB, 0 },
    { 0x1b, OP(tneaget),        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tneagetd),       INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tnecaget),       INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tnecagetd),      INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tnecget),        INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tnecgetd),       INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tneget),         INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tnegetd),        INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tnget),          INST_TYPE_RD_IMM4, F_IMM },
    { 0x13, OP(tngetd),         INST_TYPE_RD_RB, 0 },
    { 0x1b, OP(tnput),          INST_TYPE_IMM4, F_IMM },
    { 0x13, OP(tnputd),         INST_TYPE_RB, 0 },
    { 0x1b, OP(tput),           INST_TYPE_IMM4, F_IMM },
    { 0x13, OP(tputd),          INST_TYPE_RB, 0 },
    { 0x24, OP(wdc),            INST_TYPE_RA_RB, 0 },
    { 0x24, i_wdc_clear,     "wdc.clear",     INST_TYPE_RA_RB, 0 },
    { 0x24, i_wdc_clear_ea,  "wdc.clear.ea",  INST_TYPE_RA_RB, 0 },
    { 0x24, i_wdc_ext_clear, "wdc.ext.clear", INST_TYPE_RA_RB, 0 },
    { 0x24, i_wdc_ext_flush, "wdc.ext.flush", INST_TYPE_RA_RB, 0 },
    { 0x24, i_wdc_flush,     "wdc.flush",     INST_TYPE_RA_RB, 0 },
    { 0x24, OP(wic),            INST_TYPE_RA_RB, 0 },
    { 0x22, OP(xor),            INST_TYPE_RD_RA_RB, 0 },
    { 0x2a, OP(xori),           INST_TYPE_RD_RA_IMM, F_IMM },

    /* 64-bit instructions */
    { 0x00, OP(addl),           INST_TYPE_RD_RA_RB, 0 },
    { 0x01, OP(rsubl),          INST_TYPE_RD_RA_RB, 0 },
    { 0x02, OP(addlc),          INST_TYPE_RD_RA_RB, 0 },
    { 0x03, OP(rsublc),         INST_TYPE_RD_RA_RB, 0 },
    { 0x04, OP(addlk),          INST_TYPE_RD_RA_RB, 0 },
    { 0x05, OP(rsublk),         INST_TYPE_RD_RA_RB, 0 },
    { 0x06, OP(addlkc),         INST_TYPE_RD_RA_RB, 0 },
    { 0x07, OP(rsublkc),        INST_TYPE_RD_RA_RB, 0 },
    { 0x05, OP(cmpl),           INST_TYPE_RD_RA_RB, 0 },
    { 0x05, OP(cmplu),          INST_TYPE_RD_RA_RB, 0 },
    { 0x08, OP(addli),          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x09, OP(rsubli),         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0a, OP(addlic),         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0b, OP(rsublic),        INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0c, OP(addlik),         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0d, OP(rsublik),        INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0e, OP(addlikc),        INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x0f, OP(rsublikc),       INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x10, OP(mull),           INST_TYPE_RD_RA_RB, 0 },
    { 0x11, OP(bslll),          INST_TYPE_RD_RA_RB, 0 },
    { 0x11, OP(bslra),          INST_TYPE_RD_RA_RB, 0 },
    { 0x11, OP(bslrl),          INST_TYPE_RD_RA_RB, 0 },
    { 0x19, OP(bsllli),         INST_TYPE_RD_RA_IMM6, F_IMM },
    { 0x19, OP(bslrai),         INST_TYPE_RD_RA_IMM6, F_IMM },
    { 0x19, OP(bslrli),         INST_TYPE_RD_RA_IMM6, F_IMM },
    { 0x19, OP(bslefi),         INST_TYPE_RD_RA_IMM6_IMM6, F_IMM },
    { 0x19, OP(bslifi),         INST_TYPE_RD_RA_IMM6_IMM6, F_IMM },
    { 0x20, OP(orl),            INST_TYPE_RD_RA_RB, 0 },
    { 0x21, OP(andl),           INST_TYPE_RD_RA_RB, 0 },
    { 0x22, OP(xorl),           INST_TYPE_RD_RA_RB, 0 },
    { 0x23, OP(andnl),          INST_TYPE_RD_RA_RB, 0 },
    { 0x20, OP(pcmplbf),        INST_TYPE_RD_RA_RB, 0 },
    { 0x22, OP(pcmpleq),        INST_TYPE_RD_RA_RB, 0 },
    { 0x23, OP(pcmplne),        INST_TYPE_RD_RA_RB, 0 },
    { 0x24, OP(srla),           INST_TYPE_RD_RA, 0 },
    { 0x24, OP(srlc),           INST_TYPE_RD_RA, 0 },
    { 0x24, OP(srll),           INST_TYPE_RD_RA, 0 },
    { 0x24, OP(sextl8),         INST_TYPE_RD_RA, 0 },
    { 0x24, OP(sextl16),        INST_TYPE_RD_RA, 0 },
    { 0x24, OP(sextl32),        INST_TYPE_RD_RA, 0 },
    { 0x26, OP(brea),           INST_TYPE_RB, 0 },
    { 0x26, OP(bread),          INST_TYPE_RB, 0 },
    { 0x26, OP(breald),         INST_TYPE_RD_RB, 0 },
    { 0x27, OP(beaeq),          INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealeq),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beaeqd),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealeqd),        INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beane),          INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealne),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beaned),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealned),        INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealt),          INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beallt),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealtd),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealltd),        INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beale),          INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealle),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealed),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealled),        INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beagt),          INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealgt),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beagtd),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealgtd),        INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beage),          INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealge),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(beaged),         INST_TYPE_RA_RB, 0 },
    { 0x27, OP(bealged),        INST_TYPE_RA_RB, 0 },
    { 0x28, OP(orli),           INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x29, OP(andli),          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x2a, OP(xorli),          INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x2b, OP(andnli),         INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x2c, OP(imml),           INST_TYPE_IMML, F_IMM },
    { 0x2e, OP(breai),          INST_TYPE_IMM, F_IMM },
    { 0x2e, OP(breaid),         INST_TYPE_IMM, F_IMM },
    { 0x2e, OP(brealid),        INST_TYPE_RD_IMM, F_IMM },
    { 0x2f, OP(beaeqi),         INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealeqi),        INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(beaeqid),        INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealeqid),       INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(beanei),         INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealnei),        INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(beaneid),        INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealneid),       INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(bealti),         INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(beallti),        INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(bealtid),        INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealltid),       INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(bealei),         INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(beallei),        INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(bealeid),        INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealleid),       INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(beagti),         INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealgti),        INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(beagtid),        INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealgtid),       INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(beagei),         INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealgei),        INST_TYPE_RA_IMML, F_IMM },
    { 0x2f, OP(beageid),        INST_TYPE_RA_IMM, F_IMM },
    { 0x2f, OP(bealgeid),       INST_TYPE_RA_IMML, F_IMM },
    { 0x32, OP(ll),             INST_TYPE_RD_RA_RB, 0 },
    { 0x32, OP(llr),            INST_TYPE_RD_RA_RB, 0 },
    { 0x36, OP(sl),             INST_TYPE_RD_RA_RB, 0 },
    { 0x36, OP(slr),            INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(dadd),           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(drsub),          INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(dmul),           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(ddiv),           INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_dcmp_lt, "dcmp.lt", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_dcmp_eq, "dcmp.eq", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_dcmp_le, "dcmp.le", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_dcmp_gt, "dcmp.gt", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_dcmp_ne, "dcmp.ne", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_dcmp_ge, "dcmp.ge", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, i_dcmp_un, "dcmp.un", INST_TYPE_RD_RA_RB, 0 },
    { 0x16, OP(dbl),            INST_TYPE_RD_RA, 0 },
    { 0x16, OP(dlong),          INST_TYPE_RD_RA, 0 },
    { 0x16, OP(dsqrt),          INST_TYPE_RD_RA, 0 },
    { 0x3b, OP(lli),            INST_TYPE_RD_RA_IMM, F_IMM },
    { 0x3f, OP(sli),            INST_TYPE_RD_RA_IMM, F_IMM },
};

#define UNKNOWN_OPCODE ((enum Instructions)(sizeof(instruction_info) / sizeof(InstructionInfo)))

/* opcode_hash[] maps 6 most significant bits of the instruction into enum Instructions.
 * This is done to speed up opcode lookup. Some instructions have the same 6 MSb,
 * so further decode will still be necessary (done in decode_instruction). */
static enum Instructions opcode_hash[64];

static ContextAddress ctx_addr = 0;
static DisassemblerParams * disass_params = NULL;
static uint32_t instr_bits = 0;
static int en_64_bit = 0;

/* Decoded instruction */
static unsigned instr_op = UNKNOWN_OPCODE; /* index in instruction_info */
static unsigned instr_r1 = 0;
static unsigned instr_r2 = 0;
static unsigned instr_rd = 0;
static unsigned instr_imm = 0;
static unsigned instr_imm2 = 0;

typedef struct DecodingState {
    ContextAddress addr;
    uint32_t instr;
} DecodingState;

static int is_preceded_by_imml(void) {
    DecodingState * state = (DecodingState *)disass_params->state;
    return state != NULL && state->addr == ctx_addr - 4 && (state->instr & 0xff000000) == 0xb2000000;
}

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
    case 0x00:
        op = instr_bits & 0x100 ? i_addl : i_add;
        break;

    case 0x01:
        op = instr_bits & 0x100 ? i_rsubl : i_rsub;
        break;

    case 0x02:
        op = instr_bits & 0x100 ? i_addlc : i_addc;
        break;

    case 0x03:
        op = instr_bits & 0x100 ? i_rsublc : i_rsubc;
        break;

    case 0x04:
        op = instr_bits & 0x100 ? i_addlk : i_addk;
        break;

    case 0x05:
        if (instr_bits & 0x100) {
            switch (instr_bits & 0x0003) {
            case 0x0: op = i_rsublk; break;
            case 0x1: op = i_cmpl;   break;
            case 0x3: op = i_cmplu;  break;
            default: return 0;
            }
            break;
        }
        switch (instr_bits & 0x0003) {
        case 0x0: op = i_rsubk; break;
        case 0x1: op = i_cmp;   break;
        case 0x3: op = i_cmpu;  break;
        default: return 0;
        }
        break;

    case 0x06:
        op = instr_bits & 0x100 ? i_addlkc : i_addkc;
        break;

    case 0x07:
        op = instr_bits & 0x100 ? i_rsublkc : i_rsubkc;
        break;

    case 0x08:
        op = is_preceded_by_imml() ? i_addli : i_addi;
        break;

    case 0x09:
        op = is_preceded_by_imml() ? i_rsubli : i_rsubi;
        break;

    case 0x0a:
        op = is_preceded_by_imml() ? i_addlic : i_addic;
        break;

    case 0x0b:
        op = is_preceded_by_imml() ? i_rsublic : i_rsubic;
        break;

    case 0x0c:
        op = is_preceded_by_imml() ? i_addlik : i_addik;
        break;

    case 0x0d:
        op = is_preceded_by_imml() ? i_rsublik : i_rsubik;
        break;

    case 0x0e:
        op = is_preceded_by_imml() ? i_addlikc : i_addikc;
        break;

    case 0x0f:
        op = is_preceded_by_imml() ? i_rsublikc : i_rsubikc;
        break;

    case 0x10:
        switch (instr_bits & 0x3) {
        case 0x0: op = i_mul;   break;
        case 0x1: op = i_mulh;  break;
        case 0x2: op = i_mulhsu; break;
        case 0x3: op = i_mulhu; break;
        }
        break;

    case 0x11:
        switch (instr_bits & 0x600) {
        case 0x000: op = instr_bits & 0x100 ? i_bslrl : i_bsrl; break;
        case 0x200: op = instr_bits & 0x100 ? i_bslra : i_bsra; break;
        case 0x400: op = instr_bits & 0x100 ? i_bslll : i_bsll; break;
        default: return 0;
        }
        break;

    case 0x12:
        switch (instr_bits & 0x0002) {
        case 0x0000: op = i_idiv; break;
        case 0x0002: op = i_idivu; break;
        default: return 0;
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
        default: return 0;
        }
        break;

    case 0x16:  /* FP operation */
        if (instr_bits & 0x400) {
            switch ((instr_bits >> 7) & 0x7) {
            case 0x0: op = i_dadd; break;
            case 0x1: op = i_drsub; break;
            case 0x2: op = i_dmul; break;
            case 0x3: op = i_ddiv; break;
            case 0x4:
                switch ((instr_bits >> 4) & 0x7) {
                case 0: op = i_dcmp_un; break;
                case 1: op = i_dcmp_lt; break;
                case 2: op = i_dcmp_eq; break;
                case 3: op = i_dcmp_le; break;
                case 4: op = i_dcmp_gt; break;
                case 5: op = i_dcmp_ne; break;
                case 6: op = i_dcmp_ge; break;
                }
                break;
            case 0x5: op = i_dbl; break;
            case 0x6: op = i_dlong; break;
            case 0x7: op = i_dsqrt; break;
            }
            break;
        }
        switch((instr_bits >> 7) & 0x7) {
        case 0: op = i_fadd; break;
        case 1: op = i_frsub; break;
        case 2: op = i_fmul; break;
        case 3: op = i_fdiv; break;
        case 4: /* fp comparison */
            switch ((instr_bits >> 4) & 0x7) {
            case 0: op = i_fcmp_un; break;
            case 1: op = i_fcmp_lt; break;
            case 2: op = i_fcmp_eq; break;
            case 3: op = i_fcmp_le; break;
            case 4: op = i_fcmp_gt; break;
            case 5: op = i_fcmp_ne; break;
            case 6: op = i_fcmp_ge; break;
            }
            break;
        case 5: op = i_flt; break;
        case 6: op = i_fint; break;
        case 7: op = i_fsqrt; break;
        }
        break;

    case 0x19:
        switch (instr_bits & 0xe600) {
        case 0x0000: op = i_bsrli; break;
        case 0x0200: op = i_bsrai; break;
        case 0x0400: op = i_bslli; break;
        case 0x4000: op = i_bsefi; break;
        case 0x8000: op = i_bsifi; break;
        case 0x2000: op = i_bslrli; break;
        case 0x2200: op = i_bslrai; break;
        case 0x2400: op = i_bsllli; break;
        case 0x6000: op = i_bslefi; break;
        case 0xa000: op = i_bslifi; break;
        default: return 0;
        }
        break;

    case 0x1b:
        switch ((instr_bits >> 10) & 0x3f) {
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
        default: return 0;
        }
        break;

    case 0x20:
        if (instr_bits & 0x400)
            op = instr_bits & 0x100 ? i_pcmplbf : i_pcmpbf;
        else
            op = instr_bits & 0x100 ? i_orl : i_or;
        break;

    case 0x21:
        op = instr_bits & 0x100 ? i_andl : i_and;
        break;

    case 0x22:
        if (instr_bits & 0x400)
            op = instr_bits & 0x100 ? i_pcmpleq : i_pcmpeq;
        else
            op = instr_bits & 0x100 ? i_xorl : i_xor;
        break;

    case 0x23:
        if (instr_bits & 0x400)
            op = instr_bits & 0x100 ? i_pcmplne : i_pcmpne;
        else
            op = instr_bits & 0x100 ? i_andnl : i_andn;
        break;

    case 0x24:
        switch (instr_bits & 0xffff) {
        case 0x0001: op = i_sra; break;
        case 0x0021: op = i_src; break;
        case 0x0041: op = i_srl; break;
        case 0x0060: op = i_sext8; break;
        case 0x0061: op = i_sext16; break;
        case 0x0101: op = i_srla; break;
        case 0x0121: op = i_srlc; break;
        case 0x0141: op = i_srll; break;
        case 0x0160: op = i_sextl8; break;
        case 0x0161: op = i_sextl16; break;
        case 0x0162: op = i_sextl32; break;
        default:
            switch (instr_bits & 0x1fff) {
            case 0x0064: op = i_wdc; break;
            case 0x0068: op = i_wic; break;
            case 0x0074: op = i_wdc_flush; break;
            case 0x0066: op = i_wdc_clear; break;
            case 0x00e0: op = i_clz; break;
            case 0x00e6: op = i_wdc_clear_ea; break;
            case 0x01e0: op = i_swapb; break;
            case 0x01e2: op = i_swaph; break;
            case 0x0476: op = i_wdc_ext_flush; break;
            case 0x0466: op = i_wdc_ext_clear; break;
            default: return 0;
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
        case 0x00: op = i_br; break;
        case 0x10: op = i_brd; break;
        case 0x14: op = i_brld; break;
        case 0x08: op = i_bra; break;
        case 0x18: op = i_brad; break;
        case 0x1c: op = i_brald; break;
        case 0x01: op = i_brea; break;
        case 0x11: op = i_bread; break;
        case 0x15: op = i_breald; break;
        case 0x0c: op = i_brk; break;
        default: return 0;
        }
        break;

    case 0x27:
        switch ((instr_bits >> 21) & 0x1f) {
        case 0x00: op = i_beq; break;
        case 0x01: op = i_bne; break;
        case 0x02: op = i_blt; break;
        case 0x03: op = i_ble; break;
        case 0x04: op = i_bgt; break;
        case 0x05: op = i_bge; break;
        case 0x08: op = instr_bits & 0x100 ? i_bealeq : i_beaeq; break;
        case 0x09: op = instr_bits & 0x100 ? i_bealne : i_beane; break;
        case 0x0a: op = instr_bits & 0x100 ? i_beallt : i_bealt; break;
        case 0x0b: op = instr_bits & 0x100 ? i_bealle : i_beale; break;
        case 0x0c: op = instr_bits & 0x100 ? i_bealgt : i_beagt; break;
        case 0x0d: op = instr_bits & 0x100 ? i_bealge : i_beage; break;
        case 0x10: op = i_beqd; break;
        case 0x11: op = i_bned; break;
        case 0x12: op = i_bltd; break;
        case 0x13: op = i_bled; break;
        case 0x14: op = i_bgtd; break;
        case 0x15: op = i_bged; break;
        case 0x18: op = instr_bits & 0x100 ? i_bealeqd : i_beaeqd; break;
        case 0x19: op = instr_bits & 0x100 ? i_bealned : i_beaned; break;
        case 0x1a: op = instr_bits & 0x100 ? i_bealltd : i_bealtd; break;
        case 0x1b: op = instr_bits & 0x100 ? i_bealled : i_bealed; break;
        case 0x1c: op = instr_bits & 0x100 ? i_bealgtd : i_beagtd; break;
        case 0x1d: op = instr_bits & 0x100 ? i_bealged : i_beaged; break;
        default: return 0;
        }
        break;

    case 0x28:
        op = is_preceded_by_imml() ? i_orli : i_ori;
        break;

    case 0x29:
        op = is_preceded_by_imml() ? i_andli : i_andi;
        break;

    case 0x2a:
        op = is_preceded_by_imml() ? i_xorli : i_xori;
        break;

    case 0x2b:
        op = is_preceded_by_imml() ? i_andnli : i_andni;
        break;

    case 0x2c:
        if (((instr_bits >> 24) & 3) == 2) {
            op = i_imml;
            break;
        }
        break;

    case 0x2d:
        switch ((instr_bits >> 21) & 0x1F) {
        case 0x10: op = i_rtsd; break;
        case 0x11: op = i_rtid; break;
        case 0x12: op = i_rtbd; break;
        case 0x14: op = i_rted; break;
        default: return 0;
        }
        break;

    case 0x2e:
        switch ((instr_bits >> 16) & 0x1F) {
        case 0x00: op = i_bri; break;
        case 0x02:
            switch ((instr_bits >> 21) & 0x1F) {
            case 0x10: op = i_sleep; break;
            case 0x00:
            case 0x01:
            case 0x02:
                op = i_mbar;
                break;
            default: return 0;
            }
            break;
        case 0x10: op = i_brid; break;
        case 0x14: op = i_brlid; break;
        case 0x08: op = i_brai; break;
        case 0x18: op = i_braid; break;
        case 0x1c: op = i_bralid; break;
        case 0x01: op = i_breai; break;
        case 0x11: op = i_breaid; break;
        case 0x15: op = i_brealid; break;
        case 0x0c: op = i_brki; break;
        default: return 0;
        }
        break;

    case 0x2f:
        switch ((instr_bits >> 21) & 0x1F) {
        case 0x00: op = i_beqi; break;
        case 0x01: op = i_bnei; break;
        case 0x02: op = i_blti; break;
        case 0x03: op = i_blei; break;
        case 0x04: op = i_bgti; break;
        case 0x05: op = i_bgei; break;
        case 0x08: op = i_beaeqi; break;
        case 0x09: op = i_beanei; break;
        case 0x0a: op = i_bealti; break;
        case 0x0b: op = i_bealei; break;
        case 0x0c: op = i_beagti; break;
        case 0x0d: op = i_beagei; break;
        case 0x10: op = i_beqid; break;
        case 0x11: op = i_bneid; break;
        case 0x12: op = i_bltid; break;
        case 0x13: op = i_bleid; break;
        case 0x14: op = i_bgtid; break;
        case 0x15: op = i_bgeid; break;
        case 0x18: op = i_beaeqid; break;
        case 0x19: op = i_beaneid; break;
        case 0x1a: op = i_bealtid; break;
        case 0x1b: op = i_bealeid; break;
        case 0x1c: op = i_beagtid; break;
        case 0x1d: op = i_beageid; break;
        default: return 0;
        }
        break;

    case 0x30:
        switch (instr_bits & 0x7ff) {
        case 0x000: op = i_lbu; break;
        case 0x200: op = i_lbur; break;
        case 0x080: op = i_lbuea; break;
        default: return 0;
        }
        break;

    case 0x31:
        switch (instr_bits & 0x7ff) {
        case 0x000: op = i_lhu; break;
        case 0x200: op = i_lhur; break;
        case 0x080: op = i_lhuea; break;
        default: return 0;
        }
        break;

    case 0x32:
        switch (instr_bits & 0x7ff) {
        case 0x000: op = i_lw; break;
        case 0x100: op = i_ll; break;
        case 0x200: op = i_lwr; break;
        case 0x300: op = i_llr; break;
        case 0x400: op = i_lwx; break;
        case 0x080: op = i_lwea; break;
        default: return 0;
        }
        break;

    case 0x34:
        switch (instr_bits & 0x7ff) {
        case 0x000: op = i_sb; break;
        case 0x200: op = i_sbr; break;
        case 0x080: op = i_sbea; break;
        default: return 0;
        }
        break;

    case 0x35:
        switch (instr_bits & 0x7ff) {
        case 0x000: op = i_sh; break;
        case 0x200: op = i_shr; break;
        case 0x080: op = i_shea; break;
        default: return 0;
        }
        break;

    case 0x36:
        switch (instr_bits & 0x7ff) {
        case 0x000: op = i_sw; break;
        case 0x100: op = i_sl; break;
        case 0x200: op = i_swr; break;
        case 0x300: op = i_slr; break;
        case 0x400: op = i_swx; break;
        case 0x080: op = i_swea; break;
        default: return 0;
        }
        break;

    }

    instr_op = op;
    instr_rd = (instr_bits >> 21) & 0x1f;
    instr_r1 = (instr_bits >> 16) & 0x1f;
    instr_r2 = (instr_bits >> 11) & 0x1f;

    assert(op < UNKNOWN_OPCODE);
    switch (instruction_info[op].type) {
    case INST_TYPE_RD_IMM4:
    case INST_TYPE_RA_IMM4:
        instr_imm = instr_bits & 0xf;
        break;

    case INST_TYPE_RD_RA_IMM5:
        instr_imm = instr_bits & 0x1f;
        break;

    case INST_TYPE_RD_RA_IMM6:
        instr_imm = instr_bits & 0x3f;
        break;

    case INST_TYPE_RD_RA_IMM5_IMM5:
        if (instr_bits & 0x00004000)
            instr_imm = (instr_bits >> 6) & 0x1f;
        else
            instr_imm = ((instr_bits >> 6) & 0x1f) - (instr_bits & 0x1f) + 1;
        instr_imm2 = instr_bits & 0x1f;
        break;

    case INST_TYPE_RD_RA_IMM6_IMM6:
        if (instr_bits & 0x00004000)
            instr_imm = (instr_bits >> 6) & 0x3f;
        else
            instr_imm = ((instr_bits >> 6) & 0x3f) - (instr_bits & 0x3f) + 1;
        instr_imm2 = instr_bits & 0x3f;
        break;

    case INST_TYPE_RD_IMM15:
        instr_imm = instr_bits & 0x7fff;
        break;

    case INST_TYPE_RD_IMM:
    case INST_TYPE_RA_IMM:
    case INST_TYPE_RD_RA_IMM:
    case INST_TYPE_IMM:
        instr_imm = instr_bits & 0xffff;
        break;
    case INST_TYPE_IMML:
        instr_imm = instr_bits & 0xffffff;
        break;
    case INST_TYPE_IMM4:
        instr_imm = instr_bits & 0xf;
        break;
    case INST_TYPE_RDIMM:
        instr_imm = (instr_bits >> 21) & 0x1f;
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

static void add_char(char ch) {
    if (buf_pos >= sizeof(buf) - 1) return;
    buf[buf_pos++] = ch;
    if (ch == ' ') while (buf_pos < 8) buf[buf_pos++] = ch;
}

static void add_str(const char * s) {
    while (*s) add_char(*s++);
}

static void add_hex_uint64(uint64_t n) {
    char s[32];
    size_t i = 0;
    while (i < 16) {
        unsigned d = (unsigned)(n & 0xf);
        s[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        n = n >> 4;
        if (i >= 8 && n == 0) break;
    }
    while (i > 0) add_char(s[--i]);
}

static void add_addr(uint64_t addr) {
    if (!en_64_bit) addr &= 0xffffffff;
    while (buf_pos < 32) buf[buf_pos++] = ' ';
    add_str("; addr=0x");
    add_hex_uint64(addr);
#if ENABLE_Symbols
    if (disass_params->ctx != NULL) {
        Symbol * sym = NULL;
        char * name = NULL;
        ContextAddress sym_addr = 0;
        if (find_symbol_by_addr(disass_params->ctx, STACK_NO_FRAME, (ContextAddress)addr, &sym) < 0) return;
        if (get_symbol_name(sym, &name) < 0 || name == NULL) return;
        if (get_symbol_address(sym, &sym_addr) < 0) return;
        if (sym_addr <= addr) {
            add_str(": ");
            add_str(name);
            if (sym_addr < addr) {
                add_str(" + 0x");
                add_hex_uint64(addr - (uint32_t)sym_addr);
            }
        }
    }
#endif
}

static int sext16(unsigned imm) {
    if ((imm >> 15) & 1) return ~(int)0xffff | imm;
    return (int)(imm & 0xffff);
}

static int64_t sext40(uint64_t imm) {
    if ((imm >> 39) & 1) return ~(int64_t)0xffffffffff | imm;
    return (int64_t)(imm & 0xffffffffff);
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
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%-2u, r%-2u", instr_rd, instr_r1, instr_r2);
        break;
    case INST_TYPE_RD_RA_IMM:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%-2u, %d", instr_rd, instr_r1, sext16(instr_imm));
        break;
    case INST_TYPE_RD_RA_IMM5:
    case INST_TYPE_RD_RA_IMM6:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%-2u, %u", instr_rd, instr_r1, instr_imm);
        break;
    case INST_TYPE_RD_RA_IMM5_IMM5:
    case INST_TYPE_RD_RA_IMM6_IMM6:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%-2u, %u, %u", instr_rd, instr_r1, instr_imm, instr_imm2);
        break;
    case INST_TYPE_RD_RA:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%-2u", instr_rd, instr_r1);
        break;
    case INST_TYPE_RD_RB:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%-2u", instr_rd, instr_r2);
        break;
    case INST_TYPE_RD_IMM:
    case INST_TYPE_RD_IMM15:
    case INST_TYPE_RD_IMM4:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, %d", instr_rd, sext16(instr_imm));
        break;
    case INST_TYPE_RA_RB:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%-2u", instr_r1, instr_r2);
        break;
    case INST_TYPE_RA_IMM:
    case INST_TYPE_RA_IMM4:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, %d", instr_r1, sext16(instr_imm));
        break;
    case INST_TYPE_RD_SA: /* mfs */
        if (instr_bits & 0x2000) { /* PVR */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, rPVR%u", instr_rd, (unsigned)(instr_bits & 0xf));
        }
        else if (instr_bits & 0x0800) { /* STACK REGs */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%s", instr_rd, STACKREG_NAME[instr_bits & 0x3]);
        }
        else if (instr_bits & 0x1000) { /* MMU REGs */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%s", instr_rd, MMUREG_NAME_MFS[instr_bits & 0x7]);
        }
        else {
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u, r%s", instr_rd, SPREG_NAME_MFS[instr_bits & 0xf]);
        }
        break;
    case INST_TYPE_SA_RA: /* mts */
        if (instr_bits & 0x0800) { /* STACK REGs */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%s, r%-2u", STACKREG_NAME[instr_bits & 0x3], instr_r1);
        }
        else if (instr_bits & 0x1000) { /* MMU REGs */
            snprintf(tmp_buf, sizeof(tmp_buf), "r%s, r%-2u", MMUREG_NAME_MTS[instr_bits & 0x7], instr_r1);
        }
        else {
            snprintf(tmp_buf, sizeof(tmp_buf), "r%-3s, r%-2u", SPREG_NAME_MTS[instr_bits & 0x7], instr_r1);
        }
        break;
    case INST_TYPE_RA:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u", instr_r1);
        break;
    case INST_TYPE_RB:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u", instr_r2);
        break;
    case INST_TYPE_RD:
        snprintf(tmp_buf, sizeof(tmp_buf), "r%-2u", instr_rd);
        break;
    case INST_TYPE_IMM:
    case INST_TYPE_IMM4:
    case INST_TYPE_RDIMM:
        snprintf(tmp_buf, sizeof(tmp_buf), "%d", sext16(instr_imm));
        break;
    case INST_TYPE_IMML:
        snprintf(tmp_buf, sizeof(tmp_buf), "%u", instr_imm);
        break;
    case INST_TYPE_NULL:
        tmp_buf[0] = 0;
        break;
    default:
        snprintf(tmp_buf, sizeof(tmp_buf), "invalid");
        break;
    }

    add_str(tmp_buf);

    if (instr_op == i_lli || instr_op == i_lwi || instr_op == i_lhui || instr_op == i_lbui ||
            instr_op == i_sli || instr_op == i_swi || instr_op == i_shi || instr_op == i_sbi) {
        if (instr_r1 == 0) {
            DecodingState * state = (DecodingState *)disass_params->state;
            if (state != NULL && state->addr == ctx_addr - 4) {
                uint64_t addr = 0;
                if ((state->instr & 0xffff0000) == 0xb0000000) {
                    addr = ((state->instr & 0xffff) << 16) | instr_imm;
                }
                else if ((state->instr & 0xff000000) == 0xb2000000) {
                    addr = sext40(((uint64_t)(state->instr & 0xffffff) << 16) | instr_imm);
                }
                else {
                    addr = sext16(instr_imm);
                }
                add_addr(addr);
            }
        }
    }
    else if ((instruction_info[instr_op].flags & F_CTRL) != 0 &&
            (instruction_info[instr_op].flags & F_IMM) != 0 &&
            (instruction_info[instr_op].flags & F_INDIRJMP) == 0 &&
            instruction_info[instr_op].type != INST_TYPE_NULL) {
        DecodingState * state = (DecodingState *)disass_params->state;
        if (state != NULL && state->addr == ctx_addr - 4) {
            uint64_t addr = 0;
            if ((state->instr & 0xffff0000) == 0xb0000000) {
                addr = ((state->instr & 0xffff) << 16) | instr_imm;
            }
            else if ((state->instr & 0xff000000) == 0xb2000000) {
                addr = sext40(((uint64_t)(state->instr & 0xffffff) << 16) | instr_imm);
            }
            else {
                addr = sext16(instr_imm);
            }
            if ((instruction_info[instr_op].flags & F_ABS) == 0) addr += ctx_addr;
            add_addr(addr);
        }
    }

    return 0;
}

static DisassemblyResult * disassemble_instr(uint8_t * code,
        ContextAddress addr, ContextAddress size, DisassemblerParams * params) {
    static DisassemblyResult dr;
    static int ini_done = 0;
    unsigned i;

    if (!ini_done) {
        unsigned l = sizeof(opcode_hash) / sizeof(opcode_hash[0]);
        for (i = 0; i < l; i++) {
            /* make all unknown by default */
            opcode_hash[i] = UNKNOWN_OPCODE;
        }
        for (i = 0; i < UNKNOWN_OPCODE; i++) {
            unsigned n = instruction_info[i].hash;
            assert(instruction_info[i].op == (enum Instructions)i);
            assert(n < l);
            if (opcode_hash[n] != UNKNOWN_OPCODE) continue;
            opcode_hash[n] = (enum Instructions)i;
        }
        ini_done = 1;
    }

    if (size < 4) return NULL;
    buf_pos = 0;
    ctx_addr = addr;
    disass_params = params;
    instr_bits = 0;
    for (i = 0; i < 4; i++) {
        instr_bits |= (uint32_t)code[i] << (params->big_endian ? 3 - i : i) * 8;
    }
    if (disassemble_instruction() < 0) return NULL;
    buf[buf_pos++] = 0;
    memset(&dr, 0, sizeof(dr));
    dr.size = 4;
    dr.text = buf;
    if (params->state == NULL) params->state = loc_alloc_zero(sizeof(DecodingState));
    ((DecodingState *)params->state)->instr = instr_bits;
    ((DecodingState *)params->state)->addr = addr;
    return &dr;
}

DisassemblyResult * disassemble_microblaze(uint8_t * code,
        ContextAddress addr, ContextAddress size, DisassemblerParams * params) {
    en_64_bit = 0;
    return disassemble_instr(code, addr, size, params);
}

DisassemblyResult * disassemble_microblaze64(uint8_t * code,
        ContextAddress addr, ContextAddress size, DisassemblerParams * params) {
    en_64_bit = 1;
    return disassemble_instr(code, addr, size, params);
}
