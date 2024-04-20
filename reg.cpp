/*
 * 	IDA MCORE Plugin
 * 	Copyright (c) 2004-05
 *	rshade@hushmail.com
 *
 */

#include "mcore.hpp"
#include "ieee.h"
#include "ins.hpp"

int data_id;

//-----------------------------------------------------------------------
int idaapi mcore_realcvt(void *m, fpvalue_t *e, uint16 swt) {
    switch (swt) {
        // only supports normal float and double conversion
    case 001:
    case 003:
    case 011:
    case 013:
        return ieee_realcvt(m, e, swt);
    default:
        return REAL_ERROR_FORMAT;
    }
}

class McoreProc : public procmod_t {
public:
    ssize_t on_event(ssize_t msgid, va_list va) override {
        switch (msgid) {
        case processor_t::ev_init:
            inf_set_be(true); // big endian
            return 0;

        case processor_t::ev_term:
            clr_module_data(data_id);
            return 0;

        case processor_t::ev_ana_insn: {
            insn_t *out = va_arg(va, insn_t *);
            return ana(out);
        }

        case processor_t::ev_emu_insn: {
            insn_t *insn = va_arg(va, insn_t *);
            return emu(insn);
        }

        case processor_t::ev_out_insn: {
            outctx_t *ctx = va_arg(va, outctx_t *);
            out(ctx);
            return 0;
        }

        case processor_t::ev_out_operand: {
            outctx_t *ctx  = va_arg(va, outctx_t *);
            const op_t &op = *(va_arg(va, const op_t *));
            return outop(ctx, op);
        }

        case processor_t::ev_out_header: {
            outctx_t *ctx = va_arg(va, outctx_t *);
            header(ctx);
            return 0;
        }

        case processor_t::ev_out_footer: {
            outctx_t *ctx = va_arg(va, outctx_t *);
            footer(ctx);
            return 0;
        }

        case processor_t::ev_realcvt: {
            void *m      = va_arg(va, void *);
            fpvalue_t *e = va_arg(va, fpvalue_t *);
            uint16 swt   = va_arg(va, uint16);
            return mcore_realcvt(m, e, swt);
        }

        default:
            return 0;
        }
    }
};

//----------------------------------------------------------------------
static const char *RegNames[] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "pc",
    "psr", "vbr", "epsr", "fpsr", "epc", "fpc", "ss0", "ss1",
    "ss2", "ss3", "ss4", "gcr", "gsr",
    // fake virtual segment registers
    "cs", "ds"
};

static asm_t mcoreassembler = {
    .flag = AS_COLON |    // colons after data names
            AS_NCHRE |    // char constants are 'x
            ASH_HEXF3 |   // hex are 0x123
            ASD_DECF0 |   // dec are 123
            ASO_OCTF1 |   // octal are 0123
            ASB_BINF0 |   // binary are 011011b
            AS_ALIGN2 |   // .align expects exponent (eg .align 3 == 8 bytes)
            AS_ASCIIC |   // ascii directive allows C-like escapes
            AS_ONEDUP,    // one array def per line
    .uflag = 0,           // uflag: user-defined
    .name  = "MCORE GAS", // name: assembler name
                          //   I *THINK* its gas for MCORE
    .help     = 0,        // help: 0 = no help
    .header   = nullptr,  // header lines..
    .origin   = nullptr,  // org: origin directive
    .end      = nullptr,  // end: end directive
    .cmnt     = "//",     // cmnt: comment string
    .ascsep   = '"',      // ascsep: ascii string delimiter
    .accsep   = '\'',     // accsep: character delimiter
    .esccodes = "\\\"'",  // esccodes: can't appear in ascii constants

    // various directives...
    .a_ascii = ".ascii",                   // a_ascii: .asciiz also supported in MCORE assembler
                                           //          but IDA doesn't support two types of
                                           //          ascii syntax
    .a_byte          = ".byte",            // a_byte
    .a_word          = ".short",           // a_word
    .a_dword         = ".long",            // a_dword
    .a_qword         = nullptr,            // a_qword: no 8 byte values allowed
    .a_oword         = nullptr,            // a_oword: no 16 byte values allowed
    .a_float         = ".float",           // a_float
    .a_double        = ".double",          // a_double
    .a_tbyte         = nullptr,            // a_tbyte: no long double allowed
    .a_packreal      = nullptr,            // a_packreal
    .a_dups          = ".fill #d, #s, #v", // a_dups: .fill COUNT, SIZE, VALUE
    .a_bss           = ".bss %s",          // a_bss
    .a_equ           = ".equ",             // a_equ
    .a_seg           = nullptr,            // a_seg: segment prefix
    .a_curip         = ".",                // a_curip: current EIP/PC value
    .out_func_header = nullptr,            // func_header
    .out_func_footer = nullptr,            // func_footer
    .a_public        = ".export",          // a_public
    .a_weak          = ".weak",            // a_weak
    .a_extrn         = ".import",          // a_extrn
    .a_comdef        = ".comm",            // a_comdef: either this or .lcomm
    .get_type_name   = nullptr,            // get_type_name
    .a_align         = ".align",           // a_align
    .lbrace          = '(',                // lbrace
    .rbrace          = ')',                // rbrace
    .a_mod           = "%",                // a_mod
    .a_band          = "&",                // a_band
    .a_bor           = "|",                // a_bor
    .a_xor           = "^",                // a_xor
    .a_bnot          = "~",                // a_bnot
    .a_shl           = "<<",               // a_shl
    .a_shr           = ">>",               // a_shr
    .a_sizeof_fmt    = nullptr,            // a_sizeof
    .flag2           = 0,                  // uflag2
    .cmnt2           = nullptr,            // cmnt2
    .low8            = nullptr,            // low8
    .high8           = nullptr,            // high8
    .low16           = nullptr,            // low16
    .high16          = nullptr,            // high16
};

//----------------------------------------------------------------------
static ssize_t notify(void *user_data, int msgid, va_list va) {
    if (msgid == processor_t::ev_get_procmod)
        return reinterpret_cast<size_t>(SET_MODULE_DATA(McoreProc));
    return 0;
}

static asm_t *asms[] = { &mcoreassembler, nullptr };

static const char *shnames[] = { "M*CORE", nullptr };
static const char *lnames[]  = { "Motorola MCORE", nullptr };

//--------------------------------------------------------------------------
static uchar retcode_0[] = { 0x00, 0xcf };

static bytes_t retcodes[] = {
    { sizeof(retcode_0), retcode_0 },
    { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH = {
    .version = IDP_INTERFACE_VERSION,  // version
    .id      = 0x8001,                 // id
    .flag    = PR_USE32 | PR_DEFSEG32, // flag

    // 8bit bytes in code and data
    .cnbits = 8, // cnbits
    .dnbits = 8, // dnbits

    .psnames    = shnames, // psnames
    .plnames    = lnames,  // plnames
    .assemblers = asms,    // assemblers
    ._notify    = notify,  // notify

    .reg_names = RegNames,
    .regs_num  = qnumber(RegNames),

    // even though MCORE has no segment registers, IDA wants them
    // so we use a fake/virtual CS and DS registers, to support the notion of
    // "code" and "data" segments for IDA.
    .reg_first_sreg = rVcs,
    .reg_last_sreg  = rVds,
    .segreg_size    = 0,
    .reg_code_sreg  = rVcs,
    .reg_data_sreg  = rVds,

    .codestart     = nullptr,       // codestart
    .retcodes      = retcodes,      // retcodes
    .instruc_start = mcore_null,    // instruc_start
    .instruc_end   = mcore_last,    // instruc_end
    .instruc       = Instructions,  // instruc

    // approximate # decimal digits after decimal point
    // no "truncated floats" so 0 in first place (that's PDP11 only)
    // std IEEE 32bit float has 7 digits after decimal point
    // std IEEE 64bit double has 15 digits after decimal point
    // no long doubles, so 0 in last place
    // (MCORE does not natively support floats so its a bit of a moot point
    // anyway)
    .real_width = { 0, 7, 15, 0 }, // real_width

    .icode_return    = mcore_null,      // icode_return
};
