/*
 * 	IDA MCORE Plugin
 * 	Copyright (c) 2004-05
 *	rshade@hushmail.com
 *
 */

#include "mcore.hpp"
#include "ins.hpp"

void make_oi(insn_t *cmd, op_t &op, ushort i) {
    // offset immediate value, eg "5"
    // immediate value is offset by 1 (add 1 to it)
    op.type  = o_imm;
    op.dtype = dt_dword;
    op.value = i + 1;
}

void make_i(insn_t *cmd, op_t &op, ushort i) {
    // normal immediate value, eg "5"
    op.type = o_imm;
    // technically not always true but generally most sensible value
    // all-around
    op.dtype     = dt_dword;
    op.value     = i;
    op.specflag1 = 0; // DON'T use `#' in front
}

// `e' and `u' fields are essentially just numeric values
// but are displaced "specially"
void make_e(insn_t *cmd, op_t &op, ushort i) {
    op.type      = o_imm;
    op.dtype     = dt_dword;
    op.value     = i;
    op.specflag1 = 1; // show with `#' in front
}
#define make_u make_e

// note there are some insns using `make_r'
// should be change to something like make_n here because they
// are really a register range

// used in some h_ instrs, means "r4-rX"
void make_n(insn_t *cmd, op_t &op, ushort r) {
    op.type  = o_regrange; // custom op.type
    op.dtype = dt_dword;   // bleh...
    op.reg   = rR4;        // always starts with r4
    // if this is < rR4 that means "reserved, do not use"
    // see h_ret in MCORERM.PDF for example
    op.specval = r + rR4 - 1;
}

void make_r(op_t &op, ushort r) {
    // normal register, eg "r8"
    op.type  = o_reg;
    op.dtype = dt_dword;
    op.reg   = r;
}

// 's' and 'z' are just registers
#define make_s make_r
#define make_z make_r

void make_c(insn_t *cmd, op_t &op, ushort c) {
    // control register, eg "epsr"
    op.type  = o_reg;
    op.dtype = dt_dword;
    op.reg   = c + rPSR; // 1st control reg
}

void make_b(insn_t *cmd, op_t &op, ushort d) {
    // loop displacment: one's extended 4 bit displacement
    // this means put all one's above the 4 bit displacement
    // -0x10 will have all ones except for lower 4 bits
    if (d >= 0x10) {
        // warning("!!! make_b was given non-4-bit value %04x @ %08x\n", d, cmd->ip);
        d = 0xf;
    }
    adiff_t ld = ((adiff_t)-0x10) | d;
    op.type    = o_near;
    op.dtype   = dt_code;
    op.reg     = cmd->ip + 2 + (ld << 1);
}

void make_displ(insn_t *cmd, op_t &op, ushort r, ushort i, ushort sz) {
    op.type = o_displ;
    if (sz > 2) sz = 0; // !!
    // in most (rx,disp) instructions, the size field in the opcode
    // is: 0 == word(IDA dword), 1 == byte, 2 == hword(IDA word)
    // we do the sensible thing here though, sz is 0 for byte, 1 for
    // word, 2 for dword, ...
    switch (sz) {
    case 0:
        op.dtype = dt_byte;
        break;
    case 1:
        op.dtype = dt_word;
        break;
    case 2:
        op.dtype = dt_dword;
        break;
    }
    op.addr   = i << sz;
    op.phrase = r;
    // "scaled by the size of the load"
    // uh..
    // the "size" field is 1 for byte, 2 for half-word(IDA word)
    // 0 for word(IDA dword)
    // but I'm assuming they mean "scale 0 for byte, 1 for hword, ..."
}

void make_d8(insn_t *cmd, op_t &asmop, op_t &procop, ushort d) {
    // instr. using this addressing mode are "indirect"
    // meaning like, call dword ptr [X] rather than call X
    //
    // believe it or not, *NOT* sign extended!
    // can only do forward addressing this way

    // we do two operands
    // the "real" operand as it exists in the processor
    // and the "fake" operand as it exists in the assembler
    //
    // because it is highly inconvenient for an assembly programmer to write
    // code like:
    // (programmer wants to load "500" into r0)
    //    lrw r0, addr_of_foo
    //    ...
    // addr_of_foo: .long actual_foo
    // actual_foo: .long 500
    //
    // what the MTC GNU assembler does is:
    //    lrw r0, foo
    // foo: .long 500
    //
    // and then it "secretly" adds addr_of_foo and replaces `foo' with
    // addr_of_foo
    //
    // so we'll do both, but label them differently
    ea_t uld     = d;
    procop.type  = o_mem;
    procop.dtype = dt_dword;
    // 2 lower bits forced 0
    procop.addr   = (cmd->ip + 2 + (uld << 2)) & -4;
    procop.ind_op = 2;

    asmop.type   = o_near;
    asmop.dtype  = dt_code;
    asmop.addr   = get_32bit(procop.addr);
    asmop.ind_op = 1;
}

void make_d11(insn_t *cmd, op_t &op, ushort d) {
    // adiff_t is signed...
    adiff_t ld;
    // d is a signed 11-bit value
    if (d & 0x400) {
        ld = (short)(d | (-0x400));
    } else {
        ld = d;
    }
    op.type  = o_near;
    op.dtype = dt_code;
    op.addr  = (cmd->ip + 2 + (ld << 1));
}

void make_mem_d8(insn_t *cmd, op_t &asmop, op_t &procop, ushort d) {
    // forward addressing only, ala make_d8
    ea_t uld     = d;
    procop.type  = o_mem;
    procop.dtype = dt_dword;
    // 2 lower bits forced 0
    procop.addr   = (cmd->ip + 2 + (uld << 2)) & -4;
    procop.ind_op = 2;

    asmop.type   = o_mem;
    asmop.dtype  = dt_dword;
    asmop.addr   = get_32bit(procop.addr);
    asmop.ind_op = 1;
}

// this will always be run on WINDOWS
// so making this platform independent is stupid
// but whatever
uint16 myhtons(uint16 s) {
    const auto *c = reinterpret_cast<unsigned char *>(&s);
    return static_cast<uint16>(((c[0] << 8) & 0xff00) | (c[1] & 0xff));
}

uint32 myhtonl(uint32 l) {
    const auto *c = reinterpret_cast<unsigned char *>(&l);
    return ((c[0] << 24) & 0xff000000) | ((c[1] << 16) & 0xff0000) | ((c[2] << 8) & 0xff00) | (c[3] & 0xff);
}

int ana(insn_t *cmd) {
    // all instrs are (Motorola-speak)halfword (IDA-speak)word aligned
    // By that I mean, two-byte aligned
    if (cmd->ip & 1) return 0;

    // this fetches next word and fills in cmd->size with 2
    ushort code = cmd->get_next_word();

    cmd->size = 2;

    // first things first
    // MCORE is big-endian!  `inf.mf' ensures this is endian corrected
    // though (see reg.cpp!notify)
    // code = myhtons(code);

    // this gigantor switch autogenerated and then hand-edited
    // it's like a binary search tree, kinda...
    switch (((code - 0x0000) & 0xf000) >> 12) {
    case 0x0000: {
        switch (((code - 0x0000) & 0xff00) >> 8) {
        case 0x0000: {
            switch (((code - 0x0000) & 0xfff0) >> 4) {
            case 0x0000: {
                switch (((code - 0x0000) & 0xfffc) >> 2) {
                case 0x0000: {
                    switch (((code - 0x0000) & 0xffff) >> 0) {
                    case 0x0000: {
                        // bkpt
                        cmd->itype = mcore_bkpt;
                        return 2;
                    } break;
                    case 0x0001: {
                        // sync
                        cmd->itype = mcore_sync;
                        return 2;
                    } break;
                    case 0x0002: {
                        // rte
                        cmd->itype = mcore_rte;
                        return 2;
                    } break;
                    case 0x0003: {
                        // rfi
                        cmd->itype = mcore_rfi;
                        return 2;
                    } break;
                    default: return 0;
                    } // switch (((code - 0x0000) & 0xffff) >> 0)
                } break;
                case 0x0001: {
                    switch (((code - 0x0004) & 0xffff) >> 0) {
                    case 0x0000: {
                        // stop
                        cmd->itype = mcore_stop;
                        return 2;
                    } break;
                    case 0x0001: {
                        // wait
                        cmd->itype = mcore_wait;
                        return 2;
                    } break;
                    case 0x0002: {
                        // doze
                        cmd->itype = mcore_doze;
                        return 2;
                    } break;
                    default: return 0;
                    } // switch (((code - 0x0004) & 0xffff) >> 0)
                } break;
                case 0x0002: {
                    // trap
                    make_i(cmd, cmd->Op1, ((code & 0x0003) >> 0));
                    cmd->itype = mcore_trap;
                    return 2;
                } break;
                default: return 0;
                } // switch (((code - 0x0000) & 0xfffc) >> 2)
            } break;
            case 0x0002: {
                // mvc
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_mvc;
                return 2;
            } break;
            case 0x0003: {
                // mvcv
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_mvcv;
                return 2;
            } break;
            case 0x0004: {
                // ldq
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_ldq;
                return 2;
            } break;
            case 0x0005: {
                // stq
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_stq;
                return 2;
            } break;
            case 0x0006: {
                // ldm
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_ldm;
                return 2;
            } break;
            case 0x0007: {
                // stm
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_stm;
                return 2;
            } break;
            case 0x0008: {
                // dect
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_dect;
                return 2;
            } break;
            case 0x0009: {
                // decf
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_decf;
                return 2;
            } break;
            case 0x000a: {
                // inct
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_inct;
                return 2;
            } break;
            case 0x000b: {
                // incf
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_incf;
                return 2;
            } break;
            case 0x000c: {
                // jmp
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_jmp;
                return 2;
            } break;
            case 0x000d: {
                // jsr
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_jsr;
                return 2;
            } break;
            case 0x000e: {
                // ff1
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_ff1;
                return 2;
            } break;
            case 0x000f: {
                // brev
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_brev;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x0000) & 0xfff0) >> 4)
        } break;
        case 0x0001: {
            switch (((code - 0x0100) & 0xfff0) >> 4) {
            case 0x0000: {
                // xtrb3
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_xtrb3;
                return 2;
            } break;
            case 0x0001: {
                // xtrb2
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_xtrb2;
                return 2;
            } break;
            case 0x0002: {
                // xtrb1
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_xtrb1;
                return 2;
            } break;
            case 0x0003: {
                // xtrb0
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_xtrb0;
                return 2;
            } break;
            case 0x0004: {
                // zextb
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_zextb;
                return 2;
            } break;
            case 0x0005: {
                // sextb
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_sextb;
                return 2;
            } break;
            case 0x0006: {
                // zexth
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_zexth;
                return 2;
            } break;
            case 0x0007: {
                // sexth
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_sexth;
                return 2;
            } break;
            case 0x0008: {
                // declt
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_declt;
                return 2;
            } break;
            case 0x0009: {
                // tstnbz
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_tstnbz;
                return 2;
            } break;
            case 0x000a: {
                // decgt
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_decgt;
                return 2;
            } break;
            case 0x000b: {
                // decne
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_decne;
                return 2;
            } break;
            case 0x000c: {
                // clrt
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_clrt;
                return 2;
            } break;
            case 0x000d: {
                // clrf
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_clrf;
                return 2;
            } break;
            case 0x000e: {
                // abs
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_abs;
                return 2;
            } break;
            case 0x000f: {
                // not
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_not;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x0100) & 0xfff0) >> 4)
        } break;
        case 0x0002: {
            // movt
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_movt;
            return 2;
        } break;
        case 0x0003: {
            // mult
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_mult;
            return 2;
        } break;
        case 0x0004: {
            // loopt
            make_b(cmd, cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_loopt;
            return 2;
        } break;
        case 0x0005: {
            // subu
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_subu;
            return 2;
        } break;
        case 0x0006: {
            // addc
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_addc;
            return 2;
        } break;
        case 0x0007: {
            // subc
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_subc;
            return 2;
        } break;
        case 0x000a: {
            // movf
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_movf;
            return 2;
        } break;
        case 0x000b: {
            // lsr
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_lsr;
            return 2;
        } break;
        case 0x000c: {
            // cmphs
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_cmphs;
            return 2;
        } break;
        case 0x000d: {
            // cmplt
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_cmplt;
            return 2;
        } break;
        case 0x000e: {
            // tst
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_tst;
            return 2;
        } break;
        case 0x000f: {
            // cmpne
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_s(cmd->Op2, ((code & 0x00f0) >> 4));
            cmd->itype = mcore_cmpne;
            return 2;
        } break;
        default: return 0;
        } // switch (((code - 0x0000) & 0xff00) >> 8)
    } break;
    case 0x0001: {
        switch (((code - 0x1000) & 0xfe00) >> 9) {
        case 0x0000: {
            // mfcr
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_c(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_mfcr;
            return 2;
        } break;
        case 0x0001: {
            switch (((code - 0x1200) & 0xff00) >> 8) {
            case 0x0000: {
                // mov
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_mov;
                return 2;
            } break;
            case 0x0001: {
                // bgenr
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_bgenr;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x1200) & 0xff00) >> 8)
        } break;
        case 0x0002: {
            switch (((code - 0x1400) & 0xff00) >> 8) {
            case 0x0000: {
                // rsub
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_rsub;
                return 2;
            } break;
            case 0x0001: {
                // ixw
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_ixw;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x1400) & 0xff00) >> 8)
        } break;
        case 0x0003: {
            switch (((code - 0x1600) & 0xff00) >> 8) {
            case 0x0000: {
                // and
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_and;
                return 2;
            } break;
            case 0x0001: {
                // xor
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_xor;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x1600) & 0xff00) >> 8)
        } break;
        case 0x0004: {
            // mtcr
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_c(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_mtcr;
            return 2;
        } break;
        case 0x0005: {
            switch (((code - 0x1a00) & 0xff00) >> 8) {
            case 0x0000: {
                // asr
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_asr;
                return 2;
            } break;
            case 0x0001: {
                // lsl
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_lsl;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x1a00) & 0xff00) >> 8)
        } break;
        case 0x0006: {
            switch (((code - 0x1c00) & 0xff00) >> 8) {
            case 0x0000: {
                // addu
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_addu;
                return 2;
            } break;
            case 0x0001: {
                // ixh
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_ixh;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x1c00) & 0xff00) >> 8)
        } break;
        case 0x0007: {
            switch (((code - 0x1e00) & 0xff00) >> 8) {
            case 0x0000: {
                // or
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_or;
                return 2;
            } break;
            case 0x0001: {
                // andn
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_s(cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_andn;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x1e00) & 0xff00) >> 8)
        } break;
        default: return 0;
        } // switch (((code - 0x1000) & 0xfe00) >> 9)
    } break;
    case 0x0002: {
        switch (((code - 0x2000) & 0xfe00) >> 9) {
        case 0x0000: {
            // addi
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_oi(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_addi;
            return 2;
        } break;
        case 0x0001: {
            // cmplti
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_oi(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_cmplti;
            return 2;
        } break;
        case 0x0002: {
            // subi
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_oi(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_subi;
            return 2;
        } break;
        case 0x0004: {
            // rsubi
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_rsubi;
            return 2;
        } break;
        case 0x0005: {
            // cmpnei
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_cmpnei;
            return 2;
        } break;
        case 0x0006: {
            switch (((code - 0x2c00) & 0xff00) >> 8) {
            case 0x0000: {
                switch (((code - 0x2c00) & 0xff80) >> 7) {
                case 0x0000: {
                    switch (((code - 0x2c00) & 0xfff0) >> 4) {
                    case 0x0000: {
                        // bmaski
                        make_r(cmd->Op1, ((code & 0x000f) >> 0));
                        cmd->itype = mcore_bmaski;
                        return 2;
                    } break;
                    case 0x0001: {
                        // divu
                        make_r(cmd->Op1, ((code & 0x000f) >> 0));
                        cmd->itype = mcore_divu;
                        return 2;
                    } break;
                    default: return 0;
                    } // switch (((code - 0x2c00) & 0xfff0) >> 4)
                } break;
                case 0x0001: {
                    // bmaski_0
                    make_r(cmd->Op1, ((code & 0x000f) >> 0));
                    make_i(cmd, cmd->Op2, ((code & 0x0070) >> 4));
                    cmd->itype = mcore_bmaski_0;
                    return 2;
                } break;
                default: return 0;
                } // switch (((code - 0x2c00) & 0xff80) >> 7)
            } break;
            case 0x0001: {
                // bmaski_1
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_i(cmd, cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_bmaski_1;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x2c00) & 0xff00) >> 8)
        } break;
        case 0x0007: {
            // andi
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_andi;
            return 2;
        } break;
        default: return 0;
        } // switch (((code - 0x2000) & 0xfe00) >> 9)
    } break;
    case 0x0003: {
        switch (((code - 0x3000) & 0xfe00) >> 9) {
        case 0x0000: {
            // bclri
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_bclri;
            return 2;
        } break;
        case 0x0001: {
            switch (((code - 0x3200) & 0xff00) >> 8) {
            case 0x0000: {
                switch (((code - 0x3200) & 0xff80) >> 7) {
                case 0x0000: {
                    switch (((code - 0x3210) & 0xfff0) >> 4) {
                    case 0x0000: {
                        // divs
                        make_r(cmd->Op1, ((code & 0x000f) >> 0));
                        cmd->itype = mcore_divs;
                        return 2;
                    } break;
                    case 0x0006: {
                        // bgeni
                        make_r(cmd->Op1, ((code & 0x000f) >> 0));
                        cmd->itype = mcore_bgeni;
                        return 2;
                    } break;
                    default: return 0;
                    } // switch (((code - 0x3210) & 0xfff0) >> 4)
                } break;
                case 0x0001: {
                    // bgeni_0
                    make_r(cmd->Op1, ((code & 0x000f) >> 0));
                    make_i(cmd, cmd->Op2, ((code & 0x0070) >> 4));
                    cmd->itype = mcore_bgeni_0;
                    return 2;
                } break;
                default: return 0;
                } // switch (((code - 0x3200) & 0xff80) >> 7)
            } break;
            case 0x0001: {
                // bgeni_1
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_i(cmd, cmd->Op2, ((code & 0x00f0) >> 4));
                cmd->itype = mcore_bgeni_1;
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x3200) & 0xff00) >> 8)
        } break;
        case 0x0002: {
            // bseti
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_bseti;
            return 2;
        } break;
        case 0x0003: {
            // btsti
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
            cmd->itype = mcore_btsti;
            return 2;
        } break;
        case 0x0004: {
            switch (((code - 0x3800) & 0xfff0) >> 4) {
            case 0x0000: {
                // xsr
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_xsr;
                return 2;
            } break;
            default: {
                // rotli
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
                cmd->itype = mcore_rotli;
                return 2;
            } break;
            } // switch (((code - 0x3800) & 0xfff0) >> 4)
        } break;
        case 0x0005: {
            switch (((code - 0x3a00) & 0xfff0) >> 4) {
            case 0x0000: {
                // asrc
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_asrc;
                return 2;
            } break;
            default: {
                // asri
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
                cmd->itype = mcore_asri;
                return 2;
            } break;
            } // switch (((code - 0x3a00) & 0xfff0) >> 4)
        } break;
        case 0x0006: {
            switch (((code - 0x3c00) & 0xfff0) >> 4) {
            case 0x0000: {
                // lslc
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_lslc;
                return 2;
            } break;
            default: {
                // lsli
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
                cmd->itype = mcore_lsli;
                return 2;
            } break;
            } // switch (((code - 0x3c00) & 0xfff0) >> 4)
        } break;
        case 0x0007: {
            switch (((code - 0x3e00) & 0xfff0) >> 4) {
            case 0x0000: {
                // lsrc
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                cmd->itype = mcore_lsrc;
                return 2;
            } break;
            default: {
                // lsri
                make_r(cmd->Op1, ((code & 0x000f) >> 0));
                make_i(cmd, cmd->Op2, ((code & 0x01f0) >> 4));
                cmd->itype = mcore_lsri;
                return 2;
            } break;
            } // switch (((code - 0x3e00) & 0xfff0) >> 4)
        } break;
        default: return 0;
        } // switch (((code - 0x3000) & 0xfe00) >> 9)
    } break;
    case 0x0004: {
        switch (((code - 0x4000) & 0xf300) >> 8) {
        case 0x0000: {
            // h_exec
            cmd->itype = mcore_h_exec;
            make_u(cmd, cmd->Op1, (code & 0x0c00) >> 10);
            make_e(cmd, cmd->Op2, (code & 0x00ff) >> 0);
            return 2;
        } break;
        case 0x0001: {
            switch (((code - 0x4100) & 0xf380) >> 7) {
            case 0x0000: {
                // h_ret
                cmd->itype = mcore_h_ret;
                make_u(cmd, cmd->Op1, (code & 0x0c00) >> 10);
                make_n(cmd, cmd->Op2, (code & 0x0070) >> 4);
                make_e(cmd, cmd->Op3, (code & 0x000f) >> 0);
                return 2;
            } break;
            case 0x0001: {
                // h_call
                cmd->itype = mcore_h_call;
                make_u(cmd, cmd->Op1, (code & 0x0c00) >> 10);
                make_n(cmd, cmd->Op2, (code & 0x0070) >> 4);
                make_e(cmd, cmd->Op3, (code & 0x000f) >> 0);
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x4100) & 0xf380) >> 7)
        } break;
        case 0x0002: {
            switch (((code - 0x4200) & 0xf380) >> 7) {
            case 0x0000: {
                // h_ld
                cmd->itype = mcore_h_ld;
                make_u(cmd, cmd->Op1, (code & 0x0c00) >> 10);
                make_displ(cmd, cmd->Op2, (code & 0x000f) >> 0, (code & 0x0030) >> 4, 2);
                return 2;
            } break;
            case 0x0001: {
                // h_st
                cmd->itype = mcore_h_st;
                make_u(cmd, cmd->Op1, (code & 0x0c00) >> 10);
                make_displ(cmd, cmd->Op2, (code & 0x000f) >> 0, (code & 0x0030) >> 4, 2);
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x4200) & 0xf380) >> 7)
        } break;
        case 0x0003: {
            switch (((code - 0x4300) & 0xf380) >> 7) {
            case 0x0000: {
                // h_ld_h
                cmd->itype = mcore_h_ld_h;
                make_u(cmd, cmd->Op1, (code & 0x0c00) >> 10);
                make_displ(cmd, cmd->Op2, (code & 0x000f) >> 0, (code & 0x0030) >> 4, 1);
                return 2;
            } break;
            case 0x0001: {
                // h_st_h
                cmd->itype = mcore_h_st_h;
                make_u(cmd, cmd->Op1, (code & 0x0c00) >> 10);
                make_displ(cmd, cmd->Op2, (code & 0x000f) >> 0, (code & 0x0030) >> 4, 1);
                return 2;
            } break;
            default: return 0;
            } // switch (((code - 0x4300) & 0xf380) >> 7)
        } break;
        default: return 0;
        } // switch (((code - 0x4000) & 0xf300) >> 8)
    } break;
    case 0x0006: {
        switch (((code - 0x6000) & 0xf800) >> 11) {
        case 0x0000: {
            // movi
            make_r(cmd->Op1, ((code & 0x000f) >> 0));
            make_i(cmd, cmd->Op2, ((code & 0x07f0) >> 4));
            cmd->itype = mcore_movi;
            return 2;
        } break;
        default: return 0;
        } // switch (((code - 0x6000) & 0xf800) >> 11)
    } break;
    case 0x0007: {
        switch (((code - 0x7000) & 0xff00) >> 8) {
        case 0x0000: {
            // jmpi
            make_d8(cmd, cmd->Op1, cmd->Op2, ((code & 0x00ff) >> 0));
            cmd->itype = mcore_jmpi;
            return 2;
        } break;
        case 0x000f: {
            // jsri
            make_d8(cmd, cmd->Op1, cmd->Op2, ((code & 0x00ff) >> 0));
            cmd->itype = mcore_jsri;
            return 2;
        } break;
        default: {
            // lrw
            // autogenerator put this in wrong order..
            make_z(cmd->Op1, ((code & 0x0f00) >> 8));
            make_mem_d8(cmd, cmd->Op2, cmd->Op3, ((code & 0x00ff) >> 0));
            cmd->itype = mcore_lrw;
            return 2;
        } break;
        } // switch (((code - 0x7000) & 0xff00) >> 8)
    } break;
    case 0x0008: {
        // ld
        make_r(cmd->Op1, ((code & 0x0f00) >> 8));
        make_displ(cmd, cmd->Op2, ((code & 0x000f) >> 0), ((code & 0x00f0) >> 4), 2);
        cmd->itype = mcore_ld;
        return 2;
    } break;
    case 0x0009: {
        // st
        make_r(cmd->Op1, ((code & 0x0f00) >> 8));
        make_displ(cmd, cmd->Op2, ((code & 0x000f) >> 0), ((code & 0x00f0) >> 4), 2);
        cmd->itype = mcore_st;
        return 2;
    } break;
    case 0x000a: {
        // ld_b
        make_r(cmd->Op1, ((code & 0x0f00) >> 8));
        make_displ(cmd, cmd->Op2, ((code & 0x000f) >> 0), ((code & 0x00f0) >> 4), 0);
        cmd->itype = mcore_ld_b;
        return 2;
    } break;
    case 0x000b: {
        // st_b
        make_r(cmd->Op1, ((code & 0x0f00) >> 8));
        make_displ(cmd, cmd->Op2, ((code & 0x000f) >> 0), ((code & 0x00f0) >> 4), 0);
        cmd->itype = mcore_st_b;
        return 2;
    } break;
    case 0x000c: {
        // ld_h
        make_r(cmd->Op1, ((code & 0x0f00) >> 8));
        make_displ(cmd, cmd->Op2, ((code & 0x000f) >> 0), ((code & 0x00f0) >> 4), 1);
        cmd->itype = mcore_ld_h;
        return 2;
    } break;
    case 0x000d: {
        // st_h
        make_r(cmd->Op1, ((code & 0x0f00) >> 8));
        make_displ(cmd, cmd->Op2, ((code & 0x000f) >> 0), ((code & 0x00f0) >> 4), 1);
        cmd->itype = mcore_st_h;
        return 2;
    } break;
    case 0x000e: {
        switch (((code - 0xe000) & 0xf800) >> 11) {
        case 0x0000: {
            // bt
            make_d11(cmd, cmd->Op1, ((code & 0x07ff) >> 0));
            cmd->itype = mcore_bt;
            return 2;
        } break;
        case 0x0001: {
            // bf
            make_d11(cmd, cmd->Op1, ((code & 0x07ff) >> 0));
            cmd->itype = mcore_bf;
            return 2;
        } break;
        default: return 0;
        } // switch (((code - 0xe000) & 0xf800) >> 11)
    } break;
    case 0x000f: {
        switch (((code - 0xf000) & 0xf800) >> 11) {
        case 0x0000: {
            // br
            make_d11(cmd, cmd->Op1, ((code & 0x07ff) >> 0));
            cmd->itype = mcore_br;
            return 2;
        } break;
        case 0x0001: {
            // bsr
            make_d11(cmd, cmd->Op1, ((code & 0x07ff) >> 0));
            cmd->itype = mcore_bsr;
            return 2;
        } break;
        default: return 0;
        } // switch (((code - 0xf000) & 0xf800) >> 11)
    } break;
    default: return 0;
    } // switch (((code - 0x0000) & 0xf000) >> 12)
}
