/*
 * 	IDA MCORE Plugin
 * 	Copyright (c) 2004-05
 *	rshade@hushmail.com
 */

#include "mcore.hpp"
#include "ins.hpp"
#include <offset.hpp>
#include <bytes.hpp>
#include <fixup.hpp>

uint32 myhtonl(uint32);

bool check_valid_ref(ea_t base, ea_t addr) {
    if (addr == 0) {
        return exists_fixup(base);
    }
    return true;
}

void touch_arg(insn_t *cmd, op_t &x, bool store, bool call, bool jump) {
    switch (x.type) {
    case o_imm:
        set_immd(cmd->ea);
        break;
    case o_near:
        if (check_valid_ref(cmd->ea + x.offb, x.addr)) {
            op_plain_offset(cmd->ea, x.n, 0);
            cmd->add_cref(x.addr, 0, call ? fl_CN : fl_JN);
        }
        break;
    case o_mem:
        // o_mem ref's can be from normal load/store or from jumps...

        // first deal with the direct memory reference
        if (check_valid_ref(cmd->ea + x.offb, x.addr)) {
            op_plain_offset(cmd->ea, x.n, 0);
            cmd->add_dref(x.addr, 0, store ? dr_W : dr_R);
        }
        switch (x.dtype) {
        case dt_byte:
            create_dword(x.addr, 1);
            break;
        case dt_word:
            create_dword(x.addr, 2);
            break;
        case dt_dword:
            create_dword(x.addr, 4);
            break;
        default:
            break;
        }

        // next see what we can do for indirect jump/call's
        if ((jump || call) && check_valid_ref(x.addr, get_dword(x.addr))) {
            op_offset(x.addr, 0, get_default_reftype(x.addr)); // we know for sure its an address
        }
        break;
    case o_displ:
        // immediate value isn't going to be a useful offset
        // in most cases because it's small
        //
        // what's useful is what's in the register
        // and we don't know that without dataflow analysis
        // may be possible to do in limited scale
        // dunno...
        set_immd(cmd->ea);
        break;
    }
}

int emu(insn_t *cmd) {
    uint32 feature = Instructions[cmd->itype].feature;

    if ((feature & CF_STOP) == 0) {
        cmd->add_cref(cmd->ea + cmd->size, 0, fl_F);
    }

    if (feature & CF_USE1) {
        touch_arg(cmd, cmd->Op1, (feature & CF_CHG1) == CF_CHG1, (feature & CF_CALL) == CF_CALL, (feature & CF_JUMP) == CF_JUMP);
    }
    if (feature & CF_USE2) {
        touch_arg(cmd, cmd->Op2, (feature & CF_CHG2) == CF_CHG2, (feature & CF_CALL) == CF_CALL, (feature & CF_JUMP) == CF_JUMP);
    }
    if (feature & CF_USE3) {
        touch_arg(cmd, cmd->Op3, (feature & CF_CHG3) == CF_CHG3, (feature & CF_CALL) == CF_CALL, (feature & CF_JUMP) == CF_JUMP);
    }
    if (feature & CF_USE4) {
        touch_arg(cmd, cmd->Op4, (feature & CF_CHG3) == CF_CHG4, (feature & CF_CALL) == CF_CALL, (feature & CF_JUMP) == CF_JUMP);
    }

    return 1;
}
