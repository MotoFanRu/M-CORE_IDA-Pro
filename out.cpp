/*
 * 	IDA MCORE Plugin
 * 	Copyright (c) 2004-05
 *	rshade@hushmail.com
 *
 */

#include "mcore.hpp"

#include "idp.hpp"
#include "name.hpp"

//----------------------------------------------------------------------
inline void OutReg(outctx_t *ctx, int rgnum) {
    processor_t &ph = *get_ph();
    if ((rgnum >= 0) && (rgnum < ph.regs_num)) {
        ctx->out_register(ph.reg_names[rgnum]);
    } else {
        ctx->out_line("r???", COLOR_ERROR);
    }
}

inline void OutBadReg(outctx_t *ctx, int rgnum) {
    const char *reg;

    processor_t &ph = *get_ph();
    if ((rgnum >= 0) && (rgnum < ph.regs_num)) {
        reg = ph.reg_names[rgnum];
    } else {
        reg = "r???";
    }
    ctx->out_line(ph.reg_names[rgnum], COLOR_ERROR);
}

//----------------------------------------------------------------------
bool outop(outctx_t *ctx, const op_t &x) {
    switch (x.type) {
    case o_void:
        return 0;
    case o_imm:
        if (x.specflag1 == 1) ctx->out_symbol('#');
        ctx->out_value(x, 0);
        break;
    case o_regrange:
        OutReg(ctx, x.reg);
        ctx->out_symbol('-');
        if (x.specval < x.reg) {
            // bad!
            OutBadReg(ctx, x.specval);
        } else {
            OutReg(ctx, x.specval);
        }
        break;
    case o_reg:
        OutReg(ctx, x.reg);
        break;
    case o_displ:
        ctx->out_symbol('(');
        OutReg(ctx, x.reg);
        ctx->out_symbol(',');
        ctx->out_char(' ');
        ctx->out_value(x, 0);
        ctx->out_symbol(')');
        break;
    case o_near: {
        // stolen from m7900 code
        // NO IDEA if this is right
        ea_t v = to_ea(ctx->insn.cs, x.addr);
        qstring str;
        if (get_name_expr(&str, ctx->insn.ea, x.n, v, x.addr) > 0) {
            ctx->out_value(x, OOF_ADDR | OOFS_NOSIGN);
        } else {
            ctx->out_line(str.c_str());
        }
    } break;
    case o_mem: {
        ea_t v = to_ea(ctx->insn.cs, x.addr);
        qstring str;
        if (get_name_expr(&str, ctx->insn.ea, x.n, v, x.addr) > 0) {
            ctx->out_value(x, OOF_ADDR | OOFS_NOSIGN);
        } else {
            ctx->out_line(str.c_str());
        }
    } break;
    default:
        break;
    }
    return 1;
}

//----------------------------------------------------------------------
void out(outctx_t *ctx) {
    char buf[MAXSTR];
    int i;

    insn_t *cmd = &ctx->insn;

    // some instructions need to be special cased here...
    ctx->out_mnemonic();

    if ((cmd->Op1.type != o_void) && (cmd->Op1.shown())) {
        ctx->out_one_operand(0);
    }
    for (i = 1; (i < UA_MAXOP) && (cmd->ops[i].type != o_void); i++) {
        if (!cmd->ops[i].shown()) continue;
        if (cmd->ops[i].ind_op != 2) {
            // normal operand, nothing special here
            ctx->out_symbol(',');
            ctx->out_line(" ");
            ctx->out_one_operand(i);
        } else {
            // part of an "indirect operand" pair
            // 1st one was the assembler-friendly operand
            // this one would be invisible to the assembler
            // but we'll put it in { } for the disassembler to see
            ctx->out_line(" {");
            ctx->out_one_operand(i);
            ctx->out_line("}");
        }
    }

    ctx->out_immchar_cmts();
    ctx->flush_outbuf();
}

//--------------------------------------------------------------------------
void header(outctx_t *ctx) {
    asm_t &ash = *get_ash();

    ctx->gen_cmt_line("Processor:        %s", inf_get_procname().c_str());
    ctx->gen_cmt_line("Target assembler: %s", ash.name);
}

//--------------------------------------------------------------------------
void footer(outctx_t *ctx) {
    ctx->gen_cmt_line("end of file");
}
