/*
 * 	IDA MCORE plugin
 * 	Copyright (c) 2004-05
 *	rshade@hushmail.com
 *
 */

#ifndef MCORE_HPP
#define MCORE_HPP

#include "idp.hpp"

//----------------------------------------------------------------------
// Redefine temporary names
//

// means this pair of operands is an "indirect memory reference"
// 1st is the "real op" that the processor uses
// 2nd is the "programmer/assembler-friendly op" used to make cross-
// references more useful
#define ind_op specflag1
#define o_regrange o_idpspec0
//------------------------------------------------------------------------
enum mcore_registers {
    rR0,
    rR1,
    rR2,
    rR3,
    rR4,
    rR5,
    rR6,
    rR7,
    rR8,
    rR9,
    rR10,
    rR11,
    rR12,
    rR13,
    rR14,
    rR15,
    rPC,
    rPSR,
    rVBR,
    rEPSR,
    rFPSR,
    rEPC,
    rFPC,
    rSS0,
    rSS1,
    rSS2,
    rSS3,
    rSS4,
    rGCR,
    rGSR,
    rVcs,
    rVds,
    rLAST
};

//------------------------------------------------------------------------
void header(outctx_t *ctx);
void footer(outctx_t *ctx);

void segstart(ea_t ea);

int ana(insn_t *cmd);
int emu(insn_t *cmd);
void out(outctx_t *ctx);
bool outop(outctx_t *ctx, const op_t &x);

#endif
