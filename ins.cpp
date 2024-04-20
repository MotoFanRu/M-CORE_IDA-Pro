/*
 * 	IDA MCORE Plugin
 * 	Copyright (c) 2004-05
 *	rshade@hushmail.com
 */

#include <ida.hpp>
#include <idp.hpp>
#include "ins.hpp"

// kinda wish I had spit this out in alphabetical order...
instruc_t Instructions[] = {
{ "", 0 },
{ "jmpi", CF_USE1 | CF_USE2 | CF_JUMP | CF_STOP}, // unconditional jump indirect
{ "jsri", CF_USE1 | CF_USE2 | CF_CALL }, // jump to subroutine indirect
{ "lrw", CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 }, // load PC-relative word
{ "ld", CF_USE1 | CF_USE2 | CF_CHG1 }, // load 4bytes/word/dword
{ "st", CF_USE1 | CF_USE2 | CF_CHG2 }, // store 4bytes/word/dword
{ "ld.b", CF_USE1 | CF_USE2 | CF_CHG1 }, // load byte
{ "st.b", CF_USE1 | CF_USE2 | CF_CHG2 }, // store byte
{ "ld.h", CF_USE1 | CF_USE2 | CF_CHG1 }, // load 2bytes/halfword/word
{ "st.h", CF_USE1 | CF_USE2 | CF_CHG2 }, // store 2bytes/halfword/word
{ "movi", CF_USE1 | CF_USE2 | CF_CHG1 }, // move immediate
{ "bt", CF_USE1 | CF_JUMP }, // could add implicit PSR operand
{ "bf", CF_USE1 | CF_JUMP }, // could add implicit PSR operand
{ "br", CF_USE1 | CF_JUMP | CF_STOP }, // unconditional branch
{ "bsr", CF_USE1 | CF_CALL }, // branch to subroutine
{ "mfcr", CF_USE1 | CF_USE2 | CF_CHG1 }, // move from control register
{ "mtcr", CF_USE1 | CF_USE2 | CF_CHG2 }, // move to control register
{ "mov", CF_USE1 | CF_USE2 | CF_CHG1 }, // move
{ "bgenr", CF_USE1 | CF_USE2 | CF_CHG1 }, // bit generate register
{ "rsub", CF_USE1 | CF_USE2 | CF_CHG1 }, // reverse subtract
{ "ixw", CF_USE1 | CF_USE2 | CF_CHG1 }, // index 4bytes/word/dword
{ "and", CF_USE1 | CF_USE2 | CF_CHG1 }, // logical and
{ "xor", CF_USE1 | CF_USE2 | CF_CHG1 }, // bitwise exclusive-or
{ "asr", CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT}, // arithmetic shift right
{ "lsl", CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT }, // logical shift left
{ "addu", CF_USE1 | CF_USE2 | CF_CHG1 }, // add unsigned
{ "ixh", CF_USE1 | CF_USE2 | CF_CHG1 }, // index 2bytes/halfword/word
{ "or", CF_USE1 | CF_USE2 | CF_CHG1 }, // logical inclusive-or
{ "andn", CF_USE1 | CF_USE2 | CF_CHG1 }, // and not
{ "addi", CF_USE1 | CF_USE2 | CF_CHG1 }, // add immediate
{ "cmplti", CF_USE1 | CF_USE2 }, // compare less than immediate
{ "subi", CF_USE1 | CF_USE2 | CF_CHG1 }, // subtract immediate
{ "rsubi", CF_USE1 | CF_USE2 | CF_CHG1 }, // reverse subtract immediate
{ "cmpnei", CF_USE1 | CF_USE2 }, // compare not equal immediate
{ "andi", CF_USE1 | CF_USE2 | CF_CHG1 }, // logical and immediate
{ "bmaski", CF_USE1 | CF_USE2 | CF_CHG1 }, // bmaski_1: bit mask immediate
{ "bmaski", CF_USE1 | CF_USE2 | CF_CHG1 }, // bmaski_0: bit mask immediate
{ "bmaski", CF_USE1 | CF_USE2 | CF_CHG1 }, // bmaski: bit mask immediate
{ "divu", CF_USE1 | CF_CHG1 }, // unsigned divide: could add implicit R1 operand
{ "bclri", CF_USE1 | CF_USE2 | CF_CHG1 }, // clear bit
{ "bseti", CF_USE1 | CF_USE2 | CF_CHG1 }, // bit set immediate
{ "btsti", CF_USE1 | CF_USE2 }, // bit test immediate: could add implicit PSR operand
{ "xsr", CF_USE1 | CF_CHG1 | CF_SHFT }, // extended shift right
{ "rotli", CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT }, // rotate left by immediate
{ "asrc", CF_USE1 | CF_CHG1 | CF_SHFT }, // arithmetic shift right, update C bit
{ "asri", CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT }, // arithmetic shift right immediate
{ "lslc", CF_USE1 | CF_CHG1 | CF_SHFT }, // logical shift left, update C bit
{ "lsli", CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT }, // logical shift left immediate
{ "lsrc", CF_USE1 | CF_CHG1 | CF_SHFT }, // logical shift right update C bit
{ "lsri", CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT }, // logical shift right immediate
{ "bgeni", CF_USE1 | CF_USE2 | CF_CHG1 }, // bgeni_1: bit generate immediate
{ "bgeni", CF_USE1 | CF_USE2 | CF_CHG1 }, // bgeni_0: bit generate immediate
{ "divs", CF_USE1 | CF_CHG1 }, // signed divide: could add implicit R1 operand
{ "bgeni", CF_USE1 | CF_USE2 | CF_CHG1 }, // bgeni: bit generate immediate
{ "h_exec", CF_USE1 | CF_USE2 }, // hardware accelerator execute
{ "h_ret", CF_USE1 | CF_USE2 | CF_USE3 }, // hardware accelerator return
{ "h_call", CF_USE1 | CF_USE2 | CF_USE3 }, // hardware accelerator call
{ "h_ld", CF_USE1 | CF_USE2 }, // hardware accelerator load 4bytes/word/dword
{ "h_st", CF_USE1 | CF_USE2 | CF_CHG2 }, // hardware accelerator store 4bytes/word/dword
{ "h_ld.h", CF_USE1 | CF_USE2 }, // hardware accelerator load 2bytes/halfword/word
{ "h_st.h", CF_USE1 | CF_USE2 | CF_CHG2 }, // harwdare accelerator store 2bytes/halfword/word
{ "movt", CF_USE1 | CF_USE2 | CF_CHG1 }, // move on conditioni true
{ "mult", CF_USE1 | CF_USE2 | CF_CHG1 }, // multiply
{ "loopt", CF_USE1 | CF_USE2 | CF_JUMP }, // decrement w/ C-bit update and branch if condition true
{ "subu", CF_USE1 | CF_USE2 | CF_CHG1 }, // subtract unsigned
{ "addc", CF_USE1 | CF_USE2 | CF_CHG1 }, // add with C bit
{ "subc", CF_USE1 | CF_USE2 | CF_CHG1 }, // subtract with C bit
{ "movf", CF_USE1 | CF_USE2 | CF_CHG1 }, // move if conditioin false
{ "lsr", CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT }, // logical shift right
{ "cmphs", CF_USE1 | CF_USE2 }, // compare higher or same
{ "cmplt", CF_USE1 | CF_USE2 }, // compare less than
{ "tst", CF_USE1 | CF_USE2 }, // test operands
{ "cmpne", CF_USE1 | CF_USE2 }, // compare not equal
{ "mvc", CF_USE1 | CF_CHG1 }, // move C bit to register
{ "mvcv", CF_USE1 | CF_CHG1 }, // move inverted C bit to register
{ "ldq", CF_USE1 | CF_CHG1 }, // load register quadrant: could implicitly add r4-r7
{ "stq", CF_USE1 }, // store register quadrant: could implicitly add r4-r7
{ "ldm", CF_USE1 | CF_CHG1 }, // load multiple registers !!!!! FIXME
{ "stm", CF_USE1 | CF_CHG1 }, // store multiple registers !!!!! FIXME
{ "dect", CF_USE1 | CF_CHG1 }, // decrement if true condition
{ "decf", CF_USE1 | CF_CHG1 }, // decrement if false condition
{ "inct", CF_USE1 | CF_CHG1 }, // increment if true condition
{ "incf", CF_USE1 | CF_CHG1 }, // increment if false condition
{ "jmp", CF_USE1 | CF_JUMP | CF_STOP }, // unconditional jump
{ "jsr", CF_USE1 | CF_CALL }, // jump to subroutine
{ "ff1", CF_USE1 | CF_CHG1 }, // find first one
{ "brev", CF_USE1 | CF_CHG1 }, // bit reverse
{ "trap", CF_USE1 | CF_STOP }, // unconditional trap to OS
{ "bkpt", 0 }, // breakpoint
{ "sync", 0 }, // synchronize CPU
{ "rte", CF_STOP }, // return from exception
{ "rfi", CF_STOP }, // return from fast interrupt
{ "stop", CF_STOP }, // enter low-power stop
{ "wait", CF_STOP }, // stop execution and wait for interrupt
{ "doze", CF_STOP }, // enter low-power doze mode
{ "xtrb3", CF_USE1 }, // extract low-order byte into R1 and zero-extend, could add implicit r1
{ "xtrb2", CF_USE1 }, // extract byte 2 into R1 and zero-extend could add implicit r1
{ "xtrb1", CF_USE1 }, // extract byte 1 into R1 and zero-extend could add implicit r1
{ "xtrb0", CF_USE1 }, // extract byte 0 into R1 and zero-extend could add implicit r1
{ "zextb", CF_USE1 | CF_CHG1 }, // zero extend byte
{ "sextb", CF_USE1 | CF_CHG1 }, // sign extend byte
{ "zexth", CF_USE1 | CF_CHG1 }, // zero extend 2bytes/halfword/word
{ "sexth", CF_USE1 | CF_CHG1 }, // sign extend 2bytes/halfword/word
{ "declt", CF_USE1 | CF_CHG1 }, // decrement register and set condition if less than zero
{ "tstnbz", CF_USE1 }, // test for no byte equal zero
{ "decgt", CF_USE1 | CF_CHG1 }, // decrement register and set condition if result greater than zero
{ "decne", CF_USE1 | CF_CHG1 }, // decrement regsiter and set condition if result not equal to zero
{ "clrt", CF_USE1 | CF_CHG1 }, // clear register on condition true
{ "clrf", CF_USE1 | CF_CHG1 }, // clear register on condition false
{ "abs", CF_USE1 | CF_CHG1 }, // absolute value
{ "not", CF_USE1 | CF_CHG1 }, // logical complement
};

