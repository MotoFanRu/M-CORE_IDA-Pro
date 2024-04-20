#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>

typedef struct instruc {
	const char *name;
	unsigned long features;
} instruc_t;
#include "ins.hpp"

typedef unsigned short ushort;
typedef unsigned long ulong;

struct node_field {
	ushort mask;
	char *name;
};

struct node {
	ushort opmask;
	ushort opval;
	int name; // of type nameNum
	// contain data about fields...
	// e.g., how to decode regs or immediate offsets....
	int nfields;
	struct node_field *fields;
	int nkids;
	struct node **kids;
};

int instr_count = 0;

struct node *
mknode(ushort opmask, ushort opval, int name, int nkids, ...)
{
	va_list ap;
	struct node *n;
	int i;

	n = (struct node*)calloc(1,sizeof(struct node));
	if (nkids > 0) {
		n->kids = (struct node**)calloc(nkids,sizeof(struct node*));
	} else {
		n->kids = 0;
	}
	n->opmask = opmask;
	n->opval = opval;
	n->name = name;
	if (n->name != 0) instr_count++;
	n->nkids = nkids;

	va_start(ap, nkids);
	for (i = 0; i < nkids; i++) {
		n->kids[i] = va_arg(ap, struct node *);
	}
	n->nfields = va_arg(ap, int);
	if (n->nfields > 0) {
		n->fields = (struct node_field*)
			calloc(n->nfields, sizeof(node_field));
	} else {
		n->fields = 0;
	}
	for (i = 0; i < n->nfields; i++) {
		n->fields[i].mask = (ushort)va_arg(ap, int);
		n->fields[i].name = va_arg(ap, char *);
	}
	va_end(ap);

	return n;
}

int
depth(struct node *n)
{
	int i;
	int md = -1;

	for (i = 0; i < n->nkids; i++) {
		int td = depth(n->kids[i]);
		if (td > md) md = td;
	}
	return md+1;
}

int ops = 0;
struct node *
nsearch(struct node *n, ushort op, ushort prevop)
{
	int i;
	ushort curop;
	struct node *rv = 0;

	curop = op & n->opmask;

//	printf("TRY %04x/%04x AT %04x %04x %s\n", op, curop, n->opmask, n->opval, n->name);

	// try to find match among kids first
	// (attempt "maximal match")
	for (i = 0; (i < n->nkids) && !rv; i++) {
		ops++;
//		printf("TEST KID %04x...", n->kids[i]->opval);
		if (curop == n->kids[i]->opval) {
//			printf("!!!\n");
			rv = nsearch(n->kids[i], op, curop);
		}// else { printf("\n"); }
	}

	if (rv) return rv;

	ops++;
	// if above failed, see if this is a terminating node
	// and that we match
	if (!rv && n->name && (prevop == n->opval)) return n;

//	printf(" <<< ");
	return 0;

/*
	if (n->nkids == 0) {
		if ((op & n->opmask) == n->opval) return n;
		return 0;
	}

	for (i = 0; i < n->nkids; i++) {
			n->kids[i]->opmask, n->kids[i]->opval);
		if ((op & n->kids[i]->opmask) == n->kids[i]->opval) {
			return nsearch(n->kids[i], op);
		}
	}
*/
	return 0;
}

// compute least significant bit of a 32b number
// so 0100b would return 2
// 0111010110101101b would return 0
int lsb_index(ulong v)
{
	// google "bit twiddling hacks"
	const int mod37BitPos[] = // maps a bit value mod 37 to its position
	{
		32,0,1,26,2,23,27,0,3,16,24,30,28,11,0,13,4,
		7,17,0,25,22,31,15,29,10,12,6,0,21,14,9,5,
		20,8,19,18
	};
	return mod37BitPos[(-v & v) % 37];
}

double gettime() {
	struct timeval tv;
	gettimeofday(&tv, 0);
	return tv.tv_sec + tv.tv_usec/1e6;
}

int
main(int argc, char **argv)
{
	double t0, t1;
#include "nodes.h"
	/*
	struct node *n1 = mknode(0xe, 0x4, 0);
	struct node *n2 = mknode(0xe, 0x6, 0);
	struct node *n3 = mknode(0xe, 0x2, 0);
	struct node *n4 = mknode(0xf, 0, 0);
	struct node *n5 = mknode(0xc, 0x8, 0);
	struct node *n6 = mknode(0xc, 0x4, 2, n1, n2);
	struct node *n7 = mknode(0xc, 0, 2, n3, n4);
	struct node *n8 = mknode(0, 0, 3, n5, n6, n7);
*/
	static ushort codes[1048576];
	for (int i=0;i<1048576;i++) {
		codes[i] = (ushort)(rand()/(RAND_MAX+0.)*65536);
	}
	t0=gettime();
	for (int i=0;i<1048576;i++) {
		nsearch(node_0,codes[i],0);
	}
	t1=gettime();
	printf("%g sec for ~1e6 codes, %g code/sec\n",
			t1-t0, 1048576./(t1-t0));
	
	while (1) {
		ulong op;
		struct node *n;

		printf("val? "); fflush(0);
		scanf("%x", &op);
		ops = 0;
		t0 = gettime();
		n = nsearch(node_0, op, 0);
		t1 = gettime();
		printf("%g sec\n",t1-t0);
		if (n) {
			printf("opcode: %4x var: %4x name: %s fields:\n",
				n->opval, op & (~n->opmask), 
				Instructions[n->name].name);
			for (int i = 0; i < n->nfields; i++) {
				// assume all fields are contiguous sets of
				// bits, so we can just shift down from the LSB
				// of the field to bit 0 to get the real value
				// 
				// eg fields at like 00011110000
				//    and never like 01100110010
				printf("  %s: %04x\n",
					n->fields[i].name,
					(n->fields[i].mask & op) >>
					lsb_index(n->fields[i].mask));
			}
		} else {
			printf("BAD\n");
		}
		printf("TOOK %d OPS\n", ops);
	}
}

/*
vi:ts=4:et
*/

