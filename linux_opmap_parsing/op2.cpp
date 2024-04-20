#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>

#include "opins.hpp"

typedef unsigned short ushort;
typedef unsigned long ulong;

const char *nsearch(ushort code)
{
#include "switch"
}

double gettime() {
	struct timeval tv;
	gettimeofday(&tv,0);
	return tv.tv_sec + tv.tv_usec/1e6;
}

int
main(int argc, char **argv)
{
	double t0,t1;
        static ushort codes[1048576];
	        for (int i=0;i<1048576;i++) {
			                codes[i] = (ushort)(rand()/(RAND_MAX+0.)*65536);
					        }
		        t0=gettime();
			        for (int i=0;i<1048576;i++) {
					                nsearch(codes[i]);
							        }
				        t1=gettime();
					        printf("%g sec for ~1e6 codes, %g code/sec\n",
								                        t1-t0, 1048576./(t1-t0));

	while (1) {
		ulong op;
		const char *n;

		printf("val? "); fflush(0);
		scanf("%x", &op);
		t0 = gettime();
		n = nsearch(op);
		t1 = gettime();
		printf("%g sec\n", t1-t0);
		printf("%s\n",n);
	}
}

/*
vi:ts=4:et
*/

