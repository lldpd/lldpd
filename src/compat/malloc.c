/* -*- mode: c; c-file-style: "openbsd" -*- */
/* malloc replacement that can allocate 0 byte */

#include <stdlib.h>
#include <sys/types.h>
#include "compat.h"
#undef malloc

/* Allocate an N-byte block of memory from the heap.
   If N is zero, allocate a 1-byte block.  */
void *
rpl_malloc(size_t n)
{
	if (n == 0) n = 1;
	return malloc(n);
}
