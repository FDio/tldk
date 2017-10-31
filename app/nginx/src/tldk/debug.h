/*
 * Copyright (c) 2017  Intel Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _TLDK_DEBUG_H_
#define _TLDK_DEBUG_H_

#include <rte_cycles.h>

#define FUNC_STAT(v, c) do { \
	static uint64_t nb_call, nb_data; \
	nb_call++; \
	nb_data += (v); \
	if ((nb_call & ((c) - 1)) == 0) { \
		printf("%s#%d@%u: nb_call=%lu, avg(" #v ")=%#Lf\n", \
			__func__, __LINE__, rte_lcore_id(), nb_call, \
		(long double)nb_data / nb_call); \
		nb_call = 0; \
		nb_data = 0; \
	} \
} while (0)

#define FUNC_TM_STAT(v, c) do { \
	static uint64_t nb_call, nb_data; \
	static uint64_t cts, pts, sts; \
	cts = rte_rdtsc(); \
	if (pts != 0) \
		sts += cts - pts; \
	pts = cts; \
	nb_call++; \
	nb_data += (v); \
	if ((nb_call & ((c) - 1)) == 0) { \
	printf("%s#%d@%u: nb_call=%lu, " \
		"avg(" #v ")=%#Lf, " \
		"avg(cycles)=%#Lf, " \
		"avg(cycles/" #v ")=%#Lf\n", \
		__func__, __LINE__, rte_lcore_id(), nb_call, \
		(long double)nb_data / nb_call, \
		(long double)sts / nb_call, \
		(long double)sts / nb_data); \
		nb_call = 0; \
		nb_data = 0; \
		sts = 0; \
	} \
} while (0)

#define COND_FUNC_STAT(e, v, c)	do { \
	if (e) { \
		FUNC_STAT(v, c); \
	} \
} while (0)

#endif /* _TLDK_DEBUG_H_ */
