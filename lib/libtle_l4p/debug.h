/*
 * Copyright (c) 2016  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define	FUNC_SEQ_VERIFY(v) do { \
	static uint64_t nb_call; \
	static typeof(v) x; \
	if (nb_call++ != 0) \
		RTE_VERIFY(tcp_seq_leq(x, v)); \
	x = (v); \
} while (0)

#define	FUNC_VERIFY(e, c) do { \
	static uint64_t nb_call; \
	if ((e) == 0) \
		nb_call++; \
	else \
		nb_call = 0; \
	RTE_VERIFY(nb_call != (c)); \
} while (0)

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

#ifdef __cplusplus
}
#endif

#endif /* _DEBUG_H_ */
