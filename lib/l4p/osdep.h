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

#ifndef _OSDEP_H_
#define _OSDEP_H_

#include <rte_vect.h>
#include <rte_memcpy.h>
#include <rte_spinlock.h>
#include <rte_log.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * internal defines.
 */
#define	MAX_PKT_BURST	0x20

#define	MAX_DRB_BURST	4

/*
 * logging related macros.
 */

#define UDP_LOG(lvl, fmt, args...)      RTE_LOG(lvl, USER1, fmt, ##args)

#define TCP_LOG(lvl, fmt, args...)      RTE_LOG(lvl, USER1, fmt, ##args)

/*
 * if no AVX support, define _ymm_t here.
 */

#ifdef __AVX__

#define _ymm_t	rte_ymm_t

#else

#define YMM_SIZE        (2 * sizeof(rte_xmm_t))
#define YMM_MASK        (YMM_SIZE - 1)

typedef union _ymm {
	xmm_t    x[YMM_SIZE / sizeof(xmm_t)];
	uint8_t  u8[YMM_SIZE / sizeof(uint8_t)];
	uint16_t u16[YMM_SIZE / sizeof(uint16_t)];
	uint32_t u32[YMM_SIZE / sizeof(uint32_t)];
	uint64_t u64[YMM_SIZE / sizeof(uint64_t)];
	double   pd[YMM_SIZE / sizeof(double)];
} _ymm_t;

#endif /* __AVX__ */

#include "debug.h"

#ifdef __cplusplus
}
#endif

#endif /* _OSDEP_H_ */
