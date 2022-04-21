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

#ifndef _PORT_BITMAP_H_
#define _PORT_BITMAP_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Simple implementation of bitmap for all possible L4 ports [0-UINT16_MAX].
 */

#define MAX_PORT_NUM	(UINT16_MAX + 1)

#define PORT_BLK(p)	((p) / (sizeof(uint32_t) * CHAR_BIT))
#define PORT_IDX(p)	((p) % (sizeof(uint32_t) * CHAR_BIT))

#define	MAX_PORT_BLK	PORT_BLK(MAX_PORT_NUM)

struct tle_pbm {
	uint32_t nb_set; /* number of bits set. */
	uint32_t blk;    /* last block with free entry. */
	uint32_t bm[MAX_PORT_BLK];
};

static inline void
tle_pbm_init(struct tle_pbm *pbm, uint32_t blk)
{
	pbm->bm[0] = 1;
	pbm->nb_set = 1;
	pbm->blk = blk;
}

static inline void
tle_pbm_set(struct tle_pbm *pbm, uint16_t port)
{
	uint32_t i, b, v;

	i = PORT_BLK(port);
	b = 1 << PORT_IDX(port);
	v = pbm->bm[i];
	pbm->bm[i] = v | b;
	pbm->nb_set += (v & b) == 0;
}

static inline void
tle_pbm_clear(struct tle_pbm *pbm, uint16_t port)
{
	uint32_t i, b, v;

	i = PORT_BLK(port);
	b = 1 << PORT_IDX(port);
	v = pbm->bm[i];
	pbm->bm[i] = v & ~b;
	pbm->nb_set -= (v & b) != 0;
}


static inline uint32_t
tle_pbm_check(const struct tle_pbm *pbm, uint16_t port)
{
	uint32_t i, v;

	i = PORT_BLK(port);
	v = pbm->bm[i] >> PORT_IDX(port);
	return v & 1;
}

static inline uint16_t
tle_pbm_find_range(struct tle_pbm *pbm, uint32_t start_blk, uint32_t end_blk)
{
	uint32_t i, v;
	uint16_t p;

	if (pbm->nb_set == MAX_PORT_NUM)
		return 0;

	p = 0;
	for (i = start_blk; i != end_blk; i++) {
		i %= RTE_DIM(pbm->bm);
		v = pbm->bm[i];
		if (v != UINT32_MAX) {
			for (p = i * (sizeof(pbm->bm[0]) * CHAR_BIT);
					(v & 1) != 0; v >>= 1, p++)
				;

			pbm->blk = i;
			break;
		}
	}
	return p;
}

#ifdef __cplusplus
}
#endif

#endif /* _PORT_BITMAP_H_ */
