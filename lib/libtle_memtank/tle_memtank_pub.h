/*
 * Copyright (c) 2019  Intel Corporation.
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

#ifndef _TLE_MEMTANK_PUB_H_
#define _TLE_MEMTANK_PUB_H_

#include <tle_memtank.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * TLE memtank public
 * It is not recommended to include this file directly,
 * include <tle_memtank.h> instead.
 */

struct tle_memtank {
	rte_spinlock_t lock;
	uint32_t min_free;
	uint32_t max_free;
	uint32_t nb_free;
	void *free[];
} __rte_cache_aligned;


static inline void
_copy_objs(void *dst[], void * const src[], uint32_t num)
{
	uint32_t i, n;

	n = RTE_ALIGN_FLOOR(num, 4);

	for (i = 0; i != n; i += 4) {
		dst[i] = src[i];
		dst[i + 1] = src[i + 1];
		dst[i + 2] = src[i + 2];
		dst[i + 3] = src[i + 3];
	}

	switch (num % 4) {
	case 3:
		dst[i + 2] = src[i + 2];
		/* fallthrough */
	case 2:
		dst[i + 1] = src[i + 1];
		/* fallthrough */
	case 1:
		dst[i] = src[i];
		/* fallthrough */
	}
}

static inline uint32_t
_get_free(struct tle_memtank *t, void *obj[], uint32_t num)
{
	uint32_t len, n;

	rte_spinlock_lock(&t->lock);

	len = t->nb_free;
	n = RTE_MIN(num, len);
	len -= n;
	_copy_objs(obj, t->free + len, n);
	t->nb_free = len;

	rte_spinlock_unlock(&t->lock);
	return n;
}

static inline uint32_t
_put_free(struct tle_memtank *t, void * const obj[], uint32_t num)
{
	uint32_t len, n;

	rte_spinlock_lock(&t->lock);

	len = t->nb_free;
	n = t->max_free - len;
	n = RTE_MIN(num, n);
	_copy_objs(t->free + len, obj, n);
	t->nb_free = len + n;

	rte_spinlock_unlock(&t->lock);
	return n;
}

static inline void
_fill_free(struct tle_memtank *t, uint32_t num, uint32_t flags)
{
	uint32_t k, n;
	void *free[num];

	k = tle_memtank_chunk_alloc(t, free, RTE_DIM(free), flags);
	n = _put_free(t, free, k);
	if (n != k)
		tle_memtank_chunk_free(t, free + n, k - n, 0);
}

static inline uint32_t
tle_memtank_alloc(struct tle_memtank *t, void *obj[], uint32_t num,
	uint32_t flags)
{
	uint32_t n;

	n = _get_free(t, obj, num);

	/* not enough free objects, try to allocate via memchunks */
	if (n != num && flags != 0) {
		n += tle_memtank_chunk_alloc(t, obj + n, num - n, flags);

		/* refill *free* tank */
		if (n == num)
			_fill_free(t, t->min_free, flags);
	}

	return n;
}

static inline void
tle_memtank_free(struct tle_memtank *t, void * const obj[], uint32_t num,
	uint32_t flags)
{
	uint32_t n;

	n = _put_free(t, obj, num);
	if (n != num)
		tle_memtank_chunk_free(t, obj + n, num - n, flags);
}

#ifdef __cplusplus
}
#endif

#endif /* _TLE_MEMTANK_PUB_H_ */
