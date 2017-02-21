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
#include <string.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include "stream_table.h"

void
stbl_fini(struct stbl *st)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(st->ht); i++) {
		rte_hash_free(st->ht[i].t);
		rte_free(st->ht[i].ent);
	}

	memset(st, 0, sizeof(*st));
}

int
stbl_init(struct stbl *st, uint32_t num, int32_t socket)
{
	int32_t rc;
	size_t i, sz;
	struct rte_hash_parameters hprm;
	char buf[RTE_HASH_NAMESIZE];

	num = RTE_MAX(5 * num / 4, 0x10U);

	memset(&hprm, 0, sizeof(hprm));
	hprm.name = buf;
	hprm.entries = num;
	hprm.socket_id = socket;

	rc = 0;

	snprintf(buf, sizeof(buf), "stbl4@%p", st);
	hprm.key_len = sizeof(struct stbl4_key);
	st->ht[TLE_V4].t = rte_hash_create(&hprm);
	if (st->ht[TLE_V4].t == NULL)
		rc = (rte_errno != 0) ? -rte_errno : -ENOMEM;

	if (rc == 0) {
		snprintf(buf, sizeof(buf), "stbl6@%p", st);
		hprm.key_len = sizeof(struct stbl6_key);
		st->ht[TLE_V6].t = rte_hash_create(&hprm);
		if (st->ht[TLE_V6].t == NULL)
			rc = (rte_errno != 0) ? -rte_errno : -ENOMEM;
	}

	for (i = 0; i != RTE_DIM(st->ht) && rc == 0; i++) {

		sz = sizeof(*st->ht[i].ent) * num;
		st->ht[i].ent = rte_zmalloc_socket(NULL, sz,
			RTE_CACHE_LINE_SIZE, socket);
		if (st->ht[i].ent == NULL)
			rc = -ENOMEM;
		else
			st->ht[i].nb_ent = num;
	}

	if (rc != 0)
		stbl_fini(st);

	return rc;
}
