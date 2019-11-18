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
#include <rte_errno.h>

#include "stream_table.h"

void
bhash_fini(struct tle_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(ctx->bhash); i++)
		rte_hash_free(ctx->bhash[i]);
}

int
bhash_init(struct tle_ctx *ctx)
{
	int rc = 0;
	struct rte_hash_parameters hprm = {0};
	bool ipv6 = ctx->prm.lookup6 != NULL;
	char buf[RTE_HASH_NAMESIZE];

	hprm.name = buf;
	hprm.entries = 4096;
	hprm.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
	hprm.socket_id = ctx->prm.socket_id;

	snprintf(buf, sizeof(buf), "bhash4@%p", ctx);
	hprm.key_len = sizeof(struct bhash4_key);
	ctx->bhash[TLE_V4] = rte_hash_create(&hprm);
	if (ctx->bhash[TLE_V4] == NULL)
		rc = (rte_errno != 0) ? -rte_errno : -ENOMEM;

	if (rc == 0 && ipv6) {
		snprintf(buf, sizeof(buf), "bhash6@%p", ctx);
		hprm.key_len = sizeof(struct bhash6_key);
		ctx->bhash[TLE_V6] = rte_hash_create(&hprm);
		if (ctx->bhash[TLE_V6] == NULL) {
			rte_hash_free(ctx->bhash[TLE_V4]);
			rc = (rte_errno != 0) ? -rte_errno : -ENOMEM;
		}
	}

	return rc;
}
