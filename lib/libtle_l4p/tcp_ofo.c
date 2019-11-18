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
#include <rte_errno.h>

#include "tcp_stream.h"
#include "tcp_rxq.h"

#define	OFO_FRACTION	4

#define OFO_DB_MAX	0x20U

#define OFODB_OBJ_MIN	8U
#define OFODB_OBJ_MAX	0x20U

#define OFO_OBJ_MAX	(OFODB_OBJ_MAX * OFO_DB_MAX)

void
calc_ofo_elems(uint32_t nbufs, uint32_t *nobj, uint32_t *ndb)
{
	uint32_t n, nd, no;

	n = nbufs / OFO_FRACTION;
	n = RTE_MAX(n, OFODB_OBJ_MIN);
	n = RTE_MIN(n, OFO_OBJ_MAX);

	no = OFODB_OBJ_MIN / 2;
	do {
		no *= 2;
		nd = n / no;
	} while (nd > OFO_DB_MAX);

	*nobj = no;
	*ndb = nd;
}
