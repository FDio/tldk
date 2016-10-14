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

#ifndef _STREAM_TABLE_H_
#define _STREAM_TABLE_H_

#include <rte_hash.h>
#include "net_misc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* current stbl entry contains packet. */
#define	STE_PKT	1

struct stbl_entry {
	void *data;
};

struct stbl {
	uint32_t nb_ent; /* max number of entries in the table. */
	struct rte_hash *ht[TLE_VNUM];
	struct stbl_entry *ent;
};

struct stbl4_key {
	union l4_ports port;
	union ipv4_addrs addr;
} __attribute__((__packed__));

struct stbl6_key {
	union l4_ports port;
	union ipv6_addrs addr;
} __attribute__((__packed__));

struct stbl_key {
	union l4_ports port;
	union {
		union ipv4_addrs addr4;
		union ipv6_addrs addr6;
	};
} __attribute__((__packed__));

extern void stbl_fini(struct stbl *st);

extern int stbl_init(struct stbl *st, uint32_t num, int32_t socket);

static inline void
stbl_fill_key(struct stbl_key *k, const union pkt_info *pi, uint32_t type)
{
	static const struct stbl_key zero = {
		.port.raw = 0,
	};

	k->port = pi->port;
	if (type == TLE_V4)
		k->addr4 = pi->addr4;
	else if (type == TLE_V6)
		k->addr6 = *pi->addr6;
	else
		*k = zero;
}

static inline struct stbl_entry *
stbl_add_entry(struct stbl *st, const union pkt_info *pi)
{
	int32_t rc;
	uint32_t type;
	struct stbl_key k;

	type = pi->tf.type;
	stbl_fill_key(&k, pi, type);

	rc = rte_hash_add_key(st->ht[type], &k);
	if (rc < 0 || (uint32_t)rc > st->nb_ent)
		return NULL;
	return st->ent + rc;
}

static inline struct stbl_entry *
stbl_add_pkt(struct stbl *st, const union pkt_info *pi, const void *pkt)
{
	struct stbl_entry *se;

	se = stbl_add_entry(st, pi);
	if (se != NULL)
		se->data = (void *)((uintptr_t)pkt | STE_PKT);
	return se;
}

static inline struct stbl_entry *
stbl_find_entry(const struct stbl *st, const union pkt_info *pi)
{
	int32_t rc;
	uint32_t type;
	struct stbl_key k;

	type = pi->tf.type;
	stbl_fill_key(&k, pi, type);

	rc = rte_hash_lookup(st->ht[type], &k);
	if (rc < 0 || (uint32_t)rc > st->nb_ent)
		return NULL;
	return st->ent + rc;
}

static inline int
stbl_data_pkt(const void *p)
{
	return ((uintptr_t)p & STE_PKT);
}

static inline void *
stbl_get_pkt(const struct stbl_entry *se)
{
	return (void *)((uintptr_t)se->data ^ STE_PKT);
}

static inline void *
stbl_find_data(const struct stbl *st, const union pkt_info *pi)
{
	struct stbl_entry *ent;

	ent = stbl_find_entry(st, pi);
	return (ent == NULL) ? NULL : ent->data;
}

static inline void
stbl_del_pkt(struct stbl *st, struct stbl_entry *se, const union pkt_info *pi)
{
	uint32_t type;
	struct stbl_key k;

	se->data = NULL;

	type = pi->tf.type;
	stbl_fill_key(&k, pi, type);
	rte_hash_del_key(st->ht[type], &k);
}

static inline int
stbl_del_stream(struct stbl *st, const void *s)
{
	RTE_SET_USED(st);
	RTE_SET_USED(s);
	return -ENOTSUP;
}

#ifdef __cplusplus
}
#endif

#endif /* _STREAM_TABLE_H_ */
