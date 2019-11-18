/*
 * Copyright (c) 2016-2017  Intel Corporation.
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

#include <string.h>
#include <rte_hash.h>
#include "stream.h"
#include "misc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_SIZE_32K 32771
#define HASH_SIZE_64K 65537
#define HASH_SIZE_128K 131071

#define HASH_SIZE HASH_SIZE_64K

struct stbl_entry {
	void *data;
};

struct stbl {
	rte_spinlock_t l;
	uint32_t need_lock;
	struct stbl_entry head[HASH_SIZE];
} __rte_cache_aligned;

static inline int
stbl_init(struct stbl *st, uint32_t lock)
{
	st->need_lock = lock;
	return 0;
}

static inline int
stbl_fini(struct stbl *st)
{
	st->need_lock = 0;
	return 0;
}

static inline uint8_t
compare_pkt(const struct tle_stream *s, const union pkt_info *pi)
{
	if (s->type != pi->tf.type)
		return -1;

	if (s->port.raw != pi->port.raw)
		return -1;

	if (s->type == TLE_V4) {
		if (s->ipv4.addr.raw != pi->addr4.raw)
			return -1;
	} else {
		if (memcmp(&s->ipv6.addr, pi->addr6, sizeof(union ipv6_addrs)))
			return -1;
	}

	return 0;
}

static inline uint32_t
stbl_hash_stream(const struct tle_stream *s)
{
	int i;
	unsigned int hash;

	if (s->type == TLE_V4) {
		hash = s->ipv4.addr.src ^ s->ipv4.addr.dst
				^ s->port.src ^ s->port.dst;
	} else {
		hash = s->port.src ^ s->port.dst;
		for (i = 0; i < 4; i++) {
			hash ^= s->ipv6.addr.src.u32[i];
			hash ^= s->ipv6.addr.dst.u32[i];
		}
	}

	return hash % HASH_SIZE;
}

static inline uint32_t
stbl_hash_pkt(const union pkt_info* pi)
{
	int i;
	unsigned int hash;

	if (pi->tf.type == TLE_V4) {
		hash = pi->addr4.src ^ pi->addr4.dst ^ pi->port.src ^ pi->port.dst;
	} else {
		hash = pi->port.src ^ pi->port.dst;
		for (i = 0; i < 4; i++) {
			hash ^= pi->addr6->src.u32[i];
			hash ^= pi->addr6->dst.u32[i];
		}
	}

	return hash % HASH_SIZE;
}

static inline struct stbl_entry*
stbl_add_stream(struct stbl *st, struct tle_stream *s)
{
	struct stbl_entry* entry;

	if (st->need_lock)
		rte_spinlock_lock(&st->l);
	entry = &st->head[stbl_hash_stream(s)];
	s->link.stqe_next = (struct tle_stream*)entry->data;
	entry->data = s;
	if (st->need_lock)
		rte_spinlock_unlock(&st->l);

	return entry;
}

static inline struct tle_stream *
stbl_find_stream(struct stbl *st, const union pkt_info *pi)
{
	struct tle_stream* head;

	if (st->need_lock)
		rte_spinlock_lock(&st->l);
	head = (struct tle_stream*)st->head[stbl_hash_pkt(pi)].data;
	while (head != NULL) {
		if (compare_pkt(head, pi) == 0)
			break;

		head = head->link.stqe_next;
	}
	if (st->need_lock)
		rte_spinlock_unlock(&st->l);
	return head;
}

static inline void
stbl_del_stream(struct stbl *st, struct stbl_entry *se,
		struct tle_stream *s)
{
	struct tle_stream *prev, *current;

	if (st->need_lock)
		rte_spinlock_lock(&st->l);
	if (se == NULL)
		se = &st->head[stbl_hash_stream(s)];
	prev = NULL;
	current = (struct tle_stream*)se->data;
	while (current != NULL) {
		if (current != s) {
			prev = current;
			current = current->link.stqe_next;
			continue;
		}

		if (prev)
			prev->link.stqe_next = current->link.stqe_next;
		else
			se->data = current->link.stqe_next;
		break;
	}
	if (st->need_lock)
		rte_spinlock_unlock(&st->l);

	s->link.stqe_next = NULL;
}

struct bhash4_key {
	uint16_t port;
	uint32_t addr;
} __attribute__((__packed__));

struct bhash6_key {
	uint16_t port;
	rte_xmm_t addr;
} __attribute__((__packed__));

struct bhash_key {
	uint16_t port;
	union {
		uint32_t  addr4;
		rte_xmm_t addr6;
	};
} __attribute__((__packed__));

void bhash_fini(struct tle_ctx *ctx);

int bhash_init(struct tle_ctx *ctx);

static inline int
bhash_sockaddr2key(const struct sockaddr *addr, struct bhash_key *key)
{
	int t;
	const struct sockaddr_in *lin4;
	const struct sockaddr_in6 *lin6;

	if (addr->sa_family == AF_INET) {
		lin4 = (const struct sockaddr_in *)addr;
		key->port = lin4->sin_port;
		key->addr4 = lin4->sin_addr.s_addr;
		t = TLE_V4;
	} else {
		lin6 = (const struct sockaddr_in6 *)addr;
		memcpy(&key->addr6, &lin6->sin6_addr, sizeof(key->addr6));
		key->port = lin6->sin6_port;
		t = TLE_V6;
	}

	return t;
}

/* Return 0 on success;
 * Return errno on failure.
 */
static inline int
bhash_add_entry(struct tle_ctx *ctx, const struct sockaddr *addr,
		struct tle_stream *s)
{
	int t;
	int rc;
	int is_first;
	struct bhash_key key;
	struct rte_hash *bhash;
	struct tle_stream *old, *tmp;

	is_first = 0;
	t = bhash_sockaddr2key(addr, &key);

	rte_spinlock_lock(&ctx->bhash_lock[t]);
	bhash = ctx->bhash[t];
	rc = rte_hash_lookup_data(bhash, &key, (void **)&old);
	if (rc == -ENOENT) {
		is_first = 1;
		s->link.stqe_next = NULL; /* just to avoid follow */
		rc = rte_hash_add_key_data(bhash, &key, s);
	} else if (rc >= 0) {
		if (t == TLE_V4 && old->type == TLE_V6) {
			/* V6 stream may listen V4 address, assure V4 stream
			 * is ahead of V6 stream in the list
			 */
			s->link.stqe_next = old;
			rte_hash_add_key_data(bhash, &key, s);
		} else {
			tmp = old->link.stqe_next;
			old->link.stqe_next = s;
			s->link.stqe_next = tmp;
		}
	}
	rte_spinlock_unlock(&ctx->bhash_lock[t]);

	/* IPv6 socket with unspecified address could receive IPv4 packets.
	 * So the stream should also be recorded in IPv4 table.
	 * Only the first stream need be inserted into V4 list, otherwise
	 * the V6 list is already following V4 list.
	 */
	if (t == TLE_V6 && !s->option.ipv6only && is_first &&
			IN6_IS_ADDR_UNSPECIFIED(&key.addr6)) {
		t = TLE_V4;
		rte_spinlock_lock(&ctx->bhash_lock[t]);
		bhash = ctx->bhash[t];
		rc = rte_hash_lookup_data(bhash, &key, (void **)&old);
		if (rc == -ENOENT)
			rc = rte_hash_add_key_data(bhash, &key, s);
		else if (rc >= 0) {
			while(old->link.stqe_next != NULL)
				old = old->link.stqe_next;
			old->link.stqe_next = s;
			s->link.stqe_next = NULL;
		}
		rte_spinlock_unlock(&ctx->bhash_lock[t]);
	}

	return (rc >= 0) ? 0 : (-rc);
}

static inline void
bhash_del_entry(struct tle_ctx *ctx, struct tle_stream *s,
		const struct sockaddr *addr)
{
	int t;
	int rc;
	struct bhash_key key;
	struct tle_stream *f, *cur, *pre = NULL;

	t = bhash_sockaddr2key(addr, &key);

	rte_spinlock_lock(&ctx->bhash_lock[t]);
	rc = rte_hash_lookup_data(ctx->bhash[t], &key, (void **)&f);
	if (rc >= 0) {
		cur = f;
		pre = NULL;
		while (cur != s) {
			pre = cur;
			cur = cur->link.stqe_next;
		}

		if (pre == NULL) {
			cur = cur->link.stqe_next;
			if (cur == NULL)
				rte_hash_del_key(ctx->bhash[t], &key);
			else /* change data */
				rte_hash_add_key_data(ctx->bhash[t], &key, cur);
		} else
			pre->link.stqe_next = cur->link.stqe_next;
	}

	rte_spinlock_unlock(&ctx->bhash_lock[t]);

	if (rc < 0)
		return;

	s->link.stqe_next = NULL;

	/* IPv6 socket with unspecified address could receive IPv4 packets.
	 * So the stream should also be recorded in IPv4 table*/
	if (t == TLE_V6 && !s->option.ipv6only && pre == NULL &&
			IN6_IS_ADDR_UNSPECIFIED(&key.addr6)) {
		t = TLE_V4;
		rte_spinlock_lock(&ctx->bhash_lock[t]);
		rc = rte_hash_lookup_data(ctx->bhash[t], &key, (void **)&f);
		if (rc >= 0) {
			cur = f;
			pre = NULL;
			while (cur != s) {
				pre = cur;
				cur = cur->link.stqe_next;
			}

			if (pre == NULL) {
				cur = cur->link.stqe_next;
				if (cur == NULL)
					rte_hash_del_key(ctx->bhash[t], &key);
				else /* change data */
					rte_hash_add_key_data(ctx->bhash[t], &key, cur);
			} else
				pre->link.stqe_next = cur->link.stqe_next;
		}

		rte_spinlock_unlock(&ctx->bhash_lock[t]);
	}

}

static inline void *
bhash_reuseport_get_stream(struct tle_stream *s)
{
	int n = 0;
	struct tle_stream *e, *all[32];

	e = s;
	while(e && n < 32) {
		all[n++] = e;
		e = e->link.stqe_next;
	}

	/* for each connection, this function will be called twice
	 * 1st time for the first handshake: SYN
	 * 2nd time for the third handshake: ACK
	 */
	return all[(s->reuseport_seed++) % n];
}

static inline void *
bhash_lookup4(struct rte_hash *t, uint32_t addr, uint16_t port, uint8_t reuse)
{
	int rc;
	void *s = NULL;
	struct bhash_key key = {
		.port = port,
		.addr4 = addr,
	};

	rc = rte_hash_lookup_data(t, &key, &s);
	if (rc == -ENOENT) {
		key.addr4 = INADDR_ANY;
		rc = rte_hash_lookup_data(t, &key, &s);
	}

	if (rc >= 0) {
		if (reuse)
			return bhash_reuseport_get_stream(s);
		else
			return s;
	}

	return NULL;
}

static inline void *
bhash_lookup6(struct rte_hash *t, rte_xmm_t addr, uint16_t port, uint8_t reuse)
{
	int rc;
	void *s = NULL;
	struct bhash_key key = {
		.port = port,
		.addr6 = addr,
	};

	rc = rte_hash_lookup_data(t, &key, &s);
	if (rc == -ENOENT) {
		memcpy(&key.addr6, &tle_ipv6_any, sizeof(key.addr6));
		rc = rte_hash_lookup_data(t, &key, &s);
	}

	if (rc >= 0) {
		if (reuse)
			return bhash_reuseport_get_stream(s);
		else
			return s;
	}

	return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* _STREAM_TABLE_H_ */
