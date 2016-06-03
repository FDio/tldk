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

#ifndef __FWDTBL_H__
#define __FWDTBL_H__

struct fwd4_key {
	uint32_t port;
	struct in_addr addr;
} __attribute__((__packed__));

struct fwd6_key {
	uint32_t port;
	struct in6_addr addr;
} __attribute__((__packed__));

union fwd_key {
	struct fwd4_key k4;
	struct fwd6_key k6;
};

static struct rte_hash *
fwd_tbl_key_prep(const struct netfe_lcore *fe, uint16_t family,
	const struct sockaddr *sa, union fwd_key *key)
{
	struct rte_hash *h;
	const struct sockaddr_in *sin4;
	const struct sockaddr_in6 *sin6;

	if (family == AF_INET) {
		h = fe->fw4h;
		sin4 = (const struct sockaddr_in *)sa;
		key->k4.port = sin4->sin_port;
		key->k4.addr = sin4->sin_addr;
	} else {
		h = fe->fw6h;
		sin6 = (const struct sockaddr_in6 *)sa;
		key->k6.port = sin6->sin6_port;
		key->k6.addr = sin6->sin6_addr;
	}

	return h;
}

static int
fwd_tbl_add(struct netfe_lcore *fe, uint16_t family, const struct sockaddr *sa,
	struct netfe_stream *data)
{
	int32_t rc;
	struct rte_hash *h;
	union fwd_key key;

	h = fwd_tbl_key_prep(fe, family, sa, &key);
	rc = rte_hash_add_key_data(h, &key, data);
	return rc;
}

static struct netfe_stream *
fwd_tbl_lkp(struct netfe_lcore *fe, uint16_t family, const struct sockaddr *sa)
{
	int rc;
	void *d;
	struct rte_hash *h;
	union fwd_key key;

	h = fwd_tbl_key_prep(fe, family, sa, &key);
	rc = rte_hash_lookup_data(h, &key, &d);
	if (rc < 0)
		d = NULL;
	return d;
}

static int
fwd_tbl_init(struct netfe_lcore *fe, uint16_t family, uint32_t lcore)
{
	int32_t rc;
	struct rte_hash **h;
	struct rte_hash_parameters hprm;
	char buf[RTE_HASH_NAMESIZE];

	if (family == AF_INET) {
		snprintf(buf, sizeof(buf), "fwd4tbl@%u", lcore);
		h = &fe->fw4h;
		hprm.key_len = sizeof(struct fwd4_key);
	} else {
		snprintf(buf, sizeof(buf), "fwd6tbl@%u", lcore);
		h = &fe->fw6h;
		hprm.key_len = sizeof(struct fwd6_key);
	}

	hprm.name = buf;
	hprm.entries = RTE_MAX(2 * fe->snum, 0x10U);
	hprm.socket_id = rte_lcore_to_socket_id(lcore);
	hprm.hash_func = NULL;
	hprm.hash_func_init_val = 0;

	*h = rte_hash_create(&hprm);
	if (*h == NULL)
		rc = (rte_errno != 0) ? -rte_errno : -ENOMEM;
	else
		rc = 0;
	return rc;
}

#endif /* __FWDTBL_H__ */
