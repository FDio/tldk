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

#include "netbe.h"
#include "parse.h"

#define DEF_LINE_NUM	0x400

static const struct {
	const char *name;
	uint16_t op;
} name2feop[] = {
	{ .name = "rx", .op = RXONLY,},
	{ .name = "tx", .op = TXONLY,},
	{ .name = "echo", .op = RXTX,},
	{ .name = "fwd", .op = FWD,},
};

static int
parse_ipv4_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;

	rv = prm;
	if (inet_pton(AF_INET, val, &rv->in.addr4) != 1)
		return -EINVAL;
	rv->in.family = AF_INET;
	return 0;
}

static int
parse_ipv6_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;

	rv = prm;
	if (inet_pton(AF_INET6, val, &rv->in.addr6) != 1)
		return -EINVAL;
	rv->in.family = AF_INET6;
	return 0;
}

static int
parse_ip_val(__rte_unused const char *key, const char *val, void *prm)
{
	if (parse_ipv6_val(key, val, prm) != 0 &&
			parse_ipv4_val(key, val, prm) != 0)
		return -EINVAL;
	return 0;
}


#define PARSE_UINT8x16(s, v, l)	                          \
do {                                                      \
	char *end;                                        \
	unsigned long t;                                  \
	errno = 0;                                        \
	t = strtoul((s), &end, 16);                       \
	if (errno != 0 || end[0] != (l) || t > UINT8_MAX) \
		return -EINVAL;                           \
	(s) = end + 1;                                    \
	(v) = t;                                          \
} while (0)

static int
parse_mac_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;
	const char *s;

	rv = prm;
	s = val;

	PARSE_UINT8x16(s, rv->mac.addr_bytes[0], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[1], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[2], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[3], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[4], ':');
	PARSE_UINT8x16(s, rv->mac.addr_bytes[5], 0);
	return 0;
}

static int
parse_feop_val(__rte_unused const char *key, const char *val, void *prm)
{
	uint32_t i;
	union parse_val *rv;

	rv = prm;
	for (i = 0; i != RTE_DIM(name2feop); i++) {
		if (strcmp(val, name2feop[i].name) == 0) {
			rv->u64 = name2feop[i].op;
			return 0;
		}
	}

	return -EINVAL;
}

static int
parse_kvargs(const char *arg, const char *keys_man[], uint32_t nb_man,
	const char *keys_opt[], uint32_t nb_opt,
	const arg_handler_t hndl[], union parse_val val[])
{
	uint32_t j, k;
	struct rte_kvargs *kvl;

	kvl = rte_kvargs_parse(arg, NULL);
	if (kvl == NULL) {
		RTE_LOG(ERR, USER1,
			"%s: invalid parameter: %s\n",
			__func__, arg);
		return -EINVAL;
	}

	for (j = 0; j != nb_man; j++) {
		if (rte_kvargs_count(kvl, keys_man[j]) == 0) {
			RTE_LOG(ERR, USER1,
				"%s: %s missing mandatory key: %s\n",
				__func__, arg, keys_man[j]);
			rte_kvargs_free(kvl);
			return -EINVAL;
		}
	}

	for (j = 0; j != nb_man; j++) {
		if (rte_kvargs_process(kvl, keys_man[j], hndl[j],
				val + j) != 0) {
			RTE_LOG(ERR, USER1,
				"%s: %s invalid value for key: %s\n",
				__func__, arg, keys_man[j]);
			rte_kvargs_free(kvl);
			return -EINVAL;
		}
	}

	for (j = 0; j != nb_opt; j++) {
		k = j + nb_man;
		if (rte_kvargs_process(kvl, keys_opt[j], hndl[k],
				val + k) != 0) {
			RTE_LOG(ERR, USER1,
				"%s: %s invalid value for key: %s\n",
				__func__, arg, keys_opt[j]);
			rte_kvargs_free(kvl);
			return -EINVAL;
		}
	}

	rte_kvargs_free(kvl);
	return 0;
}

int
parse_netbe_arg(struct netbe_port *prt, const char *arg)
{
	int32_t rc;

	static const char *keys_man[] = {
		"port",
		"lcore",
	};

	static const char *keys_opt[] = {
		"mtu",
		"rx_offload",
		"tx_offload",
		"ipv4",
		"ipv6",
	};

	static const arg_handler_t hndl[] = {
		parse_uint_val,
		parse_uint_val,
		parse_uint_val,
		parse_uint_val,
		parse_uint_val,
		parse_ipv4_val,
		parse_ipv6_val,
	};

	union parse_val val[RTE_DIM(hndl)];

	memset(val, 0, sizeof(val));
	val[2].u64 = ETHER_MAX_VLAN_FRAME_LEN - ETHER_CRC_LEN;

	rc = parse_kvargs(arg, keys_man, RTE_DIM(keys_man),
		keys_opt, RTE_DIM(keys_opt), hndl, val);
	if (rc != 0)
		return rc;

	prt->id = val[0].u64;
	prt->lcore = val[1].u64;
	prt->mtu = val[2].u64;
	prt->rx_offload = val[3].u64;
	prt->tx_offload = val[4].u64;
	prt->ipv4 = val[5].in.addr4.s_addr;
	prt->ipv6 = val[6].in.addr6;

	return 0;
}
static int
check_netbe_dest(const struct netbe_dest *dst)
{
	if (dst->port >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, USER1, "%s(line=%u) invalid port=%u",
			__func__, dst->line, dst->port);
		return -EINVAL;
	} else if ((dst->family == AF_INET &&
			dst->prfx > sizeof(struct in_addr) * CHAR_BIT) ||
			(dst->family == AF_INET6 &&
			dst->prfx > sizeof(struct in6_addr) * CHAR_BIT)) {
		RTE_LOG(ERR, USER1, "%s(line=%u) invalid masklen=%u",
			__func__, dst->line, dst->prfx);
		return -EINVAL;
	} else if (dst->mtu > ETHER_MAX_JUMBO_FRAME_LEN - ETHER_CRC_LEN) {
		RTE_LOG(ERR, USER1, "%s(line=%u) invalid mtu=%u",
			__func__, dst->line, dst->mtu);
		return -EINVAL;
	}
	return 0;
}

static int
parse_netbe_dest(struct netbe_dest *dst, const char *arg)
{
	int32_t rc;

	static const char *keys_man[] = {
		"port",
		"addr",
		"masklen",
		"mac",
	};

	static const char *keys_opt[] = {
		"mtu",
	};

	static const arg_handler_t hndl[] = {
		parse_uint_val,
		parse_ip_val,
		parse_uint_val,
		parse_mac_val,
		parse_uint_val,
	};

	union parse_val val[RTE_DIM(hndl)];

	/* set default values. */
	memset(val, 0, sizeof(val));
	val[4].u64 = ETHER_MAX_JUMBO_FRAME_LEN - ETHER_CRC_LEN;

	rc = parse_kvargs(arg, keys_man, RTE_DIM(keys_man),
		keys_opt, RTE_DIM(keys_opt), hndl, val);
	if (rc != 0)
		return rc;

	dst->port = val[0].u64;
	dst->family = val[1].in.family;
	if (val[1].in.family == AF_INET)
		dst->ipv4 = val[1].in.addr4;
	else
		dst->ipv6 = val[1].in.addr6;
	dst->prfx = val[2].u64;
	memcpy(&dst->mac, &val[3].mac, sizeof(dst->mac));
	dst->mtu = val[4].u64;

	return 0;
}

int
netbe_parse_dest(const char *fname, struct netbe_dest_prm *prm)
{
	uint32_t i, ln, n, num;
	int32_t rc;
	size_t sz;
	char *s;
	FILE *f;
	struct netbe_dest *dp;
	char line[LINE_MAX];

	f = fopen(fname, "r");
	if (f == NULL) {
		RTE_LOG(ERR, USER1, "%s failed to open file \"%s\"\n",
			__func__, fname);
		return -EINVAL;
	}

	n = 0;
	num = 0;
	dp = NULL;

	for (ln = 0; fgets(line, sizeof(line), f) != NULL; ln++) {

		/* skip spaces at the start. */
		for (s = line; isspace(s[0]); s++)
			;

		/* skip comment line. */
		if (s[0] == '#' || s[0] == 0)
			continue;

		/* skip spaces at the end. */
		for (i = strlen(s); i-- != 0 && isspace(s[i]); s[i] = 0)
			;

		if (n == num) {
			num += DEF_LINE_NUM;
			sz = sizeof(dp[0]) * num;
			dp = realloc(dp, sizeof(dp[0]) * num);
			if (dp == NULL) {
				RTE_LOG(ERR, USER1,
					"%s(%s) allocation of %zu bytes "
					"failed\n",
					__func__, fname, sz);
				rc = -ENOMEM;
				break;
			}
			memset(&dp[n], 0, sizeof(dp[0]) * (num - n));
		}

		dp[n].line = ln + 1;
		if ((rc = parse_netbe_dest(dp + n, s)) != 0 ||
				(rc = check_netbe_dest(dp + n)) != 0) {
			RTE_LOG(ERR, USER1, "%s(%s) failed to parse line %u\n",
				__func__, fname, dp[n].line);
			break;
		}
		n++;
	}

	fclose(f);

	if (rc != 0) {
		free(dp);
		dp = NULL;
		n = 0;
	}

	prm->dest = dp;
	prm->nb_dest = n;
	return rc;
}

static void
pv2saddr(struct sockaddr_storage *ss, const union parse_val *pva,
	const union parse_val *pvp)
{
	ss->ss_family = pva->in.family;
	if (pva->in.family == AF_INET) {
		struct sockaddr_in *si = (struct sockaddr_in *)ss;
		si->sin_addr = pva->in.addr4;
		si->sin_port = rte_cpu_to_be_16((uint16_t)pvp->u64);
	} else {
		struct sockaddr_in6 *si = (struct sockaddr_in6 *)ss;
		si->sin6_addr = pva->in.addr6;
		si->sin6_port = rte_cpu_to_be_16((uint16_t)pvp->u64);
	}
}

static int
parse_netfe_arg(struct netfe_stream_prm *sp, const char *arg)
{
	int32_t rc;

	static const char *keys_man[] = {
		"lcore",
		"op",
		"laddr",
		"lport",
		"raddr",
		"rport",
	};

	static const char *keys_opt[] = {
		"txlen",
		"fwladdr",
		"fwlport",
		"fwraddr",
		"fwrport",
	};

	static const arg_handler_t hndl[] = {
		parse_uint_val,
		parse_feop_val,
		parse_ip_val,
		parse_uint_val,
		parse_ip_val,
		parse_uint_val,
		parse_uint_val,
		parse_ip_val,
		parse_uint_val,
		parse_ip_val,
		parse_uint_val,
	};

	union parse_val val[RTE_DIM(hndl)];

	memset(val, 0, sizeof(val));
	rc = parse_kvargs(arg, keys_man, RTE_DIM(keys_man),
		keys_opt, RTE_DIM(keys_opt), hndl, val);
	if (rc != 0)
		return rc;

	sp->lcore = val[0].u64;
	sp->op = val[1].u64;
	pv2saddr(&sp->sprm.prm.local_addr, val + 2, val + 3);
	pv2saddr(&sp->sprm.prm.remote_addr, val + 4, val + 5);
	sp->txlen = val[6].u64;
	pv2saddr(&sp->fprm.prm.local_addr, val + 7, val + 8);
	pv2saddr(&sp->fprm.prm.remote_addr, val + 9, val + 10);

	return 0;
}

static const char *
format_feop(uint16_t op)
{
	uint32_t i;

	for (i = 0; i != RTE_DIM(name2feop); i++) {
		if (name2feop[i].op == op)
			return name2feop[i].name;
	}

	return NULL;
}

static int
is_addr_wc(const struct sockaddr_storage *sp)
{
	const struct sockaddr_in *i4;
	const struct sockaddr_in6 *i6;

	if (sp->ss_family == AF_INET) {
		i4 = (const struct sockaddr_in *)sp;
		return  (i4->sin_addr.s_addr == INADDR_ANY);
	} else if (sp->ss_family == AF_INET6) {
		i6 = (const struct sockaddr_in6 *)sp;
		return (memcmp(&i6->sin6_addr, &in6addr_any,
			sizeof(i6->sin6_addr)) == 0);
	}
	return 0;
}

static int
check_netfe_arg(const struct netfe_stream_prm *sp)
{
	char buf[INET6_ADDRSTRLEN];

	if (sp->sprm.prm.local_addr.ss_family !=
			sp->sprm.prm.remote_addr.ss_family) {
		RTE_LOG(ERR, USER1, "invalid arg at line %u: "
			"laddr and raddr for different protocols\n",
			sp->line);
		return -EINVAL;
	}

	if (sp->op == TXONLY) {
		if (sp->txlen > RTE_MBUF_DEFAULT_DATAROOM || sp->txlen == 0) {
			RTE_LOG(ERR, USER1, "invalid arg at line %u: txlen=%u "
				"exceeds allowed values: (0, %u]\n",
				sp->line, sp->txlen, RTE_MBUF_DEFAULT_DATAROOM);
			return -EINVAL;
		} else if (is_addr_wc(&sp->sprm.prm.remote_addr)) {
			RTE_LOG(ERR, USER1, "invalid arg at line %u: "
				"raddr=%s are not allowed for op=%s;\n",
				sp->line,
				format_addr(&sp->sprm.prm.remote_addr,
				buf, sizeof(buf)),
				format_feop(sp->op));
			return -EINVAL;
		}
	} else if (sp->op == FWD) {
		if (sp->fprm.prm.local_addr.ss_family !=
				sp->fprm.prm.remote_addr.ss_family) {
			RTE_LOG(ERR, USER1, "invalid arg at line %u: "
				"fwladdr and fwraddr for different protocols\n",
				sp->line);
			return -EINVAL;
		} else if (is_addr_wc(&sp->fprm.prm.remote_addr)) {
			RTE_LOG(ERR, USER1, "invalid arg at line %u: "
				"fwaddr=%s are not allowed for op=%s;\n",
				sp->line,
				format_addr(&sp->fprm.prm.remote_addr,
				buf, sizeof(buf)),
				format_feop(sp->op));
			return -EINVAL;
		}
	}

	return 0;
}

int
netfe_parse_cfg(const char *fname, struct netfe_lcore_prm *lp)
{
	uint32_t i, ln, n, num;
	int32_t rc;
	size_t sz;
	char *s;
	FILE *f;
	struct netfe_stream_prm *sp;
	char line[LINE_MAX];

	f = fopen(fname, "r");
	if (f == NULL) {
		RTE_LOG(ERR, USER1, "%s failed to open file \"%s\"\n",
			__func__, fname);
		return -EINVAL;
	}

	n = 0;
	num = 0;
	sp = NULL;

	for (ln = 0; fgets(line, sizeof(line), f) != NULL; ln++) {

		/* skip spaces at the start. */
		for (s = line; isspace(s[0]); s++)
			;

		/* skip comment line. */
		if (s[0] == '#' || s[0] == 0)
			continue;

		/* skip spaces at the end. */
		for (i = strlen(s); i-- != 0 && isspace(s[i]); s[i] = 0)
			;

		if (n == lp->max_streams) {
			RTE_LOG(ERR, USER1,
				"%s(%s) number of entries exceed max streams "
				"value: %u\n",
				__func__, fname, n);
				rc = -EINVAL;
				break;
		}

		if (n == num) {
			num += DEF_LINE_NUM;
			sz = sizeof(sp[0]) * num;
			sp = realloc(sp, sizeof(sp[0]) * num);
			if (sp == NULL) {
				RTE_LOG(ERR, USER1,
					"%s(%s) allocation of %zu bytes "
					"failed\n",
					__func__, fname, sz);
				rc = -ENOMEM;
				break;
			}
			memset(&sp[n], 0, sizeof(sp[0]) * (num - n));
		}

		sp[n].line = ln + 1;
		if ((rc = parse_netfe_arg(sp + n, s)) != 0 ||
				(rc = check_netfe_arg(sp + n)) != 0) {
			RTE_LOG(ERR, USER1, "%s(%s) failed to parse line %u\n",
				__func__, fname, sp[n].line);
			break;
		}
		n++;
	}

	fclose(f);

	if (rc != 0) {
		free(sp);
		sp = NULL;
		n = 0;
	}

	lp->stream = sp;
	lp->nb_streams = n;
	return rc;
}
