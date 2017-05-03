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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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

#define	OPT_SHORT_ARP		'a'
#define	OPT_LONG_ARP		"enable-arp"

#define	OPT_SHORT_SBULK		'B'
#define	OPT_LONG_SBULK		"sburst"

#define	OPT_SHORT_PROMISC	'P'
#define	OPT_LONG_PROMISC	"promisc"

#define	OPT_SHORT_RBUFS	'R'
#define	OPT_LONG_RBUFS	"rbufs"

#define	OPT_SHORT_SBUFS	'S'
#define	OPT_LONG_SBUFS	"sbufs"

#define	OPT_SHORT_BECFG	'b'
#define	OPT_LONG_BECFG	"becfg"

#define	OPT_SHORT_FECFG	'f'
#define	OPT_LONG_FECFG	"fecfg"

#define	OPT_SHORT_STREAMS	's'
#define	OPT_LONG_STREAMS	"streams"

#define	OPT_SHORT_UDP	'U'
#define	OPT_LONG_UDP	"udp"

#define	OPT_SHORT_TCP	'T'
#define	OPT_LONG_TCP	"tcp"

#define	OPT_SHORT_LISTEN	'L'
#define	OPT_LONG_LISTEN		"listen"

#define OPT_SHORT_HASH         'H'
#define OPT_LONG_HASH          "hash"

#define OPT_SHORT_SEC_KEY         'K'
#define OPT_LONG_SEC_KEY          "seckey"

#define	OPT_SHORT_VERBOSE	'v'
#define	OPT_LONG_VERBOSE	"verbose"

static const struct option long_opt[] = {
	{OPT_LONG_ARP, 1, 0, OPT_SHORT_ARP},
	{OPT_LONG_SBULK, 1, 0, OPT_SHORT_SBULK},
	{OPT_LONG_PROMISC, 0, 0, OPT_SHORT_PROMISC},
	{OPT_LONG_RBUFS, 1, 0, OPT_SHORT_RBUFS},
	{OPT_LONG_SBUFS, 1, 0, OPT_SHORT_SBUFS},
	{OPT_LONG_BECFG, 1, 0, OPT_SHORT_BECFG},
	{OPT_LONG_FECFG, 1, 0, OPT_SHORT_FECFG},
	{OPT_LONG_STREAMS, 1, 0, OPT_SHORT_STREAMS},
	{OPT_LONG_UDP, 0, 0, OPT_SHORT_UDP},
	{OPT_LONG_TCP, 0, 0, OPT_SHORT_TCP},
	{OPT_LONG_HASH, 1, 0, OPT_SHORT_HASH},
	{OPT_LONG_SEC_KEY, 1, 0, OPT_SHORT_SEC_KEY},
	{OPT_LONG_LISTEN, 0, 0, OPT_SHORT_LISTEN},
	{OPT_LONG_VERBOSE, 1, 0, OPT_SHORT_VERBOSE},
	{NULL, 0, 0, 0}
};

static int
parse_uint_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;
	unsigned long v;
	char *end;

	rv = prm;
	errno = 0;
	v = strtoul(val, &end, 0);
	if (errno != 0 || end[0] != 0 || v > UINT32_MAX)
		return -EINVAL;

	rv->u64 = v;
	return 0;
}

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
parse_lcore_list_val(__rte_unused const char *key, const char *val, void *prm)
{
	union parse_val *rv;
	unsigned long a, b;
	uint32_t i;
	char *end;

	rv = prm;

	errno = 0;
	a = strtoul(val, &end, 0);
	if (errno != 0 || (end[0] != 0 && end[0] != '-') || a > UINT32_MAX)
		return -EINVAL;

	if (end[0] == '-') {
		val = end + 1;
		errno = 0;
		b = strtoul(val, &end, 0);
		if (errno != 0 || end[0] != 0 || b > UINT32_MAX)
			return -EINVAL;
	} else
		b = a;

	if (a <= b) {
		for (i = a; i <= b; i++)
			CPU_SET(i, &rv->cpuset);
	} else {
		RTE_LOG(ERR, USER1,
			"%s: lcores not in ascending order\n", __func__);
		return -EINVAL;
	}

	return 0;
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
				"%s: %s invalid value for man key: %s\n",
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
				"%s: %s invalid value for opt key: %s\n",
				__func__, arg, keys_opt[j]);
			rte_kvargs_free(kvl);
			return -EINVAL;
		}
	}

	rte_kvargs_free(kvl);
	return 0;
}

int
parse_netbe_arg(struct netbe_port *prt, const char *arg, rte_cpuset_t *pcpu)
{
	int32_t rc;
	uint32_t i, j, nc;

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
		parse_lcore_list_val,
		parse_uint_val,
		parse_uint_val,
		parse_uint_val,
		parse_ipv4_val,
		parse_ipv6_val,
	};

	union parse_val val[RTE_DIM(hndl)];

	memset(val, 0, sizeof(val));
	val[2].u64 = ETHER_MAX_LEN - ETHER_CRC_LEN;

	rc = parse_kvargs(arg, keys_man, RTE_DIM(keys_man),
		keys_opt, RTE_DIM(keys_opt), hndl, val);
	if (rc != 0)
		return rc;

	prt->id = val[0].u64;

	for (i = 0, nc = 0; i < RTE_MAX_LCORE; i++)
		nc += CPU_ISSET(i, &val[1].cpuset);
	prt->lcore_id = rte_zmalloc(NULL, nc * sizeof(prt->lcore_id[0]),
		RTE_CACHE_LINE_SIZE);
	prt->nb_lcore = nc;

	for (i = 0, j = 0; i < RTE_MAX_LCORE; i++)
		if (CPU_ISSET(i, &val[1].cpuset))
			prt->lcore_id[j++] = i;
	CPU_OR(pcpu, pcpu, &val[1].cpuset);

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
	rc = 0;
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
		rc = parse_netbe_dest(dp + n, s);
		rc = (rc != 0) ? rc : check_netbe_dest(dp + n);
		if (rc != 0) {
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
		"belcore",
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
		parse_uint_val,
	};

	union parse_val val[RTE_DIM(hndl)];

	memset(val, 0, sizeof(val));
	val[11].u64 = LCORE_ID_ANY;
	rc = parse_kvargs(arg, keys_man, RTE_DIM(keys_man),
		keys_opt, RTE_DIM(keys_opt), hndl, val);
	if (rc != 0)
		return rc;
	sp->lcore = val[0].u64;
	sp->op = val[1].u64;
	pv2saddr(&sp->sprm.local_addr, val + 2, val + 3);
	pv2saddr(&sp->sprm.remote_addr, val + 4, val + 5);
	sp->txlen = val[6].u64;
	pv2saddr(&sp->fprm.local_addr, val + 7, val + 8);
	pv2saddr(&sp->fprm.remote_addr, val + 9, val + 10);
	sp->belcore = val[11].u64;

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

	if (sp->sprm.local_addr.ss_family !=
			sp->sprm.remote_addr.ss_family) {
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
		} else if (is_addr_wc(&sp->sprm.remote_addr)) {
			RTE_LOG(ERR, USER1, "invalid arg at line %u: "
				"raddr=%s are not allowed for op=%s;\n",
				sp->line,
				format_addr(&sp->sprm.remote_addr,
				buf, sizeof(buf)),
				format_feop(sp->op));
			return -EINVAL;
		}
	} else if (sp->op == FWD) {
		if (sp->fprm.local_addr.ss_family !=
				sp->fprm.remote_addr.ss_family) {
			RTE_LOG(ERR, USER1, "invalid arg at line %u: "
				"fwladdr and fwraddr for different protocols\n",
				sp->line);
			return -EINVAL;
		} else if (is_addr_wc(&sp->fprm.remote_addr)) {
			RTE_LOG(ERR, USER1, "invalid arg at line %u: "
				"fwaddr=%s are not allowed for op=%s;\n",
				sp->line,
				format_addr(&sp->fprm.remote_addr,
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
	rc = 0;
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
		rc = parse_netfe_arg(sp + n, s);
		rc = (rc != 0) ? rc : check_netfe_arg(sp + n);
		if (rc != 0) {
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

static uint32_t
parse_hash_alg(const char *val)
{
	if (strcmp(val, "jhash") == 0)
		return TLE_JHASH;
	else if (strcmp(val, "siphash") == 0)
		return TLE_SIPHASH;
	else
		return TLE_HASH_NUM;
}

int
parse_app_options(int argc, char **argv, struct netbe_cfg *cfg,
	struct tle_ctx_param *ctx_prm,
	char *fecfg_fname, char *becfg_fname)
{
	int32_t opt, opt_idx, rc;
	uint64_t v;
	uint32_t i, j, n, nc;
	rte_cpuset_t cpuset;
	uint32_t udp = 0, tcp = 0, listen = 0;

	optind = 0;
	optarg = NULL;
	while ((opt = getopt_long(argc, argv, "aB:LPR:S:TUb:f:s:v:H:K:",
			long_opt, &opt_idx)) != EOF) {
		if (opt == OPT_SHORT_ARP) {
			cfg->arp = 1;
		} else if (opt == OPT_SHORT_SBULK) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->send_bulk_size = v;
		} else if (opt == OPT_SHORT_PROMISC) {
			cfg->promisc = 1;
		} else if (opt == OPT_SHORT_RBUFS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->max_stream_rbufs = v;
		} else if (opt == OPT_SHORT_SBUFS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->max_stream_sbufs = v;
		} else if (opt == OPT_SHORT_STREAMS) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			ctx_prm->max_streams = v;
		} else if (opt == OPT_SHORT_VERBOSE) {
			rc = parse_uint_val(NULL, optarg, &v);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "%s: invalid value: %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			verbose = (v > VERBOSE_NUM) ? VERBOSE_NUM : v;
		} else if (opt == OPT_SHORT_BECFG) {
			snprintf(becfg_fname, PATH_MAX, "%s",
				optarg);
		} else if (opt == OPT_SHORT_FECFG) {
			snprintf(fecfg_fname, PATH_MAX, "%s",
				optarg);
		} else if (opt == OPT_SHORT_UDP) {
			udp = 1;
			cfg->proto = TLE_PROTO_UDP;
		} else if (opt == OPT_SHORT_TCP) {
			tcp = 1;
			cfg->proto = TLE_PROTO_TCP;
		} else if (opt == OPT_SHORT_LISTEN) {
			listen = 1;
			cfg->server = 1;
		} else if (opt == OPT_SHORT_HASH) {
			ctx_prm->hash_alg = parse_hash_alg(optarg);
			if (ctx_prm->hash_alg >= TLE_HASH_NUM) {
				rte_exit(EXIT_FAILURE,
					"%s: invalid hash algorithm %s "
					"for option: \'%c\'\n",
					__func__, optarg, opt);
			}
		} else if (opt == OPT_SHORT_SEC_KEY) {
			n = strlen(optarg);
			if (n != sizeof(ctx_prm->secret_key)) {
				rte_exit(EXIT_FAILURE,
					"%s: invalid length %s "
					"for option \'%c\' "
					"must be 16 characters long\n",
					__func__, optarg, opt);
			}
			memcpy(&ctx_prm->secret_key, optarg,
				sizeof(ctx_prm->secret_key));
		}

		else {
			rte_exit(EXIT_FAILURE,
				"%s: unknown option: \'%c\'\n",
				__func__, opt);
		}
	}

	if (!udp && !tcp)
		rte_exit(EXIT_FAILURE, "%s: either UDP or TCP option has to be "
			"provided\n", __func__);

	if (udp && tcp)
		rte_exit(EXIT_FAILURE, "%s: both UDP and TCP options are not "
			"allowed\n", __func__);

	if (udp && listen)
		rte_exit(EXIT_FAILURE,
			"%s: listen mode cannot be opened with UDP\n",
			__func__);

	if (udp && cfg->arp)
		rte_exit(EXIT_FAILURE,
			"%s: arp cannot be enabled with UDP\n",
			__func__);

	/* parse port params */
	argc -= optind;
	argv += optind;

	/* allocate memory for number of ports defined */
	n = (uint32_t)argc;
	cfg->prt = rte_zmalloc(NULL, sizeof(struct netbe_port) * n,
		RTE_CACHE_LINE_SIZE);
	cfg->prt_num = n;

	rc = 0;
	for (i = 0; i != n; i++) {
		rc = parse_netbe_arg(cfg->prt + i, argv[i], &cpuset);
		if (rc != 0) {
			RTE_LOG(ERR, USER1,
				"%s: processing of \"%s\" failed with error "
				"code: %d\n", __func__, argv[i], rc);
			for (j = 0; j != i; j++)
				rte_free(cfg->prt[j].lcore_id);
			rte_free(cfg->prt);
			return rc;
		}
	}

	/* count the number of CPU defined in ports */
	for (i = 0, nc = 0; i < RTE_MAX_LCORE; i++)
		nc += CPU_ISSET(i, &cpuset);

	/* allocate memory for number of CPU defined */
	cfg->cpu = rte_zmalloc(NULL, sizeof(struct netbe_lcore) * nc,
		RTE_CACHE_LINE_SIZE);

	return 0;
}
