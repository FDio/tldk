/*
 * Copyright (c) 2017  Intel Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_tldk.h>

union parse_val {
	uint64_t u64;
	struct {
		uint16_t family;
		 union {
			struct in_addr addr4;
			struct in6_addr addr6;
		};
	} in;
	struct ether_addr mac;
	rte_cpuset_t cpuset;
};

struct key_handler {
	const char *name;
	int (*func)(const char *, void *);
};

static int
parse_uint_val(const char *val, void *prm)
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
parse_ipv4_val(const char *val, void *prm)
{
	union parse_val *rv;

	rv = prm;
	if (inet_pton(AF_INET, val, &rv->in.addr4) != 1)
		return -EINVAL;
	rv->in.family = AF_INET;
	return 0;
}

static int
parse_ipv6_val(const char *val, void *prm)
{
	union parse_val *rv;

	rv = prm;
	if (inet_pton(AF_INET6, val, &rv->in.addr6) != 1)
		return -EINVAL;
	rv->in.family = AF_INET6;
	return 0;
}

static int
parse_ip_val(const char *val, void *prm)
{
	if (parse_ipv6_val(val, prm) != 0 &&
			parse_ipv4_val(val, prm) != 0)
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
parse_mac_val(const char *val, void *prm)
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

static char *
tldk_port_parse(ngx_conf_t *cf, struct tldk_port_conf *prt)
{
	uint32_t i, j;
	ngx_str_t *v;

	static const struct key_handler kh[] = {
		{
			.name = "port",
			.func = parse_uint_val,
		},
		{
			.name = "mtu",
			.func = parse_uint_val,
		},
		{
			.name = "rx_offload",
			.func = parse_uint_val,
		},
		{
			.name = "tx_offload",
			.func = parse_uint_val,
		},
		{
			.name = "ipv4",
			.func = parse_ipv4_val,
		},
		{
			.name = "ipv6",
			.func = parse_ipv6_val,
		},
	};

	union parse_val pvl[RTE_DIM(kh)];

	memset(pvl, 0, sizeof(pvl));
	pvl[1].u64 = ETHER_MAX_LEN - ETHER_CRC_LEN;

	if (cf->args->nelts % 2 != 0)
		return NGX_CONF_ERROR;

	v = cf->args->elts;
	for (i = 0; i != cf->args->nelts; i += 2) {

		for (j = 0; j != RTE_DIM(kh); j++) {
			if (ngx_strcmp(v[i].data, kh[j].name) == 0) {
				 if (kh[j].func((const char *)v[i + 1].data,
						pvl + j) < 0)
					return NGX_CONF_ERROR;
				else
					break;
			}
		}

		/* unknow key */
		if (j == RTE_DIM(kh))
			return NGX_CONF_ERROR;
	}

	memset(prt, 0, sizeof(*prt));

	prt->id = pvl[0].u64;
	prt->mtu = pvl[1].u64;
	prt->rx_offload = pvl[2].u64;
	prt->tx_offload = pvl[3].u64;
	prt->ipv4 = pvl[4].in.addr4.s_addr;
	prt->ipv6 = pvl[5].in.addr6;

	return NGX_CONF_OK;
}

static char *
tldk_dev_parse(ngx_conf_t *cf, struct tldk_dev_conf *dev,
		tldk_conf_t *tcf)
{
	uint32_t i, j;
	ngx_str_t *v;

	static const struct key_handler kh[] = {
		{
			.name = "dev",
			.func = parse_uint_val,
		},
		{
			.name = "port",
			.func = parse_uint_val,
		},
		{
			.name = "queue",
			.func = parse_uint_val,
		},
	};

	union parse_val pvl[RTE_DIM(kh)];

	memset(pvl, 0, sizeof(pvl));

	if (cf->args->nelts % 2 != 0)
		return NGX_CONF_ERROR;

	v = cf->args->elts;
	for (i = 0; i != cf->args->nelts; i += 2) {

		for (j = 0; j != RTE_DIM(kh); j++) {
			if (ngx_strcmp(v[i].data, kh[j].name) == 0) {
				 if (kh[j].func((const char *)v[i + 1].data,
						pvl + j) < 0)
					return NGX_CONF_ERROR;
				else
					break;
			}
		}

		/* unknow key */
		if (j == RTE_DIM(kh))
			return NGX_CONF_ERROR;
	}

	memset(dev, 0, sizeof(*dev));

	dev->id = pvl[0].u64;
	dev->port = pvl[1].u64;
	dev->queue = pvl[2].u64;

	return NGX_CONF_OK;
}

static char *
tldk_dest_parse(ngx_conf_t *cf, struct tldk_dest_conf *dst)
{
	uint32_t i, j;
	ngx_str_t *v;

	static const struct key_handler kh[] = {
		{
			.name = "dev",
			.func = parse_uint_val,
		},
		{
			.name = "mtu",
			.func = parse_uint_val,
		},
		{
			.name = "masklen",
			.func = parse_uint_val,
		},
		{
			.name = "addr",
			.func = parse_ip_val,
		},
		{
			.name = "mac",
			.func = parse_mac_val,
		},
	};

	union parse_val pvl[RTE_DIM(kh)];

	memset(pvl, 0, sizeof(pvl));
	pvl[1].u64 = ETHER_MAX_LEN - ETHER_CRC_LEN;

	if (cf->args->nelts % 2 != 1 || cf->args->nelts == 1)
		return NGX_CONF_ERROR;

	v = cf->args->elts;
	for (i = 1; i != cf->args->nelts; i += 2) {

		for (j = 0; j != RTE_DIM(kh); j++) {
			if (ngx_strcmp(v[i].data, kh[j].name) == 0) {
				 if (kh[j].func((const char *)v[i + 1].data,
						pvl + j) < 0)
					return NGX_CONF_ERROR;
				else
					break;
			}
		}

		/* unknow key */
		if (j == RTE_DIM(kh))
			return NGX_CONF_ERROR;
	}

	memset(dst, 0, sizeof(*dst));

	dst->dev = pvl[0].u64;
	dst->mtu = pvl[1].u64;
	dst->prfx = pvl[2].u64;

	dst->family = pvl[3].in.family;
	if (pvl[3].in.family == AF_INET)
		dst->ipv4 = pvl[3].in.addr4;
	else
		dst->ipv6 = pvl[3].in.addr6;

	memcpy(&dst->mac, &pvl[4].mac, sizeof(dst->mac));

	return NGX_CONF_OK;
}

char *
tldk_block_parse(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
	uint32_t i, len, n;
	tldk_conf_t *tcf;
	ngx_str_t *v;
	char *rv, *s;
	struct tldk_port_conf prt;

	tcf = (tldk_conf_t *)((void **)conf)[0];
	v = cf->args->elts;

	if (ngx_strcmp(v[0].data, "eal_cmd") == 0) {

		if (cf->args->nelts == 1 ||
				cf->args->nelts > RTE_DIM(tcf->eal_argv))
			return NGX_CONF_ERROR;

		s = tcf->eal_cmd;
		len = sizeof(tcf->eal_cmd);
		for (i = 0; i != cf->args->nelts; i++) {
			n = snprintf(s, len, "%s", v[i].data) + 1;
			if (n > len)
				return NGX_CONF_ERROR;
			tcf->eal_argv[i] = s;
			s += n;
			len -= n;
		}

		tcf->eal_argc = i;
		return NGX_CONF_OK;

	} else if (ngx_strcmp(v[0].data, "port") == 0) {

		rv = tldk_port_parse(cf, &prt);
		if (rv == NGX_CONF_OK) {

			/* too many ports */
			if (tcf->nb_port >= RTE_DIM(tcf->port))
				return NGX_CONF_ERROR;

			/* copy stuff */
			tcf->port[tcf->nb_port++] = prt;
		}
		return rv;
	}

	return NGX_CONF_ERROR;
}

char *
tldk_ctx_parse(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
	char *rv;
	ngx_str_t *v;
	tldk_conf_t *tcf;
	struct tldk_ctx_conf *tcx;
	union parse_val pvl;

	tcf = (tldk_conf_t *)((void **)conf)[0];
	tcx = tcf->ctx + tcf->nb_ctx;
	v = cf->args->elts;

	if (ngx_strcmp(v[0].data, "worker") == 0) {
		if (cf->args->nelts != 2 ||
				parse_uint_val((const char *)v[1].data,
					&pvl) < 0)
			return NGX_CONF_ERROR;
		tcx->worker = pvl.u64;
	} else if (ngx_strcmp(v[0].data, "lcore") == 0) {
		if (cf->args->nelts != 2 ||
				parse_uint_val((const char *)v[1].data,
					&pvl) < 0)
			return NGX_CONF_ERROR;
		tcx->lcore = pvl.u64;
	} else if (ngx_strcmp(v[0].data, "mbufs") == 0) {
		if (cf->args->nelts != 2 ||
				parse_uint_val((const char *)v[1].data,
					&pvl) < 0)
			return NGX_CONF_ERROR;
		tcx->nb_mbuf = pvl.u64;
	} else if (ngx_strcmp(v[0].data, "streams") == 0) {
		if (cf->args->nelts != 2 ||
				parse_uint_val((const char *)v[1].data,
					&pvl) < 0)
			return NGX_CONF_ERROR;
		tcx->nb_stream = pvl.u64;
	} else if (ngx_strcmp(v[0].data, "rbufs") == 0) {
		if (cf->args->nelts != 2 ||
				parse_uint_val((const char *)v[1].data,
					&pvl) < 0)
			return NGX_CONF_ERROR;
		tcx->nb_rbuf = pvl.u64;
	} else if (ngx_strcmp(v[0].data, "sbufs") == 0) {
		if (cf->args->nelts != 2 ||
				parse_uint_val((const char *)v[1].data,
					&pvl) < 0)
			return NGX_CONF_ERROR;
		tcx->nb_sbuf = pvl.u64;
	} else if (ngx_strcmp(v[0].data, "be_in_worker") == 0) {
		if (cf->args->nelts != 1)
			return NGX_CONF_ERROR;
		tcx->be_in_worker = 1;
	} else if (ngx_strcmp(v[0].data, "tcp_timewait") == 0) {
		if (cf->args->nelts != 2 ||
				parse_uint_val((const char *)v[1].data,
					&pvl) < 0)
			return NGX_CONF_ERROR;
		tcx->tcp_timewait = pvl.u64;
	} else if (ngx_strcmp(v[0].data, "dev") == 0) {
		if (tcx->nb_dev >= RTE_DIM(tcx->dev))
			return NGX_CONF_ERROR;
		rv = tldk_dev_parse(cf, tcx->dev + tcx->nb_dev, tcf);
		if (rv != NGX_CONF_OK)
			return rv;
		tcx->nb_dev++;
			return rv;
	} else if (ngx_strcmp(v[0].data, "dest") == 0) {
		if (tcx->nb_dest >= RTE_DIM(tcx->dest))
			return NGX_CONF_ERROR;
		rv = tldk_dest_parse(cf, tcx->dest + tcx->nb_dest);
		if (rv != NGX_CONF_OK)
			return rv;
		tcx->nb_dest++;
	}

	return NGX_CONF_OK;
}
