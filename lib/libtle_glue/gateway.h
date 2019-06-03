/*
 * Copyright (c) 2019 Ant Financial Services Group.
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

#ifndef _TLE_GATEWAY_H_
#define _TLE_GATEWAY_H_

#ifdef __cplusplus
extern "C" {
#endif

static inline int
is_ipv4_loopback_addr(in_addr_t addr, struct glue_ctx *ctx)
{
	if (addr == ctx->ipv4 || addr == htonl(INADDR_LOOPBACK))
		return 1;
	else
		return 0;
}

static inline int
is_ipv6_loopback_addr(const struct in6_addr *addr, struct glue_ctx *ctx)
{
	if (memcmp(addr, &ctx->ipv6, sizeof(struct in6_addr)) == 0 ||
			IN6_IS_ADDR_LOOPBACK(addr) ||
			(IN6_IS_ADDR_V4COMPAT(addr) &&
					addr->__in6_u.__u6_addr32[3] == htonl(INADDR_LOOPBACK)) ||
			(IN6_IS_ADDR_V4MAPPED(addr) &&
					addr->__in6_u.__u6_addr32[3] == htonl(INADDR_LOOPBACK)))
		return 1;
	else
		return 0;
}

static inline const struct in_addr* ipv4_gateway_lookup(void *data,
		const struct in_addr *addr, struct in_addr *gate)
{
	struct glue_ctx *ctx = data;

	if (is_ipv4_loopback_addr(addr->s_addr, ctx))
		return addr;

	uint8_t ls = 32 - ctx->ipv4_ml;
	if ((addr->s_addr << ls) == (ctx->ipv4 << ls)) {
		return addr;
	}
	else {
		if (ctx->ipv4_gw != 0) {
			gate->s_addr = ctx->ipv4_gw;
			return gate;
		} else {
			return addr;
		}
	}
}

static inline const struct in6_addr* ipv6_gateway_lookup(void *data,
		const struct in6_addr *addr, struct in6_addr *gate)
{
	struct glue_ctx *ctx = data;
	uint8_t ls;

	if (is_ipv6_loopback_addr(addr, ctx))
		return addr;

	if (ctx->ipv6_ml <= 64) {
		ls = 64 - ctx->ipv6_ml;
		if ((*(const uint64_t*)addr << ls)
				== (*(const uint64_t*)&ctx->ipv6 << ls)) {
			return addr;
		}
	} else if (*(const uint64_t*)addr == *(const uint64_t*)&ctx->ipv6) {
		ls = 128 - ctx->ipv6_ml;
		if ((*((const uint64_t*)addr + 1) << ls)
				== (*((const uint64_t*)&ctx->ipv6 + 1) << ls)) {
			return addr;
		}
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&ctx->ipv6_gw)) {
		rte_memcpy(gate, &ctx->ipv6_gw, sizeof(struct in6_addr));
		return gate;
	} else {
		return addr;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* _TLE_GATEWAY_H_ */
