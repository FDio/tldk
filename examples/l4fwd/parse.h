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

#ifndef __PARSE_H__
#define __PARSE_H__

#include <sched.h>

#define PARSE_LIST_DELIM "-"

union parse_val {
	uint64_t u64;
	struct {
		uint16_t family;
		union {
			struct in_addr addr4;
			struct in6_addr addr6;
		};
	} in;
	struct rte_ether_addr mac;
	rte_cpuset_t cpuset;
};

static const char *
format_addr(const struct sockaddr_storage *sp, char buf[], size_t len)
{
	const struct sockaddr_in *i4;
	const struct sockaddr_in6 *i6;
	const void *addr;

	if (sp->ss_family == AF_INET) {
		i4 = (const struct sockaddr_in *)sp;
		addr = &i4->sin_addr;
	} else if (sp->ss_family == AF_INET6) {
		i6 = (const struct sockaddr_in6 *)sp;
		addr = &i6->sin6_addr;
	} else
		return NULL;


	return inet_ntop(sp->ss_family, addr, buf, len);
}

int parse_netbe_arg(struct netbe_port *prt, const char *arg,
	rte_cpuset_t *pcpu);

int netbe_parse_dest(const char *fname, struct netbe_dest_prm *prm);

int netfe_parse_cfg(const char *fname, struct netfe_lcore_prm *lp);

int
parse_app_options(int argc, char **argv, struct netbe_cfg *cfg,
	struct tle_ctx_param *ctx_prm,
	char *fecfg_fname, char *becfg_fname);

#endif /* __PARSE_H__ */

