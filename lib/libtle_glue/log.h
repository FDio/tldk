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

#ifndef _GLUE_LOG_H_
#define _GLUE_LOG_H_

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_vect.h>
#include <rte_memcpy.h>
#include <rte_spinlock.h>
#include <rte_log.h>
#include <rte_errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * logging related macros.
 */

#define GLUE_LOG(lvl, fmt, args...) RTE_LOG(lvl, USER1, fmt "\n", ##args)

#define	DUMMY_MACRO	do {} while (0)

#ifdef ENABLE_DEBUG
#define	GLUE_DEBUG(fmt, arg...)	fprintf(stderr, fmt "\n", ##arg)
#else
#define	GLUE_DEBUG(fmt, arg...)	DUMMY_MACRO
#endif

#ifdef ENABLE_TRACE
#define	TRACE(fmt, arg...)	fprintf(stderr, fmt "\n", ##arg)
#define	PKT_DUMP(p)		rte_pktmbuf_dump(stderr, (p), 64)
#else
#define	TRACE(fmt, arg...)	DUMMY_MACRO
#define	PKT_DUMP(p)		DUMMY_MACRO
#endif

#ifdef DEBUG_ARP
static inline void
print_arp(int af, const void *src, const struct ether_addr *mac,
	  const char *action)
{
	char str_ip[64];
	char str_mac[32];
	socklen_t sz;

	ether_format_addr(str_mac, sizeof(str_mac), mac);
	sz = (af == AF_INET) ? sizeof(struct in_addr) : sizeof(struct in6_addr);
	inet_ntop(af, src, str_ip, sz);
	RTE_LOG(INFO, "%s ARP entry: %s\tmac=%s", action, str_ip, str_mac);
}
#else
#define	print_arp(arg...)	DUMMY_MACRO
#endif

#ifdef __cplusplus
}
#endif

#endif /* _GLUE_LOG_H_ */
