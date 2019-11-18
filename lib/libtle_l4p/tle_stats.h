/*
 * Copyright (c) 2018 Ant Financial Services Group.
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

#ifndef TLE_STATS_H
#define TLE_STATS_H

#include <rte_per_lcore.h>
#include <rte_memory.h>

/* tcp mib definitions */
/*
 * RFC 1213:  MIB-II TCP group
 * RFC 2012 (updates 1213):  SNMPv2-MIB-TCP
 */
enum
{
	TCP_MIB_RTOALGORITHM,			/* RtoAlgorithm */
	TCP_MIB_RTOMIN,				/* RtoMin */
	TCP_MIB_RTOMAX,				/* RtoMax */
	TCP_MIB_MAXCONN,			/* MaxConn */
	TCP_MIB_ACTIVEOPENS,			/* ActiveOpens */
	TCP_MIB_PASSIVEOPENS,			/* PassiveOpens */
	TCP_MIB_ATTEMPTFAILS,			/* AttemptFails */
	TCP_MIB_ESTABRESETS,			/* EstabResets */
	TCP_MIB_CURRESTAB,			/* CurrEstab */
	TCP_MIB_INSEGS,				/* InSegs */
	TCP_MIB_OUTSEGS,			/* OutSegs */
	TCP_MIB_RETRANSSEGS,			/* RetransSegs */
	TCP_MIB_INERRS,				/* InErrs */
	TCP_MIB_OUTRSTS,			/* OutRsts */
	TCP_MIB_CSUMERRORS,			/* InCsumErrors */
	TCP_MIB_MAX
};

/* udp mib definitions */
/*
 * RFC 1213:  MIB-II UDP group
 * RFC 2013 (updates 1213):  SNMPv2-MIB-UDP
 */
enum
{
	UDP_MIB_INDATAGRAMS,			/* InDatagrams */
	UDP_MIB_NOPORTS,			/* NoPorts */
	UDP_MIB_INERRORS,			/* InErrors */
	UDP_MIB_OUTDATAGRAMS,			/* OutDatagrams */
	UDP_MIB_RCVBUFERRORS,			/* RcvbufErrors */
	UDP_MIB_SNDBUFERRORS,			/* SndbufErrors */
	UDP_MIB_CSUMERRORS,			/* InCsumErrors */
	UDP_MIB_IGNOREDMULTI,			/* IgnoredMulti */
	UDP_MIB_MAX
};

struct tcp_mib {
	unsigned long mibs[TCP_MIB_MAX];
};

struct udp_mib {
	unsigned long mibs[UDP_MIB_MAX];
};

struct tle_mib {
	struct tcp_mib tcp;
	struct udp_mib udp;
} __rte_cache_aligned;

extern struct tle_mib default_mib;

RTE_DECLARE_PER_LCORE(struct tle_mib *, mib);

#define PERCPU_MIB RTE_PER_LCORE(mib)

#define SNMP_INC_STATS(mib, field) (mib).mibs[field]++
#define SNMP_DEC_STATS(mib, field) (mib).mibs[field]--
#define SNMP_ADD_STATS(mib, field, n) (mib).mibs[field] += n
#define SNMP_ADD_STATS_ATOMIC(mib, field, n) \
	rte_atomic64_add((rte_atomic64_t *)(&(mib).mibs[field]), n)

#define TCP_INC_STATS(field) SNMP_INC_STATS(PERCPU_MIB->tcp, field)
#define TCP_DEC_STATS(field) SNMP_DEC_STATS(PERCPU_MIB->tcp, field)
#define TCP_ADD_STATS(field, n) SNMP_ADD_STATS(PERCPU_MIB->tcp, field, n)
#define TCP_INC_STATS_ATOMIC(field) SNMP_ADD_STATS_ATOMIC(PERCPU_MIB->tcp, field, 1)
#define TCP_DEC_STATS_ATOMIC(field) SNMP_ADD_STATS_ATOMIC(PERCPU_MIB->tcp, field, (-1))

#define UDP_INC_STATS(field) SNMP_INC_STATS(PERCPU_MIB->udp, field)
#define UDP_ADD_STATS(field, n) SNMP_ADD_STATS(PERCPU_MIB->udp, field, n)
#define UDP_ADD_STATS_ATOMIC(field, n) \
	SNMP_ADD_STATS_ATOMIC(PERCPU_MIB->udp, field, n)

#endif /* TLE_STATS_H */
