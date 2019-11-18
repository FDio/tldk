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

#include <time.h>
#include <netinet/icmp6.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_icmp.h>
#include <rte_ip.h>

#include "log.h"
#include "ctx.h"
#include "internal.h"

#define ICMP_ECHOREPLY          0    /* Echo Reply                      */
#define ICMP_ECHO               8    /* Echo Request                    */
#define ICMP_TIMESTAMP          13   /* Timestamp Request               */
#define ICMP_TIMESTAMPREPLY     14   /* Timestamp Reply                 */

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL            0    /* TTL count exceeded              */
#define ICMP_EXC_FRAGTIME       1    /* Fragment Reass time exceeded    */

/* Parameters used to convert the timespec values */
#define SECONDS_PER_DAY         86400L
#define MSEC_PER_SEC            1000L
#define USEC_PER_MSEC           1000L
#define NSEC_PER_USEC           1000L
#define NSEC_PER_MSEC           (NSEC_PER_USEC * USEC_PER_MSEC)

#define IS_IPV4_BCAST(x)        ((x) == (uint32_t)0xFFFFFFFF)

struct icmp_pkt {
	struct icmp_hdr icmp_h;
	uint32_t times[3];
};

/* Return remainder for ``dividend / divisor`` */
static inline uint32_t
div_uint64_rem(uint64_t dividend, uint32_t divisor)
{
	return dividend % divisor;
}

/* Return milliseconds since midnight (UTC) in network byte order. */
static uint32_t
current_timestamp(void)
{
	struct timespec ts;
	uint32_t msecs;
	uint32_t secs;

	(void)clock_gettime(CLOCK_REALTIME, &ts);

	/* Get secs since midnight. */
	secs = div_uint64_rem(ts.tv_sec, SECONDS_PER_DAY);
	/* Convert to msecs. */
	msecs = secs * MSEC_PER_SEC;
	/* Convert nsec to msec. */
	msecs += (uint32_t)ts.tv_nsec / NSEC_PER_MSEC;

	/* Convert to network byte order. */
	return rte_cpu_to_be_32(msecs);
}

/*
 * Process the checksum of an ICMP packet. The checksum field must be set
 * to 0 by the caller.
 */
static uint16_t
icmp_cksum(const struct icmp_hdr *icmp, uint32_t data_len)
{
	uint16_t cksum;

	cksum = rte_raw_cksum(icmp, sizeof(struct icmp_hdr) + data_len);
	return (cksum == 0xffff) ? cksum : ~cksum;
}

/**
 * Receive and handle an ICMP packet.
 *
 * @param ctx
 *   The pointer to the glue context.
 * @param pkt
 *   The pointer to the raw packet data.
 * @param l2_len
 *   The the size of the l2 header.
 * @return
 *   MUST return NULL now. :-)
 */
struct rte_mbuf *
icmp_recv(struct glue_ctx *ctx, struct rte_mbuf *pkt,
	  uint32_t l2_len, uint32_t l3_len)
{
	struct ether_addr eth_addr;
	struct icmp_pkt *icmp_pkt;
	struct ether_hdr *eth_h;
	struct icmp_hdr *icmp_h;
	struct ipv4_hdr *ip_h;
	uint32_t ip_addr;
	uint32_t cksum;

	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ip_h = (struct ipv4_hdr *) ((char *)eth_h + l2_len);

	icmp_h = (struct icmp_hdr *)((char *)ip_h + l3_len);
	if (icmp_h->icmp_type != IP_ICMP_ECHO_REQUEST &&
	    icmp_h->icmp_type != ICMP_TIMESTAMP)
		goto drop_pkt;

	icmp_pkt = (struct icmp_pkt *)icmp_h;

	ether_addr_copy(&eth_h->s_addr, &eth_addr);
	ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
	ether_addr_copy(&eth_addr, &eth_h->d_addr);

	/*
	 * Similar to Linux implementation, we silently drop the broadcast or
	 * multicast ICMP pakcets.
	 *
	 *     RFC 1122: 3.2.2.6 An ICMP_ECHO to broadcast MAY be
	 *         silently ignored.
	 *     RFC 1122: 3.2.2.8 An ICMP_TIMESTAMP MAY be silently
	 *         discarded if to broadcast/multicast.
	 */
	ip_addr = rte_be_to_cpu_32(ip_h->dst_addr);
	if (IS_IPV4_MCAST(ip_addr) || IS_IPV4_BCAST(ip_addr))
		goto drop_pkt;

	ip_addr = ip_h->src_addr;
	ip_h->src_addr = ip_h->dst_addr;
	ip_h->dst_addr = ip_addr;

	if (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST &&
	    icmp_h->icmp_code == 0) {

		/* Must clear checksum field before calling the helper. */
		ip_h->hdr_checksum = 0;
		ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);

		icmp_h->icmp_type = IP_ICMP_ECHO_REPLY;
		icmp_h->icmp_code = 0;

		/*
		 * Fix me: the data part of an ICMP echo request/reply
		 * message is implementation specific, we don't know
		 * how to verify or calculate the checksum.
		 *
		 * Need to see BSD or LINUX implementation.
		 */
		cksum = ~icmp_h->icmp_cksum & 0xffff;
		cksum += ~rte_cpu_to_be_16(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
		cksum += rte_cpu_to_be_16(IP_ICMP_ECHO_REPLY << 8);
		cksum = (cksum & 0xffff) + (cksum >> 16);
		cksum = (cksum & 0xffff) + (cksum >> 16);
		icmp_h->icmp_cksum = ~cksum;

	} else if (icmp_h->icmp_type == ICMP_TIMESTAMP &&
		   icmp_h->icmp_code == 0) {

		/*
		 * RFC 1122: 3.2.2.8 MAY implement ICMP timestamp requests.
		 *     SHOULD be in the kernel for minimum random latency.
		 *     MUST be accurate to a few minutes.
		 *     MUST be updated at least at 15Hz.
		 */
		icmp_h->icmp_type = ICMP_TIMESTAMPREPLY;
		icmp_h->icmp_code = 0;
		icmp_pkt->times[1] = current_timestamp();
		icmp_pkt->times[2] = icmp_pkt->times[1];

		icmp_h->icmp_cksum = 0;
		/* the data part of an ICMP timestamp reply is 12 bytes. */
		icmp_h->icmp_cksum = icmp_cksum(icmp_h, 12);
	} else
		goto drop_pkt;

	if (pkt->pkt_len < ETHER_MIN_LEN)
		rte_pktmbuf_append(pkt, ETHER_MIN_LEN - pkt->pkt_len);

	if (rte_eth_tx_burst(ctx->port_id, ctx->queue_id, &pkt, 1))
		GLUE_LOG(DEBUG, "Send ICMP echo reply OK");

	return NULL;

drop_pkt:
	rte_pktmbuf_free(pkt);
	return NULL;
}

/**
 * Receive and handle an ICMPv6 packet.
 *
 * @param ctx
 *   The pointer to the glue context.
 * @param pkt
 *   The pointer to the raw packet data.
 * @param l2_len
 *   The the size of the l2 header.
 * @return
 *   MUST return NULL now. :-)
 */
struct rte_mbuf *
icmp6_recv(struct glue_ctx *ctx, struct rte_mbuf *pkt,
	   uint32_t l2_len, uint32_t l3_len)
{
	struct ether_addr eth_addr;
	struct ether_hdr *eth_h;
	struct icmp6_hdr *icmp6_h;
	struct ipv6_hdr *ipv6_h;
	struct in6_addr ipv6_addr;
	uint32_t cksum;

	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ipv6_h = (struct ipv6_hdr *) ((char *)eth_h + l2_len);

	icmp6_h = (struct icmp6_hdr *)((char *)ipv6_h + l3_len);

	/* NDP pkt */
	if ((icmp6_h->icmp6_type == ND_NEIGHBOR_SOLICIT ||
	     icmp6_h->icmp6_type == ND_NEIGHBOR_ADVERT) &&
	    icmp6_h->icmp6_code == 0)
		return ndp_recv(ctx, pkt, l2_len, l3_len);

	/* only support ECHO now, other types of pkts are dropped */
	if ((icmp6_h->icmp6_type != ICMP6_ECHO_REQUEST &&
	     icmp6_h->icmp6_type != ICMP6_ECHO_REPLY) ||
	    icmp6_h->icmp6_code != 0)
		goto drop_pkt;

	ether_addr_copy(&eth_h->s_addr, &eth_addr);
	ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
	ether_addr_copy(&eth_addr, &eth_h->d_addr);

	/*
	 * Now, we silently drop the anycast or multicast ICMP pakcets.
	 * But it does not conform to RFC 4443. Maybe fix it latter.
	 *
	 *     RFC 4443: 4.2  An Echo Reply SHOULD be sent in response to an
	 *     Echo Request message sent to an IPv6 multicast or anycast address.
	 *     In this case, thesource address of the reply MUST be a unicast
	 *     address belonging to the interface on which the Echo Request
	 *     message was received.
	 */
	switch (icmp6_h->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
		if (memcmp(ipv6_h->dst_addr, &ctx->ipv6,
			   sizeof(struct in6_addr)) != 0)
			goto drop_pkt;

		rte_memcpy(&ipv6_addr, ipv6_h->src_addr,
			   sizeof(struct in6_addr));
		rte_memcpy(ipv6_h->src_addr, ipv6_h->dst_addr,
			   sizeof(struct in6_addr));
		rte_memcpy(ipv6_h->dst_addr, &ipv6_addr,
			   sizeof(struct in6_addr));

		icmp6_h->icmp6_type = ICMP6_ECHO_REPLY;

		cksum = ~icmp6_h->icmp6_cksum & 0xffff;
		cksum += ~rte_cpu_to_be_16(ICMP6_ECHO_REQUEST << 8) & 0xffff;
		cksum += rte_cpu_to_be_16(ICMP6_ECHO_REPLY << 8);
		cksum = (cksum & 0xffff) + (cksum >> 16);
		cksum = (cksum & 0xffff) + (cksum >> 16);
		icmp6_h->icmp6_cksum = ~cksum;

		break;
	default:
		goto drop_pkt;
	}

	if (pkt->pkt_len < ETHER_MIN_LEN)
		rte_pktmbuf_append(pkt, ETHER_MIN_LEN - pkt->pkt_len);

	if (rte_eth_tx_burst(ctx->port_id, ctx->queue_id, &pkt, 1))
		GLUE_LOG(DEBUG, "Send ICMP echo reply OK");

	return NULL;

drop_pkt:
	rte_pktmbuf_free(pkt);
	return NULL;
}
