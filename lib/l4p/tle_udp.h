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

#ifndef _TLE_UDP_H_
#define _TLE_UDP_H_

#include <tle_ctx.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * UDP stream creation parameters.
 */
struct tle_udp_stream_param {
	struct sockaddr_storage local_addr;  /**< stream local address. */
	struct sockaddr_storage remote_addr; /**< stream remote address. */

	/* _cb and _ev are mutually exclusive */
	struct tle_event *recv_ev;          /**< recv event to use.  */
	struct tle_stream_cb recv_cb;   /**< recv callback to use. */

	struct tle_event *send_ev;          /**< send event to use. */
	struct tle_stream_cb send_cb;   /**< send callback to use. */
};

/**
 * create a new stream within given UDP context.
 * @param ctx
 *   UDP context to create new stream within.
 * @param prm
 *   Parameters used to create and initialise the new stream.
 * @return
 *   Pointer to UDP stream structure that can be used in future UDP API calls,
 *   or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENOFILE - max limit of open streams reached for that context
 */
struct tle_stream *
tle_udp_stream_open(struct tle_ctx *ctx,
	const struct tle_udp_stream_param *prm);

/**
 * close an open stream.
 * All packets still remaining in stream receive buffer will be freed.
 * All packets still remaining in stream transmit buffer will be kept
 * for father transmission.
 * @param s
 *   Pointer to the stream to close.
 * @return
 *   zero on successful completion.
 *   - -EINVAL - invalid parameter passed to function
 */
int tle_udp_stream_close(struct tle_stream *s);

/**
 * get open stream parameters.
 * @param s
 *   Pointer to the stream.
 * @return
 *   zero on successful completion.
 *   - EINVAL - invalid parameter passed to function
 */
int
tle_udp_stream_get_param(const struct tle_stream *s,
	struct tle_udp_stream_param *prm);

/**
 * Take input mbufs and distribute them to open UDP streams.
 * expects that for each input packet:
 *	- l2_len, l3_len, l4_len are setup correctly
 *	- (packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)) != 0,
 *	- (packet_type & RTE_PTYPE_L4_UDP) != 0,
 * During delivery L3/L4 checksums will be verified
 * (either relies on HW offload or in SW).
 * This function is not multi-thread safe.
 * @param dev
 *   UDP device the packets were received from.
 * @param pkt
 *   The burst of input packets that need to be processed.
 * @param rp
 *   The array that will contain pointers of unprocessed packets at return.
 *   Should contain at least *num* elements.
 * @param rc
 *   The array that will contain error code for corresponding rp[] entry:
 *   - ENOENT - no open stream matching this packet.
 *   - ENOBUFS - receive buffer of the destination stream is full.
 *   Should contain at least *num* elements.
 * @param num
 *   Number of elements in the *pkt* input array.
 * @return
 *   number of packets delivered to the UDP streams.
 */
uint16_t tle_udp_rx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num);

/**
 * Fill *pkt* with pointers to the packets that have to be transmitted
 * over given UDP device.
 * Output packets have to be ready to be passed straight to rte_eth_tx_burst()
 * without any extra processing.
 * UDP/IPv4 checksum either already calculated or appropriate mbuf fields set
 * properly for HW offload.
 * This function is not multi-thread safe.
 * @param dev
 *   UDP device the output packets will be transmitted over.
 * @param pkt
 *   An array of pointers to *rte_mbuf* structures that
 *   must be large enough to store up to *num* pointers in it.
 * @param num
 *   Number of elements in the *pkt* array.
 * @return
 *   number of of entries filled inside *pkt* array.
 */
uint16_t tle_udp_tx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[],
	uint16_t num);

/*
 * return up to *num* mbufs that was received for given UDP stream.
 * For each returned mbuf:
 * data_off set to the start of the packet's UDP data
 * l2_len, l3_len, l4_len are setup properly
 * (so user can still extract L2/L3 address info if needed)
 * packet_type RTE_PTYPE_L2/L3/L4 bits are setup properly.
 * L3/L4 checksum is verified.
 * Packets with invalid L3/L4 checksum will be silently dropped.
 * @param s
 *   UDP stream to receive packets from.
 * @param pkt
 *   An array of pointers to *rte_mbuf* structures that
 *   must be large enough to store up to *num* pointers in it.
 * @param num
 *   Number of elements in the *pkt* array.
 * @return
 *   number of of entries filled inside *pkt* array.
 */
uint16_t tle_udp_stream_recv(struct tle_stream *s, struct rte_mbuf *pkt[],
	uint16_t num);

/**
 * Consume and queue up to *num* packets, that will be sent eventually
 * by tle_udp_tx_bulk().
 * If *dst_addr* is NULL, then default remote address associated with that
 * stream (if any) will be used.
 * The main purpose of that function is to determine over which UDP dev
 * given packets have to be sent out and do necessary preparations for that.
 * Based on the *dst_addr* it does route lookup, fills L2/L3/L4 headers,
 * and, if necessary, fragments packets.
 * Depending on the underlying device information, it either does
 * IP/UDP checksum calculations in SW or sets mbuf TX checksum
 * offload fields properly.
 * For each input mbuf the following conditions have to be met:
 *	- data_off point to the start of packet's UDP data.
 *	- there is enough header space to prepend L2/L3/L4 headers.
 * @param s
 *   UDP stream to send packets over.
 * @param pkt
 *   The burst of output packets that need to be send.
 * @param num
 *   Number of elements in the *pkt* array.
 * @param dst_addr
 *   Destination address to send packets to.
 * @return
 *   number of packets successfully queued in the stream send buffer.
 */
uint16_t tle_udp_stream_send(struct tle_stream *s, struct rte_mbuf *pkt[],
	uint16_t num, const struct sockaddr *dst_addr);

#ifdef __cplusplus
}
#endif

#endif /* _TLE_UDP_H_ */
