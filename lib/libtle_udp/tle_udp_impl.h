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

#ifndef _TLE_UDP_IMPL_H_
#define _TLE_UDP_IMPL_H_

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rte_common.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * <udp_ctx>  - each such ctx represents an 'independent copy of the stack'.
 * It owns set of <udp_stream>s and <udp_dev>s entities and provides
 * (de)multiplexing input/output packets from/into UDP devices into/from
 * UDP streams.
 * <udp_dev> is an abstraction for the underlying device, that is able
 * to RX/TX packets and may provide some HW offload capabilities.
 * It is a user responsibility to add to the <udp_ctx> all <udp_dev>s,
 * that context has to manage, before starting to do stream operations
 * (open/send/recv,close) over that context.
 * Right now adding/deleting <udp_dev>s to the context with open
 * streams is not supported.
 * <udp_stream> represents an UDP endpoint <addr, port> and is an analogy to
 * socket entity.
 * As with a socket, there are ability to do recv/send over it.
 * <udp_stream> belongs to particular <udp_ctx> but is visible globally across
 * the process, i.e. any thread within the process can do recv/send over it
 * without any further synchronisation.
 * While 'upper' layer API is thread safe, lower layer API (rx_bulk/tx_bulk)
 * is not thread safe and is not supposed to be run on multiple threads
 * in parallel.
 * So single thread can drive multiple <udp_ctx>s and do IO for them,
 * but multiple threads can't drive same <udp_ctx> without some
 * explicit synchronization.
 */

struct tle_udp_ctx;
struct tle_udp_dev;

/**
 * UDP device parameters.
 */
struct tle_udp_dev_param {
	uint32_t rx_offload; /**< DEV_RX_OFFLOAD_* supported. */
	uint32_t tx_offload; /**< DEV_TX_OFFLOAD_* supported. */
	struct in_addr local_addr4;  /**< local IPv4 address assigned. */
	struct in6_addr local_addr6; /**< local IPv6 address assigned. */
};

#define TLE_UDP_MAX_HDR	0x60

struct tle_udp_dest {
	struct rte_mempool *head_mp; /**< MP for fragment feaders. */
	struct tle_udp_dev *dev;     /**< device to send packets through. */
	uint16_t mtu;                /**< MTU for given destination. */
	uint8_t l2_len;  /**< L2 header lenght. */
	uint8_t l3_len;  /**< L3 header lenght. */
	uint8_t hdr[TLE_UDP_MAX_HDR]; /**< L2/L3 headers. */
};

/**
 * UDP context creation parameters.
 */
struct tle_udp_ctx_param {
	int32_t socket_id;         /**< socket ID to allocate memory for. */
	uint32_t max_streams;      /**< max number of streams in context. */
	uint32_t max_stream_rbufs; /**< max recv mbufs per stream. */
	uint32_t max_stream_sbufs; /**< max send mbufs per stream. */
	uint32_t send_bulk_size;   /**< expected # of packets per send call. */

	int (*lookup4)(void *opaque, const struct in_addr *addr,
		struct tle_udp_dest *res);
	/**< will be called by send() to get IPv4 packet destination info. */
	void *lookup4_data;
	/**< opaque data pointer for lookup4() callback. */

	int (*lookup6)(void *opaque, const struct in6_addr *addr,
		struct tle_udp_dest *res);
	/**< will be called by send() to get IPv6 packet destination info. */
	void *lookup6_data;
	/**< opaque data pointer for lookup6() callback. */
};

/**
 * create UDP context.
 * @param ctx_prm
 *   Parameters used to create and initialise the UDP context.
 * @return
 *   Pointer to UDP context structure that can be used in future UDP
 *   operations, or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENOMEM - out of memory
 */
struct tle_udp_ctx *
tle_udp_create(const struct tle_udp_ctx_param *ctx_prm);

/**
 * Destroy given UDP context.
 *
 * @param ctx
 *   UDP context to destroy
 */
void tle_udp_destroy(struct tle_udp_ctx *ctx);

/**
 * Add new device into the given UDP context.
 * This function is not multi-thread safe.
 *
 * @param ctx
 *   UDP context to add new device into.
 * @param dev_prm
 *   Parameters used to create and initialise new device inside the
 *   UDP context.
 * @return
 *   Pointer to UDP device structure that can be used in future UDP
 *   operations, or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENODEV - max possible value of open devices is reached
 *   - ENOMEM - out of memory
 */
struct tle_udp_dev *
tle_udp_add_dev(struct tle_udp_ctx *ctx,
		const struct tle_udp_dev_param *dev_prm);

/**
 * Remove and destroy previously added device from the given UDP context.
 * This function is not multi-thread safe.
 *
 * @param dev
 *   UDP device to remove and destroy.
 * @return
 *   zero on successful completion.
 *   - -EINVAL - invalid parameter passed to function
 */
int tle_udp_del_dev(struct tle_udp_dev *dev);

/**
 * Flags to the UDP context that destinations info might be changed,
 * so if it has any destinations data cached, then
 * it has to be invalidated.
 * @param ctx
 *   UDP context to invalidate.
 */
void tle_udp_ctx_invalidate(struct tle_udp_ctx *ctx);

struct tle_udp_stream;

/**
 * Stream asynchronous notification mechanisms:
 * a) recv/send callback.
 * Stream recv/send notification callbacks behaviour is edge-triggered (ET).
 * recv callback will be invoked if stream receive buffer was empty and
 * new packet(s) have arrived.
 * send callback will be invoked when stream send buffer was full,
 * and some packets belonging to that stream were sent
 * (part of send buffer became free again).
 * Note that both recv and send callbacks are called with sort of read lock
 * held on that stream. So it is not permitted to call stream_close()
 * within the callback function. Doing that would cause a deadlock.
 * While it is allowed to call stream send/recv functions within the
 * callback, it is not recommended: callback function will be invoked
 * within tle_udp_rx_bulk/tle_udp_tx_bulk context and some heavy processing
 * within the callback functions might cause performance degradation
 * or even loss of packets for further streams.
 * b) recv/send event.
 * Stream recv/send events behavour is level-triggered (LT).
 * receive event will be raised by either
 * tle_udp_rx_burst() or tle_udp_stream_recv() as long as there are any
 * remaining packets inside stream receive buffer.
 * send event will be raised by either
 * tle_udp_tx_burst() or tle_udp_stream_send() as long as there are any
 * free space inside stream send buffer.
 * Note that callback and event are mutually exclusive on <stream, op> basis.
 * It is not possible to  open a stream with both recv event and callback
 * specified.
 * Though it is possible to open a stream with recv callback and send event,
 * or visa-versa.
 * If the user doesn't need any notification mechanism for that stream,
 * both event and callback could be set to zero.
 */

/**
 * Stream recv/send callback function and data.
 */
struct tle_udp_stream_cb {
	void (*func)(void *, struct tle_udp_stream *);
	void *data;
};

struct tle_event;

/**
 * UDP stream creation parameters.
 */
struct tle_udp_stream_param {
	struct sockaddr_storage local_addr;  /**< stream local address. */
	struct sockaddr_storage remote_addr; /**< stream remote address. */

	/* _cb and _ev are mutually exclusive */
	struct tle_event *recv_ev;          /**< recv event to use.  */
	struct tle_udp_stream_cb recv_cb;   /**< recv callback to use. */

	struct tle_event *send_ev;          /**< send event to use. */
	struct tle_udp_stream_cb send_cb;   /**< send callback to use. */
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
struct tle_udp_stream *
tle_udp_stream_open(struct tle_udp_ctx *ctx,
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
int tle_udp_stream_close(struct tle_udp_stream *s);

/**
 * get open stream parameters.
 * @param s
 *   Pointer to the stream.
 * @return
 *   zero on successful completion.
 *   - EINVAL - invalid parameter passed to function
 */
int
tle_udp_stream_get_param(const struct tle_udp_stream *s,
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
uint16_t tle_udp_rx_bulk(struct tle_udp_dev *dev, struct rte_mbuf *pkt[],
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
uint16_t tle_udp_tx_bulk(struct tle_udp_dev *dev, struct rte_mbuf *pkt[],
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
uint16_t tle_udp_stream_recv(struct tle_udp_stream *s, struct rte_mbuf *pkt[],
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
uint16_t tle_udp_stream_send(struct tle_udp_stream *s, struct rte_mbuf *pkt[],
	uint16_t num, const struct sockaddr *dst_addr);

#ifdef __cplusplus
}
#endif

#endif /* _TLE_UDP_IMPL_H_ */
