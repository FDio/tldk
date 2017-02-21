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

#ifndef _TLE_CTX_H_
#define _TLE_CTX_H_

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rte_common.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * <tle_ctx>  - each such ctx represents an 'independent copy of the stack'.
 * It owns set of <stream>s and <dev>s entities and provides
 * (de)multiplexing input/output packets from/into devices into/from streams.
 * <dev> is an abstraction for the underlying device, that is able
 * to RX/TX packets and may provide some HW offload capabilities.
 * It is a user responsibility to add to the <ctx> all <dev>s,
 * that context has to manage, before starting to do stream operations
 * (open/send/recv,close) over that context.
 * Right now adding/deleting <dev>s to the context with open
 * streams is not supported.
 * <stream> represents an L4(UDP/TCP, etc.) endpoint <addr, port> and
 * is an analogy to socket entity.
 * As with a socket, there are ability to do recv/send over it.
 * <stream> belongs to particular <ctx> but is visible globally across
 * the process, i.e. any thread within the process can do recv/send over it
 * without any further synchronisation.
 * While 'upper' layer API is thread safe, lower layer API (rx_bulk/tx_bulk)
 * is not thread safe and is not supposed to be run on multiple threads
 * in parallel.
 * So single thread can drive multiple <ctx>s and do IO for them,
 * but multiple threads can't drive same <ctx> without some
 * explicit synchronization.
 */

struct tle_ctx;
struct tle_dev;

/**
 * Blocked L4 ports info.
 */
struct tle_bl_port {
	uint32_t nb_port;     /**< number of blocked ports. */
	const uint16_t *port; /**< list of blocked ports. */
};


/**
 * device parameters.
 */
struct tle_dev_param {
	uint32_t rx_offload; /**< DEV_RX_OFFLOAD_* supported. */
	uint32_t tx_offload; /**< DEV_TX_OFFLOAD_* supported. */
	struct in_addr local_addr4;  /**< local IPv4 address assigned. */
	struct in6_addr local_addr6; /**< local IPv6 address assigned. */
	struct tle_bl_port bl4; /**< blocked ports for IPv4 address. */
	struct tle_bl_port bl6; /**< blocked ports for IPv4 address. */
};

#define TLE_DST_MAX_HDR	0x60

struct tle_dest {
	struct rte_mempool *head_mp;
	/**< MP for fragment headers and control packets. */
	struct tle_dev *dev;     /**< device to send packets through. */
	uint16_t mtu;                /**< MTU for given destination. */
	uint8_t l2_len;  /**< L2 header length. */
	uint8_t l3_len;  /**< L3 header length. */
	uint8_t hdr[TLE_DST_MAX_HDR]; /**< L2/L3 headers. */
};

/**
 * context creation parameters.
 */

enum {
	TLE_PROTO_UDP,
	TLE_PROTO_TCP,
	TLE_PROTO_NUM
};

struct tle_ctx_param {
	int32_t socket_id;         /**< socket ID to allocate memory for. */
	uint32_t proto;            /**< L4 proto to handle. */
	uint32_t max_streams;      /**< max number of streams in context. */
	uint32_t max_stream_rbufs; /**< max recv mbufs per stream. */
	uint32_t max_stream_sbufs; /**< max send mbufs per stream. */
	uint32_t send_bulk_size;   /**< expected # of packets per send call. */

	int (*lookup4)(void *opaque, const struct in_addr *addr,
		struct tle_dest *res);
	/**< will be called by send() to get IPv4 packet destination info. */
	void *lookup4_data;
	/**< opaque data pointer for lookup4() callback. */

	int (*lookup6)(void *opaque, const struct in6_addr *addr,
		struct tle_dest *res);
	/**< will be called by send() to get IPv6 packet destination info. */
	void *lookup6_data;
	/**< opaque data pointer for lookup6() callback. */
};

/**
 * create L4 processing context.
 * @param ctx_prm
 *   Parameters used to create and initialise the L4 context.
 * @return
 *   Pointer to context structure that can be used in future operations,
 *   or NULL on error, with error code set in rte_errno.
 *
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENOMEM - out of memory
 */
struct tle_ctx *
tle_ctx_create(const struct tle_ctx_param *ctx_prm);

/**
 * Destroy given context.
 *
 * @param ctx
 *   context to destroy
 */
void tle_ctx_destroy(struct tle_ctx *ctx);

/**
 * Add new device into the given context.
 * This function is not multi-thread safe.
 *
 * @param ctx
 *   context to add new device into.
 * @param dev_prm
 *   Parameters used to create and initialise new device inside the context.
 * @return
 *   Pointer to device structure that can be used in future operations,
 *   or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENODEV - max possible value of open devices is reached
 *   - ENOMEM - out of memory
 */
struct tle_dev *
tle_add_dev(struct tle_ctx *ctx, const struct tle_dev_param *dev_prm);

/**
 * Remove and destroy previously added device from the given context.
 * This function is not multi-thread safe.
 *
 * @param dev
 *   device to remove and destroy.
 * @return
 *   zero on successful completion.
 *   - -EINVAL - invalid parameter passed to function
 */
int tle_del_dev(struct tle_dev *dev);

/**
 * Flags to the context that destinations info might be changed,
 * so if it has any destinations data cached, then
 * it has to be invalidated.
 * @param ctx
 *   context to invalidate.
 */
void tle_ctx_invalidate(struct tle_ctx *ctx);

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
 * Stream recv/send events behaviour is level-triggered (LT).
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

struct tle_event;
struct tle_stream;

/**
 * Stream recv/send callback function and data.
 */
struct tle_stream_cb {
	void (*func)(void *, struct tle_stream *);
	void *data;
};

#ifdef __cplusplus
}
#endif

#endif /* _TLE_CTX_H_ */
