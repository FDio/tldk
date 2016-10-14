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

#ifndef _TLE_TCP_H_
#define _TLE_TCP_H_

#include <tle_ctx.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * TCP stream creation parameters.
 */
struct tle_tcp_stream_addr {
	struct sockaddr_storage local;  /**< stream local address. */
	struct sockaddr_storage remote; /**< stream remote address. */
};

struct tle_tcp_stream_cfg {
	uint64_t linger_cycles;  /**< number of cycles to linger. */
	uint32_t nb_retries;     /**< max number of retransmission attempts. */

	/* _cb and _ev are mutually exclusive */
	struct tle_event *err_ev;      /**< error event to use.  */
	struct tle_stream_cb err_cb;   /**< error callback to use. */

	struct tle_event *recv_ev;      /**< recv event to use.  */
	struct tle_stream_cb recv_cb;   /**< recv callback to use. */

	struct tle_event *send_ev;      /**< send event to use. */
	struct tle_stream_cb send_cb;   /**< send callback to use. */
};

struct tle_tcp_stream_param {
	struct tle_tcp_stream_addr addr;
	struct tle_tcp_stream_cfg cfg;
};

/**
 * create a new stream within given TCP context.
 * @param ctx
 *   TCP context to create new stream within.
 * @param prm
 *   Parameters used to create and initialise the new stream.
 * @return
 *   Pointer to TCP stream structure that can be used in future TCP API calls,
 *   or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENOFILE - max limit of open streams reached for that context
 */
struct tle_stream *
tle_tcp_stream_open(struct tle_ctx *ctx,
	const struct tle_tcp_stream_param *prm);

/**
 * close an open stream.
 * if the stream is in connected state, then:
 * - connection termination would be performed.
 * - if stream contains unsent data, then actual close will be postponed
 * till either remaining data will be TX-ed, or linger timeout will expire.
 * All packets that belong to that stream and remain in the device
 * TX queue will be kept for father transmission.
 * @param s
 *   Pointer to the stream to close.
 * @return
 *   zero on successful completion.
 *   - -EINVAL - invalid parameter passed to function
 */
int tle_tcp_stream_close(struct tle_stream *s);

struct tle_evq;

uint32_t
tle_tcp_stream_close_bulk(struct tle_evq *rxq, struct tle_evq *txq,
	struct tle_evq *erq, struct tle_stream *ts[], uint32_t num);

/**
 * get open stream local and remote addresses.
 * @param s
 *   Pointer to the stream.
 * @return
 *   zero on successful completion.
 *   - EINVAL - invalid parameter passed to function
 */
int
tle_tcp_stream_get_addr(const struct tle_stream *s,
	struct tle_tcp_stream_addr *addr);

/**
 * abort the connection and close an open stream.
 * if the stream is in connected state, then:
 * any queued data is thrown away and a reset segment is sent to the peer.
 * All packets that belong to that stream and remain in the device
 * TX queue will be kept for father transmission.
 * @param s
 *   Pointer to the stream to abort.
 * @return
 *   zero on successful completion.
 *   - -EINVAL - invalid parameter passed to function
 */
int tle_tcp_stream_abort(struct tle_stream *s);

/**
 * Client mode connect API.
 */

/**
 * Attempt to establish connection with the destination TCP endpoint.
 * Stream write event (or callback) will fire, if the conenction will be
 * established successfully.
 * Note that stream in listen state or stream with already established
 * connection, can't be subject of connect() call.
 * In case of unsuccessful attempt, error event (or callback) will be
 * activated.
 * @param s
 *   Pointer to the stream.
 * @param addr
 *   Address of the destination endpoint.
 * @return
 *   zero on successful completion.
 *   - -EINVAL - invalid parameter passed to function
 */
int tle_tcp_stream_connect(struct tle_stream *s, const struct sockaddr *addr);

/*
 * Server mode connect API.
 * Basic scheme for server mode API usage:
 *
 * <stream open happens here>
 * tle_tcp_stream_listen(stream_to_listen);
 * <wait for read event/callback on that stream>
 * n = tle_tcp_synreqs(stream_to_listen, syn_reqs, sizeof(syn_reqs));
 * for (i = 0, k = 0; i != n; i++) {
 * 	rc = <decide should connection from that endpoint be allowed>;
 * 	if (rc == 0) {
 * 		//proceed with connection establishment
 * 		k++;
 * 		accept_param[k].syn = syn_reqs[i];
 * 		<fill rest of accept_param fileds for k-th connection>
 *	} else {
 *		//reject connection requests from that endpoint
		rej_reqs[i - k] = syn_reqs[i];
 *	}
 * }
 *
 *	//reject n - k connection requests
 *	tle_tcp_reject(stream_to_listen, rej_reqs, n - k);
 *
 *	//accept k new connections
 * 	rc = tle_tcp_accept(stream_to_listen, accept_param, new_con_streams, k);
 * 	<handle errors>
 */

struct tle_syn_req {
	struct rte_mbuf *pkt;
	/*< mbuf with incoming connection request. */
	void *opaque;    /*< tldk related opaque pointer. */
};

struct tle_tcp_accept_param {
	struct tle_syn_req syn;        /*< mbuf with incoming SYN request. */
	struct tle_tcp_stream_cfg cfg; /*< stream configure options. */
};


/**
 * Set stream into the listen state (passive opener), i.e. make stream ready
 * to accept new connections.
 * Stream read event (or callback) will be activated as new SYN requests
 * will arrive.
 * Note that stream with already established (or establishing) connection
 * can't be subject of listen() call.
 * @param s
 *   Pointer to the stream.
 * @return
 *   zero on successful completion.
 *   - -EINVAL - invalid parameter passed to function
 */
int tle_tcp_stream_listen(struct tle_stream *s);

/**
 * return up to *num* mbufs with SYN requests that were received
 * for given TCP endpoint.
 * Note that the stream has to be in listen state.
 * For each returned mbuf:
 * data_off set to the start of the packet
 * l2_len, l3_len, l4_len are setup properly
 * (so user can still extract L2/L3/L4 header info if needed)
 * packet_type RTE_PTYPE_L2/L3/L4 bits are setup properly.
 * L3/L4 checksum is verified.
 * @param s
 *   TCP stream to receive packets from.
 * @param rq
 *   An array of tle_syn_req structures that contains
 *   at least *num* elements in it.
 * @param num
 *   Number of elements in the *pkt* array.
 * @return
 *   number of of entries filled inside *pkt* array.
 */
uint16_t tle_tcp_stream_synreqs(struct tle_stream *s, struct tle_syn_req rq[],
	uint32_t num);

/**
 * Accept connection requests for the given stream.
 * Note that the stream has to be in listen state.
 * For each new connection a new stream will be open.
 * @param s
 *   TCP listen stream.
 * @param prm
 *   An array of *tle_tcp_accept_param* structures that
 *   contains at least *num* elements in it. 
 * @param pkt
 *   An array of pointers to *tle_stream* structures that
 *   must be large enough to store up to *num* pointers in it.
 * @param num
 *   Number of elements in the *prm* and *rs* arrays.
 * @return
 *   number of of entries filled inside *rs* array.
 *   In case of error, error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 *   - ENFILE - no more streams are avaialble to open.
 */
int tle_tcp_stream_accept(struct tle_stream *s,
	const struct tle_tcp_accept_param prm[], struct tle_stream *rs[],
	uint32_t num);

/**
 * Reject connection requests for the given stream.
 * Note that the stream has to be in listen state.
 * For each new connection a new stream will be open.
 * @param s
 *   TCP listen stream.
 * @param rq
 *   An array of tle_syn_req structures that contains
 *   at least *num* elements in it.
 * @param num
 *   Number of elements in the *pkt* array.
 */
void tle_tcp_reject(struct tle_stream *s, const struct tle_syn_req rq[],
	uint32_t num);

/**
 * return up to *num* mbufs that was received for given TCP stream.
 * Note that the stream has to be in connected state.
 * Data ordering is preserved.
 * For each returned mbuf:
 * data_off set to the start of the packet's TCP data
 * l2_len, l3_len, l4_len are setup properly
 * (so user can still extract L2/L3 address info if needed)
 * packet_type RTE_PTYPE_L2/L3/L4 bits are setup properly.
 * L3/L4 checksum is verified.
 * @param s
 *   TCP stream to receive packets from.
 * @param pkt
 *   An array of pointers to *rte_mbuf* structures that
 *   must be large enough to store up to *num* pointers in it.
 * @param num
 *   Number of elements in the *pkt* array.
 * @return
 *   number of of entries filled inside *pkt* array.
 */
uint16_t tle_tcp_stream_recv(struct tle_stream *s, struct rte_mbuf *pkt[],
	uint16_t num);

/**
 * Consume and queue up to *num* packets, that will be sent eventually
 * by tle_tcp_tx_bulk().
 * Note that the stream has to be in connected state.
 * It is resposibility of that function is to determine over which TCP dev
 * given packets have to be sent out and do necessary preparations for that.
 * Based on the *dst_addr* it does route lookup, fills L2/L3/L4 headers,
 * and, if necessary, fragments packets.
 * Depending on the underlying device information, it either does
 * IP/TCP checksum calculations in SW or sets mbuf TX checksum
 * offload fields properly.
 * For each input mbuf the following conditions have to be met:
 *	- data_off point to the start of packet's TCP data.
 *	- there is enough header space to prepend L2/L3/L4 headers.
 * @param s
 *   TCP stream to send packets over.
 * @param pkt
 *   The burst of output packets that need to be send.
 * @param num
 *   Number of elements in the *pkt* array.
 * @return
 *   number of packets successfully queued in the stream send buffer.
 */
uint16_t tle_tcp_stream_send(struct tle_stream *s, struct rte_mbuf *pkt[],
	uint16_t num);

/**
 * reads up to *iovcnt* buffers from the given TCP stream.
 * Note that the stream has to be in connected state.
 * @param s
 *   TCP stream to read data from.
 * @param iov
 *   An array of *iovec* structures that
 *   must be large enough to store up to *iovcnt* elemtents.
 * @param iovcnt
 *   Number of elements in the *iov* array.
 * @return
 *   number of bytes read on successful completion.
 *   - EINVAL - invalid parameter passed to function
 *   - ENOTCONN - stream is not connected
 */
ssize_t tle_tcp_readv(struct tle_stream *s, const struct iovec iov[],
	int iovcnt);

/**
 * writes up to *iovcnt* buffers to the given TCP stream.
 * Note that the stream has to be in connected state.
 * @param s
 *   TCP stream to read data from.
 * @param mp
 *   Mempool to allocate mbufs from.
 * @param iov
 *   An array of *iovec* structures that
 *   must be large enough to store up to *iovcnt* elemtents.
 * @param iovcnt
 *   Number of elements in the *iov* array.
 * @return
 *   number of bytes written on successful completion.
 *   - EINVAL - invalid parameter passed to function
 *   - ENOTCONN - stream is not connected
 */
ssize_t tle_tcp_writev(struct tle_stream *s, struct rte_mempool *mp,
	const struct iovec iov[], int iovcnt);

/**
 * Back End (BE) API.
 * BE API functions are not multi-thread safe.
 * Supposed to be called by the L2/L3 processing layer.
 */

/**
 * Take input mbufs and distribute them to open TCP streams.
 * expects that for each input packet:
 *	- l2_len, l3_len, l4_len are setup correctly
 *	- (packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)) != 0,
 *	- (packet_type & RTE_PTYPE_L4_TCP) != 0,
 * During delivery L3/L4 checksums will be verified
 * (either relies on HW offload or in SW).
 * May cause some extra packets to be queued for TX. 
 * This function is not multi-thread safe.
 * @param dev
 *   TCP device the packets were received from.
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
 *   number of packets delivered to the TCP streams.
 */
uint16_t tle_tcp_rx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[],
	struct rte_mbuf *rp[], int32_t rc[], uint16_t num);

/**
 * Fill *pkt* with pointers to the packets that have to be transmitted
 * over given TCP device.
 * Output packets have to be ready to be passed straight to rte_eth_tx_burst()
 * without any extra processing.
 * TCP/IPv4 checksum either already calculated or appropriate mbuf fields set
 * properly for HW offload.
 * This function is not multi-thread safe.
 * @param dev
 *   TCP device the output packets will be transmitted over.
 * @param pkt
 *   An array of pointers to *rte_mbuf* structures that
 *   must be large enough to store up to *num* pointers in it.
 * @param num
 *   Number of elements in the *pkt* array.
 * @return
 *   number of of entries filled inside *pkt* array.
 */
uint16_t tle_tcp_tx_bulk(struct tle_dev *dev, struct rte_mbuf *pkt[],
	uint16_t num);

/**
 * perform internal processing for given TCP context.
 * Checks which timers are expired and performs the required actions
 * (retransmission/connection abort, etc.)
 * May cause some extra packets to be queued for TX.
 * This function is not multi-thread safe.
 * @param ctx
 *   TCP context to process.
 * @return
 *   zero on successful completion.
 *   - EINVAL - invalid parameter passed to function
 * @return
 */
int tle_tcp_process(struct tle_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _TLE_TCP_H_ */
