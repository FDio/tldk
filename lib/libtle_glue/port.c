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

#include <sys/eventfd.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_eth_ring.h>

#include "log.h"
#include "ctx.h"
#include "config.h"
#include "internal.h"

int stopped;

static struct rte_mempool *mpool[RTE_MAX_NUMA_NODES];

struct rte_mempool *
get_mempool_by_socket(int32_t socket_id)
{
	struct rte_mempool *mp;
	char name[RTE_MEMPOOL_NAMESIZE];

	if (socket_id == SOCKET_ID_ANY)
		socket_id = 0;

	if (mpool[socket_id])
		return mpool[socket_id];

	snprintf(name, sizeof(name), "MP%u", socket_id);
	mp = rte_pktmbuf_dynamic_pool_create(name, MAX_MBUFS - 1,
			MBUF_PERCORE_CACHE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
			socket_id, MBUF_DYNAMIC_SIZE);

	if (mp == NULL)
		rte_panic("Failed to create mbuf mempool");

	mpool[socket_id] = mp;
	return mp;
}

static void
update_rss_conf(uint16_t port_id)
{
	struct rte_eth_rss_conf rss_conf = {
		.rss_key = NULL,
		.rss_key_len = 0,
		.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
	};

	if (rte_eth_dev_rss_hash_update(port_id, &rss_conf) < 0)
		rte_panic("Failed to update rss hash");
}

static void
queue_init(uint16_t port_id, uint16_t nb_queues,
	   struct rte_eth_dev_info *dev_info,
	   struct rte_eth_conf *port_conf)
{
	uint16_t q;
	int32_t socket_id, rc;
	uint16_t nb_rxd = 1024, nb_txd = 1024;
	struct rte_mempool *mp;
	struct rte_eth_txconf txq_conf = dev_info->default_txconf;
	struct rte_eth_rxconf rxq_conf = dev_info->default_rxconf;

	socket_id = rte_eth_dev_socket_id(port_id);
	mp = get_mempool_by_socket(socket_id);

	dev_info->default_rxconf.rx_drop_en = 1;

	rc = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (rc < 0)
		rte_panic("Cannot adjust number of desc");

	rxq_conf.offloads = port_conf->rxmode.offloads;
	txq_conf.offloads = port_conf->txmode.offloads;

	/* faster free of tx entries */
	txq_conf.tx_free_thresh = nb_txd - 64;

	for (q = 0; q < nb_queues; q++) {
		rc = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
			socket_id, &rxq_conf, mp);
		if (rc < 0)
			rte_panic("rx queue=%u setup failed: %d", q, rc);

		rc = setup_rx_cb(port_id, q);
		if (rc < 0)
			rte_panic("rx queue=%u rx setup failed: %d", q, rc);
	}

	for (q = 0; q < nb_queues; q++) {
		rc = rte_eth_tx_queue_setup(port_id, q, nb_txd,
			socket_id, &txq_conf);
		if (rc < 0)
			rte_panic("tx queue=%u setup failed: %d", q, rc);
	}
}

uint64_t rx_offload =
	DEV_RX_OFFLOAD_IPV4_CKSUM |
	DEV_RX_OFFLOAD_UDP_CKSUM |
	DEV_RX_OFFLOAD_TCP_CKSUM;
/* nice to have:
	DEV_RX_OFFLOAD_CRC_STRIP |
	DEV_RX_OFFLOAD_TCP_LRO |
	DEV_RX_OFFLOAD_HEADER_SPLIT |
	DEV_RX_OFFLOAD_SCATTER |
	DEV_RX_OFFLOAD_TIMESTAMP
*/

uint64_t tx_offload =
	DEV_TX_OFFLOAD_UDP_CKSUM |
	DEV_TX_OFFLOAD_TCP_CKSUM |
	DEV_TX_OFFLOAD_TCP_TSO |
	DEV_TX_OFFLOAD_MULTI_SEGS;

int
dev_rxq_wakeup(uint16_t port_id)
{
	int fd;
	uint16_t qid;
	uint32_t vec, efd_idx;
	struct rte_eth_dev *dev;
	struct rte_intr_handle *intr_handle;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

	dev = &rte_eth_devices[port_id];
	intr_handle = dev->intr_handle;
	if (!intr_handle)
		return -ENOTSUP;
	if (!intr_handle->intr_vec)
		return -EPERM;

	for (qid = 0; qid < dev->data->nb_rx_queues; qid++) {
		vec = intr_handle->intr_vec[qid];
		efd_idx = (vec >= RTE_INTR_VEC_RXTX_OFFSET) ?
			(vec - RTE_INTR_VEC_RXTX_OFFSET) : vec;
		fd = intr_handle->efds[efd_idx];
		if (eventfd_write(fd, (eventfd_t) 1) < 0)
			return -errno;
	}

	return 0;
}

void
port_reconfig(void)
{
	int32_t rc;
	struct rte_eth_dev_info dev_info;
	uint16_t port_id = 0; /* We use and only use port 0 */
	uint16_t nb_port;
	uint16_t nb_queues = nb_ctx;

	struct rte_eth_conf port_conf = {
		.intr_conf = {
			.rxq = 1,
		},
	};

	/* 0. dev number check */
	nb_port = rte_eth_dev_count_avail();
	if (nb_port < 1 || nb_port >2)
		rte_panic("One port is mandatory with an optional loopback device\n");

	stopped = 1;
	rte_wmb();
	/* wake up all rxqs */
	if (nb_ctx > 1)
		dev_rxq_wakeup(port_id);

	usleep(1); /* fix me: this cannot gurantee correctness */

	rte_eth_dev_stop(port_id);

	/* 1. offloading check and set*/
	rte_eth_dev_info_get(port_id, &dev_info);
	rx_offload &= dev_info.rx_offload_capa;
	port_conf.rxmode.offloads = rx_offload;
	tx_offload &= dev_info.tx_offload_capa;
	port_conf.txmode.offloads = tx_offload;

	GLUE_LOG(INFO, "configure queues = %d, offloads: rx = %"PRIx64", tx = %"PRIx64,
		 nb_queues, rx_offload, tx_offload);

	/* 2. dev configure */
	rc = rte_eth_dev_configure(port_id, nb_queues, nb_queues, &port_conf);
	if (rc != 0)
		rte_panic("Failed to configure device, %d", rc);

	/* 3. queue setup */
	queue_init(port_id, nb_queues, &dev_info, &port_conf);

	/* 4. rss conf */
	if (nb_queues > 1)
		update_rss_conf(port_id);

	/* 5. dev start */
	if (rte_eth_dev_start(port_id) < 0)
		rte_panic("Failed to start device");

	stopped = 0;
}

uint16_t
create_loopback(uint32_t socket_id)
{
	int ret;
	struct rte_ring* lb_queue;
	static uint16_t lb_port_id = 0xFFFF;
	const char *ring_name = "loopback-ring";

	if (lb_port_id != 0xFFFF)
		return lb_port_id;

	lb_queue = rte_ring_create(ring_name, MAX_PKTS_BURST * 8, socket_id,
				   RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (!lb_queue)
		rte_panic("Failed to create ring for loopback\n");
	ret = rte_eth_from_ring(lb_queue);
	if (ret < 0)
		rte_panic("Failed to create ethdev from ring\n");
	lb_port_id = ret;

	if (setup_rx_cb(lb_port_id, 0) < 0)
		rte_panic("Failed to set up rx cb for loopback\n");

	return lb_port_id;
}
