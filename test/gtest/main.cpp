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

#include <iostream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_errno.h>

#include "test_common.h"

struct rte_mempool *mbuf_pool;
char binpath[PATH_MAX];

int
main(int argc, char *argv[])
{
	uint8_t nb_ports = 1;
	int rc = 0;
	char *slash;

	/* Initialize GoogleTest&Mock and parse any args */
	testing::InitGoogleMock(&argc, argv);
	/* Initialize EAL */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* get the path of binary and save in a global variable to be used later*/
	realpath(argv[0], binpath);
	slash = NULL;
	slash = strrchr(binpath, '/');
	if (strcmp(binpath, "") != 0 && slash != NULL)
		binpath[slash - binpath] = 0;

	/*
	 * Creates a new mempool in memory to hold the mbufs.
	 * Multiplied by 2 because of mempeool to be used for packet
	 * fragmentation purposes.
	 */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		2 * NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rc = -rte_errno;
		printf("Mempool was not created, rc=%d\n", rc);
		return rc;
	}

	return RUN_ALL_TESTS();
}
