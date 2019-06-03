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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include "util.h"

#define NUMA_NODE_PATH "/sys/devices/system/node"

static unsigned
eal_cpu_socket_id(unsigned lcore_id)
{
        unsigned socket;

        for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
                char path[PATH_MAX];

                snprintf(path, sizeof(path), "%s/node%u/cpu%u", NUMA_NODE_PATH,
                                socket, lcore_id);
                if (access(path, F_OK) == 0)
                        return socket;
        }
        return 0;
}

uint32_t
get_socket_id(void)
{
	int err;
	uint32_t i;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	err = pthread_getaffinity_np(pthread_self(),
				     sizeof(cpuset), &cpuset);
	if (err)
		return 0;

	for (i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &cpuset))
			break;

	return eal_cpu_socket_id(i);
}
