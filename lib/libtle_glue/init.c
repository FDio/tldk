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
#include <sched.h>
#include <pthread.h>
#include <stdlib.h>

#include <rte_compat.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>

#include "util.h"
#include "fd.h"
#include "ctx.h"
#include "sym.h"
#include "log.h"
#include "internal.h"
#include "tle_glue.h"

void
glue_init1(int argc, char **argv)
{
	GLUE_LOG(INFO, "init: DPDK and fd table...");

	if (rte_eal_init(argc, argv) < 0)
		rte_panic("Failed to init DPDK");

	fd_init();
}

static void __attribute__((constructor(1000)))
glue_init(void)
{
	char *p;
	int i, err, argc = 0;
	char **argv = NULL, **argv_to_release = NULL;
	char *vnic, *params, *no_huge;
	cpu_set_t cpuset;
	pthread_t tid = pthread_self();

	symbol_init();

#define DPDK_PARAMS "DPDK_PARAMS"
	params = getenv(DPDK_PARAMS);
#define DPDK_NO_HUGE "DPDK_NO_HUGE"
	no_huge = getenv(DPDK_NO_HUGE);
#define DPDK_VNIC "DPDK_VNIC"
	vnic = getenv(DPDK_VNIC);

	if (params == NULL && no_huge == NULL && vnic == NULL)
		return;

	argv = grow_argv(argv, argc, 1);
	argv[argc++] = xstrdup("userspace-stack");

	/* Get the main thread affinity */
	CPU_ZERO(&cpuset);
	err = pthread_getaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
	if (!err) {
		for (i = 0; i < CPU_SETSIZE; i++) {
			if (CPU_ISSET(i, &cpuset)) {
				argv = grow_argv(argv, argc, 2);
				argv[argc++] = xstrdup("-l");
				argv[argc++] = xasprintf("%d", i);
				i = CPU_SETSIZE;
			}
		}
	} else {
		argv = grow_argv(argv, argc, 2);
		argv[argc++] = xstrdup("-l");
		argv[argc++] = xasprintf("0");
	}

	if (params)
		p = strtok(params, " ");
	else
		p = NULL;
	while (p != NULL) {
		argv = grow_argv(argv, argc, 1);
		argv[argc++] = xstrdup(p);
		p = strtok(NULL, " ");
	}

	if (no_huge) {
		argv = grow_argv(argv, argc, 3);
		argv[argc++] = xstrdup("-m");
		argv[argc++] = xstrdup("2048");
		argv[argc++] = xstrdup("--no-huge");
	}

	if (vnic) {
		argv = grow_argv(argv, argc, 2);
		argv[argc++] = xstrdup(vnic);
		argv[argc++] = xstrdup("--no-pci");
	}

	argv = grow_argv(argv, argc, 1);
	argv[argc++] = xstrdup("--");

	argv_to_release = grow_argv(argv_to_release, 0, argc);
	for (i = 0; i < argc; ++i)
		argv_to_release[i] = argv[i];

	glue_init1(argc, argv);

	/* Alloc and setup this default ctx for any sockets operations before
	 * thread/ctx binding which happens when epoll_wait.
	 */
	glue_ctx_alloc();

	release_argv(argc, argv_to_release, argv);

	/* Set back the affinity */
	err = pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
	if (err)
		GLUE_LOG(ERR, "Failed to set back affinity");
}

static void __attribute__((destructor))
glue_uninit(void)
{
	struct sock *so;
	struct glue_ctx *ctx;
	int i, max = fd_table.fd_base + fd_table.fd_num;

	/* TODO: lets optimize it */
	for (i = fd_table.fd_base; i < max; i++) {
		so = fd2sock(i);
		if (!so || !so->valid)
			continue;
		if (IS_TCP(so))
			tle_tcp_stream_kill(so->s);
	}

	for (i = 0; i < nb_ctx; ++i) {
		ctx = glue_ctx_lookup(0, i);
		while (be_process(ctx)) { /* empty */ };
	}
}
