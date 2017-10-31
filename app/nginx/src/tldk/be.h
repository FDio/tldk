/*
 * Copyright (c) 2017  Intel Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __BE_H__
#define __BE_H__

#include "ngx_tldk.h"

extern volatile int force_quit;

int be_lpm4_dst_lookup(void *data, const struct in_addr *addr,
			struct tle_dest *res);
int be_lpm6_dst_lookup(void *data, const struct in6_addr *addr,
			struct tle_dest *res);
int be_lcore_lpm_init(struct tldk_ctx *tcx, uint32_t sid,
		const struct tldk_ctx_conf *cf);
int be_port_init(tldk_conf_t *cf);
int be_dst_init(struct tldk_ctx *tcx, const tldk_conf_t *cf);
int be_add_dev(struct tldk_ctx *tcx, const tldk_conf_t *cf);
int be_mpool_init(struct tldk_ctx *tcx);
int be_queue_init(struct tldk_ctx *tcx, const tldk_conf_t *cf);
int be_check_lcore(uint32_t lc);

void
be_lcore_tcp(struct tldk_ctx *tcx);

int be_lcore_main(void *arg);
int be_lcore_setup(struct tldk_ctx *tcx);
void be_lcore_clear(struct tldk_ctx *tcx);

void be_stop_port(uint32_t port);

#endif /*__BE_H__ */
