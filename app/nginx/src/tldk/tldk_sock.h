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

#ifndef __TLDK_SOCK_H__
#define __TLDK_SOCK_H__

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <tle_tcp.h>

extern ngx_module_t ngx_tldk_event_module;

extern int tldk_stbl_init(const ngx_cycle_t *, const struct tldk_ctx *);
extern void tldk_stbl_fini(void);

extern int
tldk_open_bind_listen(struct tldk_ctx *tcx, int domain, int type,
	const struct sockaddr *addr, socklen_t addrlen, int backlog);

extern void
tldk_dump_event_stats(void);

#define	TLDK_ACCEPT_BULK	0x10

struct tldk_sock {
	LIST_ENTRY(tldk_sock) link;
	struct tle_stream *s;
	struct tle_event *erev;
	struct tle_event *rxev;
	struct tle_event *txev;
	ngx_event_t *rev;
	ngx_event_t *wev;
	uint16_t posterr;
	struct {
		uint32_t num;
		struct tle_stream *buf[TLDK_ACCEPT_BULK];
	} acpt;
};

struct tldk_sock_list {
        uint32_t num;
        LIST_HEAD(, tldk_sock) head;
};

struct tldk_stbl {
        struct tle_evq *syneq;
        struct tle_evq *ereq;
        struct tle_evq *rxeq;
        struct tle_evq *txeq;
        struct tldk_sock_list free;
        struct tldk_sock_list lstn;
        struct tldk_sock_list use;
        int32_t nosd;
        uint32_t snum;
        struct tldk_sock *sd;
};


#define SOCK_TO_SD(s)   (stbl.nosd + ((s) - stbl.sd))
#define SD_TO SOCK(d)   (stbl.sd + ((d) - stbl.nosd))

/* One socket/file table per worker */
extern struct tldk_stbl stbl;

static inline struct tldk_sock *
sd_to_sock(int32_t sd)
{
        uint32_t n;

        n = sd - stbl.nosd;
        if (n >= stbl.snum)
                return NULL;

        return stbl.sd + n;
}



#endif /* __TLDK_SOCK_H__ */
