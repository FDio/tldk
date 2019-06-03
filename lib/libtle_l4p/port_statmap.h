/*
 * Copyright (c) 2019 Ant Financial Services Group.
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

#ifndef _PORT_STATMAP_H_
#define _PORT_STATMAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PORT_NUM	(UINT16_MAX + 1)
#define	ALLOC_PORT_START	0x8000

struct tle_psm {
	uint32_t nb_used; /* number of ports already in use. */
	uint32_t next_alloc; /* next port to try allocate. */
	uint8_t stat[MAX_PORT_NUM]; /* use status of each port. first bit
								shows if SO_REUSEPORT is allowed, last
								7 bits record the count of sockets who
								use this port. */
};

static inline void
tle_psm_init(struct tle_psm *psm)
{
	memset(psm, 0, sizeof(struct tle_psm));
	psm->next_alloc = ALLOC_PORT_START;
}

static inline int
tle_psm_set(struct tle_psm *psm, uint16_t port, uint8_t reuseport)
{
	if (psm->stat[port] == 0) {
		/* port has not been used */
		psm->stat[port]++;
		if (reuseport)
			psm->stat[port] |= 0x80;
	} else {
		/* port is used by some socket */
		if (reuseport && (psm->stat[port] & 0x80)) {
			/* all sockets set reuseport */
			psm->stat[port]++;
		}
		else{
			return -1;
		}
	}

	return 0;
}

static inline void
tle_psm_clear(struct tle_psm *psm, uint16_t port)
{
	psm->stat[port]--;
	if ((psm->stat[port] & 0x7f) == 0)
		psm->stat[port] = 0;
}


static inline uint8_t
tle_psm_check(const struct tle_psm *psm, uint16_t port)
{
	return psm->stat[port];
}

static inline uint16_t
tle_psm_alloc_port(struct tle_psm *psm)
{
	uint32_t i = psm->next_alloc;

	for (; i < MAX_PORT_NUM; i++) {
		if (psm->stat[i] == 0) {
			psm->next_alloc = i + 1;
			return (uint16_t)i;
		}
	}

	for (i = ALLOC_PORT_START; i < psm->next_alloc; i++) {
		if (psm->stat[i] == 0) {
			psm->next_alloc = i + 1;
			return (uint16_t)i;
		}
	}

	return 0;
}

static inline uint16_t
tle_psm_alloc_dual_port(struct tle_psm *psm4, struct tle_psm *psm6)
{
	uint32_t i = psm6->next_alloc;

	for (; i < MAX_PORT_NUM; i++) {
		if (psm6->stat[i] == 0 && psm4->stat[i] == 0) {
			psm6->next_alloc = i + 1;
			return (uint16_t)i;
		}
	}

	for (i = ALLOC_PORT_START; i < psm6->next_alloc; i++) {
		if (psm6->stat[i] == 0 && psm4->stat[i] == 0) {
			psm6->next_alloc = i + 1;
			return (uint16_t)i;
		}
	}

	return 0;
}


#ifdef __cplusplus
}
#endif

#endif /* _PORT_STATMAP_H_ */
