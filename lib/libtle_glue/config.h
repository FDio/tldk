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

#ifndef _TLE_GLUE_CONFIG_H_
#define _TLE_GLUE_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_STREAMS_PER_CORE		64 * 1024
#define MIN_STREAMS_PER_CORE		16
#define DELTA_STREAMS			64
#define FRAG_BUCKET			8
#define FRAG_ENTRIES_PER_BUCKET		8
#define MAX_ARP_ENTRY			(1 << 10)

/* RCV buffer & SND buffer
 * This is not a reall rcv/snd buffer implementation. Below number means
 * the slots to store mbufs of sent or received data. Each slot could
 * contains a single mbuf with size of (1500B or 2048B) or a chained
 * mbuf with size <= 64KB.
 *
 * TODO: add real snd/rcv buffer
 */
#define MAX_RECV_BUFS_PER_STREAM	256
#define MAX_SEND_BUFS_PER_STREAM	256

#ifdef LOOK_ASIDE_BACKEND
#define MAX_NB_CTX			1
#else
#define MAX_NB_CTX			16
#endif

#define MAX_MBUFS			0x80000
/* should calculated by:
 * MAX_NB_CTX * MAX_STREAMS_PER_CORE * (MAX_RECV_BUFS_PER_STREAM + MAX_SEND_BUFS_PER_STREAM))
 */

#define MBUF_DYNAMIC_SIZE		0x800

#define MBUF_PERCORE_CACHE		64

#define MAX_PKTS_BURST			0x20

#define TCP_MAX_PROCESS			32

#ifdef __cplusplus
}
#endif

#endif /*_TLE_GLUE_CONFIG_H_ */
