/*
 * Copyright (c) 2016-2017  Intel Corporation.
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

#ifndef _TCP_TX_SEG_H_
#define _TCP_TX_SEG_H_

#ifdef __cplusplus
extern "C" {
#endif

static inline int32_t
tcp_segmentation(struct rte_mbuf *mbin, struct rte_mbuf *mbout[], uint16_t num,
	const struct tle_dest *dst, uint16_t mss)
{
	struct rte_mbuf *in_seg = NULL;
	uint32_t nbseg, in_seg_data_pos;
	uint32_t more_in_segs;

	in_seg = mbin;
	in_seg_data_pos = 0;
	nbseg = 0;

	/* Check that pkts_out is big enough to hold all fragments */
	if (mss * num < (uint16_t)mbin->pkt_len)
		return -ENOSPC;

	more_in_segs = 1;
	while (more_in_segs) {
		struct rte_mbuf *out_pkt = NULL, *out_seg_prev = NULL;
		uint32_t more_out_segs;

		/* Allocate direct buffer */
		out_pkt = rte_pktmbuf_alloc(dst->head_mp);
		if (out_pkt == NULL) {
			free_mbufs(mbout, nbseg);
			return -ENOMEM;
		}

		out_seg_prev = out_pkt;
		more_out_segs = 1;
		while (more_out_segs && more_in_segs) {
			struct rte_mbuf *out_seg = NULL;
			uint32_t len;

			/* Allocate indirect buffer */
			out_seg = rte_pktmbuf_alloc(dst->head_mp);
			if (out_seg == NULL) {
				rte_pktmbuf_free(out_pkt);
				free_mbufs(mbout, nbseg);
				return -ENOMEM;
			}
			out_seg_prev->next = out_seg;
			out_seg_prev = out_seg;

			/* Prepare indirect buffer */
			rte_pktmbuf_attach(out_seg, in_seg);
			len = mss;
			if (len > (in_seg->data_len - in_seg_data_pos))
				len = in_seg->data_len - in_seg_data_pos;

			out_seg->data_off = in_seg->data_off + in_seg_data_pos;
			out_seg->data_len = (uint16_t)len;
			out_pkt->pkt_len = (uint16_t)(len + out_pkt->pkt_len);
			out_pkt->nb_segs += 1;
			in_seg_data_pos += len;

			/* Current output packet (i.e. fragment) done ? */
			if (out_pkt->pkt_len >= mss)
				more_out_segs = 0;

			/* Current input segment done ? */
			if (in_seg_data_pos == in_seg->data_len) {
				in_seg = in_seg->next;
				in_seg_data_pos = 0;

				if (in_seg == NULL)
					more_in_segs = 0;
			}
		}

		/* Write the segment to the output list */
		mbout[nbseg] = out_pkt;
		nbseg++;
	}

	return nbseg;
}

#ifdef __cplusplus
}
#endif

#endif /* _TCP_TX_SEG_H_ */
