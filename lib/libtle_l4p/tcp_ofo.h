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

#ifndef _TCP_OFO_H_
#define _TCP_OFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

struct ofodb {
	uint32_t nb_elem;
	uint32_t nb_max;
	union seqlen sl;
	struct rte_mbuf **obj;
};

struct ofo {
	uint32_t nb_elem;
	uint32_t nb_max;
	struct ofodb db[];
};

static inline void
_ofodb_move(struct ofodb *dst, struct ofodb *src)
{
	uint32_t i;

	dst->nb_elem = src->nb_elem;
	dst->sl = src->sl;
	for (i = 0; i < src->nb_elem; i++)
		dst->obj[i] = src->obj[i];
}

static inline void
_ofodb_free(struct ofodb *db)
{
	uint32_t i;

	for (i = 0; i != db->nb_elem; i++)
		rte_pktmbuf_free(db->obj[i]);
}

static inline void
_ofo_remove(struct ofo *ofo, uint32_t pos, uint32_t num)
{
	uint32_t i, n;

	n = ofo->nb_elem - num - pos;
	for (i = 0; i != n; i++)
		_ofodb_move(&ofo->db[pos + i], &ofo->db[pos + num + i]);
	ofo->nb_elem -= num;
}

static inline void
tcp_ofo_reset(struct ofo *ofo)
{
	uint32_t i;

	for (i = 0; i != ofo->nb_elem; i++)
		_ofodb_free(&ofo->db[i]);

	_ofo_remove(ofo, 0, ofo->nb_elem);
}

static inline uint32_t
_ofo_insert_mbuf(struct ofo* ofo, uint32_t pos, union seqlen* sl,
		 struct rte_mbuf* mb[], uint32_t num, bool is_compact) {
	uint32_t i, k, n;
	uint32_t end, seq;

	struct ofodb* db = ofo->db + pos;

	/* new pkts may overlap with right side db,
	 * don't insert overlapped part from 'end'
	 * function could be called from _ofo_compact,
	 * no overlap in this condition.
	 */
	if (!is_compact && pos < ofo->nb_elem - 1)
		end = ofo->db[pos + 1].sl.seq;
	else
		end = sl->seq + sl->len;

	/* copy non-overlapping mbufs */
	k = db->nb_elem;
	n = RTE_MIN(db->nb_max - k, num);
	for (i = 0, seq = sl->seq; i != n && tcp_seq_lt(seq, end); i++) {
		seq += mb[i]->pkt_len;
		db->obj[k + i] = mb[i];
	}
	if (tcp_seq_lt(end, seq))
		_rte_pktmbuf_trim(mb[i - 1], seq - end);

	db->nb_elem += i;
	db->sl.len += tcp_seq_min(seq, end) - sl->seq;
	sl->len = sl->seq + sl->len - seq;
	sl->seq = seq;
	return i;
}

static inline uint32_t
_ofo_insert_new(struct ofo *ofo, uint32_t pos, union seqlen *sl,
		struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i, n;

	n = ofo->nb_elem;

	/* out of space */
	if (n == ofo->nb_max)
		return 0;

	/* allocate new one */
	ofo->nb_elem = n + 1;

	/* insert into a proper position. */
	for (i = n; i != pos; i--)
		_ofodb_move(&ofo->db[i], &ofo->db[i - 1]);

	ofo->db[pos].nb_elem = 0;
	ofo->db[pos].sl.seq = sl->seq;
	ofo->db[pos].sl.len = 0;

	i = _ofo_insert_mbuf(ofo, pos, sl, mb, num, false);
	return i;
}

static inline uint32_t
_ofo_insert_right(struct ofo *ofo, uint32_t pos, union seqlen *sl,
		  struct rte_mbuf *mb[], uint32_t num, bool is_compact)
{
	uint32_t i, j, n;
	uint32_t end, plen, skip;
	struct ofodb *db;

	db = ofo->db + pos;
	end = db->sl.seq + db->sl.len;

	skip = end - sl->seq;

	/* skip overlapping packets */
	for (i = 0, n = skip; i != num && n != 0; i++, n -= plen) {
		plen = mb[i]->pkt_len;
		if (n < plen) {
			/* adjust partially overlapped packet. */
			mb[i] = _rte_pktmbuf_adj(mb[i], n);
			break;
		}
	}

	/* free totally overlapped packets. */
	for (j = 0; j != i; j++)
		rte_pktmbuf_free(mb[j]);

	sl->seq += skip;
	sl->len -= skip;
	j = _ofo_insert_mbuf(ofo, pos, sl, mb + i,  num - i, is_compact);
	return i + j;
}

static inline uint32_t
_ofo_step(struct ofo *ofo, union seqlen *sl, struct rte_mbuf *mb[],
	  uint32_t num)
{
	uint32_t i, n;
	struct ofodb *db, *nextdb;

	db = NULL;
	n = ofo->nb_elem;

	/*
	 * start from the right side, assume that after some gap,
	 * we keep receiving packets in order.
	 */
	for (i = n; i-- != 0; ) {
		db = ofo->db + i;
		if (tcp_seq_leq(db->sl.seq, sl->seq))
			break;
	}

	/*
	 * if db has right consecutive dbs, find the most right one.
	 * we should insert new packets after this db, rather than left ones.
	 */
	for (; i < n - 1; i++) {
		nextdb = db + 1;
		if (db->sl.seq + db->sl.len != nextdb->sl.seq)
			break;
		db = nextdb;
	}

	/* new db required */
	if ((int32_t)i < 0 || tcp_seq_lt(db->sl.seq + db->sl.len, sl->seq))
		return _ofo_insert_new(ofo, i + 1, sl, mb, num);

	/* new one is right adjacent, or overlap */

	/* new one is completely overlapped by old one */
	if (tcp_seq_leq(sl->seq + sl->len, db->sl.seq + db->sl.len))
		return 0;

	/* either overlap OR (adjacent AND some free space remains) */
	if (tcp_seq_lt(sl->seq, db->sl.seq + db->sl.len) ||
	    db->nb_elem != db->nb_max)
		return _ofo_insert_right(ofo, i, sl, mb, num, false);

	/* adjacent, no free space in current block */
	return _ofo_insert_new(ofo, i + 1, sl, mb, num);
}

static inline void
_ofo_compact(struct ofo *ofo)
{
	uint32_t i, j, k, n, ro;
	struct ofodb *db;

	for (i = 0; i < ofo->nb_elem; i++) {

		for (j = i + 1; j != ofo->nb_elem; j++) {

			/* no intersection */
			ro = ofo->db[j].sl.seq - ofo->db[i].sl.seq;
			if (ro > ofo->db[i].sl.len)
				break;

			db = ofo->db + j;
			n = _ofo_insert_right(ofo, i, &db->sl, db->obj,
				db->nb_elem, true);
			if (n < db->nb_elem) {
				db->nb_elem -= n;
				for (k = 0; k < db->nb_elem; k++)
					db->obj[k] = db->obj[n + k];
				break;
			}
		}

		n = j - i - 1;
		if (n != 0)
			_ofo_remove(ofo, i + 1, n);
	}
}

static inline uint32_t
_ofodb_enqueue(struct rte_ring *r, const struct ofodb *db, uint32_t *seq)
{
	uint32_t i, n, num, begin, end;
	struct rte_mbuf *pkt;

	n = 0;
	num = db->nb_elem;
	begin = db->sl.seq;
	i = 0;
	pkt = db->obj[0];

	/* removed overlapped part from db */
	while (tcp_seq_lt(begin, *seq)) {
		end = begin + pkt->pkt_len;
		if (tcp_seq_leq(end, *seq)) {
			/* pkt is completely overlapped */
			begin = end;
			rte_pktmbuf_free(pkt);
			pkt = db->obj[++i];
		} else {
			/* pkt is partly overlapped */
			rte_pktmbuf_adj(pkt, *seq - begin);
			break;
		}
	}

	n = i;
	n += _rte_ring_enqueue_burst(r, (void * const *)(db->obj + i), num - i);

	*seq = db->sl.seq + db->sl.len;
	*seq -= tcp_mbuf_seq_free(db->obj + n, num - n);
	return num - n;
}

struct ofo *
tcp_ofo_alloc(uint32_t nbufs, int32_t socket);

void
tcp_ofo_free(struct ofo *ofo);

#ifdef __cplusplus
}
#endif

#endif /* _TCP_OFO_H_ */
