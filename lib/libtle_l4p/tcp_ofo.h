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
		ofo->db[pos + i] = ofo->db[pos + num + i];
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
_ofo_insert_new(struct ofo *ofo, uint32_t pos, union seqlen *sl,
	struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i, n, plen;
	struct ofodb *db;

	n = ofo->nb_elem;

	/* out of space */
	if (n == ofo->nb_max)
		return 0;

	/* allocate new one */
	db = ofo->db + n;
	ofo->nb_elem = n + 1;

	/* insert into a proper position. */
	for (i = n; i != pos; i--)
		ofo->db[i] = ofo->db[i - 1];

	/* fill new block */
	n = RTE_MIN(db->nb_max, num);
	for (i = 0; i != n; i++)
		db->obj[i] = mb[i];

	/* can't queue some packets. */
	plen = 0;
	for (i = n; i != num; i++)
		plen += mb[i]->pkt_len;

	db->nb_elem = n;
	db->sl.seq = sl->seq;
	db->sl.len = sl->len - plen;

	sl->seq += db->sl.len;
	sl->len -= db->sl.len;
	return n;
}

static inline uint32_t
_ofo_insert_right(struct ofo *ofo, uint32_t pos, union seqlen *sl,
	struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i, j, k, n;
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
			rte_pktmbuf_adj(mb[i], plen - n);
			break;
		}
	}

	/* free totally overlapped packets. */
	for (j = 0; j != i; j++)
		rte_pktmbuf_free(mb[j]);

	/* copy non-overlapping mbufs */
	k = db->nb_elem;
	n = RTE_MIN(db->nb_max - k, num - i);

	plen = 0;
	for (j = 0; j != n; j++) {
		db->obj[k + j] = mb[i + j];
		plen += mb[i + j]->pkt_len;
	}

	db->nb_elem += n;
	db->sl.len += plen;

	plen += skip;
	sl->len -= plen;
	sl->seq += plen;
	return n + i;
}

static inline uint32_t
_ofo_step(struct ofo *ofo, union seqlen *sl, struct rte_mbuf *mb[],
	uint32_t num)
{
	uint32_t i, n, end, lo, ro;
	struct ofodb *db;

	db = NULL;
	end = sl->seq + sl->len;
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

	/* new db required */
	if ((int32_t)i < 0 || tcp_seq_lt(db->sl.seq + db->sl.len, sl->seq))
		return _ofo_insert_new(ofo, i + 1, sl, mb, num);

	/* new one is right adjacent, or overlap */

	ro = sl->seq - db->sl.seq;
	lo = end - db->sl.seq;

	/* new one is completely overlapped by old one */
	if (lo <= db->sl.len)
		return 0;

	/* either overlap OR (adjacent AND some free space remains) */
	if (ro < db->sl.len || db->nb_elem != db->nb_max)
		return _ofo_insert_right(ofo, i, sl, mb, num);

	/* adjacent, no free space in current block */
	return _ofo_insert_new(ofo, i + 1, sl, mb, num);
}

static inline void
_ofo_compact(struct ofo *ofo)
{
	uint32_t i, j, n, ro;
	struct ofodb *db;

	for (i = 0; i < ofo->nb_elem; i = j) {

		for (j = i + 1; j != ofo->nb_elem; j++) {

			/* no intersection */
			ro = ofo->db[j].sl.seq - ofo->db[i].sl.seq;
			if (ro > ofo->db[i].sl.len)
				break;

			db = ofo->db + j;
			n = _ofo_insert_right(ofo, i, &db->sl, db->obj,
				db->nb_elem);
			if (n < db->nb_elem) {
				db->nb_elem -= n;
				break;
			}
		}

		n = j - i - 1;
		if (n != 0)
			_ofo_remove(ofo, i + 1, n);
	}
}

static inline uint32_t
_ofodb_enqueue(struct rte_ring *r, const struct ofodb *db, union seqlen *sl)
{
	uint32_t n, num;

	num = db->nb_elem;
	sl->raw = db->sl.raw;
	n = rte_ring_enqueue_burst(r, (void * const *)db->obj, num);

	sl->len -= tcp_mbuf_seq_free(db->obj + n, num - n);
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
