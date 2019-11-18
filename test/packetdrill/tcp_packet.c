/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * Implementation for module for formatting TCP packets.
 */

#include "tcp_packet.h"

#include "ip_packet.h"
#include "tcp.h"

/* The full list of valid TCP bit flag characters */
static const char valid_tcp_flags[] = "FSRP.EWCU";

/* Are all the TCP flags in the given string valid? */
static bool is_tcp_flags_spec_valid(const char *flags, char **error)
{
	const char *s;

	for (s = flags; *s != '\0'; ++s) {
		if (!strchr(valid_tcp_flags, *s)) {
			asprintf(error, "Invalid TCP flag: '%c'", *s);
			return false;
		}
	}
	return true;
}

/* Parse tcpdump-style ASCII representation of flags to look for a flag */
static inline int is_tcp_flag_set(char flag, const char *flags)
{
	return (strchr(flags, flag) != NULL) ? 1 : 0;
}

struct packet *new_tcp_packet(int address_family,
			       enum direction_t direction,
			       struct ip_info ip_info,
			       u16 src_port,
			       u16 dst_port,
			       const char *flags,
			       u32 start_sequence,
			       u16 tcp_payload_bytes,
			       u32 ack_sequence,
			       s32 window,
			       u16 urg_ptr,
			       const struct tcp_options *tcp_options,
			       char **error)
{
	struct packet *packet = NULL;  /* the newly-allocated result packet */
	struct header *tcp_header = NULL;  /* the TCP header info */
	/* Calculate lengths in bytes of all sections of the packet */
	const int ip_option_bytes = 0;
	const int tcp_option_bytes = tcp_options ? tcp_options->length : 0;
	const int ip_header_bytes = (ip_header_min_len(address_family) +
				     ip_option_bytes);
	const int tcp_header_bytes = sizeof(struct tcp) + tcp_option_bytes;
	const int ip_bytes =
		 ip_header_bytes + tcp_header_bytes + tcp_payload_bytes;

	/* Sanity-check all the various lengths */
	if (ip_option_bytes & 0x3) {
		asprintf(error, "IP options are not padded correctly "
			 "to ensure IP header is a multiple of 4 bytes: "
			 "%d excess bytes", ip_option_bytes & 0x3);
		return NULL;
	}
	if (tcp_option_bytes & 0x3) {
		asprintf(error,
			 "TCP options are not padded correctly "
			 "to ensure TCP header is a multiple of 4 bytes: "
			 "%d excess bytes", tcp_option_bytes & 0x3);
		return NULL;
	}
	assert((tcp_header_bytes & 0x3) == 0);
	assert((ip_header_bytes & 0x3) == 0);

	if (tcp_header_bytes > MAX_TCP_HEADER_BYTES) {
		asprintf(error, "TCP header too large");
		return NULL;
	}

	if (ip_bytes > MAX_TCP_DATAGRAM_BYTES) {
		asprintf(error, "TCP segment too large");
		return NULL;
	}

	if (!is_tcp_flags_spec_valid(flags, error))
		return NULL;

	/* Allocate and zero out a packet object of the desired size */
	packet = packet_new(ip_bytes);
	memset(packet->buffer, 0, ip_bytes);

	packet->direction = direction;
	packet->flags = 0;
	packet->tos_chk = ip_info.tos.check;

	/* Set IP header fields */
	set_packet_ip_header(packet, address_family, ip_bytes,
			     ip_info.tos.value, ip_info.flow_label,
			     ip_info.ttl, IPPROTO_TCP);

	tcp_header = packet_append_header(packet, HEADER_TCP, tcp_header_bytes);
	tcp_header->total_bytes = tcp_header_bytes + tcp_payload_bytes;

	/* Find the start of TCP sections of the packet */
	packet->tcp = (struct tcp *) (ip_start(packet) + ip_header_bytes);
	u8 *tcp_option_start = (u8 *) (packet->tcp + 1);

	/* Set TCP header fields */
	packet->tcp->src_port = htons(src_port);
	packet->tcp->dst_port = htons(dst_port);
	packet->tcp->seq = htonl(start_sequence);
	packet->tcp->ack_seq = htonl(ack_sequence);
	packet->tcp->doff = tcp_header_bytes / 4;
	if (window == -1) {
		if (direction == DIRECTION_INBOUND) {
			asprintf(error, "window must be specified"
				 " for inbound packets");
			return NULL;
		}
		packet->tcp->window = 0;
		packet->flags |= FLAG_WIN_NOCHECK;
	} else {
		packet->tcp->window = htons(window);
	}
	packet->tcp->check = 0;
	packet->tcp->urg_ptr = htons(urg_ptr);
	packet->tcp->fin = is_tcp_flag_set('F', flags);
	packet->tcp->syn = is_tcp_flag_set('S', flags);
	packet->tcp->rst = is_tcp_flag_set('R', flags);
	packet->tcp->psh = is_tcp_flag_set('P', flags);
	packet->tcp->ack = is_tcp_flag_set('.', flags);
	packet->tcp->urg = is_tcp_flag_set('U', flags);
	packet->tcp->ece = is_tcp_flag_set('E', flags);
	packet->tcp->cwr = is_tcp_flag_set('W', flags);

	if (tcp_options == NULL) {
		packet->flags |= FLAG_OPTIONS_NOCHECK;
	} else if (tcp_options->length > 0) {
		/* Copy TCP options into packet */
		memcpy(tcp_option_start, tcp_options->data,
		       tcp_options->length);
	}

	packet->ip_bytes = ip_bytes;
	return packet;
}
