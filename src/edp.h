/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _EDP_H
#define _EDP_H

#define EDP_MULTICAST_ADDR	{						\
	0x00, 0xe0, 0x2b, 0x00, 0x00, 0x00					\
}
#define LLC_ORG_EXTREME { 0x00, 0xe0, 0x2b }
#define LLC_PID_EDP 0x00bb

#define EDP_TLV_MARKER	 0x99

#include "llc.h"

struct edp_header {
	u_int8_t        version;
	u_int8_t	reserved;
	u_int16_t	len;
	u_int16_t	checksum;
	u_int16_t	sequence;
	u_int16_t	idtype;	/* Should be 0 for MAC */
	u_int8_t	mac[ETH_ALEN];
} __attribute__ ((__packed__));

struct edp_tlv_head {
	u_int8_t	 tlv_marker; /* 0x99 */
	u_int8_t	 tlv_type;
	u_int16_t	 tlv_len;
} __attribute__ ((__packed__));

enum {
	EDP_TLV_NULL			= 0,
	EDP_TLV_DISPLAY			= 1,
	EDP_TLV_INFO			= 2,
	EDP_TLV_VLAN			= 5,
	EDP_TLV_ESRP			= 8,
};

struct edp_tlv_info {
	struct edp_tlv_head head;
	u_int16_t	slot;
	u_int16_t	port;
	u_int16_t	vchassis;
	u_int8_t	reserved[6];
	u_int8_t	version[4];
	u_int8_t	connections[16];
} __attribute__ ((__packed__));

#define EDP_VLAN_HAS_IP (1 << 8)
struct edp_tlv_vlan {
	struct edp_tlv_head head;
	u_int8_t	flags;
	u_int8_t	reserved1[1];
	u_int16_t	vid;
	u_int8_t	reserved2[4];
	struct in_addr	ip;
} __attribute__ ((__packed__));

#endif /* _EDP_H */
