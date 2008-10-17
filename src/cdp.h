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

#ifndef _CDP_H
#define _CDP_H

#define CDP_MULTICAST_ADDR	{						\
	0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc					\
}
#define LLC_ORG_CISCO { 0x00, 0x00, 0x0c }
#define LLC_PID_CDP 0x2000
/* Other protocols */
#define LLC_PID_DRIP 0x102
#define LLC_PID_PAGP 0x104
#define LLC_PID_PVSTP 0x10b
#define LLC_PID_UDLD 0x111
#define LLC_PID_VTP 0x2003
#define LLC_PID_DTP 0x2004
#define LLC_PID_STP 0x200a

struct cdp_header {
	u_int8_t        version;
	u_int8_t	  ttl;
	u_int16_t	  checksum;
} __attribute__ ((__packed__));

struct cdp_tlv_head {
	u_int16_t	 tlv_type;
	u_int16_t	 tlv_len;
} __attribute__ ((__packed__));

enum {
	CDP_TLV_CHASSIS			= 1,
	CDP_TLV_ADDRESSES		= 2,
	CDP_TLV_PORT			= 3,
	CDP_TLV_CAPABILITIES		= 4,
	CDP_TLV_SOFTWARE		= 5,
	CDP_TLV_PLATFORM		= 6
};

struct cdp_tlv_address_head {
	struct cdp_tlv_head head;
	u_int32_t nb;
} __attribute__ ((__packed__));

struct cdp_tlv_address_one {
	u_int8_t  ptype;	/* Should be 1 */
	u_int8_t  plen;		/* Should be 1 */
#define CDP_ADDRESS_PROTO_IP 0xcc
	u_int8_t  proto;	/* 0xcc for IP */
	u_int16_t alen;		/* Should be 4 */
	struct in_addr addr;
} __attribute__ ((__packed__));

struct cdp_tlv_capabilities {
	struct cdp_tlv_head head;
	u_int32_t cap;
} __attribute__ ((__packed__));

#define CDP_CAP_ROUTER 1
#define CDP_CAP_BRIDGE 8

#endif /* _CDP_H */

