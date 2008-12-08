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

#ifndef _LLDP_H
#define _LLDP_H

/* Should be defined in net/ethertypes.h */
#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP	0x88cc
#endif

#define LLDP_MULTICAST_ADDR	{						\
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e					\
}

#define LLDP_TLV_HEAD(type, len) htons(((type) << 9) | (len))
struct lldp_tlv_head {
	u_int16_t	type_len;
} __attribute__ ((__packed__));

enum {
	LLDP_TLV_END			= 0,
	LLDP_TLV_CHASSIS_ID		= 1,
	LLDP_TLV_PORT_ID		= 2,
	LLDP_TLV_TTL			= 3,
	LLDP_TLV_PORT_DESCR		= 4,
	LLDP_TLV_SYSTEM_NAME		= 5,
	LLDP_TLV_SYSTEM_DESCR		= 6,
	LLDP_TLV_SYSTEM_CAP		= 7,
	LLDP_TLV_MGMT_ADDR		= 8,
	LLDP_TLV_ORG			= 127
};

#define LLDP_TLV_ORG_DOT1 {0x00, 0x80, 0xc2}
#define LLDP_TLV_ORG_DOT3 {0x00, 0x12, 0x0f}
#define LLDP_TLV_ORG_MED {0x00, 0x12, 0xbb}

enum {
	LLDP_TLV_DOT1_PVID		= 1,
	LLDP_TLV_DOT1_PPVID		= 2,
	LLDP_TLV_DOT1_VLANNAME		= 3,
	LLDP_TLV_DOT1_PI		= 4
};

enum {
	LLDP_TLV_DOT3_MAC		= 1,
	LLDP_TLV_DOT3_POWER		= 2,
	LLDP_TLV_DOT3_LA		= 3,
	LLDP_TLV_DOT3_MFS		= 4
};

/* Chassis ID or Port ID */
struct lldp_id {
	struct lldp_tlv_head	 tlv_head;	
	u_int8_t	 	 tlv_id_subtype;
} __attribute__ ((__packed__));

enum {
	LLDP_CHASSISID_SUBTYPE_CHASSIS	= 1,
	LLDP_CHASSISID_SUBTYPE_IFALIAS	= 2,
	LLDP_CHASSISID_SUBTYPE_PORT	= 3,
	LLDP_CHASSISID_SUBTYPE_LLADDR	= 4,
	LLDP_CHASSISID_SUBTYPE_ADDR	= 5,
	LLDP_CHASSISID_SUBTYPE_IFNAME	= 6,
	LLDP_CHASSISID_SUBTYPE_LOCAL	= 7
};

enum {
	LLDP_PORTID_SUBTYPE_IFALIAS	= 1,
	LLDP_PORTID_SUBTYPE_PORT	= 2,
	LLDP_PORTID_SUBTYPE_LLADDR	= 3,
	LLDP_PORTID_SUBTYPE_ADDR	= 4,
	LLDP_PORTID_SUBTYPE_IFNAME	= 5,
	LLDP_PORTID_SUBTYPE_AGENTCID	= 6,
	LLDP_PORTID_SUBTYPE_LOCAL	= 7
};

struct lldp_ttl {
	struct lldp_tlv_head	 tlv_head;	
	u_int16_t		 tlv_ttl;
} __attribute__ ((__packed__));

struct lldp_string {
	struct lldp_tlv_head	 tlv_head;
} __attribute__ ((__packed__));

struct lldp_cap {
	struct lldp_tlv_head	 tlv_head;
	u_int16_t		 tlv_cap_available;
	u_int16_t		 tlv_cap_enabled;
} __attribute__ ((__packed__));

/* Operational MAU Type field, from RFC 3636 */
#define LLDP_DOT3_MAU_AUI 1
#define LLDP_DOT3_MAU_10BASE5 2
#define LLDP_DOT3_MAU_FOIRL 3
#define LLDP_DOT3_MAU_10BASE2 4
#define LLDP_DOT3_MAU_10BASET 5
#define LLDP_DOT3_MAU_10BASEFP 6
#define LLDP_DOT3_MAU_10BASEFB 7
#define LLDP_DOT3_MAU_10BASEFL 8
#define LLDP_DOT3_MAU_10BROAD36 9
#define LLDP_DOT3_MAU_10BASETHD 10
#define LLDP_DOT3_MAU_10BASETFD 11
#define LLDP_DOT3_MAU_10BASEFLHD 12
#define LLDP_DOT3_MAU_10BASEFLDF 13
#define LLDP_DOT3_MAU_10BASET4 14
#define LLDP_DOT3_MAU_100BASETXHD 15
#define LLDP_DOT3_MAU_100BASETXFD 16
#define LLDP_DOT3_MAU_100BASEFXHD 17
#define LLDP_DOT3_MAU_100BASEFXFD 18
#define LLDP_DOT3_MAU_100BASET2HD 19
#define LLDP_DOT3_MAU_100BASET2DF 20
#define LLDP_DOT3_MAU_1000BASEXHD 21
#define LLDP_DOT3_MAU_1000BASEXFD 22
#define LLDP_DOT3_MAU_1000BASELXHD 23
#define LLDP_DOT3_MAU_1000BASELXFD 24
#define LLDP_DOT3_MAU_1000BASESXHD 25
#define LLDP_DOT3_MAU_1000BASESXFD 26
#define LLDP_DOT3_MAU_1000BASECXHD 27
#define LLDP_DOT3_MAU_1000BASECXFD 28
#define LLDP_DOT3_MAU_1000BASETHD 29
#define LLDP_DOT3_MAU_1000BASETFD 30
#define LLDP_DOT3_MAU_10GIGBASEX 31
#define LLDP_DOT3_MAU_10GIGBASELX4 32
#define LLDP_DOT3_MAU_10GIGBASER 33
#define LLDP_DOT3_MAU_10GIGBASEER 34
#define LLDP_DOT3_MAU_10GIGBASELR 35
#define LLDP_DOT3_MAU_10GIGBASESR 36
#define LLDP_DOT3_MAU_10GIGBASEW 37
#define LLDP_DOT3_MAU_10GIGBASEEW 38
#define LLDP_DOT3_MAU_10GIGBASELW 39
#define LLDP_DOT3_MAU_10GIGBASESW 40

/* PMD Auto-Negotiation Advertised Capability field, from RFC 3636 */
#define LLDP_DOT3_LINK_AUTONEG_OTHER		0x8000
#define LLDP_DOT3_LINK_AUTONEG_10BASE_T		0x4000
#define LLDP_DOT3_LINK_AUTONEG_10BASET_FD	0x2000
#define LLDP_DOT3_LINK_AUTONEG_100BASE_T4	0x1000
#define LLDP_DOT3_LINK_AUTONEG_100BASE_TX	0x0800
#define LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD	0x0400
#define LLDP_DOT3_LINK_AUTONEG_100BASE_T2	0x0200
#define LLDP_DOT3_LINK_AUTONEG_100BASE_T2FD	0x0100
#define LLDP_DOT3_LINK_AUTONEG_FDX_PAUSE	0x0080
#define LLDP_DOT3_LINK_AUTONEG_FDX_APAUSE	0x0040
#define LLDP_DOT3_LINK_AUTONEG_FDX_SPAUSE	0x0020
#define LLDP_DOT3_LINK_AUTONEG_FDX_BPAUSE	0x0010
#define LLDP_DOT3_LINK_AUTONEG_1000BASE_X	0x0008
#define LLDP_DOT3_LINK_AUTONEG_1000BASE_XFD	0x0004
#define LLDP_DOT3_LINK_AUTONEG_1000BASE_T	0x0002
#define LLDP_DOT3_LINK_AUTONEG_1000BASE_TFD	0x0001

#define LLDP_CAP_OTHER		0x01
#define LLDP_CAP_REPEATER	0x02
#define LLDP_CAP_BRIDGE		0x04
#define LLDP_CAP_WLAN		0x08
#define LLDP_CAP_ROUTER		0x10
#define LLDP_CAP_TELEPHONE	0x20
#define LLDP_CAP_DOCSIS		0x40
#define LLDP_CAP_STATION	0x80

/* see http://www.iana.org/assignments/address-family-numbers */
enum {
	LLDP_MGMT_ADDR_IP4	= 1,
	LLDP_MGMT_ADDR_IP6	= 2
};

enum {
	LLDP_MGMT_IFACE_UNKNOWN	= 1,
	LLDP_MGMT_IFACE_IFINDEX	= 2,
	LLDP_MGMT_IFACE_SYSPORT	= 3
};

/* Supports only IPv4 */
struct lldp_mgmt {
	struct lldp_tlv_head	 tlv_head;
	u_int8_t		 mgmt_len;
	u_int8_t		 mgmt_subtype; /* Should be 1 */
	struct in_addr		 mgmt_addr;
	u_int8_t		 mgmt_iface_subtype;
	u_int32_t		 mgmt_iface_id;
	u_int8_t		 mgmt_oid_len;
	u_int8_t		 mgmt_oid[0];
} __attribute__ ((__packed__));

struct lldp_org {
	struct lldp_tlv_head	 tlv_head;
	u_int8_t		 tlv_org_id[3];
	u_int8_t		 tlv_org_subtype;
} __attribute__ ((__packed__));

struct lldp_vlan {
	struct lldp_tlv_head	 tlv_head;
	u_int8_t		 tlv_org_id[3];
	u_int8_t		 tlv_org_subtype;
	u_int16_t		 vid;
	u_int8_t		 len;
} __attribute__ ((__packed__));

struct lldp_aggreg {
	struct lldp_tlv_head	 tlv_head;
	u_int8_t		 tlv_org_id[3];
	u_int8_t		 tlv_org_subtype;
	u_int8_t		 status;
	u_int32_t		 id;
} __attribute__ ((__packed__));

struct lldp_macphy {
	struct lldp_tlv_head	 tlv_head;
	u_int8_t		 tlv_org_id[3];
	u_int8_t		 tlv_org_subtype;
	u_int8_t		 autoneg;
	u_int16_t		 advertised;
	u_int16_t		 mau;
} __attribute__ ((__packed__));

struct lldp_end {
	struct lldp_tlv_head	 tlv_head;
} __attribute__ ((__packed__));

#ifdef ENABLE_LLDPMED
enum {
	LLDP_TLV_MED_CAP	= 1,
	LLDP_TLV_MED_POLICY	= 2,
	LLDP_TLV_MED_LOCATION	= 3,
	LLDP_TLV_MED_MDI	= 4,
	LLDP_TLV_MED_IV_HW	= 5,
	LLDP_TLV_MED_IV_FW	= 6,
	LLDP_TLV_MED_IV_SW	= 7,
	LLDP_TLV_MED_IV_SN	= 8,
	LLDP_TLV_MED_IV_MANUF	= 9,
	LLDP_TLV_MED_IV_MODEL	= 10,
	LLDP_TLV_MED_IV_ASSET	= 11
};

#define LLDPMED_CLASS_I 1
#define LLDPMED_CLASS_II 2
#define LLDPMED_CLASS_III 3
#define LLDPMED_NETWORK_DEVICE 4

#define LLDPMED_APPTYPE_VOICE 1
#define LLDPMED_APPTYPE_VOICESIGNAL 2
#define LLDPMED_APPTYPE_GUESTVOICE 3
#define LLDPMED_APPTYPE_GUESTVOICESIGNAL 4
#define LLDPMED_APPTYPE_SOFTPHONEVOICE 5
#define LLDPMED_APPTYPE_VIDEOCONFERENCE 6
#define LLDPMED_APPTYPE_VIDEOSTREAM 7
#define LLDPMED_APPTYPE_VIDEOSIGNAL 8
#define LLDPMED_APPTYPE_LAST LLDPMED_APPTYPE_VIDEOSIGNAL

#define LLDPMED_LOCFORMAT_COORD 1
#define LLDPMED_LOCFORMAT_CIVIC 2
#define LLDPMED_LOCFORMAT_ELIN 3
#define LLDPMED_LOCFORMAT_LAST LLDPMED_LOCFORMAT_ELIN

#define LLDPMED_POW_TYPE_PSE 1
#define LLDPMED_POW_TYPE_PD 2
#define LLDPMED_POW_TYPE_RESERVED 3

#define LLDPMED_POW_SOURCE_UNKNOWN 1
#define LLDPMED_POW_SOURCE_PRIMARY 2
#define LLDPMED_POW_SOURCE_BACKUP 3
#define LLDPMED_POW_SOURCE_RESERVED 4
#define LLDPMED_POW_SOURCE_PSE 5
#define LLDPMED_POW_SOURCE_LOCAL 6
#define LLDPMED_POW_SOURCE_BOTH 7

#define LLDPMED_POW_PRIO_UNKNOWN 1
#define LLDPMED_POW_PRIO_CRITICAL 2
#define LLDPMED_POW_PRIO_HIGH 3
#define LLDPMED_POW_PRIO_LOW 4

#define LLDPMED_CAP_CAP 0x01
#define LLDPMED_CAP_POLICY 0x02
#define LLDPMED_CAP_LOCATION 0x04
#define LLDPMED_CAP_MDI_PSE 0x08
#define LLDPMED_CAP_MDI_PD 0x10
#define LLDPMED_CAP_IV 0x20

struct lldpmed_cap {
	struct lldp_tlv_head	 tlv_head;
	u_int8_t		 tlv_org_id[3];
	u_int8_t		 tlv_org_subtype;
	u_int16_t		 tlv_cap;
	u_int8_t		 tlv_type;
} __attribute__ ((__packed__));
#endif /* ENABLE_LLDPMED */


#endif /* _LLDP_H */
