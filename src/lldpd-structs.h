/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#ifndef _LLDPD_STRUCTS_H
#define _LLDPD_STRUCTS_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#ifndef INCLUDE_LINUX_IF_H
#  include <net/if.h>
#else
#  include <arpa/inet.h>
#  include <linux/if.h>
#endif
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/queue.h>

#include "compat/compat.h"
#include "marshal.h"
#include "lldp-const.h"

#ifdef ENABLE_DOT1
struct lldpd_ppvid {
	TAILQ_ENTRY(lldpd_ppvid) p_entries;
	u_int8_t		p_cap_status;
	u_int16_t		p_ppvid;
};
MARSHAL_BEGIN(lldpd_ppvid)
MARSHAL_TQE(lldpd_ppvid, p_entries)
MARSHAL_END;

struct lldpd_vlan {
	TAILQ_ENTRY(lldpd_vlan)  v_entries;
	char			*v_name;
	u_int16_t		 v_vid;
};
MARSHAL_BEGIN(lldpd_vlan)
MARSHAL_TQE(lldpd_vlan, v_entries)
MARSHAL_STR(lldpd_vlan, v_name)
MARSHAL_END;

struct lldpd_pi {
	TAILQ_ENTRY(lldpd_pi)  p_entries;
	char			*p_pi;
	int			 p_pi_len;
};
MARSHAL_BEGIN(lldpd_pi)
MARSHAL_TQE(lldpd_pi, p_entries)
MARSHAL_FSTR(lldpd_pi, p_pi, p_pi_len)
MARSHAL_END;
#endif

#ifdef ENABLE_LLDPMED
struct lldpd_med_policy {
	u_int8_t		 index; /* Not used. */
	u_int8_t		 type;
	u_int8_t		 unknown;
	u_int8_t		 tagged;
	u_int16_t		 vid;
	u_int8_t		 priority;
	u_int8_t		 dscp;
};
MARSHAL(lldpd_med_policy);

struct lldpd_med_loc {
	u_int8_t		 index; /* Not used. */
	u_int8_t		 format;
	char			*data;
	int			 data_len;
};
MARSHAL_BEGIN(lldpd_med_loc)
MARSHAL_FSTR(lldpd_med_loc, data, data_len)
MARSHAL_END;

struct lldpd_med_power {
	u_int8_t		 devicetype; /* PD or PSE */
	u_int8_t		 source;
	u_int8_t		 priority;
	u_int16_t		 val;
};
MARSHAL(lldpd_med_power);
#endif

#ifdef ENABLE_DOT3
struct lldpd_dot3_macphy {
	u_int8_t		 autoneg_support;
	u_int8_t		 autoneg_enabled;
	u_int16_t		 autoneg_advertised;
	u_int16_t		 mau_type;
};

struct lldpd_dot3_power {
	u_int8_t		devicetype;
	u_int8_t		supported;
	u_int8_t		enabled;
	u_int8_t		paircontrol;
	u_int8_t		pairs;
	u_int8_t		class;
	u_int8_t		powertype; /* If set to LLDP_DOT3_POWER_8023AT_OFF,
					      following fields have no meaning */
	u_int8_t		source;
	u_int8_t		priority;
	u_int16_t		requested;
	u_int16_t		allocated;
};
MARSHAL(lldpd_dot3_power);
#endif

enum {
	LLDPD_AF_UNSPEC = 0,
	LLDPD_AF_IPV4,
	LLDPD_AF_IPV6,
	LLDPD_AF_LAST
};

inline static int
lldpd_af(int af)
{
	switch (af) {
	case LLDPD_AF_IPV4: return AF_INET;
	case LLDPD_AF_IPV6: return AF_INET6;
	case LLDPD_AF_LAST: return AF_MAX;
	default: return AF_UNSPEC;
	}
}

#define LLDPD_MGMT_MAXADDRSIZE	16 /* sizeof(struct in6_addr) */
struct lldpd_mgmt {
	TAILQ_ENTRY(lldpd_mgmt) m_entries;
	int				m_family;
	union {
		struct in_addr		inet;
		struct in6_addr		inet6;
		u_int8_t 			octets[LLDPD_MGMT_MAXADDRSIZE];
	} m_addr;
	size_t 			m_addrsize;
	u_int32_t		m_iface;
};
MARSHAL_BEGIN(lldpd_mgmt)
MARSHAL_TQE(lldpd_mgmt, m_entries)
MARSHAL_END;

struct lldpd_chassis {
	TAILQ_ENTRY(lldpd_chassis) c_entries;
	u_int16_t		 c_refcount; /* Reference count by ports */
	u_int16_t		 c_index;    /* Monotonic index */
	u_int8_t		 c_protocol; /* Protocol used to get this chassis */
	u_int8_t	 	 c_id_subtype;
	char			*c_id;
	int			 c_id_len;
	char			*c_name;
	char			*c_descr;

	u_int16_t		 c_cap_available;
	u_int16_t		 c_cap_enabled;

	u_int16_t		 c_ttl;

	TAILQ_HEAD(, lldpd_mgmt) c_mgmt;

#ifdef ENABLE_LLDPMED
	u_int16_t		 c_med_cap_available;
	u_int8_t		 c_med_type;
	char			*c_med_hw;
	char			*c_med_fw;
	char			*c_med_sw;
	char			*c_med_sn;
	char			*c_med_manuf;
	char			*c_med_model;
	char			*c_med_asset;
#endif

};
/* WARNING: any change to this structure should also be reflected into
   `lldpd_copy_chassis()` which is not using marshaling. */
MARSHAL_BEGIN(lldpd_chassis)
MARSHAL_TQE(lldpd_chassis, c_entries)
MARSHAL_FSTR(lldpd_chassis, c_id, c_id_len)
MARSHAL_STR(lldpd_chassis, c_name)
MARSHAL_STR(lldpd_chassis, c_descr)
MARSHAL_SUBTQ(lldpd_chassis, lldpd_mgmt, c_mgmt)
#ifdef ENABLE_LLDPMED
MARSHAL_STR(lldpd_chassis, c_med_hw)
MARSHAL_STR(lldpd_chassis, c_med_fw)
MARSHAL_STR(lldpd_chassis, c_med_sw)
MARSHAL_STR(lldpd_chassis, c_med_sn)
MARSHAL_STR(lldpd_chassis, c_med_manuf)
MARSHAL_STR(lldpd_chassis, c_med_model)
MARSHAL_STR(lldpd_chassis, c_med_asset)
#endif
MARSHAL_END;


struct lldpd_port {
	TAILQ_ENTRY(lldpd_port)	 p_entries;
	struct lldpd_chassis	*p_chassis;    /* Attached chassis */
	time_t			 p_lastchange; /* Time of last change of values */
	time_t			 p_lastupdate; /* Time of last update received */
	struct lldpd_frame	*p_lastframe;  /* Frame received during last update */
	u_int8_t		 p_protocol;   /* Protocol used to get this port */
	u_int8_t		 p_id_subtype;
	char			*p_id;
	int			 p_id_len;
	char			*p_descr;
	u_int16_t		 p_mfs;
	u_int8_t		 p_hidden_in:1; /* Considered as hidden for reception */
	u_int8_t		 p_hidden_out:2; /* Considered as hidden for emission */

#ifdef ENABLE_DOT3
	/* Dot3 stuff */
	u_int32_t		 p_aggregid;
	struct lldpd_dot3_macphy p_macphy;
	struct lldpd_dot3_power	 p_power;
#endif

#ifdef ENABLE_LLDPMED
	u_int16_t		 p_med_cap_enabled;
	struct lldpd_med_policy	 p_med_policy[LLDP_MED_APPTYPE_LAST];
	struct lldpd_med_loc	 p_med_location[LLDP_MED_LOCFORMAT_LAST];
	struct lldpd_med_power	 p_med_power;
#endif

#ifdef ENABLE_DOT1
	u_int16_t		 p_pvid;
	TAILQ_HEAD(, lldpd_vlan) p_vlans;
	TAILQ_HEAD(, lldpd_ppvid) p_ppvids;
	TAILQ_HEAD(, lldpd_pi)	  p_pids;
#endif
};
MARSHAL_BEGIN(lldpd_port)
MARSHAL_TQE(lldpd_port, p_entries)
MARSHAL_POINTER(lldpd_port, lldpd_chassis, p_chassis)
MARSHAL_IGNORE(lldpd_port, p_lastframe)
MARSHAL_FSTR(lldpd_port, p_id, p_id_len)
MARSHAL_STR(lldpd_port, p_descr)
#ifdef ENABLE_LLDPMED
MARSHAL_SUBSTRUCT(lldpd_port, lldpd_med_loc, p_med_location[0])
MARSHAL_SUBSTRUCT(lldpd_port, lldpd_med_loc, p_med_location[1])
MARSHAL_SUBSTRUCT(lldpd_port, lldpd_med_loc, p_med_location[2])
#endif
#ifdef ENABLE_DOT1
MARSHAL_SUBTQ(lldpd_port, lldpd_vlan, p_vlans)
MARSHAL_SUBTQ(lldpd_port, lldpd_ppvid, p_ppvids)
MARSHAL_SUBTQ(lldpd_port, lldpd_pi, p_pids)
#endif
MARSHAL_END;

/* Used to modify some port related settings */
struct lldpd_port_set {
	char *ifname;
#ifdef ENABLE_LLDPMED
	struct lldpd_med_policy *med_policy;
	struct lldpd_med_loc    *med_location;
	struct lldpd_med_power  *med_power;
#endif
#ifdef ENABLE_DOT3
	struct lldpd_dot3_power *dot3_power;
#endif
};
MARSHAL_BEGIN(lldpd_port_set)
MARSHAL_STR(lldpd_port_set, ifname)
#ifdef ENABLE_LLDPMED
MARSHAL_POINTER(lldpd_port_set, lldpd_med_policy, med_policy)
MARSHAL_POINTER(lldpd_port_set, lldpd_med_loc,    med_location)
MARSHAL_POINTER(lldpd_port_set, lldpd_med_power,  med_power)
#endif
#ifdef ENABLE_DOT3
MARSHAL_POINTER(lldpd_port_set, lldpd_dot3_power, dot3_power)
#endif
MARSHAL_END;

struct lldpd_frame {
	int size;
	unsigned char frame[1];
};

struct lldpd_hardware;
struct lldpd;
struct lldpd_ops {
	int(*send)(struct lldpd *,
		   struct lldpd_hardware*,
		   char *, size_t); /* Function to send a frame */
	int(*recv)(struct lldpd *,
		   struct lldpd_hardware*,
		   int, char *, size_t); /* Function to receive a frame */
	int(*cleanup)(struct lldpd *, struct lldpd_hardware *); /* Cleanup function. */
};

/* An interface is uniquely identified by h_ifindex, h_ifname and h_ops. This
 * means if an interface becomes enslaved, it will be considered as a new
 * interface. The same applies for renaming and we include the index in case of
 * renaming to an existing interface. */
struct lldpd_hardware {
	TAILQ_ENTRY(lldpd_hardware)	 h_entries;

	struct lldpd		*h_cfg;	    /* Pointer to main configuration */
	void			*h_recv;    /* FD for reception */
	int			 h_sendfd;  /* FD for sending, only used by h_ops */
	struct lldpd_ops	*h_ops;	    /* Hardware-dependent functions */
	void			*h_data;    /* Hardware-dependent data */

	int			 h_mtu;
	int			 h_flags; /* Packets will be sent only
					     if IFF_RUNNING. Will be
					     removed if this is left
					     to 0. */
	int			 h_ifindex; /* Interface index, used by SNMP */
	char			 h_ifname[IFNAMSIZ]; /* Should be unique */
	u_int8_t		 h_lladdr[ETHER_ADDR_LEN];

	u_int64_t		 h_tx_cnt;
	u_int64_t		 h_rx_cnt;
	u_int64_t		 h_rx_discarded_cnt;
	u_int64_t		 h_rx_ageout_cnt;
	u_int64_t		 h_rx_unrecognized_cnt;

	struct lldpd_port	 h_lport;  /* Port attached to this hardware port */
	TAILQ_HEAD(, lldpd_port) h_rports; /* Remote ports */
};
MARSHAL_BEGIN(lldpd_hardware)
MARSHAL_IGNORE(lldpd_hardware, h_entries.tqe_next)
MARSHAL_IGNORE(lldpd_hardware, h_entries.tqe_prev)
MARSHAL_IGNORE(lldpd_hardware, h_ops)
MARSHAL_IGNORE(lldpd_hardware, h_data)
MARSHAL_IGNORE(lldpd_hardware, h_cfg)
MARSHAL_SUBSTRUCT(lldpd_hardware, lldpd_port, h_lport)
MARSHAL_SUBTQ(lldpd_hardware, lldpd_port, h_rports)
MARSHAL_END;

struct lldpd_interface {
	TAILQ_ENTRY(lldpd_interface) next;
	char			*name;
};
MARSHAL_BEGIN(lldpd_interface)
MARSHAL_TQE(lldpd_interface, next)
MARSHAL_STR(lldpd_interface, name)
MARSHAL_END;
TAILQ_HEAD(lldpd_interface_list, lldpd_interface);
MARSHAL_TQ(lldpd_interface_list, lldpd_interface);

/* Cleanup functions */
void	 lldpd_chassis_mgmt_cleanup(struct lldpd_chassis *);
void	 lldpd_chassis_cleanup(struct lldpd_chassis *, int);
void	 lldpd_remote_cleanup(struct lldpd_hardware *, int);
void	 lldpd_port_cleanup(struct lldpd_port *, int);
#ifdef ENABLE_DOT1
void	 lldpd_ppvid_cleanup(struct lldpd_port *);
void	 lldpd_vlan_cleanup(struct lldpd_port *);
void	 lldpd_pi_cleanup(struct lldpd_port *);
#endif

#endif
