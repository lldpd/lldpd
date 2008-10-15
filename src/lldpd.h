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

#ifndef _LLDPD_H
#define _LLDPD_H

#if HAVE_CONFIG_H
 #include <config.h>
#endif

#define _GNU_SOURCE 1
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef INCLUDE_LINUX_IF_H
#include <net/if.h>
#else
#include <arpa/inet.h>
#include <linux/if.h>
#endif
#include <net/ethernet.h>
#include <netinet/in.h>

#include "compat.h"
#include "lldp.h"
#include "cdp.h"
#include "sonmp.h"
#include "edp.h"

#define LLDPD_TTL		120
#define LLDPD_TX_DELAY		30
#define LLDPD_TX_MSGDELAY	1
#define LLDPD_CTL_SOCKET	"/var/run/lldpd.socket"
#define LLDPD_PID_FILE		"/var/run/lldpd.pid"

#define UNIX_PATH_MAX	108

#define USING_AGENTX_SUBAGENT_MODULE 1

struct lldpd_vlan {
	TAILQ_ENTRY(lldpd_vlan)  v_entries;
	char			*v_name;
	u_int16_t		 v_vid;
};
#define STRUCT_LLDPD_VLAN "Lsw"

struct lldpd_chassis {
	u_int8_t	 	 c_id_subtype;
	char			*c_id;
	int			 c_id_len;
	char			*c_name;
	char			*c_descr;

	u_int16_t		 c_cap_available;
	u_int16_t		 c_cap_enabled;

	u_int16_t		 c_ttl;

	struct in_addr		 c_mgmt;
	u_int32_t		 c_mgmt_if;
};
#define STRUCT_LLDPD_CHASSIS "bCsswwwll"

struct lldpd_port {
	u_int8_t		 p_id_subtype;
	char			*p_id;
	int			 p_id_len;
	char			*p_descr;

	/* Dot3 stuff */
	u_int32_t		 p_aggregid;
	u_int8_t		 p_autoneg_support;
	u_int8_t		 p_autoneg_enabled;
	u_int16_t		 p_autoneg_advertised;
	u_int16_t		 p_mau_type;

	TAILQ_HEAD(, lldpd_vlan) p_vlans;
};
#define STRUCT_LLDPD_PORT "bCslbbwwPP"

struct lldpd_frame {
	int size;
	unsigned char frame[];
};

struct lldpd_hardware {
	TAILQ_ENTRY(lldpd_hardware)	 h_entries;

#define INTERFACE_OPENED(x) ((x)->h_raw != -1)
	
	int			 h_raw;
	int			 h_raw_real; /* For bonding */
	int			 h_master;   /* For bonding */

#define LLDPD_MODE_ANY 0
#define LLDPD_MODE_LLDP 1
#define LLDPD_MODE_CDPV1 2
#define LLDPD_MODE_CDPV2 3
#define LLDPD_MODE_SONMP 4
#define LLDPD_MODE_EDP 5
	int			 h_mode;

	int			 h_flags;
	int			 h_mtu;
	char			 h_ifname[IFNAMSIZ];
	u_int8_t		 h_lladdr[ETHER_ADDR_LEN];

	u_int64_t		 h_tx_cnt;
	u_int64_t		 h_rx_cnt;
	u_int64_t		 h_rx_discarded_cnt;
	u_int64_t		 h_rx_ageout_cnt;

	u_int8_t		*h_proto_macs;
	time_t			 h_start_probe;

	struct lldpd_port	 h_lport;
	time_t			 h_llastchange;
	struct lldpd_frame	*h_llastframe;

	time_t			 h_rlastchange;
	time_t			 h_rlastupdate;
	int			 h_rid;
	struct lldpd_frame	*h_rlastframe;
	struct lldpd_port	*h_rport;
	struct lldpd_chassis	*h_rchassis;
};

struct lldpd_interface {
	TAILQ_ENTRY(lldpd_interface) next;
	char			*name;
};
#define STRUCT_LLDPD_INTERFACE "Ls"

struct lldpd_client {
	TAILQ_ENTRY(lldpd_client) next;
	int fd;
};

#define PROTO_SEND_SIG struct lldpd *, struct lldpd_chassis *, struct lldpd_hardware *
#define PROTO_DECODE_SIG struct lldpd *, char *, int, struct lldpd_hardware *, struct lldpd_chassis **, struct lldpd_port **
#define PROTO_GUESS_SIG char *, int

struct lldpd;
struct protocol {
	int		 mode;		/* > 0 mode identifier (unique per protocol) */
	int		 enabled;	/* Is this protocol enabled? */
	char		*name;		/* Name of protocol */
	char		 arg;		/* Argument to enable this protocol */
	int(*send)(PROTO_SEND_SIG);	/* How to send a frame */
	int(*decode)(PROTO_DECODE_SIG); /* How to decode a frame */
	int(*guess)(PROTO_GUESS_SIG);   /* Can be NULL, use MAC address in this case */
	u_int8_t	 mac[ETH_ALEN];  /* Destination MAC address used by this protocol */
	struct sock_filter *filter;	/* BPF filter */
	size_t		 filterlen;	/* Size of BPF filter */
};

struct lldpd {
	int			 g_sock;
	int			 g_delay;

	struct protocol		*g_protocols;
	int			 g_multi; /* Set to 1 if multiple protocols */
	int			 g_probe_time;

	time_t			 g_lastsent;
	int			 g_lastrid;
#ifdef USE_SNMP
	int			 g_snmp;
#endif /* USE_SNMP */

	/* Unix socket handling */
	int			 g_ctl;
	TAILQ_HEAD(, lldpd_client) g_clients;

	char			*g_mgmt_pattern;

	struct lldpd_chassis	 g_lchassis;

	TAILQ_HEAD(, lldpd_hardware) g_hardware;
};

enum hmsg_type {
	HMSG_NONE,
	HMSG_GET_INTERFACES,
	HMSG_GET_CHASSIS,
	HMSG_GET_PORT,
	HMSG_GET_VLANS,
	HMSG_SHUTDOWN
};

struct hmsg_hdr {
	enum hmsg_type	 type;
	int16_t		 len;
	pid_t		 pid;
} __attribute__ ((__packed__));

struct hmsg {
	struct hmsg_hdr	 hdr;
	void		*data;
} __attribute__ ((__packed__));

#define HMSG_HEADER_SIZE	sizeof(struct hmsg_hdr)
#define MAX_HMSGSIZE		8192

/* lldpd.c */
void	 lldpd_cleanup(struct lldpd *);
void	 lldpd_vlan_cleanup(struct lldpd_port *);
void	 lldpd_remote_cleanup(struct lldpd *, struct lldpd_hardware *, int);
void	 lldpd_port_cleanup(struct lldpd_port *);
void	 lldpd_chassis_cleanup(struct lldpd_chassis *);

/* lldp.c */
int	 lldp_send(PROTO_SEND_SIG);
int	 lldp_decode(PROTO_DECODE_SIG);

/* cdp.c */
int	 cdpv1_send(PROTO_SEND_SIG);
int	 cdpv2_send(PROTO_SEND_SIG);
int	 cdp_decode(PROTO_DECODE_SIG);
int	 cdpv1_guess(PROTO_GUESS_SIG);
int	 cdpv2_guess(PROTO_GUESS_SIG);

/* sonmp.c */
int	 sonmp_send(PROTO_SEND_SIG);
int	 sonmp_decode(PROTO_DECODE_SIG);

/* edp.c */
int	 edp_send(PROTO_SEND_SIG);
int	 edp_decode(PROTO_DECODE_SIG);

/* ctl.c */
int	 ctl_create(struct lldpd *, char *);
int	 ctl_connect(char *);
void	 ctl_cleanup(int, char *);
int	 ctl_accept(struct lldpd *, int);
int	 ctl_close(struct lldpd *, int);
void	 ctl_msg_init(struct hmsg *, enum hmsg_type);
int	 ctl_msg_send(int, struct hmsg *);
int	 ctl_msg_recv(int, struct hmsg *);
int	 ctl_msg_pack_list(char *, void *, unsigned int, struct hmsg *, void **);
int	 ctl_msg_unpack_list(char *, void *, unsigned int, struct hmsg *, void **);
int	 ctl_msg_pack_structure(char *, void *, unsigned int, struct hmsg *, void **);
int	 ctl_msg_unpack_structure(char *, void *, unsigned int, struct hmsg *, void **);

/* features.c */
int	 iface_is_bridge(struct lldpd *, const char *);
int	 iface_is_bridged(struct lldpd *, const char *);
int	 iface_is_wireless(struct lldpd *, const char *);
int	 iface_is_vlan(struct lldpd *, const char *);
int	 iface_is_bond(struct lldpd *, const char *);
int	 iface_is_bond_slave(struct lldpd *,
	    const char *, const char *);
int	 iface_is_enslaved(struct lldpd *, const char *);

/* log.c */
void             log_init(int);
void             log_warn(const char *, ...);
#define LLOG_WARN(x,...) log_warn("%s: " x, __FUNCTION__, ##__VA_ARGS__)
void             log_warnx(const char *, ...);
#define LLOG_WARNX(x,...) log_warnx("%s: " x,  __FUNCTION__, ##__VA_ARGS__)
void             log_info(const char *, ...);
#define LLOG_INFO(x,...) log_info("%s: " x, __FUNCTION__, ##__VA_ARGS__)
void             log_debug(const char *, ...);
#define LLOG_DEBUG(x,...) log_debug("%s: " x, __FUNCTION__, ##__VA_ARGS__)
void             fatal(const char *);
void             fatalx(const char *);

/* agent.c */
void		 agent_shutdown();
void		 agent_init(struct lldpd *, int);

/* strlcpy.c */
size_t	strlcpy(char *, const char *, size_t);

/* iov.c */
void		 iov_dump(struct lldpd_frame **, struct iovec *, int);
u_int16_t	 iov_checksum(struct iovec *, int, int);

#endif /* _LLDPD_H */
