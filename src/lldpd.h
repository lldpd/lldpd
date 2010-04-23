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
#  include <config.h>
#endif

#define _GNU_SOURCE 1
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifndef INCLUDE_LINUX_IF_H
#  include <net/if.h>
#else
#  include <arpa/inet.h>
#  include <linux/if.h>
#endif
#if HAVE_GETIFADDRS
#  include <ifaddrs.h>
#endif
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/ethtool.h>
#include <sys/un.h>

#include "compat.h"
#include "lldp.h"
#if defined (ENABLE_CDP) || defined (ENABLE_FDP)
#  include "cdp.h"
#endif
#ifdef ENABLE_SONMP
#  include "sonmp.h"
#endif
#ifdef ENABLE_EDP
#  include "edp.h"
#endif

#define SYSFS_CLASS_NET "/sys/class/net/"
#define SYSFS_CLASS_DMI "/sys/class/dmi/id/"
#define LLDPD_TTL		120
#define LLDPD_TX_DELAY		30
#define LLDPD_TX_MSGDELAY	1
#define LLDPD_CTL_SOCKET	"/var/run/lldpd.socket"
#define LLDPD_PID_FILE		"/var/run/lldpd.pid"

#define UNIX_PATH_MAX	108

#define USING_AGENTX_SUBAGENT_MODULE 1

#ifdef ENABLE_DOT1
struct lldpd_vlan {
	TAILQ_ENTRY(lldpd_vlan)  v_entries;
	char			*v_name;
	u_int16_t		 v_vid;
};
#define STRUCT_LLDPD_VLAN "(Lsw)"
#endif

#ifdef ENABLE_LLDPMED
#define STRUCT_LLDPD_MED_POLICY "(bbbwbb)"
struct lldpd_med_policy {
	u_int8_t		 type;
	u_int8_t		 unknown;
	u_int8_t		 tagged;
	u_int16_t		 vid;
	u_int8_t		 priority;
	u_int8_t		 dscp;
};

#define STRUCT_LLDPD_MED_LOC "(bC)"
struct lldpd_med_loc {
	u_int8_t		 format;
	char			*data;
	int			 data_len;
};

#define STRUCT_LLDPD_MED_POWER "(bbbw)"
struct lldpd_med_power {
	u_int8_t		 devicetype; /* PD or PSE */
	u_int8_t		 source;
	u_int8_t		 priority;
	u_int16_t		 val;
};
#endif

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

	struct in_addr		 c_mgmt;
	u_int32_t		 c_mgmt_if;

#ifdef ENABLE_LLDPMED
#define STRUCT_LLDPD_CHASSIS_MED "wbsssssss"
	u_int16_t		 c_med_cap_available;
	u_int8_t		 c_med_type;
	char			*c_med_hw;
	char			*c_med_fw;
	char			*c_med_sw;
	char			*c_med_sn;
	char			*c_med_manuf;
	char			*c_med_model;
	char			*c_med_asset;
#else
#define STRUCT_LLDPD_CHASSIS_MED ""
#endif

};
#define STRUCT_LLDPD_CHASSIS "(LwwbbCsswwwll" STRUCT_LLDPD_CHASSIS_MED ")"

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

#ifdef ENABLE_DOT3
#define STRUCT_LLDPD_PORT_DOT3 "lbbww"
	/* Dot3 stuff */
	u_int32_t		 p_aggregid;
	u_int8_t		 p_autoneg_support;
	u_int8_t		 p_autoneg_enabled;
	u_int16_t		 p_autoneg_advertised;
	u_int16_t		 p_mau_type;
#else
#define STRUCT_LLDPD_PORT_DOT3 ""
#endif

#ifdef ENABLE_LLDPMED
#define STRUCT_LLDPD_PORT_MED "w"      \
	STRUCT_LLDPD_MED_POLICY	       \
	STRUCT_LLDPD_MED_POLICY	       \
	STRUCT_LLDPD_MED_POLICY	       \
	STRUCT_LLDPD_MED_POLICY	       \
	STRUCT_LLDPD_MED_POLICY	       \
	STRUCT_LLDPD_MED_POLICY	       \
	STRUCT_LLDPD_MED_POLICY	       \
	STRUCT_LLDPD_MED_POLICY	       \
	STRUCT_LLDPD_MED_LOC	       \
	STRUCT_LLDPD_MED_LOC	       \
	STRUCT_LLDPD_MED_LOC	       \
	STRUCT_LLDPD_MED_POWER
	u_int16_t		 p_med_cap_enabled;
	struct lldpd_med_policy	 p_med_policy[LLDPMED_APPTYPE_LAST];
	struct lldpd_med_loc	 p_med_location[LLDPMED_LOCFORMAT_LAST];
	struct lldpd_med_power	 p_med_power;
#else
#define STRUCT_LLDPD_PORT_MED ""
#endif

#ifdef ENABLE_DOT1
#define STRUCT_LLDPD_PORT_DOT1 "wPP"
	u_int16_t		 p_pvid;
	TAILQ_HEAD(, lldpd_vlan) p_vlans;
#else
#define STRUCT_LLDPD_PORT_DOT1 ""
#endif
};

#define STRUCT_LLDPD_PORT "(LPttPbbCsw"				\
	STRUCT_LLDPD_PORT_DOT3					\
	STRUCT_LLDPD_PORT_MED					\
	STRUCT_LLDPD_PORT_DOT1 ")"

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

	fd_set			 h_recvfds; /* FD for reception */
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

struct lldpd_interface {
	TAILQ_ENTRY(lldpd_interface) next;
	char			*name;
};
#define STRUCT_LLDPD_INTERFACE "(Ls)"

#define PROTO_SEND_SIG struct lldpd *, struct lldpd_hardware *
#define PROTO_DECODE_SIG struct lldpd *, char *, int, struct lldpd_hardware *, struct lldpd_chassis **, struct lldpd_port **
#define PROTO_GUESS_SIG char *, int

struct protocol {
#define LLDPD_MODE_LLDP 1
#define LLDPD_MODE_CDPV1 2
#define LLDPD_MODE_CDPV2 3
#define LLDPD_MODE_SONMP 4
#define LLDPD_MODE_EDP 5
#define LLDPD_MODE_FDP 6
	int		 mode;		/* > 0 mode identifier (unique per protocol) */
	int		 enabled;	/* Is this protocol enabled? */
	char		*name;		/* Name of protocol */
	char		 arg;		/* Argument to enable this protocol */
	int(*send)(PROTO_SEND_SIG);	/* How to send a frame */
	int(*decode)(PROTO_DECODE_SIG); /* How to decode a frame */
	int(*guess)(PROTO_GUESS_SIG);   /* Can be NULL, use MAC address in this case */
	u_int8_t	 mac[ETH_ALEN];  /* Destination MAC address used by this protocol */
};

#define CALLBACK_SIG struct lldpd*, struct lldpd_callback*
struct lldpd_callback {
	TAILQ_ENTRY(lldpd_callback) next;
	int	 fd;	      /* FD that will trigger this callback */
	void(*function)(CALLBACK_SIG); /* Function called */
	void	*data;		/* Optional data for this callback*/
};

struct lldpd {
	int			 g_sock;
	int			 g_delay;

	struct protocol		*g_protocols;
#ifdef ENABLE_LISTENVLAN
	int			 g_listen_vlans;
#endif
#ifdef ENABLE_LLDPMED
	int			 g_noinventory;
#endif
	int			 g_advertise_version;

	time_t			 g_lastsent;
	int			 g_lastrid;
#ifdef USE_SNMP
	int			 g_snmp;
#endif /* USE_SNMP */

	/* Unix socket handling */
	int			 g_ctl;

	TAILQ_HEAD(, lldpd_callback) g_callbacks;

	char			*g_mgmt_pattern;

        char                    *g_descr_override;

#define LOCAL_CHASSIS(cfg) ((struct lldpd_chassis *)(TAILQ_FIRST(&cfg->g_chassis)))
	TAILQ_HEAD(, lldpd_chassis) g_chassis;
	TAILQ_HEAD(, lldpd_hardware) g_hardware;
};

typedef void(*lldpd_ifhandlers)(struct lldpd *, struct ifaddrs *);

enum hmsg_type {
	HMSG_NONE,
	HMSG_GET_INTERFACES,
	HMSG_GET_NB_PORTS,
	HMSG_GET_PORT,
	HMSG_GET_CHASSIS,
	HMSG_GET_VLANS,
	HMSG_SET_LOCATION,
	HMSG_SET_POLICY,
	HMSG_SET_POWER,
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
struct lldpd_hardware	*lldpd_get_hardware(struct lldpd *,
    char *, int, struct lldpd_ops *);
struct lldpd_hardware	*lldpd_alloc_hardware(struct lldpd *, char *);
void	 lldpd_hardware_cleanup(struct lldpd*, struct lldpd_hardware *);
#ifdef ENABLE_DOT1
void	 lldpd_vlan_cleanup(struct lldpd_port *);
#endif
void	 lldpd_remote_cleanup(struct lldpd *, struct lldpd_hardware *, int);
void	 lldpd_port_cleanup(struct lldpd*, struct lldpd_port *, int);
void	 lldpd_chassis_cleanup(struct lldpd_chassis *, int);
int	 lldpd_callback_add(struct lldpd *, int, void(*fn)(CALLBACK_SIG), void *);
void	 lldpd_callback_del(struct lldpd *, int, void(*fn)(CALLBACK_SIG));
int	 lldpd_main(int, char **);

/* lldp.c */
int	 lldp_send(PROTO_SEND_SIG);
int	 lldp_decode(PROTO_DECODE_SIG);

/* cdp.c */
#ifdef ENABLE_CDP
int	 cdpv1_send(PROTO_SEND_SIG);
int	 cdpv2_send(PROTO_SEND_SIG);
int	 cdpv1_guess(PROTO_GUESS_SIG);
int	 cdpv2_guess(PROTO_GUESS_SIG);
#endif
#if defined (ENABLE_CDP) || defined (ENABLE_FDP)
int	 cdp_decode(PROTO_DECODE_SIG);
#endif
#ifdef ENABLE_FDP
int	 fdp_send(PROTO_SEND_SIG);
#endif

#ifdef ENABLE_SONMP
/* sonmp.c */
int	 sonmp_send(PROTO_SEND_SIG);
int	 sonmp_decode(PROTO_DECODE_SIG);
#endif

#ifdef ENABLE_EDP
/* edp.c */
int	 edp_send(PROTO_SEND_SIG);
int	 edp_decode(PROTO_DECODE_SIG);
#endif

/* ctl.c */
int	 ctl_create(char *);
int	 ctl_connect(char *);
void	 ctl_cleanup(char *);
void	 ctl_accept(struct lldpd *, struct lldpd_callback *);
void	 ctl_msg_init(struct hmsg *, enum hmsg_type);
int	 ctl_msg_send(int, struct hmsg *);
int	 ctl_msg_recv(int, struct hmsg *);
int	 ctl_msg_pack_list(char *, void *, unsigned int, struct hmsg *, void **);
int	 ctl_msg_unpack_list(char *, void *, unsigned int, struct hmsg *, void **);
int	 ctl_msg_pack_structure(char *, void *, unsigned int, struct hmsg *, void **);
int	 ctl_msg_unpack_structure(char *, void *, unsigned int, struct hmsg *, void **);

/* interfaces.c */
void	 lldpd_ifh_bond(struct lldpd *, struct ifaddrs *);
void	 lldpd_ifh_eth(struct lldpd *, struct ifaddrs *);
#ifdef ENABLE_DOT1
void	 lldpd_ifh_vlan(struct lldpd *, struct ifaddrs *);
#endif
void	 lldpd_ifh_mgmt(struct lldpd *, struct ifaddrs *);

/* dmi.c */
#ifdef ENABLE_LLDPMED
char	*dmi_hw(void);
char	*dmi_fw(void);
char	*dmi_sn(void);
char	*dmi_manuf(void);
char	*dmi_model(void);
char	*dmi_asset(void);
#endif

/* log.c */
void             log_init(int, const char *);
void             log_warn(const char *, ...) __attribute__ ((format (printf, 1, 2)));
#define LLOG_WARN(x,...) log_warn("%s: " x, __FUNCTION__ , ## __VA_ARGS__)
void             log_warnx(const char *, ...) __attribute__ ((format (printf, 1, 2)));
#define LLOG_WARNX(x,...) log_warnx("%s: " x,  __FUNCTION__ , ## __VA_ARGS__)
void             log_info(const char *, ...) __attribute__ ((format (printf, 1, 2)));
#define LLOG_INFO(x,...) log_info("%s: " x, __FUNCTION__ , ## __VA_ARGS__)
void             log_debug(const char *, ...) __attribute__ ((format (printf, 1, 2)));
#define LLOG_DEBUG(x,...) log_debug("%s: " x, __FUNCTION__ , ## __VA_ARGS__)
void             fatal(const char *);
void             fatalx(const char *);

/* agent.c */
void		 agent_shutdown(void);
void		 agent_init(struct lldpd *, char *, int);

/* agent_priv.c */
void		 agent_priv_register_domain(void);

/* client.c */
struct client_handle {
	enum hmsg_type type;
	void (*handle)(struct lldpd*, struct hmsg*, struct hmsg*);
};

void	 client_handle_client(struct lldpd *, struct lldpd_callback *,
    char *, int);
void	 client_handle_none(struct lldpd *, struct hmsg *,
	    struct hmsg *);
void	 client_handle_get_interfaces(struct lldpd *, struct hmsg *,
	    struct hmsg *);
void	 client_handle_port_related(struct lldpd *, struct hmsg *,
	    struct hmsg *);
void	 client_handle_shutdown(struct lldpd *, struct hmsg *,
	    struct hmsg *);

/* priv.c */
void	 priv_init(char*);
int 	 priv_ctl_create(void);
void	 priv_ctl_cleanup(void);
char   	*priv_gethostbyname(void);
int    	 priv_open(char*);
int    	 priv_ethtool(char*, struct ethtool_cmd*);
int    	 priv_iface_init(const char *);
int	 priv_iface_multicast(const char *, u_int8_t *, int);
int	 priv_snmp_socket(struct sockaddr_un *);

/* privsep_fdpass.c */
int	 receive_fd(int);
void	 send_fd(int, int);

#endif /* _LLDPD_H */
