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

#ifndef _LLDPD_H
#define _LLDPD_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#else
# define RUNNING_ON_VALGRIND 0
#endif

#define _GNU_SOURCE 1
#include <stdlib.h>
#include <stddef.h>
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

#include "lldp-tlv.h"
#if defined (ENABLE_CDP) || defined (ENABLE_FDP)
#  include "cdp.h"
#endif
#ifdef ENABLE_SONMP
#  include "sonmp.h"
#endif
#ifdef ENABLE_EDP
#  include "edp.h"
#endif

#include "../compat/compat.h"
#include "../marshal.h"
#include "../log.h"
#include "../ctl.h"
#include "../lldpd-structs.h"

/* We don't want to import event2/event.h. We only need those as
   opaque structs. */
struct event;
struct event_base;

#define SYSFS_CLASS_NET "/sys/class/net/"
#define SYSFS_CLASS_DMI "/sys/class/dmi/id/"
#define LLDPD_TTL		120
#define LLDPD_TX_DELAY		30
#define LLDPD_TX_MSGDELAY	1
#define LLDPD_PID_FILE		"/var/run/lldpd.pid"

#define USING_AGENTX_SUBAGENT_MODULE 1

#define PROTO_SEND_SIG struct lldpd *, struct lldpd_hardware *
#define PROTO_DECODE_SIG struct lldpd *, char *, int, struct lldpd_hardware *, struct lldpd_chassis **, struct lldpd_port **
#define PROTO_GUESS_SIG char *, int

struct protocol {
	int		 mode;		/* > 0 mode identifier (unique per protocol) */
	int		 enabled;	/* Is this protocol enabled? */
	char		*name;		/* Name of protocol */
	char		 arg;		/* Argument to enable this protocol */
	int(*send)(PROTO_SEND_SIG);	/* How to send a frame */
	int(*decode)(PROTO_DECODE_SIG); /* How to decode a frame */
	int(*guess)(PROTO_GUESS_SIG);   /* Can be NULL, use MAC address in this case */
	u_int8_t	 mac[ETH_ALEN];  /* Destination MAC address used by this protocol */
};

#define SMART_HIDDEN(port) (port->p_hidden_in)

struct lldpd {
	int			 g_sock;
	struct event_base	*g_base;
#ifdef USE_SNMP
#endif

	struct lldpd_config	 g_config;

	struct protocol		*g_protocols;
	time_t			 g_lastsent;
	int			 g_lastrid;
	struct event		*g_main_loop;
#ifdef USE_SNMP
	int			 g_snmp;
	struct event		*g_snmp_timeout;
	void			*g_snmp_fds;
	char			*g_snmp_agentx;
#endif /* USE_SNMP */

	/* Unix socket handling */
	int			 g_ctl;
	struct event		*g_ctl_event;

	char			*g_lsb_release;

#define LOCAL_CHASSIS(cfg) ((struct lldpd_chassis *)(TAILQ_FIRST(&cfg->g_chassis)))
	TAILQ_HEAD(, lldpd_chassis) g_chassis;
	TAILQ_HEAD(, lldpd_hardware) g_hardware;
};

typedef void(*lldpd_ifhandlers)(struct lldpd *, struct ifaddrs *);

/* lldpd.c */
struct lldpd_hardware	*lldpd_get_hardware(struct lldpd *,
    char *, int, struct lldpd_ops *);
struct lldpd_hardware	*lldpd_alloc_hardware(struct lldpd *, char *);
void	 lldpd_hardware_cleanup(struct lldpd*, struct lldpd_hardware *);
struct lldpd_mgmt *lldpd_alloc_mgmt(int family, void *addr, size_t addrsize, u_int32_t iface);
void	 lldpd_recv(struct lldpd *, struct lldpd_hardware *, int);
void	 lldpd_loop(struct lldpd *);
int	 lldpd_main(int, char **);

/* event.c */
void	 levent_loop(struct lldpd *);
void	 levent_hardware_init(struct lldpd_hardware *);
void	 levent_hardware_add_fd(struct lldpd_hardware *, int);
void	 levent_hardware_release(struct lldpd_hardware *);
void	 levent_ctl_notify(char *, int, struct lldpd_port *);
void	 levent_send_now(struct lldpd *);

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

/* interfaces.c */
void	 lldpd_ifh_whitelist(struct lldpd *, struct ifaddrs *);
void	 lldpd_ifh_bond(struct lldpd *, struct ifaddrs *);
void	 lldpd_ifh_eth(struct lldpd *, struct ifaddrs *);
#ifdef ENABLE_DOT1
void	 lldpd_ifh_vlan(struct lldpd *, struct ifaddrs *);
#endif
void	 lldpd_ifh_mgmt(struct lldpd *, struct ifaddrs *);
void	 lldpd_ifh_chassis(struct lldpd *, struct ifaddrs *);

/* dmi.c */
#ifdef ENABLE_LLDPMED
#if __i386__ || __amd64__
char	*dmi_hw(void);
char	*dmi_fw(void);
char	*dmi_sn(void);
char	*dmi_manuf(void);
char	*dmi_model(void);
char	*dmi_asset(void);
#endif
#endif

/* agent.c */
void		 agent_shutdown(void);
void		 agent_init(struct lldpd *, char *);

/* agent_priv.c */
void		 agent_priv_register_domain(void);

/* client.c */
int
client_handle_client(struct lldpd *cfg,
    ssize_t(*send)(void *, int, void *, size_t),
    void *,
    enum hmsg_type type, void *buffer, size_t n,
    int*);

/* priv.c */
void	 priv_init(char*, int, uid_t, gid_t);
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
