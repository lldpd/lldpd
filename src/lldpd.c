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

#include "lldpd.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <time.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <linux/filter.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#ifdef USE_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#endif /* USE_SNMP */

void		 usage(void);

int			 lldpd_iface_init(struct lldpd *, struct lldpd_hardware *);
int			 lldpd_iface_init_vlan(struct lldpd *, struct lldpd_vif *);
void			 lldpd_iface_init_mtu(struct lldpd *, struct lldpd_hardware *);
int			 lldpd_iface_init_socket(struct lldpd *, struct lldpd_hardware *);
int			 lldpd_iface_close(struct lldpd *, struct lldpd_hardware *);
void			 lldpd_iface_multicast(struct lldpd *, const char *, int);

/* "ether proto 0x88cc and ether dst 01:80:c2:00:00:0e" */
#define LLDPD_FILTER_LLDP_F						\
	{ 0x28, 0, 0, 0x0000000c },					\
        { 0x15, 0, 5, 0x000088cc },					\
        { 0x20, 0, 0, 0x00000002 },					\
        { 0x15, 0, 3, 0xc200000e },					\
        { 0x28, 0, 0, 0x00000000 },					\
        { 0x15, 0, 1, 0x00000180 },					\
        { 0x6, 0, 0, 0x0000ffff },					\
        { 0x6, 0, 0, 0x00000000 },
struct sock_filter lldpd_filter_lldp_f[] = { LLDPD_FILTER_LLDP_F };
/* "ether dst 01:00:0c:cc:cc:cc" */
#define LLDPD_FILTER_CDP_F			\
        { 0x20, 0, 0, 0x00000002 },		\
        { 0x15, 0, 3, 0x0ccccccc },		\
        { 0x28, 0, 0, 0x00000000 },		\
        { 0x15, 0, 1, 0x00000100 },		\
        { 0x6, 0, 0, 0x0000ffff },		\
        { 0x6, 0, 0, 0x00000000 },
struct sock_filter lldpd_filter_cdp_f[] = { LLDPD_FILTER_CDP_F };
/* "ether dst 01:00:81:00:01:00" */
#define LLDPD_FILTER_SONMP_F			\
        { 0x20, 0, 0, 0x00000002 },		\
        { 0x15, 0, 3, 0x81000100 },		\
        { 0x28, 0, 0, 0x00000000 },		\
        { 0x15, 0, 1, 0x00000100 },		\
        { 0x6, 0, 0, 0x0000ffff },		\
        { 0x6, 0, 0, 0x00000000 },
struct sock_filter lldpd_filter_sonmp_f[] = { LLDPD_FILTER_SONMP_F };
/* "ether dst 00:e0:2b:00:00:00" */
#define LLDPD_FILTER_EDP_F              \
	{ 0x20, 0, 0, 0x00000002 },	\
	{ 0x15, 0, 3, 0x2b000000 },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 0, 1, 0x000000e0 },	\
	{ 0x6, 0, 0, 0x0000ffff },	\
	{ 0x6, 0, 0, 0x00000000 },
struct sock_filter lldpd_filter_edp_f[] = { LLDPD_FILTER_EDP_F };
#define LLDPD_FILTER_ANY_F		\
	{ 0x28, 0, 0, 0x0000000c },	\
	{ 0x15, 0, 4, 0x000088cc },	\
	{ 0x20, 0, 0, 0x00000002 },	\
	{ 0x15, 0, 2, 0xc200000e },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 8, 9, 0x00000180 },	\
	{ 0x20, 0, 0, 0x00000002 },	\
	{ 0x15, 0, 2, 0x2b000000 },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 4, 5, 0x000000e0 },	\
	{ 0x15, 1, 0, 0x0ccccccc },	\
	{ 0x15, 0, 3, 0x81000100 },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 0, 1, 0x00000100 },	\
	{ 0x6, 0, 0, 0x0000ffff },	\
	{ 0x6, 0, 0, 0x00000000 },
struct sock_filter lldpd_filter_any_f[] = { LLDPD_FILTER_ANY_F };

struct protocol protos[] =
{
	{ LLDPD_MODE_LLDP, 1, "LLDP", ' ', lldp_send, lldp_decode, NULL,
	  LLDP_MULTICAST_ADDR, lldpd_filter_lldp_f, sizeof(lldpd_filter_lldp_f) },
	{ LLDPD_MODE_CDPV1, 0, "CDPv1", 'c', cdpv1_send, cdp_decode, cdpv1_guess,
	  CDP_MULTICAST_ADDR, lldpd_filter_cdp_f, sizeof(lldpd_filter_cdp_f) },
	{ LLDPD_MODE_CDPV2, 0, "CDPv2", 'c', cdpv2_send, cdp_decode, cdpv2_guess,
	  CDP_MULTICAST_ADDR, lldpd_filter_cdp_f, sizeof(lldpd_filter_cdp_f) },
	{ LLDPD_MODE_SONMP, 0, "SONMP", 's', sonmp_send, sonmp_decode, NULL,
	  SONMP_MULTICAST_ADDR, lldpd_filter_sonmp_f, sizeof(lldpd_filter_sonmp_f) },
	{ LLDPD_MODE_EDP, 0, "EDP", 'e', edp_send, edp_decode, NULL,
	  EDP_MULTICAST_ADDR, lldpd_filter_edp_f, sizeof(lldpd_filter_edp_f) },
	{ 0, 0, "any", ' ', NULL, NULL, NULL,
	  {0,0,0,0,0,0}, lldpd_filter_any_f, sizeof(lldpd_filter_any_f) }
};

int			 lldpd_iface_switchto(struct lldpd *, short int,
			    struct lldpd_hardware *);
struct lldpd_hardware	*lldpd_port_add(struct lldpd *, struct ifaddrs *);
void			 lldpd_loop(struct lldpd *);
void			 lldpd_hangup(int);
void			 lldpd_shutdown(int);
void			 lldpd_exit();
void			 lldpd_send_all(struct lldpd *);
void			 lldpd_recv_all(struct lldpd *);
int			 lldpd_guess_type(struct lldpd *, char *, int);
void			 lldpd_decode(struct lldpd *, char *, int,
			    struct lldpd_hardware *, int);

char	**saved_argv;

void
usage(void)
{
	extern const char	*__progname;
#ifndef USE_SNMP
	fprintf(stderr, "usage: %s [-d] [-v] [-c] [-s] [-e] [-p|-P] [-m ip]\n", __progname);
#else /* USE_SNMP */
	fprintf(stderr, "usage: %s [-d] [-v] [-c] [-s] [-e] [-p|-P] [-m ip] [-x]\n", __progname);
#endif /* USE_SNMP */
	exit(1);
}

void
lldpd_iface_init_mtu(struct lldpd *global, struct lldpd_hardware *hardware)
{
	struct ifreq ifr;

	/* get MTU */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, hardware->h_ifname, sizeof(ifr.ifr_name));
	if (ioctl(global->g_sock, SIOCGIFMTU, (char*)&ifr) == -1) {
		LLOG_WARN("unable to get MTU of %s, using 1500", hardware->h_ifname);
		hardware->h_mtu = 1500;
	} else
		hardware->h_mtu = ifr.ifr_mtu;
}

int
lldpd_iface_init_socket(struct lldpd *global, struct lldpd_hardware *hardware)
{
	struct sockaddr_ll sa;

	/* Open listening socket to receive/send frames */
	if ((hardware->h_raw = socket(PF_PACKET, SOCK_RAW,
		    htons(ETH_P_ALL))) < 0)
		return errno;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = 0;
	sa.sll_ifindex = if_nametoindex(hardware->h_ifname);
	if (bind(hardware->h_raw, (struct sockaddr*)&sa, sizeof(sa)) < 0)
		return errno;

	return 0;
}

int
lldpd_iface_init_vlan(struct lldpd *global, struct lldpd_vif *vif)
{
	int status;
	short int filter;

	lldpd_iface_init_mtu(global, (struct lldpd_hardware*)vif);
	status = lldpd_iface_init_socket(global, (struct lldpd_hardware*)vif);
	if (status != 0)
		return status;

	if (global->g_multi)
		filter = LLDPD_MODE_ANY;
	else
		filter = LLDPD_MODE_LLDP;

	if (lldpd_iface_switchto(global, filter,
		(struct lldpd_hardware*)vif) == -1) {
		LLOG_WARNX("unable to apply filter");
		return ENETDOWN;
	}

	lldpd_iface_multicast(global, vif->vif_ifname, 0);

	LLOG_DEBUG("vlan interface %s initialized (fd=%d)", vif->vif_ifname,
	    vif->vif_raw);
	return 0;
}

int
lldpd_iface_init(struct lldpd *global, struct lldpd_hardware *hardware)
{
	struct sockaddr_ll sa;
	int master;		/* Bond device */
	char if_bond[IFNAMSIZ];
	int un = 1;
	int status;
	short int filter;

	lldpd_iface_init_mtu(global, hardware);
	status = lldpd_iface_init_socket(global, hardware);
	if (status != 0)
		return status;

	if ((master = iface_is_enslaved(global, hardware->h_ifname)) != -1) {
		/* With bonding device, we need to listen on the bond ! */
		if (if_indextoname(master, if_bond) == NULL) {
			LLOG_WARN("unable to get index for interface %d (master of %s)",
			    master, hardware->h_ifname);
			return ENETDOWN;
		}
		hardware->h_raw_real = hardware->h_raw;
		hardware->h_master = master;
		hardware->h_raw = -1;
		if ((hardware->h_raw = socket(PF_PACKET, SOCK_RAW,
			    htons(ETH_P_ALL))) < 0)
			return errno;
		memset(&sa, 0, sizeof(sa));
		sa.sll_family = AF_PACKET;
		sa.sll_protocol = 0;
		sa.sll_ifindex = master;
		if (bind(hardware->h_raw, (struct sockaddr*)&sa,
			sizeof(sa)) < 0)
			return errno;
		/* With bonding, we need to listen to bond device. We use
		 * setsockopt() PACKET_ORIGDEV to get physical device instead of
		 * bond device */
		if (setsockopt(hardware->h_raw, SOL_PACKET,
			PACKET_ORIGDEV, &un, sizeof(un)) == -1) {
			LLOG_WARN("unable to setsockopt for master bonding device of %s. "
                            "You will get inaccurate results",
			    hardware->h_ifname);
                }
	}

	if (global->g_multi)
		filter = LLDPD_MODE_ANY;
	else
		filter = LLDPD_MODE_LLDP;
	if (lldpd_iface_switchto(global, filter, hardware) == -1) {
		LLOG_WARNX("unable to apply filter");
		return ENETDOWN;
	}

	if (master != -1)
		lldpd_iface_multicast(global, if_bond, 0);
	lldpd_iface_multicast(global, hardware->h_ifname, 0);

	LLOG_DEBUG("interface %s initialized (fd=%d)", hardware->h_ifname,
	    hardware->h_raw);
	return 0;
}

void
lldpd_iface_multicast(struct lldpd *global, const char *name, int remove)
{
	struct ifreq ifr;
	int i;

	for (i=0; global->g_protocols[i].mode != 0; i++) {
		if (!global->g_protocols[i].enabled) continue;
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
		memcpy(ifr.ifr_hwaddr.sa_data,
		    global->g_protocols[i].mac, ETH_ALEN);
		if (ioctl(global->g_sock, (remove)?SIOCDELMULTI:SIOCADDMULTI,
			&ifr) < 0) {
			if (errno == ENOENT)
				return;
			LLOG_INFO("unable to %s %s address to multicast filter for %s",
			    (remove)?"delete":"add",
			    global->g_protocols[i].name,
			    name);
		}
	}
}

int
lldpd_iface_close(struct lldpd *global, struct lldpd_hardware *hardware)
{
	char listen[IFNAMSIZ];

	close(hardware->h_raw);
	hardware->h_raw = -1;

	if (hardware->h_raw_real > 0) {
		if (if_indextoname(hardware->h_master, listen) == NULL) {
			LLOG_WARN("unable to get index for interface %d",
			    hardware->h_master);
			strlcpy(listen, hardware->h_ifname, sizeof(listen));
		}
		close(hardware->h_raw_real);
		lldpd_iface_multicast(global, listen, 1);
	}
	strlcpy(listen, hardware->h_ifname, sizeof(listen));
	lldpd_iface_multicast(global, listen, 1);

	hardware->h_raw_real = -1;
	return 0;
}

int
lldpd_iface_switchto(struct lldpd *cfg, short int filter, struct lldpd_hardware *hardware)
{
	struct sock_fprog prog;
	int i;

	memset(&prog, 0, sizeof(prog));
	for (i=0; cfg->g_protocols[i].mode != 0; i++) {
		if (!cfg->g_protocols[i].enabled) continue;
		if (cfg->g_protocols[i].mode == filter)
			break;
	}
	prog.filter = cfg->g_protocols[i].filter;
	prog.len = cfg->g_protocols[i].filterlen / sizeof(struct sock_filter);
	if (setsockopt(hardware->h_raw, SOL_SOCKET, SO_ATTACH_FILTER,
                &prog, sizeof(prog)) < 0) {
		LLOG_WARN("unable to change filter for %s", hardware->h_ifname);
		return -1;
	}
	if ((hardware->h_raw_real > 0) && 
	    (setsockopt(hardware->h_raw_real, SOL_SOCKET, SO_ATTACH_FILTER,
                &prog, sizeof(prog)) < 0)) {
		LLOG_WARN("unable to change filter for real device %s", hardware->h_ifname);
		return -1;
	}
	return 0;
}


void
lldpd_vlan_cleanup(struct lldpd_port *port)
{
	struct lldpd_vlan *vlan, *vlan_next;
	for (vlan = TAILQ_FIRST(&port->p_vlans);
	    vlan != NULL;
	    vlan = vlan_next) {
		free(vlan->v_name);
		vlan_next = TAILQ_NEXT(vlan, v_entries);
		TAILQ_REMOVE(&port->p_vlans, vlan, v_entries);
		free(vlan);
	}
}

void
lldpd_port_cleanup(struct lldpd_port *port)
{
	lldpd_vlan_cleanup(port);
	free(port->p_id);
	free(port->p_descr);
	free(port);
}

void
lldpd_chassis_cleanup(struct lldpd_chassis *chassis)
{
	free(chassis->c_id);
	free(chassis->c_name);
	free(chassis->c_descr);
	free(chassis);
}

void
lldpd_remote_cleanup(struct lldpd *cfg, struct lldpd_hardware *hardware, int reset)
{
	if (hardware->h_rport != NULL) {
		lldpd_port_cleanup(hardware->h_rport);
		hardware->h_rport = NULL;
	}
	if (hardware->h_rchassis != NULL) {
		lldpd_chassis_cleanup(hardware->h_rchassis);
		hardware->h_rchassis = NULL;
	}
	hardware->h_rlastchange = hardware->h_rlastupdate = 0;
	free(hardware->h_rlastframe);
	hardware->h_rlastframe = NULL;
	if (reset && cfg->g_multi) {
		hardware->h_mode = LLDPD_MODE_ANY;
		memset(hardware->h_proto_macs, 0, ETH_ALEN*(cfg->g_multi+1));
		hardware->h_start_probe = 0;
		lldpd_iface_switchto(cfg, LLDPD_MODE_ANY, hardware);
	}
}

void
lldpd_cleanup(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware, *hardware_next;
	struct lldpd_vif *vif, *vif_next;

	for (hardware = TAILQ_FIRST(&cfg->g_hardware); hardware != NULL;
	     hardware = hardware_next) {
		hardware_next = TAILQ_NEXT(hardware, h_entries);
		if (hardware->h_flags == 0) {
			TAILQ_REMOVE(&cfg->g_hardware, hardware, h_entries);
			lldpd_iface_close(cfg, hardware);
			lldpd_vlan_cleanup(&hardware->h_lport);
			lldpd_remote_cleanup(cfg, hardware, 1);
			free(hardware->h_proto_macs);
			free(hardware->h_llastframe);
			free(hardware);
		} else if (hardware->h_rchassis != NULL) {
			if (time(NULL) - hardware->h_rlastupdate >
			    hardware->h_rchassis->c_ttl) {
				lldpd_remote_cleanup(cfg, hardware, 1);
				hardware->h_rx_ageout_cnt++;
			}
		}
	}
	for (vif = TAILQ_FIRST(&cfg->g_vif); vif != NULL;
	     vif = vif_next) {
		vif_next = TAILQ_NEXT(vif, vif_entries);
		if (vif->vif_flags == 0) {
			TAILQ_REMOVE(&cfg->g_vif, vif, vif_entries);
			lldpd_iface_close(cfg, (struct lldpd_hardware*)vif);
			free(vif);
		}
	}
}

struct lldpd_vif *
lldpd_port_add_vlan(struct lldpd *cfg, struct ifaddrs *ifa)
{
	struct lldpd_vif *vif;
	struct lldpd_hardware *hardware;
	struct vlan_ioctl_args ifv;

	TAILQ_FOREACH(vif, &cfg->g_vif, vif_entries) {
		if (strcmp(vif->vif_ifname, ifa->ifa_name) == 0)
			break;
	}

	if (vif == NULL) {
		if ((vif = (struct lldpd_vif *)
			calloc(1, sizeof(struct lldpd_vif))) == NULL)
			return NULL;
		vif->vif_raw = -1;
		vif->vif_raw_real = -1;
	}
	strlcpy(vif->vif_ifname, ifa->ifa_name, sizeof(vif->vif_ifname));
	vif->vif_flags = ifa->ifa_flags;

	if (vif->vif_raw == -1) {

		if (lldpd_iface_init_vlan(cfg, vif) != 0) {
			free(vif);
			return NULL;
		}
		/* Find the real interface */
		vif->vif_real = NULL;
		TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
			memset(&ifv, 0, sizeof(ifv));
			ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
			strlcpy(ifv.device1, ifa->ifa_name, sizeof(ifv.device1));
			if ((ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) >= 0) &&
			    (strncmp(hardware->h_ifname,
				ifv.u.device2,
				sizeof(ifv.u.device2)) == 0))
				vif->vif_real = hardware;
		}
		if (vif->vif_real == NULL) {
			LLOG_WARNX("unable to find real interface for %s",
			    ifa->ifa_name);
			free(vif);
			return NULL;
		}

		TAILQ_INSERT_TAIL(&cfg->g_vif, vif, vif_entries);
	}

	return vif;
}

struct lldpd_hardware *
lldpd_port_add(struct lldpd *cfg, struct ifaddrs *ifa)
{
	struct ifaddrs *oifap, *oifa;
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
	struct lldpd_vlan *vlan;
	struct ifreq ifr;
	struct vlan_ioctl_args ifv;
	struct ethtool_cmd ethc;
	u_int8_t *lladdr;

	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if (strcmp(hardware->h_ifname, ifa->ifa_name) == 0)
			break;
	}

	if (hardware == NULL) {
		if ((hardware = (struct lldpd_hardware *)
		    calloc(1, sizeof(struct lldpd_hardware))) == NULL)
			return (NULL);
		hardware->h_raw = -1;
		hardware->h_raw_real = -1;
		hardware->h_start_probe = 0;
		hardware->h_proto_macs = (u_int8_t*)calloc(cfg->g_multi+1, ETH_ALEN);
		TAILQ_INIT(&hardware->h_lport.p_vlans);
	} else {
		lldpd_vlan_cleanup(&hardware->h_lport);
	}

	port = &hardware->h_lport;
	hardware->h_flags = ifa->ifa_flags;

	strlcpy(hardware->h_ifname, ifa->ifa_name, sizeof(hardware->h_ifname));
	lladdr = (u_int8_t*)(((struct sockaddr_ll *)ifa->ifa_addr)->sll_addr);
	memcpy(&hardware->h_lladdr, lladdr, sizeof(hardware->h_lladdr));
	port->p_id_subtype = LLDP_PORTID_SUBTYPE_LLADDR;
	port->p_id = (char*)hardware->h_lladdr;
	port->p_id_len = sizeof(hardware->h_lladdr);
	port->p_descr = hardware->h_ifname;

	if (cfg->g_lchassis.c_id == NULL) {
		/* Use the first port's l2 addr as the chassis ID */
		if ((cfg->g_lchassis.c_id = malloc(sizeof(hardware->h_lladdr))) == NULL)
			fatal(NULL);
		cfg->g_lchassis.c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
		cfg->g_lchassis.c_id_len = sizeof(hardware->h_lladdr);
		memcpy(cfg->g_lchassis.c_id,
		    hardware->h_lladdr, sizeof(hardware->h_lladdr));
	}

	/* Get VLANS and aggregation status */
	if (getifaddrs(&oifap) != 0)
		fatal("lldpd_port_add: failed to get interface list");
	for (oifa = oifap; oifa != NULL; oifa = oifa->ifa_next) {
		/* Check if we already have checked this one */
		int skip = 0;
		TAILQ_FOREACH(vlan, &port->p_vlans, v_entries) {
			if (strcmp(vlan->v_name, oifa->ifa_name) == 0)
				skip = 1;
		}
		if (skip) continue;

		/* Aggregation check */
		if (iface_is_bond_slave(cfg, hardware->h_ifname, oifa->ifa_name))
			port->p_aggregid = if_nametoindex(oifa->ifa_name);
		
		/* VLAN check */
		memset(&ifv, 0, sizeof(ifv));
		ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
		strlcpy(ifv.device1, oifa->ifa_name, sizeof(ifv.device1));
		if ((ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) >= 0) &&
		    ((iface_is_bond_slave(cfg, hardware->h_ifname, ifv.u.device2)) ||
		     (strncmp(hardware->h_ifname, ifv.u.device2, sizeof(ifv.u.device2)) == 0))) {
			if ((vlan = (struct lldpd_vlan *)
			     calloc(1, sizeof(struct lldpd_vlan))) == NULL)
				continue;
			if (asprintf(&vlan->v_name, "%s", oifa->ifa_name) == -1) {
				free(vlan);
				continue;
			}
			memset(&ifv, 0, sizeof(ifv));
			ifv.cmd = GET_VLAN_VID_CMD;
			strlcpy(ifv.device1, oifa->ifa_name, sizeof(ifv.device1));
			if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) < 0) {
				/* Dunno what happened */
				free(vlan->v_name);
				free(vlan);
			} else {
				vlan->v_vid = ifv.u.VID;
				TAILQ_INSERT_TAIL(&port->p_vlans, vlan, v_entries);
			}
		}
	}
	freeifaddrs(oifap);

	/* MAC/PHY */
	memset(&ifr, 0, sizeof(ifr));
	memset(&ethc, 0, sizeof(ethc));
	strlcpy(ifr.ifr_name, hardware->h_ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&ethc;
	ethc.cmd = ETHTOOL_GSET;
	if (ioctl(cfg->g_sock, SIOCETHTOOL, &ifr) == 0) {
		int j;
		int advertised_ethtool_to_rfc3636[][2] = {
			{ADVERTISED_10baseT_Half, LLDP_DOT3_LINK_AUTONEG_10BASE_T},
			{ADVERTISED_10baseT_Full, LLDP_DOT3_LINK_AUTONEG_10BASET_FD},
			{ADVERTISED_100baseT_Half, LLDP_DOT3_LINK_AUTONEG_100BASE_TX},
			{ADVERTISED_100baseT_Full, LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD},
			{ADVERTISED_1000baseT_Half, LLDP_DOT3_LINK_AUTONEG_1000BASE_T},
			{ADVERTISED_1000baseT_Full, LLDP_DOT3_LINK_AUTONEG_1000BASE_TFD},
			{ADVERTISED_10000baseT_Full, LLDP_DOT3_LINK_AUTONEG_OTHER},
			{ADVERTISED_Pause, LLDP_DOT3_LINK_AUTONEG_FDX_PAUSE},
			{ADVERTISED_Asym_Pause, LLDP_DOT3_LINK_AUTONEG_FDX_APAUSE},
			{ADVERTISED_2500baseX_Full, LLDP_DOT3_LINK_AUTONEG_OTHER},
			{0,0}};

		port->p_autoneg_support = (ethc.supported & SUPPORTED_Autoneg) ? 1 : 0;
		port->p_autoneg_enabled = (ethc.autoneg == AUTONEG_DISABLE) ? 0 : 1;
		for (j=0; advertised_ethtool_to_rfc3636[j][0]; j++) {
			if (ethc.advertising & advertised_ethtool_to_rfc3636[j][0])
				port->p_autoneg_advertised |= advertised_ethtool_to_rfc3636[j][1];
		}
		switch (ethc.speed) {
		case SPEED_10:
			port->p_mau_type = (ethc.duplex == DUPLEX_FULL) ? \
				LLDP_DOT3_MAU_10BASETFD : LLDP_DOT3_MAU_10BASETHD;
			if (ethc.port == PORT_BNC) port->p_mau_type = LLDP_DOT3_MAU_10BASE2;
			if (ethc.port == PORT_FIBRE)
				port->p_mau_type = (ethc.duplex == DUPLEX_FULL) ? \
					LLDP_DOT3_MAU_10BASEFLDF : LLDP_DOT3_MAU_10BASEFLHD;
			break;
		case SPEED_100:
			port->p_mau_type = (ethc.duplex == DUPLEX_FULL) ? \
				LLDP_DOT3_MAU_100BASETXFD : LLDP_DOT3_MAU_100BASETXHD;
			if (ethc.port == PORT_BNC)
				port->p_mau_type = (ethc.duplex == DUPLEX_FULL) ? \
					LLDP_DOT3_MAU_100BASET2DF : LLDP_DOT3_MAU_100BASET2HD;
			if (ethc.port == PORT_FIBRE)
				port->p_mau_type = (ethc.duplex == DUPLEX_FULL) ? \
					LLDP_DOT3_MAU_100BASEFXFD : LLDP_DOT3_MAU_100BASEFXHD;
			break;
		case SPEED_1000:
			port->p_mau_type = (ethc.duplex == DUPLEX_FULL) ? \
				LLDP_DOT3_MAU_1000BASETFD : LLDP_DOT3_MAU_1000BASETHD;
			if (ethc.port == PORT_FIBRE)
				port->p_mau_type = (ethc.duplex == DUPLEX_FULL) ? \
					LLDP_DOT3_MAU_1000BASEXFD : LLDP_DOT3_MAU_1000BASEXHD;
			break;
		case SPEED_10000:
			port->p_mau_type = (ethc.port == PORT_FIBRE) ? \
					LLDP_DOT3_MAU_10GIGBASEX : LLDP_DOT3_MAU_10GIGBASER;
			break;
		}
		if (ethc.port == PORT_AUI) port->p_mau_type = LLDP_DOT3_MAU_AUI;
	}

	if (!INTERFACE_OPENED(hardware)) {

		if (lldpd_iface_init(cfg, hardware) != 0) {
			lldpd_vlan_cleanup(&hardware->h_lport);
			free(hardware->h_proto_macs);
			free(hardware);
			return (NULL);
		}

		TAILQ_INSERT_TAIL(&cfg->g_hardware, hardware, h_entries);
	}

	return (hardware);
}

int
lldpd_guess_type(struct lldpd *cfg, char *frame, int s)
{
	int i;
	if (s < ETH_ALEN)
		return -1;
	for (i=0; cfg->g_protocols[i].mode != 0; i++) {
		if (!cfg->g_protocols[i].enabled)
			continue;
		if (cfg->g_protocols[i].guess == NULL) {
			if (memcmp(frame, cfg->g_protocols[i].mac, ETH_ALEN) == 0)
				return cfg->g_protocols[i].mode;
		} else {
			if (cfg->g_protocols[i].guess(frame, s))
				return cfg->g_protocols[i].mode;
		}
	}
	return -1;
}

void
lldpd_decode(struct lldpd *cfg, char *frame, int s,
    struct lldpd_hardware *hardware, int bond)
{
	int result = 0, i, j, candidatetonull;
	u_int8_t nullmac[ETH_ALEN] = {0,0,0,0,0,0};
	u_int8_t broadcastmac[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
	struct lldpd_chassis *chassis;
	struct lldpd_port *port;
	struct lldpd_hardware *ohardware, *firstnull = NULL, *older = NULL;
	int guess = LLDPD_MODE_LLDP;

	/* Discard VLAN frames */
	if ((s >= sizeof(struct ieee8023)) &&
	    (((struct ieee8023*)frame)->size == htons(ETHERTYPE_VLAN)))
		return;

	if ((hardware->h_rlastframe != NULL) &&
	    (hardware->h_rlastframe->size == s) &&
	    (memcmp(hardware->h_rlastframe->frame, frame, s) == 0)) {
		/* Already received the same frame */
		hardware->h_rlastupdate = time(NULL);
		return;
	}

	if (cfg->g_multi) {
		if (hardware->h_mode == LLDPD_MODE_ANY)
			guess = lldpd_guess_type(cfg, frame, s);
		else
			guess = hardware->h_mode;
		for (i=0; cfg->g_protocols[i].mode != 0; i++) {
			if (!cfg->g_protocols[i].enabled)
				continue;
			if (cfg->g_protocols[i].mode == guess) {
				if ((result = cfg->g_protocols[i].decode(cfg, frame,
					    s, hardware, &chassis, &port)) == -1)
					return;
				break;
			}
		}
		if (cfg->g_protocols[i].mode == 0) {
			LLOG_INFO("unable to guess frame type");
			return;
		}
	} else if (cfg->g_protocols[0].decode(cfg, frame, s, hardware,
		&chassis, &port) == -1)
		/* Nothing has been received */
		return;

        if (bond) {
                /* Eh, wait ! The frame we just received was for a bonding
                 * device. We need to attach it to a real device. What is the
                 * best candidate? Drum rolling... */
                TAILQ_FOREACH(ohardware, &cfg->g_hardware, h_entries) {
                        if (ohardware->h_master == hardware->h_master) {
                                /* Same bond */
				if (ohardware->h_rchassis == NULL) {
					candidatetonull = 1;
					if (cfg->g_multi &&
					    (ohardware->h_mode == LLDPD_MODE_ANY)) {
						for (i=j=0;
						     cfg->g_protocols[i].mode != 0;
						     i++) {
							if (!cfg->g_protocols[i].enabled)
								continue;
							if ((cfg->g_protocols[i].mode == guess) &&
							    (memcmp(frame + ETH_ALEN,
								ohardware->h_proto_macs + ETH_ALEN*j,
								ETH_ALEN) == 0)) {
								hardware = ohardware;
								bond = 0;
								break;
							}
							j++;
						}
						if (!bond) break;
						if (firstnull != NULL) {
							for (i=j=0;
							     cfg->g_protocols[i].mode != 0;
							     i++) {
								if (!cfg->g_protocols[i].enabled)
									continue;
								if ((cfg->g_protocols[i].mode == guess) &&
								    (memcmp(nullmac,
									ohardware->h_proto_macs +
									ETH_ALEN*j,
									ETH_ALEN) != 0)) {
									/* We need to
									 * find a better
									 * candidate */
									candidatetonull = 0;
									break;
								}
								j++;
							}
						}
					}
					/* Ok, this is the first candidate if we
					 * don't find a matching chassis/port */
					if (candidatetonull) firstnull = ohardware;
                                        continue;
                                }
                                if ((older == NULL) ||
                                    (older->h_rlastupdate > ohardware->h_rlastupdate))
                                        /* If there is no matching chassis/port
                                         * and no free hardware, we will use
                                         * this one. */
                                        older = ohardware;
                                if ((chassis->c_id_subtype !=
                                        ohardware->h_rchassis->c_id_subtype) ||
                                    (chassis->c_id_len != ohardware->h_rchassis->c_id_len) ||
                                    (memcmp(chassis->c_id, ohardware->h_rchassis->c_id,
                                            chassis->c_id_len) != 0) ||
                                    (port->p_id_subtype != ohardware->h_rport->p_id_subtype) ||
                                    (port->p_id_len != ohardware->h_rport->p_id_len) ||
                                    (memcmp(port->p_id, ohardware->h_rport->p_id,
                                        port->p_id_len) != 0))
                                        continue;
                                /* We got a match! */
                                hardware = ohardware; /* We switch hardware */
                                bond = 0;
                                break;
                        }
                }
                if (bond) {
                        /* No match found */
                        if (firstnull != NULL)
                                hardware = firstnull;
                        else hardware = older;
                }
        }
	
	if (cfg->g_multi &&
	    (hardware->h_mode == LLDPD_MODE_ANY)) {
		u_int8_t *mac;
		char *modename;
		int filter;
		
		for (i=j=0; cfg->g_protocols[i].mode != 0; i++) {
			if (!cfg->g_protocols[i].enabled)
				continue;
			if (cfg->g_protocols[i].mode == guess) {
				mac = hardware->h_proto_macs + ETH_ALEN*j;
				modename = cfg->g_protocols[i].name;
				filter = cfg->g_protocols[i].mode;
				break;
			}
			j++;
		}
		if (cfg->g_protocols[i].mode == 0) {
			LLOG_WARNX("should not be there");
			goto cleanup;
		}

		if (hardware->h_start_probe == 0)
			hardware->h_start_probe = time(NULL) - 1;
		/* Handle switching respecting probe time */
		if ((memcmp(mac, frame + ETH_ALEN, ETH_ALEN) == 0) &&
		    ((time(NULL) - hardware->h_start_probe) > cfg->g_probe_time) &&
		    /* Don't switch to this protocol if not LLDP and LLDP is
		     * a valid candidate */
		    ((filter == LLDPD_MODE_LLDP) ||
			(memcmp(hardware->h_proto_macs,
			    broadcastmac, ETH_ALEN) == 0) ||
			(memcmp(hardware->h_proto_macs,
			    nullmac, ETH_ALEN) == 0))) {
			LLOG_INFO("switching to %s on port %s", modename,
			    hardware->h_ifname);
			hardware->h_mode = guess;
			lldpd_iface_switchto(cfg, filter, hardware);
		} else {
			/* Wait twice probe time to be able to receive packets of all kind */
			if ((time(NULL) - hardware->h_start_probe) > cfg->g_probe_time * 2) {
				LLOG_DEBUG("probe expired on %s, retry", hardware->h_ifname);
				hardware->h_start_probe = 0;
				memset(hardware->h_proto_macs, 0, ETH_ALEN*(cfg->g_multi+1));
				goto cleanup;
			}
			if (memcmp(mac, broadcastmac, ETH_ALEN) == 0)
				goto cleanup;
			LLOG_INFO("received a %s frame on %s but wait for %d sec",
			    modename, hardware->h_ifname, cfg->g_probe_time - time(NULL) +
			    hardware->h_start_probe);
			if (memcmp(mac, frame + ETH_ALEN, ETH_ALEN) == 0)
				goto cleanup;
			if (memcmp(mac, nullmac, ETH_ALEN) == 0) {
				memcpy(mac, frame + ETH_ALEN, ETH_ALEN);
				goto cleanup;
			}
			LLOG_INFO("several MAC for %s on %s, discarding %s for this interface",
			    modename, hardware->h_ifname, modename);
			memcpy(mac, broadcastmac, ETH_ALEN);
			goto cleanup;
                }
        }

	result = 0;
	if ((hardware->h_rchassis == NULL) ||
	    (chassis->c_id_subtype != hardware->h_rchassis->c_id_subtype) ||
	    (chassis->c_id_len != hardware->h_rchassis->c_id_len) ||
	    (memcmp(chassis->c_id, hardware->h_rchassis->c_id,
		chassis->c_id_len) != 0))
		result = 1;

	/* We have our new frame */
	lldpd_remote_cleanup(cfg, hardware, 0);
	hardware->h_rport = port;
	hardware->h_rchassis = chassis;
	hardware->h_rlastchange = hardware->h_rlastupdate = time(NULL);

	/* We remember this frame */
	free(hardware->h_rlastframe);
	if ((hardware->h_rlastframe = (struct lldpd_frame *)malloc(s +
		    sizeof(int))) != NULL) {
		hardware->h_rlastframe->size = s;
		memcpy(hardware->h_rlastframe->frame, frame, s);
	}

	if (result) {
		/* This is a new remote system */
		LLOG_DEBUG("we discovered a new remote system on %s",
		    hardware->h_ifname);
		/* Do we already know this remote system? */
		TAILQ_FOREACH(ohardware, &cfg->g_hardware, h_entries) {
			if ((ohardware->h_ifname != hardware->h_ifname) &&
			    (ohardware->h_rchassis != NULL) &&
			    (ohardware->h_rchassis->c_id_subtype ==
				chassis->c_id_subtype) &&
			    (ohardware->h_rchassis->c_id_len == 
				chassis->c_id_len) &&
			    (memcmp(ohardware->h_rchassis->c_id,
				chassis->c_id, chassis->c_id_len) == 0)) {
				LLOG_DEBUG("but it was already on %s",
				    ohardware->h_ifname);
				hardware->h_rid = ohardware->h_rid;
				return;
			}
		}
		hardware->h_rid = ++cfg->g_lastrid;
	}
	return;

cleanup:
	lldpd_chassis_cleanup(chassis);
	lldpd_port_cleanup(port);
	return;
}

void
lldpd_recv_all(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
	struct lldpd_vif *vif;
	struct lldpd_client *client, *client_next;
	fd_set rfds;
	struct timeval tv;
	struct sockaddr_ll from;
	socklen_t fromlen;
	int onreal;
#ifdef USE_SNMP
	int fakeblock = 0;
	struct timeval *tvp = &tv;
#endif
	int rc, nfds, n, bond;
	char *buffer;

	do {
		tv.tv_sec = cfg->g_delay - (time(NULL) - cfg->g_lastsent);
		if (tv.tv_sec < 0)
			tv.tv_sec = LLDPD_TX_DELAY;
		if (tv.tv_sec >= cfg->g_delay)
			tv.tv_sec = cfg->g_delay;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);
		nfds = -1;
		
		TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
			/* Ignore if interface is down */
			if ((hardware->h_flags & IFF_UP) == 0)
				continue;
			FD_SET(hardware->h_raw, &rfds);
			if (nfds < hardware->h_raw)
				nfds = hardware->h_raw;
			/* Listen to real interface too. In 2.6.27, we can
			 * receive packets if this is the slave interface. */
			if (hardware->h_raw_real > 0) {
				FD_SET(hardware->h_raw_real, &rfds);
				if (nfds < hardware->h_raw_real)
				nfds = hardware->h_raw_real;
			}
		}
		TAILQ_FOREACH(vif, &cfg->g_vif, vif_entries) {
			if ((vif->vif_flags & IFF_UP) == 0)
				continue;
			FD_SET(vif->vif_raw, &rfds);
			if (nfds < vif->vif_raw)
				nfds = vif->vif_raw;
		}
		TAILQ_FOREACH(client, &cfg->g_clients, next) {
			FD_SET(client->fd, &rfds);
			if (nfds < client->fd)
				nfds = client->fd;
		}
		FD_SET(cfg->g_ctl, &rfds);
		if (nfds < cfg->g_ctl)
			nfds = cfg->g_ctl;
		
#ifdef USE_SNMP
		if (cfg->g_snmp)
			snmp_select_info(&nfds, &rfds, tvp, &fakeblock);
#endif /* USE_SNMP */
		if (nfds == -1) {
			sleep(cfg->g_delay);
			return;
		}

		rc = select(nfds + 1, &rfds, NULL, NULL, &tv);
		if (rc == -1) {
			if (errno == EINTR)
				continue;
			LLOG_WARN("failure on select");
			break;
		}
#ifdef USE_SNMP
		if (cfg->g_snmp) {
			if (rc > 0)
				snmp_read(&rfds);
			else if (rc == 0)
				snmp_timeout();
		}
#endif /* USE_SNMP */
		TAILQ_FOREACH(vif, &cfg->g_vif, vif_entries) {
			if (!FD_ISSET(vif->vif_raw, &rfds))
				continue;
			if ((buffer = (char *)malloc(
					vif->vif_mtu)) == NULL) {
				LLOG_WARN("failed to alloc reception buffer");
				continue;
			}
			fromlen = sizeof(from);
			if ((n = recvfrom(vif->vif_raw,
				    buffer,
				    vif->vif_mtu, 0,
				    (struct sockaddr *)&from,
				    &fromlen)) == -1) {
				LLOG_WARN("error while receiving frame on vlan %s",
				    vif->vif_ifname);
				vif->vif_real->h_rx_discarded_cnt++;
				free(buffer);
				continue;
			}
			if (from.sll_pkttype == PACKET_OUTGOING) {
				free(buffer);
				continue;
			}
			if (!((cfg->g_multi) &&
				(vif->vif_real->h_mode != LLDPD_MODE_ANY) &&
				(lldpd_guess_type(cfg, buffer, n) !=
				    vif->vif_real->h_mode))) {
				vif->vif_real->h_rx_cnt++;
				lldpd_decode(cfg, buffer, n, vif->vif_real, 0);
			}

			free(buffer);
		}
		TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
			/* We could have received something on _real_
			 * interface. However, even in this case, this could be
			 * just an outgoing packet. We will try to handle both
			 * cases, but maybe not in the same select. */
			onreal = ((hardware->h_raw_real > 0) &&
			    (FD_ISSET(hardware->h_raw_real, &rfds)));
			if (onreal || (FD_ISSET(hardware->h_raw, &rfds))) {
				if ((buffer = (char *)malloc(
						hardware->h_mtu)) == NULL) {
					LLOG_WARN("failed to alloc reception buffer");
					continue;
				}
				fromlen = sizeof(from);
				if ((n = recvfrom(
						onreal?hardware->h_raw_real:hardware->h_raw,
						    buffer,
						    hardware->h_mtu, 0,
						    (struct sockaddr *)&from,
						    &fromlen)) == -1) {
					LLOG_WARN("error while receiving frame on %s",
					    hardware->h_ifname);
					hardware->h_rx_discarded_cnt++;
					free(buffer);
					continue;
				}
				if (from.sll_pkttype == PACKET_OUTGOING) {
					free(buffer);
					continue;
				}
                                bond = 0;
				/* If received on real interface, we act like if
				 * this is not a bond! */
				if (!onreal && (hardware->h_raw_real > 0)) {
					/* Bonding. Is it for the correct
					 * physical interface ? */
                                        if (from.sll_ifindex == hardware->h_master) {
                                                /* It seems that we don't know from
                                                   which physical interface it comes
                                                   (kernel < 2.6.24 ?) */
                                                bond = 1;
                                        } else if (from.sll_ifindex !=
					    if_nametoindex(hardware->h_ifname)) {
						free(buffer);
						continue;
					}
                                }
				hardware->h_rx_cnt++;
				lldpd_decode(cfg, buffer, n, hardware, bond);
				free(buffer);
			}
			
		}
		if (FD_ISSET(cfg->g_ctl, &rfds)) {
			if (ctl_accept(cfg, cfg->g_ctl) == -1)
				LLOG_WARN("unable to accept new client");
		}
		for (client = TAILQ_FIRST(&cfg->g_clients);
		     client != NULL;
		     client = client_next) {
			client_next = TAILQ_NEXT(client, next);
			if (FD_ISSET(client->fd, &rfds)) {
				/* Got a message */
				if ((buffer = (char *)malloc(MAX_HMSGSIZE)) ==
				    NULL) {
					LLOG_WARN("failed to alloc reception buffer");
					continue;
				}
				if ((n = recv(client->fd, buffer,
					    MAX_HMSGSIZE, 0)) == -1) {
					LLOG_WARN("error while receiving message");
					free(buffer);
					continue;
				}
				if (n > 0)
					client_handle_client(cfg, client, buffer, n);
				else
					ctl_close(cfg, client->fd); /* Will use TAILQ_REMOVE ! */
				free(buffer);
			}
		}

#ifdef USE_SNMP
		if (cfg->g_snmp) {
			run_alarms();
			netsnmp_check_outstanding_agent_requests();
		}
#endif /* USE_SNMP */
	} while ((rc != 0) || (time(NULL) - cfg->g_lastsent < cfg->g_delay));
}

void
lldpd_send_all(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
	int i;
	cfg->g_lastsent = time(NULL);
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		/* Ignore if interface is down */
		if ((hardware->h_flags & IFF_UP) == 0)
			continue;

		for (i=0; cfg->g_protocols[i].mode != 0; i++) {
			if (!cfg->g_protocols[i].enabled)
				continue;
			if ((hardware->h_mode == cfg->g_protocols[i].mode) ||
			    (cfg->g_protocols[i].mode == LLDPD_MODE_LLDP))
				cfg->g_protocols[i].send(cfg, &cfg->g_lchassis, hardware);
		}
	}
}

void
lldpd_loop(struct lldpd *cfg)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_ll *sdl;
	struct lldpd_hardware *hardware;
	struct lldpd_vif *vif;
	int f;
	char status;
	struct utsname *un;
	struct hostent *hp;

	/* Set system name and description */
	if ((un = (struct utsname*)malloc(sizeof(struct utsname))) == NULL)
		fatal(NULL);
	if (uname(un) != 0)
		fatal("failed to get system information");
	if ((hp = gethostbyname(un->nodename)) == NULL)
		fatal("failed to get system name");
	free(cfg->g_lchassis.c_name);
	free(cfg->g_lchassis.c_descr);
	if (asprintf(&cfg->g_lchassis.c_name, "%s",
		hp->h_name) == -1)
		fatal("failed to set system name");
	if (asprintf(&cfg->g_lchassis.c_descr, "%s %s %s %s",
		un->sysname, un->release, un->version, un->machine) == -1)
		fatal("failed to set system description");
	free(un);

	/* Check forwarding */
	cfg->g_lchassis.c_cap_enabled = 0;
	if ((f = open("/proc/sys/net/ipv4/ip_forward", 0)) >= 0) {
		if ((read(f, &status, 1) == 1) && (status == '1'))
			cfg->g_lchassis.c_cap_enabled = LLDP_CAP_ROUTER;
		close(f);
	}

	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries)
	    hardware->h_flags = 0;
	TAILQ_FOREACH(vif, &cfg->g_vif, vif_entries)
	    vif->vif_flags = 0;

	if (getifaddrs(&ifap) != 0)
		fatal("lldpd_loop: failed to get interface list");

	cfg->g_lchassis.c_mgmt.s_addr = INADDR_ANY;
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (cfg->g_lchassis.c_mgmt.s_addr == INADDR_ANY)
			/* Get management address, if available */
			if ((ifa->ifa_addr != NULL) &&
			    (ifa->ifa_addr->sa_family == AF_INET)) {
				struct sockaddr_in *sa;
				sa = (struct sockaddr_in *)ifa->ifa_addr;
				if ((ntohl(*(u_int32_t*)&sa->sin_addr) != INADDR_LOOPBACK) &&
				    (cfg->g_mgmt_pattern == NULL)) {
					memcpy(&cfg->g_lchassis.c_mgmt,
					    &sa->sin_addr,
					    sizeof(struct in_addr));
					cfg->g_lchassis.c_mgmt_if = if_nametoindex(ifa->ifa_name);
				}
				else if (cfg->g_mgmt_pattern != NULL) {
					char *ip;
					ip = inet_ntoa(sa->sin_addr);
					if (fnmatch(cfg->g_mgmt_pattern,
						ip, 0) == 0) {
						memcpy(&cfg->g_lchassis.c_mgmt,
						    &sa->sin_addr,
						    sizeof(struct in_addr));
						cfg->g_lchassis.c_mgmt_if =
						    if_nametoindex(ifa->ifa_name);
					}
				}
			}

		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != PF_PACKET)
			continue;

		sdl = (struct sockaddr_ll *)ifa->ifa_addr;
		if (sdl->sll_hatype != ARPHRD_ETHER || !sdl->sll_halen)
			continue;

		if (iface_is_bridge(cfg, ifa->ifa_name)) {
			cfg->g_lchassis.c_cap_enabled |= LLDP_CAP_BRIDGE;
			continue;
		}

		if ((iface_is_vlan(cfg, ifa->ifa_name)) ||
		    (iface_is_bond(cfg, ifa->ifa_name)))
			continue;

                if (!(ifa->ifa_flags & IFF_MULTICAST))
                        continue;

		if (iface_is_wireless(cfg, ifa->ifa_name))
			cfg->g_lchassis.c_cap_enabled |= LLDP_CAP_WLAN;

		if (lldpd_port_add(cfg, ifa) == NULL)
			LLOG_WARNX("failed to allocate port %s, skip it",
				ifa->ifa_name);
	}

	/* Handle VLAN */
	if (cfg->g_listen_vlans) {
		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if ((iface_is_vlan(cfg, ifa->ifa_name)) &&
			    (lldpd_port_add_vlan(cfg, ifa) == NULL)) {
				LLOG_WARNX("unable to allocate vlan %s, skip it",
				    ifa->ifa_name);
			}
		}
	}

	freeifaddrs(ifap);

	lldpd_cleanup(cfg);

	lldpd_send_all(cfg);
	lldpd_recv_all(cfg);
}

void
lldpd_hangup(int sig)
{
	/* Re-execute */
	LLOG_INFO("sighup received, reloading");
	lldpd_exit();
	execv(saved_argv[0], saved_argv);	
}

void
lldpd_shutdown(int sig)
{
	LLOG_INFO("signal received, exiting");
	exit(0);
}

/* For signal handling */
struct lldpd *gcfg = NULL;

void
lldpd_exit()
{
	struct lldpd_hardware *hardware;
	struct lldpd_vif *vif;
	ctl_cleanup(gcfg->g_ctl, LLDPD_CTL_SOCKET);
	TAILQ_FOREACH(hardware, &gcfg->g_hardware, h_entries) {
		if (INTERFACE_OPENED(hardware))
			lldpd_iface_close(gcfg, hardware);
	}
	TAILQ_FOREACH(vif, &gcfg->g_vif, vif_entries) {
		if (vif->vif_raw != -1)
			lldpd_iface_close(gcfg, (struct lldpd_hardware*)vif);
	}
#ifdef USE_SNMP
	if (gcfg->g_snmp)
		agent_shutdown();
#endif /* USE_SNMP */
}

int
main(int argc, char *argv[])
{
	struct lldpd *cfg;
	int ch, snmp = 0, debug = 0;
	char *mgmtp = NULL;
	char *popt, opts[] = "vdxm:p:@                    ";
	int probe = 0, i, found, vlan = 0;

	saved_argv = argv;

	/*
	 * Get and parse command line options
	 */
	popt = index(opts, '@');
	for (i=0; protos[i].mode != 0; i++) {
		if (protos[i].enabled == 1) continue;
		*(popt++) = protos[i].arg;
	}
	*popt = '\0';
	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'v':
			vlan = 1;
			break;
		case 'd':
			debug++;
			break;
		case 'm':
			mgmtp = optarg;
			break;
		case 'p':
			probe = atoi(optarg);
			break;
		case 'x':
			snmp = 1;
			break;
		default:
			found = 0;
			for (i=0; protos[i].mode != 0; i++) {
				if (protos[i].enabled) continue;
				if (ch == protos[i].arg) {
					protos[i].enabled = 1;
					found = 1;
				}
			}
			if (!found)
				usage();
		}
	}

	log_init(debug);

	if (probe == 0) probe = LLDPD_TTL;

	if ((cfg = (struct lldpd *)
	    calloc(1, sizeof(struct lldpd))) == NULL)
		fatal(NULL);

	cfg->g_mgmt_pattern = mgmtp;
	cfg->g_listen_vlans = vlan;

	/* Get ioctl socket */
	if ((cfg->g_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("failed to get ioctl socket");
	cfg->g_delay = LLDPD_TX_DELAY;

	/* Set system capabilities */
	cfg->g_lchassis.c_cap_available = LLDP_CAP_BRIDGE | LLDP_CAP_WLAN |
	    LLDP_CAP_ROUTER;

	/* Set TTL */
	cfg->g_lchassis.c_ttl = LLDPD_TTL;

	cfg->g_protocols = protos;
	cfg->g_probe_time = probe;
	for (i=0; protos[i].mode != 0; i++)
		if (protos[i].enabled) {
			cfg->g_multi++;
			LLOG_INFO("protocol %s enabled", protos[i].name);
		} else
			LLOG_INFO("protocol %s disabled", protos[i].name);
	cfg->g_multi--;

	TAILQ_INIT(&cfg->g_hardware);
	TAILQ_INIT(&cfg->g_vif);

#ifdef USE_SNMP
	if (snmp) {
		cfg->g_snmp = 1;
		agent_init(cfg, debug);
	}
#endif /* USE_SNMP */

	/* Create socket */
	if ((cfg->g_ctl = ctl_create(cfg, LLDPD_CTL_SOCKET)) == -1)
		fatal("unable to create control socket " LLDPD_CTL_SOCKET);

	if (!debug && daemon(0, 0) != 0) {
		ctl_cleanup(cfg->g_ctl, LLDPD_CTL_SOCKET);
		fatal("failed to detach daemon");
	}
	gcfg = cfg;
	if (atexit(lldpd_exit) != 0) {
		ctl_cleanup(cfg->g_ctl, LLDPD_CTL_SOCKET);
		fatal("unable to set exit function");
	}
	if (!debug) {
		int pid;
		char *spid;
		if ((pid = open(LLDPD_PID_FILE,
			    O_TRUNC | O_CREAT | O_WRONLY)) == -1)
			fatal("unable to open pid file " LLDPD_PID_FILE);
		if (asprintf(&spid, "%d\n", getpid()) == -1)
			fatal("unable to create pid file " LLDPD_PID_FILE);
		if (write(pid, spid, strlen(spid)) == -1)
			fatal("unable to write pid file " LLDPD_PID_FILE);
		free(spid);
		close(pid);
	}

	/* Signal handling */
	signal(SIGHUP, lldpd_hangup);
	signal(SIGINT, lldpd_shutdown);
	signal(SIGTERM, lldpd_shutdown);

	for (;;)
		lldpd_loop(cfg);

	return (0);
}
