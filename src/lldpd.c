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
#include <libgen.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <linux/filter.h>
#include <linux/if_vlan.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>

#ifdef USE_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#endif /* USE_SNMP */

static void		 usage(void);

static int		 lldpd_iface_init(struct lldpd *, struct lldpd_hardware *);
static void		 lldpd_iface_init_mtu(struct lldpd *, struct lldpd_hardware *);
static int		 lldpd_iface_close(struct lldpd *, struct lldpd_hardware *);
static void		 lldpd_iface_multicast(struct lldpd *, const char *, int);

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
static struct sock_filter lldpd_filter_lldp_f[] = { LLDPD_FILTER_LLDP_F };
#ifdef ENABLE_FDP
/* "ether dst 01:e0:52:cc:cc:cc" */
#define LLDPD_FILTER_FDP_F			\
        { 0x20, 0, 0, 0x00000002 },		\
        { 0x15, 0, 3, 0x52cccccc },		\
        { 0x28, 0, 0, 0x00000000 },		\
        { 0x15, 0, 1, 0x000001e0 },		\
        { 0x6, 0, 0, 0x0000ffff },		\
        { 0x6, 0, 0, 0x00000000 },
static struct sock_filter lldpd_filter_fdp_f[] = { LLDPD_FILTER_FDP_F };
#endif /* ENABLE_FDP */
#ifdef ENABLE_CDP
/* "ether dst 01:00:0c:cc:cc:cc" */
#define LLDPD_FILTER_CDP_F			\
        { 0x20, 0, 0, 0x00000002 },		\
        { 0x15, 0, 3, 0x0ccccccc },		\
        { 0x28, 0, 0, 0x00000000 },		\
        { 0x15, 0, 1, 0x00000100 },		\
        { 0x6, 0, 0, 0x0000ffff },		\
        { 0x6, 0, 0, 0x00000000 },
static struct sock_filter lldpd_filter_cdp_f[] = { LLDPD_FILTER_CDP_F };
#endif /* ENABLE_CDP */
#ifdef ENABLE_SONMP
/* "ether dst 01:00:81:00:01:00" */
#define LLDPD_FILTER_SONMP_F			\
        { 0x20, 0, 0, 0x00000002 },		\
        { 0x15, 0, 3, 0x81000100 },		\
        { 0x28, 0, 0, 0x00000000 },		\
        { 0x15, 0, 1, 0x00000100 },		\
        { 0x6, 0, 0, 0x0000ffff },		\
        { 0x6, 0, 0, 0x00000000 },
static struct sock_filter lldpd_filter_sonmp_f[] = { LLDPD_FILTER_SONMP_F };
#endif /* ENABLE_SONMP */
#ifdef ENABLE_EDP
/* "ether dst 00:e0:2b:00:00:00" */
#define LLDPD_FILTER_EDP_F              \
	{ 0x20, 0, 0, 0x00000002 },	\
	{ 0x15, 0, 3, 0x2b000000 },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 0, 1, 0x000000e0 },	\
	{ 0x6, 0, 0, 0x0000ffff },	\
	{ 0x6, 0, 0, 0x00000000 },
static struct sock_filter lldpd_filter_edp_f[] = { LLDPD_FILTER_EDP_F };
#endif /* ENABLE_EDP */
#define LLDPD_FILTER_ANY_F		\
	{ 0x28, 0, 0, 0x0000000c },	\
	{ 0x15, 0, 4, 0x000088cc },	\
	{ 0x20, 0, 0, 0x00000002 },	\
	{ 0x15, 0, 2, 0xc200000e },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 11, 12, 0x00000180 },	\
	{ 0x20, 0, 0, 0x00000002 },	\
	{ 0x15, 0, 2, 0x2b000000 },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 7, 8, 0x000000e0 },	\
	{ 0x15, 1, 0, 0x0ccccccc },	\
	{ 0x15, 0, 2, 0x81000100 },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 3, 4, 0x00000100 },	\
	{ 0x15, 0, 3, 0x52cccccc },	\
	{ 0x28, 0, 0, 0x00000000 },	\
	{ 0x15, 0, 1, 0x000001e0 },	\
	{ 0x6, 0, 0, 0x0000ffff },	\
	{ 0x6, 0, 0, 0x00000000 },
static struct sock_filter lldpd_filter_any_f[] = { LLDPD_FILTER_ANY_F };

static struct protocol protos[] =
{
	{ LLDPD_MODE_LLDP, 1, "LLDP", ' ', lldp_send, lldp_decode, NULL,
	  LLDP_MULTICAST_ADDR, lldpd_filter_lldp_f, sizeof(lldpd_filter_lldp_f) },
#ifdef ENABLE_CDP
	{ LLDPD_MODE_CDPV1, 0, "CDPv1", 'c', cdpv1_send, cdp_decode, cdpv1_guess,
	  CDP_MULTICAST_ADDR, lldpd_filter_cdp_f, sizeof(lldpd_filter_cdp_f) },
	{ LLDPD_MODE_CDPV2, 0, "CDPv2", 'c', cdpv2_send, cdp_decode, cdpv2_guess,
	  CDP_MULTICAST_ADDR, lldpd_filter_cdp_f, sizeof(lldpd_filter_cdp_f) },
#endif
#ifdef ENABLE_SONMP
	{ LLDPD_MODE_SONMP, 0, "SONMP", 's', sonmp_send, sonmp_decode, NULL,
	  SONMP_MULTICAST_ADDR, lldpd_filter_sonmp_f, sizeof(lldpd_filter_sonmp_f) },
#endif
#ifdef ENABLE_EDP
	{ LLDPD_MODE_EDP, 0, "EDP", 'e', edp_send, edp_decode, NULL,
	  EDP_MULTICAST_ADDR, lldpd_filter_edp_f, sizeof(lldpd_filter_edp_f) },
#endif
#ifdef ENABLE_FDP
	{ LLDPD_MODE_FDP, 0, "FDP", 'f', fdp_send, cdp_decode, NULL,
	  FDP_MULTICAST_ADDR, lldpd_filter_fdp_f, sizeof(lldpd_filter_fdp_f) },
#endif
	{ 0, 0, "any", ' ', NULL, NULL, NULL,
	  {0,0,0,0,0,0}, lldpd_filter_any_f, sizeof(lldpd_filter_any_f) }
};

static int		 lldpd_iface_switchto(struct lldpd *, short int,
			    struct lldpd_hardware *);
static
struct lldpd_hardware	*lldpd_port_add(struct lldpd *, struct ifaddrs *);
static void		 lldpd_loop(struct lldpd *);
static void		 lldpd_shutdown(int);
static void		 lldpd_exit();
static void		 lldpd_send_all(struct lldpd *);
static void		 lldpd_recv_all(struct lldpd *);
static int		 lldpd_guess_type(struct lldpd *, char *, int);
static void		 lldpd_decode(struct lldpd *, char *, int,
			    struct lldpd_hardware *, int);
#ifdef ENABLE_LLDPMED
static void		 lldpd_med(struct lldpd_chassis *);
#endif

static char		**saved_argv;

static void
usage(void)
{
	extern const char	*__progname;
	fprintf(stderr, "usage: %s [options]\n", __progname);
	fprintf(stderr, "see manual page lldpd(8) for more information\n");
	exit(1);
}

static void
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
		hardware->h_mtu = hardware->h_lport.p_mfs = ifr.ifr_mtu;
}

static int
lldpd_iface_init(struct lldpd *global, struct lldpd_hardware *hardware)
{
	int master;		/* Bond device */
	char if_bond[IFNAMSIZ];
	int status;
	short int filter;

	lldpd_iface_init_mtu(global, hardware);
	status = priv_iface_init(hardware, -1);
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
		status = priv_iface_init(hardware, master);
		if (status != 0) {
			close(hardware->h_raw_real);
			if (hardware->h_raw != -1)
				close(hardware->h_raw);
			return status;
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

static void
lldpd_iface_multicast(struct lldpd *global, const char *name, int remove)
{
	int i, rc;

	for (i=0; global->g_protocols[i].mode != 0; i++) {
		if (!global->g_protocols[i].enabled) continue;
		if ((rc = priv_iface_multicast(name,
			    global->g_protocols[i].mac, !remove)) != 0) {
			errno = rc;
			if (errno != ENOENT)
				LLOG_INFO("unable to %s %s address to multicast filter for %s",
				    (remove)?"delete":"add",
				    global->g_protocols[i].name,
				    name);
		}
	}
}

static int
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
	memcpy(listen, hardware->h_ifname, IFNAMSIZ);
	lldpd_iface_multicast(global, listen, 1);

	hardware->h_raw_real = -1;
	return 0;
}

static int
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

#ifdef ENABLE_DOT1
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
#endif

/* If `all' is true, clear all information, including information that
   are not refreshed periodically. If `all' is true, also free the
   port. */
void
lldpd_port_cleanup(struct lldpd_port *port, int all)
{
#ifdef ENABLE_LLDPMED
	int i;
	if (all)
		for (i=0; i < LLDPMED_LOCFORMAT_LAST; i++)
			free(port->p_med_location[i].data);
#endif
#ifdef ENABLE_DOT1
	lldpd_vlan_cleanup(port);
#endif
	free(port->p_id);
	free(port->p_descr);
	if (all)
		free(port);
}

void
lldpd_chassis_cleanup(struct lldpd_chassis *chassis)
{
#ifdef ENABLE_LLDPMED
	free(chassis->c_med_hw);
	free(chassis->c_med_sw);
	free(chassis->c_med_fw);
	free(chassis->c_med_sn);
	free(chassis->c_med_manuf);
	free(chassis->c_med_model);
	free(chassis->c_med_asset);
#endif
	free(chassis->c_id);
	free(chassis->c_name);
	free(chassis->c_descr);
	free(chassis);
}

void
lldpd_remote_cleanup(struct lldpd *cfg, struct lldpd_hardware *hardware, int reset)
{
	if (hardware->h_rport != NULL) {
		lldpd_port_cleanup(hardware->h_rport, 1);
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
lldpd_hardware_cleanup(struct lldpd_hardware *hardware)
{
	lldpd_port_cleanup(&hardware->h_lport, 1);
	free(hardware->h_proto_macs);
	free(hardware->h_llastframe);
	free(hardware);
}

void
lldpd_cleanup(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware, *hardware_next;

	for (hardware = TAILQ_FIRST(&cfg->g_hardware); hardware != NULL;
	     hardware = hardware_next) {
		hardware_next = TAILQ_NEXT(hardware, h_entries);
		if (hardware->h_flags == 0) {
			TAILQ_REMOVE(&cfg->g_hardware, hardware, h_entries);
			lldpd_iface_close(cfg, hardware);
			lldpd_remote_cleanup(cfg, hardware, 0);
			lldpd_hardware_cleanup(hardware);
		} else if (hardware->h_rchassis != NULL) {
			if (time(NULL) - hardware->h_rlastupdate >
			    hardware->h_rchassis->c_ttl) {
				lldpd_remote_cleanup(cfg, hardware, 1);
				hardware->h_rx_ageout_cnt++;
			}
		}
	}
}

static struct lldpd_hardware *
lldpd_port_add(struct lldpd *cfg, struct ifaddrs *ifa)
{
#if defined (ENABLE_DOT1) || defined (ENABLE_DOT3)
	struct ifaddrs *oifap, *oifa;
#endif
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
#ifdef ENABLE_DOT1
	struct lldpd_vlan *vlan;
	struct vlan_ioctl_args ifv;
#endif
#ifdef ENABLE_DOT3
	struct ethtool_cmd ethc;
#endif
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
#ifdef ENABLE_LLDPMED
		if (cfg->g_lchassis.c_med_cap_available) {
			hardware->h_lport.p_med_cap_enabled = LLDPMED_CAP_CAP;
			if (!cfg->g_noinventory)
				hardware->h_lport.p_med_cap_enabled |= LLDPMED_CAP_IV;
		}
#endif
#ifdef ENABLE_DOT1
		TAILQ_INIT(&hardware->h_lport.p_vlans);
	} else {
		lldpd_port_cleanup(&hardware->h_lport, 0);
#endif
	}

	port = &hardware->h_lport;
	hardware->h_flags = ifa->ifa_flags;

	strlcpy(hardware->h_ifname, ifa->ifa_name, sizeof(hardware->h_ifname));
	lladdr = (u_int8_t*)(((struct sockaddr_ll *)ifa->ifa_addr)->sll_addr);
	memcpy(&hardware->h_lladdr, lladdr, sizeof(hardware->h_lladdr));
	iface_get_permanent_mac(cfg, hardware);
	port->p_id_subtype = LLDP_PORTID_SUBTYPE_LLADDR;
	if ((port->p_id = calloc(1, sizeof(hardware->h_lladdr))) == NULL)
		fatal(NULL);
	memcpy(port->p_id, hardware->h_lladdr, sizeof(hardware->h_lladdr));
	port->p_id_len = sizeof(hardware->h_lladdr);
	port->p_descr = strdup(hardware->h_ifname);

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
#if defined (ENABLE_DOT3) || defined (ENABLE_DOT1)
	if (getifaddrs(&oifap) != 0)
		fatal("lldpd_port_add: failed to get interface list");
	for (oifa = oifap; oifa != NULL; oifa = oifa->ifa_next) {
#ifdef ENABLE_DOT1
		/* Check if we already have checked this one */
		int skip = 0;
		TAILQ_FOREACH(vlan, &port->p_vlans, v_entries) {
			if (strcmp(vlan->v_name, oifa->ifa_name) == 0) {
				skip = 1;
				break;
			}
		}
		if (skip) continue;
#endif

		/* Aggregation check */
#ifdef ENABLE_DOT3
		if (iface_is_bond_slave(cfg, hardware->h_ifname, oifa->ifa_name, NULL))
			port->p_aggregid = if_nametoindex(oifa->ifa_name);
#endif

#ifdef ENABLE_DOT1	
		/* VLAN check */
		memset(&ifv, 0, sizeof(ifv));
		ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
		strlcpy(ifv.device1, oifa->ifa_name, sizeof(ifv.device1));
		if ((ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) >= 0) &&
		    ((iface_is_bond_slave(cfg, hardware->h_ifname, ifv.u.device2, NULL)) ||
		     (iface_is_bridged_to(cfg, hardware->h_ifname, ifv.u.device2)) ||
		     (strncmp(hardware->h_ifname, ifv.u.device2, sizeof(ifv.u.device2)) == 0))) {
			if ((vlan = (struct lldpd_vlan *)
			     calloc(1, sizeof(struct lldpd_vlan))) == NULL)
				continue;
			if ((vlan->v_name = strdup(oifa->ifa_name)) == NULL) {
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
#endif
	}
	freeifaddrs(oifap);
#endif

#ifdef ENABLE_DOT3
	/* MAC/PHY */
	if (priv_ethtool(hardware->h_ifname, &ethc) == 0) {
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
	} else
		LLOG_DEBUG("unable to get eth info for %s", hardware->h_ifname);
#endif

	if (!INTERFACE_OPENED(hardware)) {

		if (lldpd_iface_init(cfg, hardware) != 0) {
			LLOG_WARN("unable to initialize %s", hardware->h_ifname);
			lldpd_hardware_cleanup(hardware);
			return (NULL);
		}

		TAILQ_INSERT_TAIL(&cfg->g_hardware, hardware, h_entries);
	}

	return (hardware);
}

static int
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

static void
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
	if ((s >= sizeof(struct ethhdr)) &&
	    (((struct ethhdr*)frame)->h_proto == htons(ETHERTYPE_VLAN)))
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
	lldpd_port_cleanup(port, 1);
	return;
}

static void
lldpd_recv_all(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
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
			if (((hardware->h_flags & IFF_UP) == 0) ||
			    ((hardware->h_flags & IFF_RUNNING) == 0))
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

static void
lldpd_send_all(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
	u_int8_t saved_lladdr[ETHER_ADDR_LEN];
	int i, altermac;

	cfg->g_lastsent = time(NULL);
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		/* Ignore if interface is down */
		if (((hardware->h_flags & IFF_UP) == 0) ||
		    ((hardware->h_flags & IFF_RUNNING) == 0))
			continue;

		/* When sending on inactive slaves, just send using a 0:0:0:0:0:0 address */
		altermac = 0;
		if ((hardware->h_raw_real > 0) &&
		    (!iface_is_slave_active(cfg, hardware->h_master,
			hardware->h_ifname))) {
			altermac = 1;
			memcpy(saved_lladdr, hardware->h_lladdr, ETHER_ADDR_LEN);
			memset(hardware->h_lladdr, 0, ETHER_ADDR_LEN);
		}

		for (i=0; cfg->g_protocols[i].mode != 0; i++) {
			if (!cfg->g_protocols[i].enabled)
				continue;
			if ((hardware->h_mode == cfg->g_protocols[i].mode) ||
			    (cfg->g_protocols[i].mode == LLDPD_MODE_LLDP))
				cfg->g_protocols[i].send(cfg, &cfg->g_lchassis, hardware);
		}
		/* Restore MAC if needed */
		if (altermac)
			memcpy(hardware->h_lladdr, saved_lladdr, ETHER_ADDR_LEN);
	}
}

#ifdef ENABLE_LLDPMED
static void
lldpd_med(struct lldpd_chassis *chassis)
{
	free(chassis->c_med_hw);
	free(chassis->c_med_fw);
	free(chassis->c_med_sn);
	free(chassis->c_med_manuf);
	free(chassis->c_med_model);
	free(chassis->c_med_asset);
	chassis->c_med_hw = dmi_hw();
	chassis->c_med_fw = dmi_fw();
	chassis->c_med_sn = dmi_sn();
	chassis->c_med_manuf = dmi_manuf();
	chassis->c_med_model = dmi_model();
	chassis->c_med_asset = dmi_asset();
}
#endif

static void
lldpd_loop(struct lldpd *cfg)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_ll *sdl;
	struct lldpd_hardware *hardware;
	int f;
	char status;
	struct utsname *un;
	char *hp;

	/* Set system name and description */
	if ((un = (struct utsname*)malloc(sizeof(struct utsname))) == NULL)
		fatal(NULL);
	if (uname(un) != 0)
		fatal("failed to get system information");
	if ((hp = priv_gethostbyname()) == NULL)
		fatal("failed to get system name");
	free(cfg->g_lchassis.c_name);
	free(cfg->g_lchassis.c_descr);
	if ((cfg->g_lchassis.c_name = strdup(hp)) == NULL)
		fatal(NULL);
	if (asprintf(&cfg->g_lchassis.c_descr, "%s %s %s %s",
		un->sysname, un->release, un->version, un->machine) == -1)
		fatal("failed to set system description");

	/* Check forwarding */
	cfg->g_lchassis.c_cap_enabled = 0;
	if ((f = priv_open("/proc/sys/net/ipv4/ip_forward")) >= 0) {
		if ((read(f, &status, 1) == 1) && (status == '1')) {
			cfg->g_lchassis.c_cap_enabled = LLDP_CAP_ROUTER;
		}
		close(f);
	}
#ifdef ENABLE_LLDPMED
	if (cfg->g_lchassis.c_cap_available & LLDP_CAP_TELEPHONE)
		cfg->g_lchassis.c_cap_enabled |= LLDP_CAP_TELEPHONE;
	lldpd_med(&cfg->g_lchassis);
	free(cfg->g_lchassis.c_med_sw);
	cfg->g_lchassis.c_med_sw = strdup(un->release);
#endif
	free(un);

	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries)
	    hardware->h_flags = 0;

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

                if (!(ifa->ifa_flags & (IFF_MULTICAST|IFF_BROADCAST)))
                        continue;

		if (iface_is_wireless(cfg, ifa->ifa_name))
			cfg->g_lchassis.c_cap_enabled |= LLDP_CAP_WLAN;

		if (lldpd_port_add(cfg, ifa) == NULL)
			LLOG_WARNX("failed to allocate port %s, skip it",
				ifa->ifa_name);
	}

	freeifaddrs(ifap);

	lldpd_cleanup(cfg);

	lldpd_send_all(cfg);
	lldpd_recv_all(cfg);
}

static void
lldpd_shutdown(int sig)
{
	LLOG_INFO("signal received, exiting");
	exit(0);
}

/* For signal handling */
static struct lldpd *gcfg = NULL;

static void
lldpd_exit()
{
	struct lldpd_hardware *hardware;
	close(gcfg->g_ctl);
	priv_ctl_cleanup();
	TAILQ_FOREACH(hardware, &gcfg->g_hardware, h_entries) {
		if (INTERFACE_OPENED(hardware))
			lldpd_iface_close(gcfg, hardware);
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
	int ch, debug = 0;
#ifdef USE_SNMP
	int snmp = 0;
#endif
	char *mgmtp = NULL;
	char *popt, opts[] = "dxm:p:M:i@                    ";
	int probe = 0, i, found;
#ifdef ENABLE_LLDPMED
	int lldpmed = 0, noinventory = 0;
#endif

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
		case 'd':
			debug++;
			break;
		case 'm':
			mgmtp = optarg;
			break;
#ifdef ENABLE_LLDPMED
		case 'M':
			lldpmed = atoi(optarg);
			if ((lldpmed < 1) || (lldpmed > 4)) {
				fprintf(stderr, "-M requires an argument between 1 and 4\n");
				usage();
			}
			break;
		case 'i':
			noinventory = 1;
			break;
#else
		case 'M':
		case 'i':
		case 'P':
			fprintf(stderr, "LLDP-MED support is not built-in\n");
			usage();
			break;
#endif
		case 'p':
			probe = atoi(optarg);
			break;
		case 'x':
#ifdef USE_SNMP
			snmp = 1;
#else
			fprintf(stderr, "SNMP support is not built-in\n");
			usage();
#endif
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

	if (!debug) {
		int pid;
		char *spid;
		if (daemon(0, 0) != 0)
			fatal("failed to detach daemon");
		if ((pid = open(LLDPD_PID_FILE,
			    O_TRUNC | O_CREAT | O_WRONLY, 0644)) == -1)
			fatal("unable to open pid file " LLDPD_PID_FILE);
		if (asprintf(&spid, "%d\n", getpid()) == -1)
			fatal("unable to create pid file " LLDPD_PID_FILE);
		if (write(pid, spid, strlen(spid)) == -1)
			fatal("unable to write pid file " LLDPD_PID_FILE);
		free(spid);
		close(pid);
	}

	priv_init(PRIVSEP_CHROOT);

	if (probe == 0) probe = LLDPD_TTL;

	if ((cfg = (struct lldpd *)
	    calloc(1, sizeof(struct lldpd))) == NULL)
		fatal(NULL);

	cfg->g_mgmt_pattern = mgmtp;

	/* Get ioctl socket */
	if ((cfg->g_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("failed to get ioctl socket");
	cfg->g_delay = LLDPD_TX_DELAY;

	/* Set system capabilities */
	cfg->g_lchassis.c_cap_available = LLDP_CAP_BRIDGE | LLDP_CAP_WLAN |
	    LLDP_CAP_ROUTER;
#ifdef ENABLE_LLDPMED
	if (lldpmed > 0) {
		if (lldpmed == LLDPMED_CLASS_III)
			cfg->g_lchassis.c_cap_available |= LLDP_CAP_TELEPHONE;
		cfg->g_lchassis.c_med_type = lldpmed;
		cfg->g_lchassis.c_med_cap_available = LLDPMED_CAP_CAP |
		    LLDPMED_CAP_IV | LLDPMED_CAP_LOCATION;
		cfg->g_noinventory = noinventory;
	} else
		cfg->g_noinventory = 1;
#endif

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

#ifdef USE_SNMP
	if (snmp) {
		cfg->g_snmp = 1;
		agent_init(cfg, debug);
	}
#endif /* USE_SNMP */

	/* Create socket */
	if ((cfg->g_ctl = priv_ctl_create(cfg)) == -1)
		fatalx("unable to create control socket " LLDPD_CTL_SOCKET);
	TAILQ_INIT(&cfg->g_clients);

	gcfg = cfg;
	if (atexit(lldpd_exit) != 0) {
		close(cfg->g_ctl);
		priv_ctl_cleanup();
		fatal("unable to set exit function");
	}

	/* Signal handling */
	signal(SIGHUP, lldpd_shutdown);
	signal(SIGINT, lldpd_shutdown);
	signal(SIGTERM, lldpd_shutdown);

	for (;;)
		lldpd_loop(cfg);

	return (0);
}
