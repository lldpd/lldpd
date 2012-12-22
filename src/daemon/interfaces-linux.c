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

#include "lldpd.h"

#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/if_bonding.h>
#include <linux/if_bridge.h>
#include <linux/wireless.h>
#include <linux/sockios.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/ethtool.h>

#define SYSFS_PATH_MAX 256
#define MAX_PORTS 1024
#define MAX_BRIDGES 1024

/* BPF filter to get revelant information from interfaces */
/* LLDP: "ether proto 0x88cc and ether dst 01:80:c2:00:00:0e" */
/* FDP: "ether dst 01:e0:52:cc:cc:cc" */
/* CDP: "ether dst 01:00:0c:cc:cc:cc" */
/* SONMP: "ether dst 01:00:81:00:01:00" */
/* EDP: "ether dst 00:e0:2b:00:00:00" */
/* For optimization purpose, we first check if the first bit of the
   first byte is 1. if not, this can only be an EDP packet:

   tcpdump -dd "(ether[0] & 1 = 1 and
                 ((ether proto 0x88cc and ether dst 01:80:c2:00:00:0e) or
                  (ether dst 01:e0:52:cc:cc:cc) or
                  (ether dst 01:00:0c:cc:cc:cc) or
                  (ether dst 01:00:81:00:01:00))) or
                (ether dst 00:e0:2b:00:00:00)"
*/

#define LLDPD_FILTER_F				\
	{ 0x30, 0, 0, 0x00000000 },		\
	{ 0x54, 0, 0, 0x00000001 },		\
	{ 0x15, 0, 14, 0x00000001 },		\
	{ 0x28, 0, 0, 0x0000000c },		\
	{ 0x15, 0, 4, 0x000088cc },		\
	{ 0x20, 0, 0, 0x00000002 },		\
	{ 0x15, 0, 2, 0xc200000e },		\
	{ 0x28, 0, 0, 0x00000000 },		\
	{ 0x15, 12, 13, 0x00000180 },		\
	{ 0x20, 0, 0, 0x00000002 },		\
	{ 0x15, 0, 2, 0x52cccccc },		\
	{ 0x28, 0, 0, 0x00000000 },		\
	{ 0x15, 8, 9, 0x000001e0 },		\
	{ 0x15, 1, 0, 0x0ccccccc },		\
	{ 0x15, 0, 2, 0x81000100 },		\
	{ 0x28, 0, 0, 0x00000000 },		\
	{ 0x15, 4, 5, 0x00000100 },		\
	{ 0x20, 0, 0, 0x00000002 },		\
	{ 0x15, 0, 3, 0x2b000000 },		\
	{ 0x28, 0, 0, 0x00000000 },		\
	{ 0x15, 0, 1, 0x000000e0 },		\
	{ 0x6, 0, 0, 0x0000ffff },		\
	{ 0x6, 0, 0, 0x00000000 },

static struct sock_filter lldpd_filter_f[] = { LLDPD_FILTER_F };

struct lldpd_ops eth_ops;
struct lldpd_ops bond_ops;

static int
pattern_match(char *iface, char *list, int found)
{
	char *interfaces = NULL;
	char *pattern;

	if ((interfaces = strdup(list)) == NULL) {
		log_warnx("interfaces", "unable to allocate memory");
		return 0;
	}

	for (pattern = strtok(interfaces, ",");
	     pattern != NULL;
	     pattern = strtok(NULL, ",")) {
		if ((pattern[0] == '!') &&
		    ((fnmatch(pattern + 1, iface, 0) == 0))) {
			/* Blacklisted. No need to search further. */
			found = 0;
			break;
		}
		if (fnmatch(pattern, iface, 0) == 0)
			found = 1;
	}

	free(interfaces);
	return found;
}

static struct netlink_interface*
iface_nametointerface(struct netlink_interface_list *interfaces,
    const char *device)
{
	struct netlink_interface *iface;
	TAILQ_FOREACH(iface, interfaces, next) {
		if (!strcmp(iface->name, device))
			return iface;
	}
	log_debug("interfaces", "cannot get interface for index %s",
	    device);
	return NULL;
}

static struct netlink_interface*
iface_indextointerface(struct netlink_interface_list *interfaces,
    int index)
{
	struct netlink_interface *iface;
	TAILQ_FOREACH(iface, interfaces, next) {
		if (iface->index == index)
			return iface;
	}
	log_debug("interfaces", "cannot get interface for index %d",
	    index);
	return NULL;
}

#ifdef ENABLE_OLDIES
static int
iface_indextoname(struct netlink_interface_list *interfaces,
    int index, char *name)
{
	struct netlink_interface *iface =
	    iface_indextointerface(interfaces, index);
	if (iface == NULL) return -1;
	strncpy(name, iface->name, IFNAMSIZ);
	return 0;
}
#endif

static int
old_iface_is_bridge(struct lldpd *cfg,
    struct netlink_interface_list *interfaces,
    struct netlink_interface *iface)
{
#ifdef ENABLE_OLDIES
	int ifindices[MAX_BRIDGES];
	char ifname[IFNAMSIZ];
	int num, i;
	unsigned long args[3] = { BRCTL_GET_BRIDGES,
				  (unsigned long)ifindices, MAX_BRIDGES };
	if ((num = ioctl(cfg->g_sock, SIOCGIFBR, args)) < 0)
		/* This can happen with a 64bit kernel and 32bit
		   userland, don't output anything about this to avoid
		   to fill logs. */
		return 0;
	for (i = 0; i < num; i++) {
		if (iface_indextoname(interfaces, ifindices[i], ifname) == -1)
			log_info("interfaces", "unable to get name of interface %d",
			    ifindices[i]);
		else if (strncmp(iface->name, ifname, IFNAMSIZ) == 0)
			return 1;
	}
#endif
	return 0;
}

static int
iface_is_bridge(struct lldpd *cfg,
    struct netlink_interface_list *interfaces,
    struct netlink_interface *iface)
{
	char path[SYSFS_PATH_MAX];
	int f;

	if ((snprintf(path, SYSFS_PATH_MAX,
		    SYSFS_CLASS_NET "%s/" SYSFS_BRIDGE_FDB,
		    iface->name)) >= SYSFS_PATH_MAX)
		log_warnx("interfaces", "path truncated");
	if ((f = priv_open(path)) < 0) {
		return old_iface_is_bridge(cfg, interfaces, iface);
	}
	close(f);
	return 1;
}

#ifdef ENABLE_DOT1
static int
old_iface_is_bridged_to(struct lldpd *cfg,
    struct netlink_interface_list *interfaces,
    struct netlink_interface *slave,
    struct netlink_interface *master)
{
#ifdef ENABLE_OLDIES
	int j;
	int ifptindices[MAX_PORTS];
	unsigned long args2[4] = { BRCTL_GET_PORT_LIST,
				   (unsigned long)ifptindices, MAX_PORTS, 0 };
	struct ifreq ifr;
	if (slave->index == 0) return 0;

	strncpy(ifr.ifr_name, master->name, IFNAMSIZ);
	memset(ifptindices, 0, sizeof(ifptindices));
	ifr.ifr_data = (char *)&args2;

	if (ioctl(cfg->g_sock, SIOCDEVPRIVATE, &ifr) < 0)
		/* This can happen with a 64bit kernel and 32bit
		   userland, don't output anything about this to avoid
		   to fill logs. */
		return 0;

	for (j = 0; j < MAX_PORTS; j++) {
		if (ifptindices[j] == slave->index)
			return 1;
	}
#endif
	return 0;
}

static int
iface_is_bridged_to(struct lldpd *cfg,
    struct netlink_interface_list *interfaces,
    struct netlink_interface *slave,
    struct netlink_interface *master)
{
	char path[SYSFS_PATH_MAX];
	int f;

	/* Master should be a bridge, first */
	if (!iface_is_bridge(cfg, interfaces, master)) return 0;

	if (snprintf(path, SYSFS_PATH_MAX,
		SYSFS_CLASS_NET "%s/" SYSFS_BRIDGE_PORT_SUBDIR "/%s/port_no",
		master->name, slave->name) >= SYSFS_PATH_MAX)
		log_warnx("interfaces", "path truncated");
	if ((f = priv_open(path)) < 0) {
		return old_iface_is_bridged_to(cfg, interfaces, slave, master);
	}
	close(f);
	return 1;
}
#endif

static int
iface_is_vlan(struct lldpd *cfg,
	struct netlink_interface *iface)
{
	struct vlan_ioctl_args ifv;
	memset(&ifv, 0, sizeof(ifv));
	ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
	if ((strlcpy(ifv.device1, iface->name, sizeof(ifv.device1))) >=
	    sizeof(ifv.device1))
		log_warnx("interfaces", "device name truncated");
	if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) >= 0)
		return 1;
	return 0;
}

static int
iface_is_wireless(struct lldpd *cfg,
    struct netlink_interface *iface)
{
	struct iwreq iwr;
	strlcpy(iwr.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(cfg->g_sock, SIOCGIWNAME, &iwr) >= 0)
		return 1;
	return 0;
}

static int
iface_is_bond(struct lldpd *cfg,
    struct netlink_interface *iface)
{
	struct ifreq ifr;
	struct ifbond ifb;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifb, 0, sizeof(ifb));
	strlcpy(ifr.ifr_name, iface->name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (char *)&ifb;
	if (ioctl(cfg->g_sock, SIOCBONDINFOQUERY, &ifr) >= 0)
		return 1;
	return 0;
}

static int
iface_is_bond_slave(struct lldpd *cfg,
    struct netlink_interface *slave,
    struct netlink_interface *master,
    int *active)
{
	struct ifreq ifr;
	struct ifbond ifb;
	struct ifslave ifs;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifb, 0, sizeof(ifb));
	strlcpy(ifr.ifr_name, master->name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (char *)&ifb;
	if (ioctl(cfg->g_sock, SIOCBONDINFOQUERY, &ifr) >= 0) {
		while (ifb.num_slaves--) {
			memset(&ifr, 0, sizeof(ifr));
			memset(&ifs, 0, sizeof(ifs));
			strlcpy(ifr.ifr_name, master->name, sizeof(ifr.ifr_name));
			ifr.ifr_data = (char *)&ifs;
			ifs.slave_id = ifb.num_slaves;
			if ((ioctl(cfg->g_sock, SIOCBONDSLAVEINFOQUERY, &ifr) >= 0) &&
			    (strncmp(ifs.slave_name, slave->name, sizeof(ifs.slave_name)) == 0)) {
				if (active)
					*active = ifs.state;
				return 1;
			}
		}
	}
	return 0;
}

static struct netlink_interface*
iface_is_enslaved(struct lldpd *cfg,
    struct netlink_interface_list *interfaces,
    struct netlink_interface *iface)
{
	struct netlink_interface *master;

	TAILQ_FOREACH(master, interfaces, next) {
		if (iface_is_bond_slave(cfg, iface, master, NULL))
			return master;
	}
	return NULL;
}

static void
iface_get_permanent_mac(struct lldpd *cfg,
    struct netlink_interface_list *interfaces,
    struct netlink_interface *iface,
    struct lldpd_hardware *hardware)
{
	struct netlink_interface *master;
	int f, state = 0;
	FILE *netbond;
	const char *slaveif = "Slave Interface: ";
	const char *hwaddr = "Permanent HW addr: ";
	u_int8_t mac[ETHER_ADDR_LEN];
	char path[SYSFS_PATH_MAX];
	char line[100];

	if ((master = iface_is_enslaved(cfg, interfaces,
		    iface)) == NULL)
		return;

	log_debug("interfaces", "get MAC address for %s",
	    hardware->h_ifname);

	/* We have a bond, we need to query it to get real MAC addresses */
	if (snprintf(path, SYSFS_PATH_MAX, "/proc/net/bonding/%s",
		master->name) >= SYSFS_PATH_MAX) {
		log_warnx("interfaces", "path truncated");
		return;
	}
	if ((f = priv_open(path)) < 0) {
		if (snprintf(path, SYSFS_PATH_MAX, "/proc/self/net/bonding/%s",
			master->name) >= SYSFS_PATH_MAX) {
			log_warnx("interfaces", "path truncated");
			return;
		}
		f = priv_open(path);
	}
	if (f < 0) {
		log_warnx("interfaces",
		    "unable to find %s in /proc/net/bonding or /proc/self/net/bonding",
		    master->name);
		return;
	}
	if ((netbond = fdopen(f, "r")) == NULL) {
		log_warn("interfaces", "unable to read stream from %s", path);
		close(f);
		return;
	}
	/* State 0:
	     We parse the file to search "Slave Interface: ". If found, go to
	     state 1.
	   State 1:
	     We parse the file to search "Permanent HW addr: ". If found, we get
	     the mac.
	*/
	while (fgets(line, sizeof(line), netbond)) {
		switch (state) {
		case 0:
			if (strncmp(line, slaveif, strlen(slaveif)) == 0) {
				if (line[strlen(line)-1] == '\n')
					line[strlen(line)-1] = '\0';
				if (strcmp(iface->name,
					line + strlen(slaveif)) == 0)
					state++;
			}
			break;
		case 1:
			if (strncmp(line, hwaddr, strlen(hwaddr)) == 0) {
				if (line[strlen(line)-1] == '\n')
					line[strlen(line)-1] = '\0';
				if (sscanf(line + strlen(hwaddr),
					"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
					&mac[0], &mac[1], &mac[2],
					&mac[3], &mac[4], &mac[5]) !=
				    ETHER_ADDR_LEN) {
					log_warn("interfaces", "unable to parse %s",
					    line + strlen(hwaddr));
					fclose(netbond);
					return;
				}
				memcpy(hardware->h_lladdr, mac,
				    ETHER_ADDR_LEN);
				fclose(netbond);
				return;
			}
			break;
		}
	}
	log_warnx("interfaces", "unable to find real mac address for %s",
	    iface->name);
	fclose(netbond);
}

/* Generic minimal checks to handle a given interface. */
static int
iface_minimal_checks(struct lldpd *cfg,
    struct netlink_interface_list *interfaces,
    struct netlink_interface *iface)
{
	struct ifreq ifr;
	struct ethtool_drvinfo ethc;
	const char * const *rif;

	/* White-list some drivers */
	const char * const regular_interfaces[] = {
		"dsa",
		"veth",
		NULL
	};

	int is_bridge = iface_is_bridge(cfg, interfaces, iface);

	log_debug("interfaces", "minimal checks for %s", iface->name);

	if (!(LOCAL_CHASSIS(cfg)->c_cap_enabled & LLDP_CAP_BRIDGE) &&
	    is_bridge) {
		log_debug("interfaces", "skip %s: is a bridge",
		    iface->name);
		LOCAL_CHASSIS(cfg)->c_cap_enabled |= LLDP_CAP_BRIDGE;
		return 0;
	}

	if (!(LOCAL_CHASSIS(cfg)->c_cap_enabled & LLDP_CAP_WLAN) &&
	    iface_is_wireless(cfg, iface))
		LOCAL_CHASSIS(cfg)->c_cap_enabled |= LLDP_CAP_WLAN;

	/* First, check if this interface has already been handled */
	if (!iface->flags) {
		log_debug("interfaces", "skip %s: already been handled",
		    iface->name);
		return 0;
	}

	if (iface->type != ARPHRD_ETHER) {
		log_debug("interfaces", "skip %s: not an Ethernet device",
		    iface->name);
		return 0;
	}

	/* We request that the interface is able to do either multicast
	 * or broadcast to be able to send discovery frames. */
	if (!(iface->flags & (IFF_MULTICAST|IFF_BROADCAST))) {
		log_debug("interfaces", "skip %s: not able to do multicast nor broadcast",
		    iface->name);
		return 0;
	}

	/* If the interface is linked to another one, skip it too. */
	if (iface->link != -1 && iface->index != iface->link) {
		log_debug("interfaces", "skip %s: there is a lower interface (%d)",
		    iface->name, iface->link);
		return 0;
	}

	/* Check if the driver is whitelisted */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, iface->name);
	memset(&ethc, 0, sizeof(ethc));
	ifr.ifr_data = (caddr_t) &ethc;
	ethc.cmd = ETHTOOL_GDRVINFO;
	if (ioctl(cfg->g_sock, SIOCETHTOOL, &ifr) == 0) {
		for (rif = regular_interfaces; *rif; rif++) {
			if (strcmp(ethc.driver, *rif) == 0) {
				/* White listed! */
				log_debug("interfaces", "accept %s: whitelisted",
				    iface->name);
				return 1;
			}
		}
	}
	log_debug("interfaces", "keep checking %s: not whitelisted",
	    iface->name);

	/* Check queue len. If no queue, this usually means that this
	   is not a "real" interface. */
	if (iface->txqueue == 0) {
		log_debug("interfaces", "skip %s: no queue",
		    iface->name);
		return 0;
	}

	/* Don't handle bond and VLAN, nor bridge  */
	if (iface_is_vlan(cfg, iface)) {
		log_debug("interfaces", "skip %s: is a VLAN",
		    iface->name);
		return 0;
	}
	if (iface_is_bond(cfg, iface)) {
		log_debug("interfaces", "skip %s: is a bond",
		    iface->name);
		return 0;
	}
	if (is_bridge) {
		log_debug("interfaces", "skip %s: is a bridge",
		    iface->name);
		return 0;
	}

	log_debug("interfaces", "%s passes the minimal checks",
	    iface->name);
	return 1;
}

static int
iface_set_filter(const char *name, int fd)
{
	struct sock_fprog prog;
	log_debug("interfaces", "set BPF filter for %s", name);

	memset(&prog, 0, sizeof(struct sock_fprog));
	prog.filter = lldpd_filter_f;
	prog.len = sizeof(lldpd_filter_f) / sizeof(struct sock_filter);

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
                &prog, sizeof(prog)) < 0) {
		log_info("interfaces", "unable to change filter for %s", name);
		return ENETDOWN;
	}
	return 0;
}

/* Fill up port name and description */
static void
iface_port_name_desc(struct lldpd_hardware *hardware,
    struct netlink_interface *iface)
{
	struct lldpd_port *port = &hardware->h_lport;

	/* There are two cases:

	     1. We have a kernel recent enough to support ifAlias
	     _and_ a non empty ifAlias, then we will use it for
	     description and use ifname for port ID.

	     2. Otherwise, we will use the MAC address as ID and the
	     port name in description.
	*/

	if (iface->alias == NULL || strlen(iface->alias) == 0) {
		/* Case 2: MAC address and port name */
		log_debug("interfaces", "use ifname and MAC address for %s",
		    hardware->h_ifname);
		port->p_id_subtype = LLDP_PORTID_SUBTYPE_LLADDR;
		if ((port->p_id =
			calloc(1, sizeof(hardware->h_lladdr))) == NULL)
			fatal("interfaces", NULL);
		memcpy(port->p_id, hardware->h_lladdr,
		    sizeof(hardware->h_lladdr));
		port->p_id_len = sizeof(hardware->h_lladdr);
		port->p_descr = strdup(hardware->h_ifname);
		return;
	}
	/* Case 1: port name and port description */
	log_debug("interfaces", "use ifname and ifalias for %s",
	    hardware->h_ifname);
	port->p_id_subtype = LLDP_PORTID_SUBTYPE_IFNAME;
	port->p_id_len = strlen(hardware->h_ifname);
	if ((port->p_id =
		calloc(1, port->p_id_len)) == NULL)
		fatal("interfaces", NULL);
	memcpy(port->p_id, hardware->h_ifname, port->p_id_len);
	port->p_descr = strdup(iface->alias);
}

/* Fill up MAC/PHY for a given hardware port */
static void
iface_macphy(struct lldpd_hardware *hardware)
{
#ifdef ENABLE_DOT3
	struct ethtool_cmd ethc;
	struct lldpd_port *port = &hardware->h_lport;
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

	log_debug("interfaces", "ask ethtool for the appropriate MAC/PHY for %s",
	    hardware->h_ifname);
	if (priv_ethtool(hardware->h_ifname, &ethc, sizeof(struct ethtool_cmd)) == 0) {
		port->p_macphy.autoneg_support = (ethc.supported & SUPPORTED_Autoneg) ? 1 : 0;
		port->p_macphy.autoneg_enabled = (ethc.autoneg == AUTONEG_DISABLE) ? 0 : 1;
		for (j=0; advertised_ethtool_to_rfc3636[j][0]; j++) {
			if (ethc.advertising & advertised_ethtool_to_rfc3636[j][0])
				port->p_macphy.autoneg_advertised |= 
				    advertised_ethtool_to_rfc3636[j][1];
		}
		switch (ethc.speed) {
		case SPEED_10:
			port->p_macphy.mau_type = (ethc.duplex == DUPLEX_FULL) ? \
			    LLDP_DOT3_MAU_10BASETFD : LLDP_DOT3_MAU_10BASETHD;
			if (ethc.port == PORT_BNC) port->p_macphy.mau_type = LLDP_DOT3_MAU_10BASE2;
			if (ethc.port == PORT_FIBRE)
				port->p_macphy.mau_type = (ethc.duplex == DUPLEX_FULL) ? \
				    LLDP_DOT3_MAU_10BASEFLDF : LLDP_DOT3_MAU_10BASEFLHD;
			break;
		case SPEED_100:
			port->p_macphy.mau_type = (ethc.duplex == DUPLEX_FULL) ? \
			    LLDP_DOT3_MAU_100BASETXFD : LLDP_DOT3_MAU_100BASETXHD;
			if (ethc.port == PORT_BNC)
				port->p_macphy.mau_type = (ethc.duplex == DUPLEX_FULL) ? \
				    LLDP_DOT3_MAU_100BASET2FD : LLDP_DOT3_MAU_100BASET2HD;
			if (ethc.port == PORT_FIBRE)
				port->p_macphy.mau_type = (ethc.duplex == DUPLEX_FULL) ? \
				    LLDP_DOT3_MAU_100BASEFXFD : LLDP_DOT3_MAU_100BASEFXHD;
			break;
		case SPEED_1000:
			port->p_macphy.mau_type = (ethc.duplex == DUPLEX_FULL) ? \
			    LLDP_DOT3_MAU_1000BASETFD : LLDP_DOT3_MAU_1000BASETHD;
			if (ethc.port == PORT_FIBRE)
				port->p_macphy.mau_type = (ethc.duplex == DUPLEX_FULL) ? \
				    LLDP_DOT3_MAU_1000BASEXFD : LLDP_DOT3_MAU_1000BASEXHD;
			break;
		case SPEED_10000:
			port->p_macphy.mau_type = (ethc.port == PORT_FIBRE) ?	\
					LLDP_DOT3_MAU_10GIGBASEX : LLDP_DOT3_MAU_10GIGBASER;
			break;
		}
		if (ethc.port == PORT_AUI) port->p_macphy.mau_type = LLDP_DOT3_MAU_AUI;
	}
#endif
}

static void
iface_multicast(struct lldpd *cfg, const char *name, int remove)
{
	int i, rc;

	for (i=0; cfg->g_protocols[i].mode != 0; i++) {
		if (!cfg->g_protocols[i].enabled) continue;
		if ((rc = priv_iface_multicast(name,
			    cfg->g_protocols[i].mac, !remove)) != 0) {
			errno = rc;
			if (errno != ENOENT)
				log_info("interfaces", "unable to %s %s address to multicast filter for %s",
				    (remove)?"delete":"add",
				    cfg->g_protocols[i].name,
				    name);
		}
	}
}

static int
iface_eth_init(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	int fd, status;

	log_debug("interfaces", "initialize ethernet device %s",
	    hardware->h_ifname);
	if ((fd = priv_iface_init(hardware->h_ifindex)) == -1)
		return -1;
	hardware->h_sendfd = fd; /* Send */

	/* Set filter */
	if ((status = iface_set_filter(hardware->h_ifname, fd)) != 0) {
		close(fd);
		return status;
	}

	iface_multicast(cfg, hardware->h_ifname, 0);

	levent_hardware_add_fd(hardware, fd); /* Receive */
	log_debug("interfaces", "interface %s initialized (fd=%d)", hardware->h_ifname,
	    fd);
	return 0;
}

static int
iface_eth_send(struct lldpd *cfg, struct lldpd_hardware *hardware,
    char *buffer, size_t size)
{
	log_debug("interfaces", "send PDU to ethernet device %s (fd=%d)",
	    hardware->h_ifname, hardware->h_sendfd);
	return write(hardware->h_sendfd,
	    buffer, size);
}

static int
iface_eth_recv(struct lldpd *cfg, struct lldpd_hardware *hardware,
    int fd, char *buffer, size_t size)
{
	int n;
	struct sockaddr_ll from;
	socklen_t fromlen;

	log_debug("interfaces", "receive PDU from ethernet device %s",
	    hardware->h_ifname);
	fromlen = sizeof(from);
	if ((n = recvfrom(fd,
		    buffer,
		    size, 0,
		    (struct sockaddr *)&from,
		    &fromlen)) == -1) {
		log_warn("interfaces", "error while receiving frame on %s",
		    hardware->h_ifname);
		hardware->h_rx_discarded_cnt++;
		return -1;
	}
	if (from.sll_pkttype == PACKET_OUTGOING)
		return -1;
	return n;
}

static int
iface_eth_close(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	log_debug("interfaces", "close ethernet device %s",
	    hardware->h_ifname);
	iface_multicast(cfg, hardware->h_ifname, 1);
	return 0;
}

static void
lldpd_ifh_eth(struct lldpd *cfg, struct netlink_interface_list *interfaces)
{
	struct netlink_interface *iface;
	struct lldpd_hardware *hardware;

	TAILQ_FOREACH(iface, interfaces, next) {
		log_debug("interfaces", "check if %s is a real ethernet device",
		    iface->name);
		if (!iface_minimal_checks(cfg, interfaces, iface))
			continue;

		log_debug("interfaces", "%s is an acceptable ethernet device",
		    iface->name);
		if ((hardware = lldpd_get_hardware(cfg,
			    iface->name,
			    iface->index,
			    &eth_ops)) == NULL) {
			if  ((hardware = lldpd_alloc_hardware(cfg,
				    iface->name,
				    iface->index)) == NULL) {
				log_warnx("interfaces", "Unable to allocate space for %s",
				    iface->name);
				continue;
			}
			if (iface_eth_init(cfg, hardware) != 0) {
				log_warn("interfaces", "unable to initialize %s", hardware->h_ifname);
				lldpd_hardware_cleanup(cfg, hardware);
				continue;
			}
			hardware->h_ops = &eth_ops;
			TAILQ_INSERT_TAIL(&cfg->g_hardware, hardware, h_entries);
		} else {
			if (hardware->h_flags) continue; /* Already seen this time */
			lldpd_port_cleanup(&hardware->h_lport, 0);
		}

		hardware->h_flags = iface->flags;   /* Should be non-zero */
		iface->flags = 0;		    /* Future handlers
						       don't have to
						       care about this
						       interface. */

		/* Get local address */
		memcpy(&hardware->h_lladdr, iface->address, ETHER_ADDR_LEN);

		/* Fill information about port */
		iface_port_name_desc(hardware, iface);

		/* Fill additional info */
		iface_macphy(hardware);
		hardware->h_mtu = iface->mtu ? iface->mtu : 1500;
	}
}

static void
lldpd_ifh_whitelist(struct lldpd *cfg, struct netlink_interface_list *interfaces)
{
	struct netlink_interface *iface;

	if (!cfg->g_config.c_iface_pattern)
		return;

	TAILQ_FOREACH(iface, interfaces, next) {
		if (iface->flags == 0) continue; /* Already handled by someone else */
		if (!pattern_match(iface->name, cfg->g_config.c_iface_pattern, 0)) {
			/* This interface was not found. We flag it. */
			log_debug("interfaces", "blacklist %s", iface->name);
			iface->flags = 0;
		}
	}
}

struct bond_master {
	char name[IFNAMSIZ];
	int  index;
};

static int
iface_bond_init(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	struct bond_master *master = hardware->h_data;
	int fd, status;
	int un = 1;

	if (!master) return -1;

	log_debug("interfaces", "initialize bonded device %s",
	    hardware->h_ifname);

	/* First, we get a socket to the raw physical interface */
	if ((fd = priv_iface_init(hardware->h_ifindex)) == -1)
		return -1;
	hardware->h_sendfd = fd;
	if ((status = iface_set_filter(hardware->h_ifname, fd)) != 0) {
		close(fd);
		return status;
	}
	iface_multicast(cfg, hardware->h_ifname, 0);

	/* Then, we open a raw interface for the master */
	if ((fd = priv_iface_init(master->index)) == -1) {
		close(hardware->h_sendfd);
		return -1;
	}
	if ((status = iface_set_filter(master->name, fd)) != 0) {
		close(hardware->h_sendfd);
		close(fd);
		return status;
	}
	/* With bonding and older kernels (< 2.6.27) we need to listen
	 * to bond device. We use setsockopt() PACKET_ORIGDEV to get
	 * physical device instead of bond device (works with >=
	 * 2.6.24). */
	if (setsockopt(fd, SOL_PACKET,
		PACKET_ORIGDEV, &un, sizeof(un)) == -1) {
		log_info("interfaces", "unable to setsockopt for master bonding device of %s. "
		    "You will get inaccurate results",
		    hardware->h_ifname);
	}
	iface_multicast(cfg, master->name, 0);

	levent_hardware_add_fd(hardware, hardware->h_sendfd);
	levent_hardware_add_fd(hardware, fd);
	log_debug("interfaces", "interface %s initialized (fd=%d,master=%s[%d])",
	    hardware->h_ifname,
	    hardware->h_sendfd,
	    master->name, fd);
	return 0;
}

static int
iface_bond_send(struct lldpd *cfg, struct lldpd_hardware *hardware,
    char *buffer, size_t size)
{
	/* With bonds, we have duplicate MAC address on different physical
	 * interfaces. We need to alter the source MAC address when we send on
	 * an inactive slave. To avoid any future problem, we always set the
	 * source MAC address to 0. */
	log_debug("interfaces", "send PDU to bonded device %s",
	    hardware->h_ifname);
	if (size < 2 * ETH_ALEN) {
		log_warnx("interfaces",
		    "packet to send on %s is too small!",
		    hardware->h_ifname);
		return 0;
	}
	memset(buffer + ETH_ALEN, 0, ETH_ALEN);
	return write(hardware->h_sendfd,
	    buffer, size);
}

static int
iface_bond_recv(struct lldpd *cfg, struct lldpd_hardware *hardware,
    int fd, char *buffer, size_t size)
{
	int n;
	struct sockaddr_ll from;
	socklen_t fromlen;
	struct bond_master *master = hardware->h_data;

	log_debug("interfaces", "receive PDU from bonded device %s",
	    hardware->h_ifname);
	fromlen = sizeof(from);
	if ((n = recvfrom(fd, buffer, size, 0,
		    (struct sockaddr *)&from,
		    &fromlen)) == -1) {
		log_warn("interfaces", "error while receiving frame on %s",
		    hardware->h_ifname);
		hardware->h_rx_discarded_cnt++;
		return -1;
	}
	if (from.sll_pkttype == PACKET_OUTGOING)
		return -1;
	if (fd == hardware->h_sendfd)
		/* We received this on the physical interface. */
		return n;
	/* We received this on the bonding interface. Is it really for us? */
	if (from.sll_ifindex == hardware->h_ifindex)
		/* This is for us */
		return n;
	if (from.sll_ifindex == master->index)
		/* We don't know from which physical interface it comes (kernel
		 * < 2.6.24). In doubt, this is for us. */
		return n;
	return -1;		/* Not for us */
}

static int
iface_bond_close(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	struct bond_master *master = hardware->h_data;
	log_debug("interfaces", "closing bonded device %s",
	    hardware->h_ifname);
	iface_multicast(cfg, hardware->h_ifname, 1);
	iface_multicast(cfg, master->name, 1);
	free(hardware->h_data);
	return 0;
}

static void
lldpd_ifh_bond(struct lldpd *cfg, struct netlink_interface_list *interfaces)
{
	struct netlink_interface *iface;
	struct netlink_interface *master;
	struct lldpd_hardware *hardware;
	struct bond_master *bmaster;
	TAILQ_FOREACH(iface, interfaces, next) {
		log_debug("interfaces", "check if %s is part of a bond",
		    iface->name);
		if (!iface_minimal_checks(cfg, interfaces, iface))
			continue;
		if ((master = iface_is_enslaved(cfg, interfaces,
			    iface)) == NULL)
			continue;

		log_debug("interfaces", "%s is an acceptable bonded device (master=%s)",
		    iface->name, master->name);
		if ((hardware = lldpd_get_hardware(cfg,
			    iface->name,
			    iface->index,
			    &bond_ops)) == NULL) {
			if  ((hardware = lldpd_alloc_hardware(cfg,
				    iface->name,
				    iface->index)) == NULL) {
				log_warnx("interfaces", "Unable to allocate space for %s",
				    iface->name);
				continue;
			}
			hardware->h_data = bmaster = calloc(1, sizeof(struct bond_master));
			if (!hardware->h_data) {
				log_warn("interfaces", "not enough memory");
				lldpd_hardware_cleanup(cfg, hardware);
				continue;
			}
			if (iface_bond_init(cfg, hardware) != 0) {
				log_warn("interfaces", "unable to initialize %s",
				    hardware->h_ifname);
				lldpd_hardware_cleanup(cfg, hardware);
				continue;
			}
			hardware->h_ops = &bond_ops;
			TAILQ_INSERT_TAIL(&cfg->g_hardware, hardware, h_entries);
		} else {
			if (hardware->h_flags) continue; /* Already seen this time */
			bmaster = hardware->h_data;
			memset(hardware->h_data, 0, sizeof(struct bond_master));
			bmaster->index = master->index;
			strncpy(bmaster->name, master->name, IFNAMSIZ);
			lldpd_port_cleanup(&hardware->h_lport, 0);
		}

		hardware->h_flags = iface->flags;
		iface->flags = 0;

		/* Get local address */
		iface_get_permanent_mac(cfg, interfaces, iface, hardware);

		/* Fill information about port */
		iface_port_name_desc(hardware, iface);

		/* Fill additional info */
#ifdef ENABLE_DOT3
		hardware->h_lport.p_aggregid = master->index;
#endif
		iface_macphy(hardware);
		hardware->h_mtu = iface->mtu ? iface->mtu : 1500;
	}
}

#ifdef ENABLE_DOT1
static void
iface_append_vlan(struct lldpd *cfg,
    struct netlink_interface *vlan,
    struct netlink_interface *lower)
{
	struct lldpd_hardware *hardware =
	    lldpd_get_hardware(cfg, lower->name, lower->index, NULL);
	struct lldpd_port *port;
	struct lldpd_vlan *v;
	struct vlan_ioctl_args ifv;

	if (hardware == NULL) {
		log_debug("interfaces",
		    "cannot find real interface %s for VLAN %s",
		    lower->name, vlan->name);
		return;
	}

	/* Check if the VLAN is already here. */
	port = &hardware->h_lport;
	TAILQ_FOREACH(v, &port->p_vlans, v_entries)
	    if (strncmp(vlan->name, v->v_name, IFNAMSIZ) == 0)
		    return;
	if ((v = (struct lldpd_vlan *)
		calloc(1, sizeof(struct lldpd_vlan))) == NULL)
		return;
	if ((v->v_name = strdup(vlan->name)) == NULL) {
		free(v);
		return;
	}
	memset(&ifv, 0, sizeof(ifv));
	ifv.cmd = GET_VLAN_VID_CMD;
	strlcpy(ifv.device1, vlan->name, sizeof(ifv.device1));
	if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) < 0) {
		/* Dunno what happened */
		free(v->v_name);
		free(v);
		return;
	}
	v->v_vid = ifv.u.VID;
	log_debug("interfaces", "append VLAN %s for %s",
	    v->v_name,
	    hardware->h_ifname);
	TAILQ_INSERT_TAIL(&port->p_vlans, v, v_entries);
}

/**
 * Append VLAN to the lowest possible interface.
 *
 * @param vlan  The VLAN interface (used to get VLAN ID).
 * @param upper The upper interface we are currently examining.
 *
 * Initially, upper == vlan. This function will be called recursively.
 */
static void
iface_append_vlan_to_lower(struct lldpd *cfg,
    struct netlink_interface_list *interfaces,
    struct netlink_interface *vlan,
    struct netlink_interface *upper)
{
	log_debug("interfaces",
	    "looking to apply VLAN %s to physical interface behind %s",
	    vlan->name, upper->name);

	/* Easy: check if we have a physical link. */
	if (upper->link != -1 && upper->link != upper->index) {
		struct netlink_interface *lower =
		    iface_indextointerface(interfaces, upper->link);
		if (lower) {
			iface_append_vlan_to_lower(cfg,
			    interfaces, vlan,
			    lower);
			return;
		}
		log_debug("interfaces", "unknown lower interface for %s",
		    upper->name);
		return;
	}

	/* Less easy, it can be a bond, a bridge, or a VLAN ! */
	/* Check if it is a VLAN */
	if (vlan == upper || iface_is_vlan(cfg, upper)) {
		struct vlan_ioctl_args ifv;
		log_debug("interfaces", "VLAN %s on VLAN %s",
		    vlan->name, upper->name);
		memset(&ifv, 0, sizeof(ifv));
		ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
		strlcpy(ifv.device1, vlan->name, sizeof(ifv.device1));
		if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) >= 0) {
			struct netlink_interface *lower =
			    iface_nametointerface(interfaces, ifv.u.device2);
			if (lower) {
				iface_append_vlan_to_lower(cfg,
				    interfaces, vlan, lower);
				return;
			}
		}
		log_debug("interfaces",
		    "unknown lower interface for VLAN %s",
		    upper->name);
		return;
	}

	/* Check if it is a bond. */
	if (iface_is_bond(cfg, upper)) {
		struct netlink_interface *lower;
		log_debug("interfaces", "VLAN %s on bond %s",
		    vlan->name, upper->name);
		TAILQ_FOREACH(lower, interfaces, next) {
			if (iface_is_bond_slave(cfg,
				lower, upper, NULL)) {
				iface_append_vlan_to_lower(cfg,
				    interfaces, vlan, lower);
			}
		}
		return;
	}

	/* Check if it is a bridge. */
	if (iface_is_bridge(cfg, interfaces, upper)) {
		struct netlink_interface *lower;
		log_debug("interfaces", "VLAN %s on bridge %s",
		    vlan->name, upper->name);
		TAILQ_FOREACH(lower, interfaces, next) {
			if (iface_is_bridged_to(cfg,
				interfaces,
				lower, upper)) {
				iface_append_vlan_to_lower(cfg,
				    interfaces, vlan, lower);
			}
		}
		return;
	}

	log_debug("interfaces", "VLAN %s on physical interface %s",
	    vlan->name, upper->name);
	iface_append_vlan(cfg, vlan, upper);
}

static void
lldpd_ifh_vlan(struct lldpd *cfg,
    struct netlink_interface_list *interfaces)
{
	struct netlink_interface *iface;

	TAILQ_FOREACH(iface, interfaces, next) {
		if (!iface->flags)
			continue;
		if (!iface_is_vlan(cfg, iface))
			continue;

		/* We need to find the physical interfaces of this
		   vlan, through bonds and bridges. */
		log_debug("interfaces", "search physical interface for VLAN interface %s",
		    iface->name);
		iface_append_vlan_to_lower(cfg, interfaces,
		    iface, iface);
	}
}
#endif

#ifndef IN_IS_ADDR_LOOPBACK
#define IN_IS_ADDR_LOOPBACK(a) ((a)->s_addr == htonl(INADDR_LOOPBACK))
#endif
#ifndef IN_IS_ADDR_GLOBAL
#define IN_IS_ADDR_GLOBAL(a) (!IN_IS_ADDR_LOOPBACK(a))
#endif
#ifndef IN6_IS_ADDR_GLOBAL
#define IN6_IS_ADDR_GLOBAL(a) \
	(!IN6_IS_ADDR_LOOPBACK(a) && !IN6_IS_ADDR_LINKLOCAL(a))
#endif

/* Find a management address in all available interfaces, even those that were
   already handled. This is a special interface handler because it does not
   really handle interface related information (management address is attached
   to the local chassis). */
static void
lldpd_ifh_mgmt(struct lldpd *cfg, struct netlink_address_list *addrs)
{
	struct netlink_address *addr;
	char addrstrbuf[INET6_ADDRSTRLEN];
	struct lldpd_mgmt *mgmt;
	void *sin_addr_ptr;
	size_t sin_addr_size;
	int af;
	int allnegative = 0;

	lldpd_chassis_mgmt_cleanup(LOCAL_CHASSIS(cfg));

	/* Is the pattern provided all negative? */
	if (cfg->g_config.c_mgmt_pattern == NULL) allnegative = 1;
	else if (cfg->g_config.c_mgmt_pattern[0] == '!') {
		/* If each comma is followed by '!', its an all
		   negative pattern */
		char *sep = cfg->g_config.c_mgmt_pattern;
		while ((sep = strchr(sep, ',')) &&
		       (*(++sep) == '!'));
		if (sep == NULL) allnegative = 1;
	}

	/* Find management addresses */
	for (af = LLDPD_AF_UNSPEC + 1; af != LLDPD_AF_LAST; af++) {
		/* We only take one of each address family, unless a
		   pattern is provided and is not all negative. For
		   example !*:*,!10.* will only blacklist
		   addresses. We will pick the first IPv4 address not
		   matching 10.*. */
		TAILQ_FOREACH(addr, addrs, next) {
			if (addr->address.ss_family != lldpd_af(af))
				continue;

			switch (af) {
			case LLDPD_AF_IPV4:
				sin_addr_ptr = &((struct sockaddr_in *)&addr->address)->sin_addr;
				sin_addr_size = sizeof(struct in_addr);
				if (!IN_IS_ADDR_GLOBAL((struct in_addr *)sin_addr_ptr))
					continue;
				break;
			case LLDPD_AF_IPV6:
				sin_addr_ptr = &((struct sockaddr_in6 *)&addr->address)->sin6_addr;
				sin_addr_size = sizeof(struct in6_addr);
				if (!IN6_IS_ADDR_GLOBAL((struct in6_addr *)sin_addr_ptr))
					continue;
				break;
			default:
				assert(0);
				continue;
			}
			if (inet_ntop(lldpd_af(af), sin_addr_ptr,
				addrstrbuf, sizeof(addrstrbuf)) == NULL) {
				log_warn("interfaces", "unable to convert IP address to a string");
				continue;
			}
			if (cfg->g_config.c_mgmt_pattern == NULL ||
			    pattern_match(addrstrbuf, cfg->g_config.c_mgmt_pattern, allnegative)) {
				mgmt = lldpd_alloc_mgmt(af, sin_addr_ptr, sin_addr_size,
							addr->index);
				if (mgmt == NULL) {
					assert(errno == ENOMEM); /* anything else is a bug */
					log_warn("interfaces", "out of memory error");
					return;
				}
				log_debug("interfaces", "add management address %s", addrstrbuf);
				TAILQ_INSERT_TAIL(&LOCAL_CHASSIS(cfg)->c_mgmt, mgmt, m_entries);

				/* Don't take additional address if the pattern is all negative. */
				if (allnegative) break;
			}
		}
	}
}


/* Fill out chassis ID if not already done. This handler is special
   because we will only handle interfaces that are already handled. */
static void
lldpd_ifh_chassis(struct lldpd *cfg, struct netlink_interface_list *interfaces)
{
	struct netlink_interface *iface;
	struct lldpd_hardware *hardware;
	char *name = NULL;

	if (LOCAL_CHASSIS(cfg)->c_id != NULL &&
	    LOCAL_CHASSIS(cfg)->c_id_subtype == LLDP_CHASSISID_SUBTYPE_LLADDR)
		return;		/* We already have one */

	TAILQ_FOREACH(iface, interfaces, next) {
		if (iface->flags) continue;
		if (cfg->g_config.c_cid_pattern &&
		    !pattern_match(iface->name, cfg->g_config.c_cid_pattern, 0)) continue;

		if ((hardware = lldpd_get_hardware(cfg,
			    iface->name,
			    iface->index,
			    NULL)) == NULL)
			/* That's odd. Let's skip. */
			continue;

		name = malloc(sizeof(hardware->h_lladdr));
		if (!name) {
			log_warn("interfaces", "not enough memory for chassis ID");
			return;
		}
		free(LOCAL_CHASSIS(cfg)->c_id);
		memcpy(name, hardware->h_lladdr, sizeof(hardware->h_lladdr));
		LOCAL_CHASSIS(cfg)->c_id = name;
		LOCAL_CHASSIS(cfg)->c_id_len = sizeof(hardware->h_lladdr);
		LOCAL_CHASSIS(cfg)->c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
		return;
	}
}

struct lldpd_ops eth_ops = {
	.send = iface_eth_send,
	.recv = iface_eth_recv,
	.cleanup = iface_eth_close,
};
struct lldpd_ops bond_ops = {
	.send = iface_bond_send,
	.recv = iface_bond_recv,
	.cleanup = iface_bond_close,
};

void
interfaces_update(struct lldpd *cfg)
{
	struct netlink_interface_list *interfaces = NULL;
	struct netlink_address_list *addresses = NULL;
	interfaces = netlink_get_interfaces();
	addresses = netlink_get_addresses();
	if (interfaces == NULL || addresses == NULL) {
		log_warnx("interfaces", "cannot update the list of local interfaces");
		goto end;
	}

	lldpd_ifh_whitelist(cfg, interfaces);
	lldpd_ifh_bond(cfg, interfaces);
	lldpd_ifh_eth(cfg, interfaces);
#ifdef ENABLE_DOT1
	lldpd_ifh_vlan(cfg, interfaces);
#endif
	lldpd_ifh_mgmt(cfg, addresses);
	lldpd_ifh_chassis(cfg, interfaces);

end:
	netlink_free_interfaces(interfaces);
	netlink_free_addresses(addresses);
	return;

}
