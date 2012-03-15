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

#define INCLUDE_LINUX_IF_H
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

/* net/if.h */
extern unsigned int if_nametoindex (__const char *__ifname) __THROW;
extern char *if_indextoname (unsigned int __ifindex, char *__ifname) __THROW;

struct lldpd_ops eth_ops;
struct lldpd_ops bond_ops;

static int
pattern_match(char *iface, char *list, int found)
{
	char *interfaces = NULL;
	char *pattern;

	if ((interfaces = strdup(list)) == NULL) {
		LLOG_WARNX("unable to allocate memory");
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

static int
old_iface_is_bridge(struct lldpd *cfg, const char *name)
{
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
		if (if_indextoname(ifindices[i], ifname) == NULL)
			LLOG_INFO("unable to get name of interface %d",
			    ifindices[i]);
		else if (strncmp(name, ifname, IFNAMSIZ) == 0)
			return 1;
	}
	return 0;
}

static int
iface_is_bridge(struct lldpd *cfg, const char *name)
{
#ifdef SYSFS_BRIDGE_FDB
	char path[SYSFS_PATH_MAX];
	int f;

	if ((snprintf(path, SYSFS_PATH_MAX,
		    SYSFS_CLASS_NET "%s/" SYSFS_BRIDGE_FDB, name)) >= SYSFS_PATH_MAX)
		LLOG_WARNX("path truncated");
	if ((f = priv_open(path)) < 0) {
		return old_iface_is_bridge(cfg, name);
	}
	close(f);
	return 1;
#else
	return old_iface_is_bridge(cfg, name);
#endif
}

#ifdef ENABLE_DOT1
static int
old_iface_is_bridged_to(struct lldpd *cfg, const char *slave, const char *master)
{
	int j, index = if_nametoindex(slave);
	int ifptindices[MAX_PORTS];
	unsigned long args2[4] = { BRCTL_GET_PORT_LIST,
				   (unsigned long)ifptindices, MAX_PORTS, 0 };
	struct ifreq ifr;

	strncpy(ifr.ifr_name, master, IFNAMSIZ);
	memset(ifptindices, 0, sizeof(ifptindices));
	ifr.ifr_data = (char *)&args2;

	if (ioctl(cfg->g_sock, SIOCDEVPRIVATE, &ifr) < 0)
		/* This can happen with a 64bit kernel and 32bit
		   userland, don't output anything about this to avoid
		   to fill logs. */
		return 0;

	for (j = 0; j < MAX_PORTS; j++) {
		if (ifptindices[j] == index)
			return 1;
	}

	return 0;
}

static int
iface_is_bridged_to(struct lldpd *cfg, const char *slave, const char *master)
{
#ifdef SYSFS_BRIDGE_PORT_SUBDIR
	char path[SYSFS_PATH_MAX];
	int f;

	/* Master should be a bridge, first */
	if (!iface_is_bridge(cfg, master)) return 0;

	if (snprintf(path, SYSFS_PATH_MAX,
		SYSFS_CLASS_NET "%s/" SYSFS_BRIDGE_PORT_SUBDIR "/%s/port_no",
		master, slave) >= SYSFS_PATH_MAX)
		LLOG_WARNX("path truncated");
	if ((f = priv_open(path)) < 0) {
		return old_iface_is_bridged_to(cfg, slave, master);
	}
	close(f);
	return 1;
#else
	return old_iface_is_bridged_to(cfg, slave, master);
#endif
}
#endif

static int
iface_is_vlan(struct lldpd *cfg, const char *name)
{
	struct vlan_ioctl_args ifv;
	memset(&ifv, 0, sizeof(ifv));
	ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
	if ((strlcpy(ifv.device1, name, sizeof(ifv.device1))) >=
	    sizeof(ifv.device1))
		LLOG_WARNX("device name truncated");
	if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) >= 0)
		return 1;
	return 0;
}

static int
iface_is_wireless(struct lldpd *cfg, const char *name)
{
	struct iwreq iwr;
	strlcpy(iwr.ifr_name, name, IFNAMSIZ);
	if (ioctl(cfg->g_sock, SIOCGIWNAME, &iwr) >= 0)
		return 1;
	return 0;
}

static int
iface_is_bond(struct lldpd *cfg, const char *name)
{
	struct ifreq ifr;
	struct ifbond ifb;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifb, 0, sizeof(ifb));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (char *)&ifb;
	if (ioctl(cfg->g_sock, SIOCBONDINFOQUERY, &ifr) >= 0)
		return 1;
	return 0;
}

static int
iface_is_bond_slave(struct lldpd *cfg, const char *slave, const char *master,
    int *active)
{
	struct ifreq ifr;
	struct ifbond ifb;
	struct ifslave ifs;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifb, 0, sizeof(ifb));
	strlcpy(ifr.ifr_name, master, sizeof(ifr.ifr_name));
	ifr.ifr_data = (char *)&ifb;
	if (ioctl(cfg->g_sock, SIOCBONDINFOQUERY, &ifr) >= 0) {
		while (ifb.num_slaves--) {
			memset(&ifr, 0, sizeof(ifr));
			memset(&ifs, 0, sizeof(ifs));
			strlcpy(ifr.ifr_name, master, sizeof(ifr.ifr_name));
			ifr.ifr_data = (char *)&ifs;
			ifs.slave_id = ifb.num_slaves;
			if ((ioctl(cfg->g_sock, SIOCBONDSLAVEINFOQUERY, &ifr) >= 0) &&
			    (strncmp(ifs.slave_name, slave, sizeof(ifs.slave_name)) == 0)) {
				if (active)
					*active = ifs.state;
				return 1;
			}
		}
	}
	return 0;
}

static int
iface_is_enslaved(struct lldpd *cfg, const char *name)
{
	struct ifaddrs *ifap, *ifa;
	int master;

	if (getifaddrs(&ifap) != 0) {
		LLOG_WARN("unable to get interface list");
		return -1;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (iface_is_bond_slave(cfg, name, ifa->ifa_name, NULL)) {
			master = if_nametoindex(ifa->ifa_name);
			freeifaddrs(ifap);
			return master;
		}
	}
	freeifaddrs(ifap);
	return -1;
}

static void
iface_get_permanent_mac(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	int master, f, state = 0;
	FILE *netbond;
	const char *slaveif = "Slave Interface: ";
	const char *hwaddr = "Permanent HW addr: ";
	u_int8_t mac[ETHER_ADDR_LEN];
	char bond[IFNAMSIZ];
	char path[SYSFS_PATH_MAX];
	char line[100];
	if ((master = iface_is_enslaved(cfg, hardware->h_ifname)) == -1)
		return;
	/* We have a bond, we need to query it to get real MAC addresses */
	if ((if_indextoname(master, bond)) == NULL) {
		LLOG_WARNX("unable to get bond name");
		return;
	}

	if (snprintf(path, SYSFS_PATH_MAX, "/proc/net/bonding/%s",
		bond) >= SYSFS_PATH_MAX) {
		LLOG_WARNX("path truncated");
		return;
	}
	if ((f = priv_open(path)) < 0) {
		if (snprintf(path, SYSFS_PATH_MAX, "/proc/self/net/bonding/%s",
			bond) >= SYSFS_PATH_MAX) {
			LLOG_WARNX("path truncated");
			return;
		}
		f = priv_open(path);
	}
	if (f < 0) {
		LLOG_WARNX("unable to find %s in /proc/net/bonding or /proc/self/net/bonding",
		    bond);
		return;
	}
	if ((netbond = fdopen(f, "r")) == NULL) {
		LLOG_WARN("unable to read stream from %s", path);
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
				if (strncmp(hardware->h_ifname,
					line + strlen(slaveif),
					sizeof(hardware->h_ifname)) == 0)
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
					LLOG_WARN("unable to parse %s",
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
	LLOG_WARNX("unable to find real mac address for %s",
	    bond);
	fclose(netbond);
}

/* Generic minimal checks to handle a given interface. */
static int
iface_minimal_checks(struct lldpd *cfg, struct ifaddrs *ifa)
{
	struct sockaddr_ll sdl;
	struct ifreq ifr;
	struct ethtool_drvinfo ethc;
	const char * const *rif;

	/* White-list some drivers */
	const char * const regular_interfaces[] = {
		"dsa",
		"veth",
		NULL
	};

	int is_bridge = iface_is_bridge(cfg, ifa->ifa_name);

	if (!(LOCAL_CHASSIS(cfg)->c_cap_enabled & LLDP_CAP_BRIDGE) &&
	    is_bridge) {
		LOCAL_CHASSIS(cfg)->c_cap_enabled |= LLDP_CAP_BRIDGE;
		return 0;
	}
	
	if (!(LOCAL_CHASSIS(cfg)->c_cap_enabled & LLDP_CAP_WLAN) &&
	    iface_is_wireless(cfg, ifa->ifa_name))
		LOCAL_CHASSIS(cfg)->c_cap_enabled |= LLDP_CAP_WLAN;
	
	/* First, check if this interface has already been handled */
	if (!ifa->ifa_flags)
		return 0;

	if (ifa->ifa_addr == NULL ||
	    ifa->ifa_addr->sa_family != PF_PACKET)
		return 0;

	memcpy(&sdl, ifa->ifa_addr, sizeof(struct sockaddr_ll));
	if (sdl.sll_hatype != ARPHRD_ETHER || !sdl.sll_halen)
		return 0;

	/* We request that the interface is able to do either multicast
	 * or broadcast to be able to send discovery frames. */
	if (!(ifa->ifa_flags & (IFF_MULTICAST|IFF_BROADCAST)))
		return 0;

	/* Check if the driver is whitelisted */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifa->ifa_name);
	ifr.ifr_data = (caddr_t) &ethc;
	ethc.cmd = ETHTOOL_GDRVINFO;
	if (ioctl(cfg->g_sock, SIOCETHTOOL, &ifr) == 0) {
		for (rif = regular_interfaces; *rif; rif++) {
			if (strcmp(ethc.driver, *rif) == 0) {
				/* White listed! */
				return 1;
			}
		}
	}

	/* Check queue len. If no queue, this usually means that this
	   is not a "real" interface. */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifa->ifa_name);
	if ((ioctl(cfg->g_sock, SIOCGIFTXQLEN, &ifr) < 0) || !ifr.ifr_qlen)
		return 0;

	/* Don't handle bond and VLAN, nor bridge  */
	if ((iface_is_vlan(cfg, ifa->ifa_name)) ||
	    (iface_is_bond(cfg, ifa->ifa_name)) ||
	    is_bridge)
		return 0;

	return 1;
}

static int
iface_set_filter(const char *name, int fd)
{
	const struct sock_fprog prog = {
		.filter = lldpd_filter_f,
		.len = sizeof(lldpd_filter_f) / sizeof(struct sock_filter)
	};
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
                &prog, sizeof(prog)) < 0) {
		LLOG_WARN("unable to change filter for %s", name);
		return ENETDOWN;
	}
	return 0;
}

/* Fill up port name and description */
static void
iface_port_name_desc(struct lldpd_hardware *hardware)
{
	struct lldpd_port *port = &hardware->h_lport;
	char buffer[256];	/* 256 = IFALIASZ */
	char path[SYSFS_PATH_MAX];
	int f;

	/* There are two cases:

	     1. We have a kernel recent enough to support ifAlias
	     _and_ a non empty ifAlias, then we will use it for
	     description and use ifname for port ID.

	     2. Otherwise, we will use the MAC address as ID and the
	     port name in description.
	*/

	if ((snprintf(path, SYSFS_PATH_MAX,
		    SYSFS_CLASS_NET "%s/ifalias", hardware->h_ifname)) >= SYSFS_PATH_MAX)
		LLOG_WARNX("path truncated");
	memset(buffer, 0, sizeof(buffer));
	if (((f = priv_open(path)) < 0) || (read(f, buffer, sizeof(buffer)-1) < 1)) {
		/* Case 2: MAC address and port name */
		close(f);
		port->p_id_subtype = LLDP_PORTID_SUBTYPE_LLADDR;
		if ((port->p_id =
			calloc(1, sizeof(hardware->h_lladdr))) == NULL)
			fatal(NULL);
		memcpy(port->p_id, hardware->h_lladdr,
		    sizeof(hardware->h_lladdr));
		port->p_id_len = sizeof(hardware->h_lladdr);
		port->p_descr = strdup(hardware->h_ifname);
		return;
	}
	/* Case 1: port name and port description */
	close(f);
	port->p_id_subtype = LLDP_PORTID_SUBTYPE_IFNAME;
	port->p_id_len = strlen(hardware->h_ifname);
	if ((port->p_id =
		calloc(1, port->p_id_len)) == NULL)
		fatal(NULL);
	memcpy(port->p_id, hardware->h_ifname, port->p_id_len);
	if (buffer[strlen(buffer) - 1] == '\n')
		buffer[strlen(buffer) - 1] = '\0';
	port->p_descr = strdup(buffer);
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

	if (priv_ethtool(hardware->h_ifname, &ethc) == 0) {
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
				    LLDP_DOT3_MAU_100BASET2DF : LLDP_DOT3_MAU_100BASET2HD;
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
iface_mtu(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	struct ifreq ifr;

	/* get MTU */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, hardware->h_ifname, sizeof(ifr.ifr_name));
	if (ioctl(cfg->g_sock, SIOCGIFMTU, (char*)&ifr) == -1) {
		LLOG_WARN("unable to get MTU of %s, using 1500", hardware->h_ifname);
		hardware->h_mtu = 1500;
	} else
		hardware->h_mtu = ifr.ifr_mtu;
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
				LLOG_INFO("unable to %s %s address to multicast filter for %s",
				    (remove)?"delete":"add",
				    cfg->g_protocols[i].name,
				    name);
		}
	}
}

static void
iface_fds_close(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	int i;
	for (i=0; i < LLDPD_FD_SETSIZE; i++)
		if (FD_ISSET(i, &hardware->h_recvfds)) {
			FD_CLR(i, &hardware->h_recvfds);
			close(i);
		}
}


static int
iface_eth_init(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	int fd, status;

	if ((fd = priv_iface_init(hardware->h_ifname)) == -1)
		return -1;
	hardware->h_sendfd = fd;

	/* fd to receive is the same as fd to send */
	FD_SET(fd, &hardware->h_recvfds);

	/* Set filter */
	if ((status = iface_set_filter(hardware->h_ifname, fd)) != 0) {
		close(fd);
		return status;
	}

	iface_multicast(cfg, hardware->h_ifname, 0);

	LLOG_DEBUG("interface %s initialized (fd=%d)", hardware->h_ifname,
	    fd);
	return 0;
}

static int
iface_eth_send(struct lldpd *cfg, struct lldpd_hardware *hardware,
    char *buffer, size_t size)
{
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

	fromlen = sizeof(from);
	if ((n = recvfrom(fd,
		    buffer,
		    size, 0,
		    (struct sockaddr *)&from,
		    &fromlen)) == -1) {
		LLOG_WARN("error while receiving frame on %s",
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
	close(hardware->h_sendfd);
	iface_multicast(cfg, hardware->h_ifname, 1);
	return 0;
}

void
lldpd_ifh_eth(struct lldpd *cfg, struct ifaddrs *ifap)
{
	struct ifaddrs *ifa;
	struct lldpd_hardware *hardware;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (!iface_minimal_checks(cfg, ifa))
			continue;

		if ((hardware = lldpd_get_hardware(cfg,
			    ifa->ifa_name,
			    if_nametoindex(ifa->ifa_name),
			    &eth_ops)) == NULL) {
			if  ((hardware = lldpd_alloc_hardware(cfg,
				    ifa->ifa_name)) == NULL) {
				LLOG_WARNX("Unable to allocate space for %s",
				    ifa->ifa_name);
				continue;
			}
			if (iface_eth_init(cfg, hardware) != 0) {
				LLOG_WARN("unable to initialize %s", hardware->h_ifname);
				lldpd_hardware_cleanup(cfg, hardware);
				continue;
			}
			hardware->h_ops = &eth_ops;
			hardware->h_ifindex = if_nametoindex(ifa->ifa_name);
			TAILQ_INSERT_TAIL(&cfg->g_hardware, hardware, h_entries);
		} else {
			if (hardware->h_flags) continue; /* Already seen this time */
			lldpd_port_cleanup(cfg, &hardware->h_lport, 0);
		}

		hardware->h_flags = ifa->ifa_flags; /* Should be non-zero */
		ifa->ifa_flags = 0;		    /* Future handlers
						       don't have to
						       care about this
						       interface. */

		/* Get local address */
		memcpy(&hardware->h_lladdr,
		    (u_int8_t*)((u_int8_t*)ifa->ifa_addr +
			offsetof(struct sockaddr_ll, sll_addr)),
		    sizeof(hardware->h_lladdr));

		/* Fill information about port */
		iface_port_name_desc(hardware);

		/* Fill additional info */
		iface_macphy(hardware);
		iface_mtu(cfg, hardware);
	}
}

void
lldpd_ifh_whitelist(struct lldpd *cfg, struct ifaddrs *ifap)
{
	struct ifaddrs *ifa;

	if (!cfg->g_interfaces)
		return;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_flags == 0) continue; /* Already handled by someone else */
		if (!pattern_match(ifa->ifa_name, cfg->g_interfaces, 0)) {
			/* This interface was not found. We flag it. */
			LLOG_DEBUG("blacklist %s", ifa->ifa_name);
			ifa->ifa_flags = 0;
		}
	}
}

static int
iface_bond_init(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	char *mastername = (char *)hardware->h_data; /* Master name */
	int fd, status;
	int un = 1;

	if (!mastername) return -1;

	/* First, we get a socket to the raw physical interface */
	if ((fd = priv_iface_init(hardware->h_ifname)) == -1)
		return -1;
	hardware->h_sendfd = fd;
	FD_SET(fd, &hardware->h_recvfds);
	if ((status = iface_set_filter(hardware->h_ifname, fd)) != 0) {
		close(fd);
		return status;
	}
	iface_multicast(cfg, hardware->h_ifname, 0);

	/* Then, we open a raw interface for the master */
	if ((fd = priv_iface_init(mastername)) == -1) {
		close(hardware->h_sendfd);
		return -1;
	}
	FD_SET(fd, &hardware->h_recvfds);
	if ((status = iface_set_filter(mastername, fd)) != 0) {
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
		LLOG_DEBUG("[priv]: unable to setsockopt for master bonding device of %s. "
			   "You will get inaccurate results",
			   hardware->h_ifname);
	}
	iface_multicast(cfg, mastername, 0);

	LLOG_DEBUG("interface %s initialized (fd=%d,master=%s[%d])",
	    hardware->h_ifname,
	    hardware->h_sendfd,
	    mastername, fd);
	return 0;
}

static int
iface_bond_send(struct lldpd *cfg, struct lldpd_hardware *hardware,
    char *buffer, size_t size)
{
	/* With bonds, we have duplicate MAC address on different physical
	 * interfaces. We need to alter the source MAC address when we send on
	 * an inactive slave. */
	char *master = (char*)hardware->h_data;
	int active;
	if (!iface_is_bond_slave(cfg, hardware->h_ifname, master, &active)) {
		LLOG_WARNX("%s seems to not be enslaved anymore?",
		    hardware->h_ifname);
		return 0;
	}
	if (active) {
		/* We need to modify the source MAC address */
		if (size < 2 * ETH_ALEN) {
			LLOG_WARNX("packet to send on %s is too small!",
			    hardware->h_ifname);
			return 0;
		}
		memset(buffer + ETH_ALEN, 0, ETH_ALEN);
	}
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

	fromlen = sizeof(from);
	if ((n = recvfrom(fd, buffer, size, 0,
		    (struct sockaddr *)&from,
		    &fromlen)) == -1) {
		LLOG_WARN("error while receiving frame on %s",
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
	if (from.sll_ifindex == if_nametoindex((char*)hardware->h_data))
		/* We don't know from which physical interface it comes (kernel
		 * < 2.6.24). In doubt, this is for us. */
		return n;
	return -1;		/* Not for us */
}

static int
iface_bond_close(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	iface_fds_close(cfg, hardware); /* h_sendfd is here too */
	iface_multicast(cfg, hardware->h_ifname, 1);
	iface_multicast(cfg, (char*)hardware->h_data, 1);
	free(hardware->h_data);
	return 0;
}

void
lldpd_ifh_bond(struct lldpd *cfg, struct ifaddrs *ifap)
{
	struct ifaddrs *ifa;
	struct lldpd_hardware *hardware;
	int master;
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (!iface_minimal_checks(cfg, ifa))
			continue;
		if ((master = iface_is_enslaved(cfg, ifa->ifa_name)) == -1)
			continue;

		if ((hardware = lldpd_get_hardware(cfg,
			    ifa->ifa_name,
			    if_nametoindex(ifa->ifa_name),
			    &bond_ops)) == NULL) {
			if  ((hardware = lldpd_alloc_hardware(cfg,
				    ifa->ifa_name)) == NULL) {
				LLOG_WARNX("Unable to allocate space for %s",
				    ifa->ifa_name);
				continue;
			}
			hardware->h_data = (char *)calloc(1, IFNAMSIZ);
			if_indextoname(master, hardware->h_data);
			if (iface_bond_init(cfg, hardware) != 0) {
				LLOG_WARN("unable to initialize %s",
				    hardware->h_ifname);
				lldpd_hardware_cleanup(cfg, hardware);
				continue;
			}
			hardware->h_ops = &bond_ops;
			hardware->h_ifindex = if_nametoindex(ifa->ifa_name);
			TAILQ_INSERT_TAIL(&cfg->g_hardware, hardware, h_entries);
		} else {
			if (hardware->h_flags) continue; /* Already seen this time */
			memset(hardware->h_data, 0, IFNAMSIZ);
			if_indextoname(master, hardware->h_data);
			lldpd_port_cleanup(cfg, &hardware->h_lport, 0);
		}
		
		hardware->h_flags = ifa->ifa_flags;
		ifa->ifa_flags = 0;

		/* Get local address */
		iface_get_permanent_mac(cfg, hardware);
		
		/* Fill information about port */
		iface_port_name_desc(hardware);
		
		/* Fill additional info */
#ifdef ENABLE_DOT3
		hardware->h_lport.p_aggregid = master;
#endif
		iface_macphy(hardware);
		iface_mtu(cfg, hardware);
	}
}

#ifdef ENABLE_DOT1
static void
iface_append_vlan(struct lldpd *cfg,
    struct lldpd_hardware *hardware, struct ifaddrs *ifa)
{
	struct lldpd_port *port = &hardware->h_lport;
	struct lldpd_vlan *vlan;
	struct vlan_ioctl_args ifv;

	/* Check if the VLAN is already here. */
	TAILQ_FOREACH(vlan, &port->p_vlans, v_entries)
	    if (strncmp(ifa->ifa_name, vlan->v_name, IFNAMSIZ) == 0)
		    return;
	if ((vlan = (struct lldpd_vlan *)
		calloc(1, sizeof(struct lldpd_vlan))) == NULL)
		return;
	if ((vlan->v_name = strdup(ifa->ifa_name)) == NULL) {
		free(vlan);
		return;
	}
	memset(&ifv, 0, sizeof(ifv));
	ifv.cmd = GET_VLAN_VID_CMD;
	strlcpy(ifv.device1, ifa->ifa_name, sizeof(ifv.device1));
	if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) < 0) {
		/* Dunno what happened */
		free(vlan->v_name);
		free(vlan);
		return;
	}
	vlan->v_vid = ifv.u.VID;
	TAILQ_INSERT_TAIL(&port->p_vlans, vlan, v_entries);
}

void
lldpd_ifh_vlan(struct lldpd *cfg, struct ifaddrs *ifap)
{
	struct ifaddrs *ifa;
	struct vlan_ioctl_args ifv;
	struct lldpd_hardware *hardware;
	
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_flags)
			continue;
		if (!iface_is_vlan(cfg, ifa->ifa_name))
			continue;

		/* We need to find the physical interfaces of this
		   vlan, through bonds and bridges. */
		memset(&ifv, 0, sizeof(ifv));
		ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
		strlcpy(ifv.device1, ifa->ifa_name, sizeof(ifv.device1));
		if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) >= 0) {
			/* Three cases:
			    1. we get a real device
			    2. we get a bond
			    3. we get a bridge
			*/
			if ((hardware = lldpd_get_hardware(cfg,
				    ifv.u.device2,
				    if_nametoindex(ifv.u.device2),
				    NULL)) == NULL) {
				if (iface_is_bond(cfg, ifv.u.device2)) {
					TAILQ_FOREACH(hardware, &cfg->g_hardware,
					    h_entries)
					    if (iface_is_bond_slave(cfg,
						    hardware->h_ifname,
						    ifv.u.device2, NULL))
						    iface_append_vlan(cfg,
							hardware, ifa);
				} else if (iface_is_bridge(cfg, ifv.u.device2)) {
					TAILQ_FOREACH(hardware, &cfg->g_hardware,
					    h_entries)
					    if (iface_is_bridged_to(cfg,
						    hardware->h_ifname,
						    ifv.u.device2))
						    iface_append_vlan(cfg,
							hardware, ifa);
				}
			} else iface_append_vlan(cfg,
			    hardware, ifa);
		}
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
#define IN6_IS_ADDR_GLOBAL(a) (!IN6_IS_ADDR_LOOPBACK(a) && \
								!IN6_IS_ADDR_LINKLOCAL(a))
#endif

/* Find a management address in all available interfaces, even those that were
   already handled. This is a special interface handler because it does not
   really handle interface related information (management address is attached
   to the local chassis). */
void
lldpd_ifh_mgmt(struct lldpd *cfg, struct ifaddrs *ifap)
{
	struct ifaddrs *ifa;
	char addrstrbuf[INET6_ADDRSTRLEN];
	struct lldpd_mgmt *mgmt;
	void *sin_addr_ptr;
	size_t sin_addr_size;
	int af;
	int allnegative = 0;

	lldpd_chassis_mgmt_cleanup(LOCAL_CHASSIS(cfg));

	/* Is the pattern provided all negative? */
	if (cfg->g_mgmt_pattern == NULL) allnegative = 1;
	else if (cfg->g_mgmt_pattern[0] == '!') {
		/* If each comma is followed by '!', its an all
		   negative pattern */
		char *sep = cfg->g_mgmt_pattern;
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
		for (ifa = ifap;
		     ifa != NULL;
		     ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL)
				continue;
			if (ifa->ifa_addr->sa_family != lldpd_af(af))
				continue;

			switch (af) {
			case LLDPD_AF_IPV4:
				sin_addr_ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
				sin_addr_size = sizeof(struct in_addr);
				if (!IN_IS_ADDR_GLOBAL((struct in_addr *)sin_addr_ptr))
					continue;
				break;
			case LLDPD_AF_IPV6:
				sin_addr_ptr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
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
				LLOG_WARN("unable to convert IP address to a string");
				continue;
			}
			if (cfg->g_mgmt_pattern == NULL ||
			    pattern_match(addrstrbuf, cfg->g_mgmt_pattern, allnegative)) {
				mgmt = lldpd_alloc_mgmt(af, sin_addr_ptr, sin_addr_size,
							if_nametoindex(ifa->ifa_name));
				if (mgmt == NULL) {
					assert(errno == ENOMEM); /* anything else is a bug */
					LLOG_WARN("out of memory error");
					return;
				}
				TAILQ_INSERT_TAIL(&LOCAL_CHASSIS(cfg)->c_mgmt, mgmt, m_entries);

				/* Don't take additional address if the pattern is all negative. */
				if (allnegative) break;
			}
		}
	}
}


/* Fill out chassis ID if not already done. This handler is special
   because we will only handle interfaces that are already handled. */
void
lldpd_ifh_chassis(struct lldpd *cfg, struct ifaddrs *ifap)
{
	struct ifaddrs *ifa;
	struct lldpd_hardware *hardware;

	if (LOCAL_CHASSIS(cfg)->c_id != NULL &&
	    LOCAL_CHASSIS(cfg)->c_id_subtype == LLDP_CHASSISID_SUBTYPE_LLADDR)
		return;		/* We already have one */

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_flags) continue;
		if (cfg->g_cid_pattern &&
		    !pattern_match(ifa->ifa_name, cfg->g_cid_pattern, 0)) continue;

		if ((hardware = lldpd_get_hardware(cfg,
			    ifa->ifa_name,
			    if_nametoindex(ifa->ifa_name),
			    NULL)) == NULL)
			/* That's odd. Let's skip. */
			continue;

		char *name = malloc(sizeof(hardware->h_lladdr));
		if (!name) {
			LLOG_WARN("Not enough memory for chassis ID");
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
