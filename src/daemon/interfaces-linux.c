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
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
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

static struct sock_filter lldpd_filter_f[] = { LLDPD_FILTER_F };
static int
iflinux_set_filter(const char *name, int fd)
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

static int
iflinux_eth_init(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	int fd, status;

	log_debug("interfaces", "initialize ethernet device %s",
	    hardware->h_ifname);
	if ((fd = priv_iface_init(hardware->h_ifindex)) == -1)
		return -1;
	hardware->h_sendfd = fd; /* Send */

	/* Set filter */
	if ((status = iflinux_set_filter(hardware->h_ifname, fd)) != 0) {
		close(fd);
		return status;
	}

	interfaces_setup_multicast(cfg, hardware->h_ifname, 0);

	levent_hardware_add_fd(hardware, fd); /* Receive */
	log_debug("interfaces", "interface %s initialized (fd=%d)", hardware->h_ifname,
	    fd);
	return 0;
}

/* Generic ethernet send/receive */
static int
iflinux_eth_send(struct lldpd *cfg, struct lldpd_hardware *hardware,
    char *buffer, size_t size)
{
	log_debug("interfaces", "send PDU to ethernet device %s (fd=%d)",
	    hardware->h_ifname, hardware->h_sendfd);
	return write(hardware->h_sendfd,
	    buffer, size);
}

static int
iflinux_eth_recv(struct lldpd *cfg, struct lldpd_hardware *hardware,
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
iflinux_eth_close(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	log_debug("interfaces", "close ethernet device %s",
	    hardware->h_ifname);
	interfaces_setup_multicast(cfg, hardware->h_ifname, 1);
	return 0;
}

static struct lldpd_ops eth_ops = {
	.send = iflinux_eth_send,
	.recv = iflinux_eth_recv,
	.cleanup = iflinux_eth_close,
};

static int
old_iflinux_is_bridge(struct lldpd *cfg,
    struct interfaces_device_list *interfaces,
    struct interfaces_device *iface)
{
#ifdef ENABLE_OLDIES
	int j;
	int ifptindices[MAX_PORTS];
	unsigned long args2[4] = {
		BRCTL_GET_PORT_LIST,
		(unsigned long)ifptindices,
		MAX_PORTS,
		0
	};
	struct ifreq ifr;

	strncpy(ifr.ifr_name, iface->name, IFNAMSIZ);
	memset(ifptindices, 0, sizeof(ifptindices));
	ifr.ifr_data = (char *)&args2;

	if (ioctl(cfg->g_sock, SIOCDEVPRIVATE, &ifr) < 0)
		/* This can happen with a 64bit kernel and 32bit
		   userland, don't output anything about this to avoid
		   to fill logs. */
		return 0;

	for (j = 0; j < MAX_PORTS; j++) {
		struct interfaces_device *port;
		if (!ifptindices[j]) continue;
		port = interfaces_indextointerface(interfaces, ifptindices[j]);
		if (!port) continue;
		if (port->upper) {
			log_debug("interfaces",
			    "strange, port %s for bridge %s already has upper interface %s",
			    port->name, iface->name, port->upper->name);
		} else {
			log_debug("interfaces",
			    "port %s is bridged to %s",
			    port->name, iface->name);
			port->upper = iface;
		}
	}
	return 1;
#else
	return 0;
#endif
}

static int
iflinux_is_bridge(struct lldpd *cfg,
    struct interfaces_device_list *interfaces,
    struct interfaces_device *iface)
{
	struct interfaces_device *port;
	char path[SYSFS_PATH_MAX];
	int f;

	if ((snprintf(path, SYSFS_PATH_MAX,
		    SYSFS_CLASS_NET "%s/" SYSFS_BRIDGE_FDB,
		    iface->name)) >= SYSFS_PATH_MAX)
		log_warnx("interfaces", "path truncated");
	if ((f = priv_open(path)) < 0)
		return old_iflinux_is_bridge(cfg, interfaces, iface);
	close(f);

	/* Also grab all ports */
	TAILQ_FOREACH(port, interfaces, next) {
		if (port->upper) continue;
		if (snprintf(path, SYSFS_PATH_MAX,
			SYSFS_CLASS_NET "%s/" SYSFS_BRIDGE_PORT_SUBDIR "/%s/port_no",
			iface->name, port->name) >= SYSFS_PATH_MAX)
			log_warnx("interfaces", "path truncated");
		if ((f = priv_open(path)) < 0)
			continue;
		log_debug("interfaces",
		    "port %s is bridged to %s",
		    port->name, iface->name);
		port->upper = iface;
		close(f);
	}

	return 1;
}

static int
iflinux_is_vlan(struct lldpd *cfg,
    struct interfaces_device_list *interfaces,
    struct interfaces_device *iface)
{
	struct vlan_ioctl_args ifv;
	memset(&ifv, 0, sizeof(ifv));
	ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
	strlcpy(ifv.device1, iface->name, sizeof(ifv.device1));
	if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) >= 0) {
		/* This is a VLAN, get the lower interface and the VID */
		struct interfaces_device *lower =
		    interfaces_nametointerface(interfaces, ifv.u.device2);
		if (!lower) {
			log_debug("interfaces",
			    "unable to find lower interface for VLAN %s",
			    iface->name);
			return 0;
		}

		memset(&ifv, 0, sizeof(ifv));
		ifv.cmd = GET_VLAN_VID_CMD;
		strlcpy(ifv.device1, iface->name, sizeof(ifv.device1));
		if (ioctl(cfg->g_sock, SIOCGIFVLAN, &ifv) < 0) {
			log_debug("interfaces",
			    "unable to find VID for VLAN %s",
			    iface->name);
			return 0;
		}

		iface->lower = lower;
		iface->vlanid = ifv.u.VID;
		return 1;
	}
	return 0;
}

static int
iflinux_is_bond(struct lldpd *cfg,
    struct interfaces_device_list *interfaces,
    struct interfaces_device *master)
{
	struct ifreq ifr;
	struct ifbond ifb;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifb, 0, sizeof(ifb));
	strlcpy(ifr.ifr_name, master->name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (char *)&ifb;
	if (ioctl(cfg->g_sock, SIOCBONDINFOQUERY, &ifr) >= 0) {
		while (ifb.num_slaves--) {
			struct ifslave ifs;
			memset(&ifr, 0, sizeof(ifr));
			memset(&ifs, 0, sizeof(ifs));
			strlcpy(ifr.ifr_name, master->name, sizeof(ifr.ifr_name));
			ifr.ifr_data = (char *)&ifs;
			ifs.slave_id = ifb.num_slaves;
			if (ioctl(cfg->g_sock, SIOCBONDSLAVEINFOQUERY, &ifr) >= 0) {
				struct interfaces_device *slave =
				    interfaces_nametointerface(interfaces,
					ifs.slave_name);
				if (slave == NULL) continue;
				if (slave->upper) continue;
				log_debug("interfaces",
				    "interface %s is enslaved to %s",
				    slave->name, master->name);
				slave->upper = master;
			}
		}
		return 1;
	}
	return 0;
}

static void
iflinux_get_permanent_mac(struct lldpd *cfg,
    struct interfaces_device_list *interfaces,
    struct interfaces_device *iface)
{
	struct interfaces_device *master;
	int f, state = 0;
	FILE *netbond;
	const char const *slaveif = "Slave Interface: ";
	const char const *hwaddr = "Permanent HW addr: ";
	u_int8_t mac[ETHER_ADDR_LEN];
	char path[SYSFS_PATH_MAX];
	char line[100];

	if ((master = iface->upper) == NULL)
		return;

	log_debug("interfaces", "get MAC address for %s",
	    iface->name);

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
				memcpy(iface->address, mac,
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

/* Fill up MAC/PHY for a given hardware port */
static void
iflinux_macphy(struct lldpd_hardware *hardware)
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
	if ((status = iflinux_set_filter(hardware->h_ifname, fd)) != 0) {
		close(fd);
		return status;
	}
	interfaces_setup_multicast(cfg, hardware->h_ifname, 0);

	/* Then, we open a raw interface for the master */
	if ((fd = priv_iface_init(master->index)) == -1) {
		close(hardware->h_sendfd);
		return -1;
	}
	if ((status = iflinux_set_filter(master->name, fd)) != 0) {
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
	interfaces_setup_multicast(cfg, master->name, 0);

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
	interfaces_setup_multicast(cfg, hardware->h_ifname, 1);
	interfaces_setup_multicast(cfg, master->name, 1);
	free(hardware->h_data);
	return 0;
}

struct lldpd_ops bond_ops = {
	.send = iface_bond_send,
	.recv = iface_bond_recv,
	.cleanup = iface_bond_close,
};

static void
iflinux_handle_bond(struct lldpd *cfg, struct interfaces_device_list *interfaces)
{
	struct interfaces_device *iface;
	struct interfaces_device *master;
	struct lldpd_hardware *hardware;
	struct bond_master *bmaster;
	TAILQ_FOREACH(iface, interfaces, next) {
		if (!(iface->type & IFACE_PHYSICAL_T)) continue;
		if (!iface->flags) continue;
		if (!iface->upper || !(iface->upper->type & IFACE_BOND_T)) continue;

		master = iface->upper;
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
		memcpy(&hardware->h_lladdr, iface->address, ETHER_ADDR_LEN);

		/* Fill information about port */
		interfaces_helper_port_name_desc(hardware, iface);

		/* Fill additional info */
#ifdef ENABLE_DOT3
		hardware->h_lport.p_aggregid = master->index;
#endif
		hardware->h_mtu = iface->mtu ? iface->mtu : 1500;
	}
}

/* Query each interface to get the appropriate driver */
static void
iflinux_add_driver(struct lldpd *cfg,
    struct interfaces_device_list *interfaces)
{
	struct interfaces_device *iface;
	TAILQ_FOREACH(iface, interfaces, next) {
		struct ethtool_drvinfo ethc = {
			.cmd = ETHTOOL_GDRVINFO
		};
		struct ifreq ifr = {
			.ifr_data = (caddr_t)&ethc
		};
		if (iface->driver) continue;

		strlcpy(ifr.ifr_name, iface->name, IFNAMSIZ);
		if (ioctl(cfg->g_sock, SIOCETHTOOL, &ifr) == 0) {
			iface->driver = strdup(ethc.driver);
			log_debug("interfaces", "driver for %s is `%s`",
			    iface->name, iface->driver);
		}
	}
}

/* Query each interface to see if it is a wireless one */
static void
iflinux_add_wireless(struct lldpd *cfg,
    struct interfaces_device_list *interfaces)
{
	struct interfaces_device *iface;
	TAILQ_FOREACH(iface, interfaces, next) {
		struct iwreq iwr;
		memset(&iwr, 0, sizeof(struct iwreq));
		strlcpy(iwr.ifr_name, iface->name, IFNAMSIZ);
		if (ioctl(cfg->g_sock, SIOCGIWNAME, &iwr) >= 0) {
			log_debug("interfaces", "%s is wireless",
			    iface->name);
			iface->type |= IFACE_WIRELESS_T | IFACE_PHYSICAL_T;
		}
	}
}

/* Query each interface to see if it is a bridge */
static void
iflinux_add_bridge(struct lldpd *cfg,
    struct interfaces_device_list *interfaces)
{
	struct interfaces_device *iface;

	TAILQ_FOREACH(iface, interfaces, next) {
		if (iface->type & (IFACE_PHYSICAL_T|
			IFACE_VLAN_T|IFACE_BOND_T|IFACE_BRIDGE_T))
			continue;
		if (iflinux_is_bridge(cfg, interfaces, iface)) {
			log_debug("interfaces",
			    "interface %s is a bridge",
			    iface->name);
			iface->type |= IFACE_BRIDGE_T;
		}
	}
}

/* Query each interface to see if it is a bond */
static void
iflinux_add_bond(struct lldpd *cfg,
    struct interfaces_device_list *interfaces)
{
	struct interfaces_device *iface;

	TAILQ_FOREACH(iface, interfaces, next) {
		if (iface->type & (IFACE_PHYSICAL_T|IFACE_VLAN_T|
			IFACE_BOND_T|IFACE_BRIDGE_T))
			continue;
		if (iflinux_is_bond(cfg, interfaces, iface)) {
			log_debug("interfaces",
			    "interface %s is a bond",
			    iface->name);
			iface->type |= IFACE_BOND_T;
			iflinux_get_permanent_mac(cfg,
			    interfaces, iface);
		}
	}
}

/* Query each interface to see if it is a vlan */
static void
iflinux_add_vlan(struct lldpd *cfg,
    struct interfaces_device_list *interfaces)
{
	struct interfaces_device *iface;

	TAILQ_FOREACH(iface, interfaces, next) {
		if (iface->type & (IFACE_PHYSICAL_T|IFACE_VLAN_T|
			IFACE_BOND_T|IFACE_BRIDGE_T))
			continue;
		if (iflinux_is_vlan(cfg, interfaces, iface)) {
			log_debug("interfaces",
			    "interface %s is a VLAN",
			    iface->name);
			iface->type |= IFACE_VLAN_T;
		}
	}
}

static void
iflinux_add_physical(struct lldpd *cfg,
    struct interfaces_device_list *interfaces)
{
	struct interfaces_device *iface;
	/* White-list some drivers */
	const char * const *rif;
	const char * const regular_interfaces[] = {
		"dsa",
		"veth",
		NULL
	};

	TAILQ_FOREACH(iface, interfaces, next) {
		if (iface->type & (IFACE_VLAN_T|
			IFACE_BOND_T|IFACE_BRIDGE_T))
			continue;

		iface->type &= ~IFACE_PHYSICAL_T;

		/* We request that the interface is able to do either multicast
		 * or broadcast to be able to send discovery frames. */
		if (!(iface->flags & (IFF_MULTICAST|IFF_BROADCAST))) {
			log_debug("interfaces", "skip %s: not able to do multicast nor broadcast",
			    iface->name);
			continue;
		}

		/* If the interface is linked to another one, skip it too. */
		if (iface->lower) {
			log_debug("interfaces", "skip %s: there is a lower interface (%s)",
			    iface->name, iface->lower->name);
			continue;
		}

		/* Check if the driver is whitelisted */
		if (iface->driver) {
			for (rif = regular_interfaces; *rif; rif++) {
				if (strcmp(iface->driver, *rif) == 0) {
					/* White listed! */
					log_debug("interfaces", "accept %s: whitelisted",
					    iface->name);
					iface->type |= IFACE_PHYSICAL_T;
					continue;
				}
			}
		}

		/* Check queue len. If no queue, this usually means that this
		   is not a "real" interface. */
		if (iface->txqueue == 0) {
			log_debug("interfaces", "skip %s: no queue",
			    iface->name);
			continue;
		}

		log_debug("interfaces",
		    "%s is a physical interface",
		    iface->name);
		iface->type |= IFACE_PHYSICAL_T;
	}
}

void
interfaces_update(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
	struct interfaces_device_list *interfaces = NULL;
	struct interfaces_address_list *addresses = NULL;
	interfaces = netlink_get_interfaces();
	addresses = netlink_get_addresses();
	if (interfaces == NULL || addresses == NULL) {
		log_warnx("interfaces", "cannot update the list of local interfaces");
		goto end;
	}

	/* Add missing bits to list of interfaces */
	iflinux_add_driver(cfg, interfaces);
	iflinux_add_wireless(cfg, interfaces);
	iflinux_add_bridge(cfg, interfaces);
	iflinux_add_bond(cfg, interfaces);
	iflinux_add_vlan(cfg, interfaces);
	iflinux_add_physical(cfg, interfaces);

	interfaces_helper_whitelist(cfg, interfaces);
	iflinux_handle_bond(cfg, interfaces);
	interfaces_helper_physical(cfg, interfaces,
	    &eth_ops,
	    iflinux_eth_init);
#ifdef ENABLE_DOT1
	interfaces_helper_vlan(cfg, interfaces);
#endif
	interfaces_helper_mgmt(cfg, addresses);
	interfaces_helper_chassis(cfg, interfaces);

	/* Mac/PHY */
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if (!hardware->h_flags) continue;
		iflinux_macphy(hardware);
	}

end:
	interfaces_free_devices(interfaces);
	interfaces_free_addresses(addresses);
	return;

}
