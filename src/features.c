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

#define INCLUDE_LINUX_IF_H
#include "lldpd.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/if_bonding.h>
#include <linux/if_bridge.h>
#include <linux/wireless.h>
#include <linux/sockios.h>

#define SYSFS_PATH_MAX 256
#define MAX_PORTS 1024
#define MAX_BRIDGES 1024

/* net/if.h */
extern unsigned int if_nametoindex (__const char *__ifname) __THROW;
extern char *if_indextoname (unsigned int __ifindex, char *__ifname) __THROW;

static int
old_iface_is_bridge(struct lldpd *cfg, const char *name)
{
	int ifindices[MAX_BRIDGES];
	char ifname[IFNAMSIZ];
	int num, i;
	unsigned long args[3] = { BRCTL_GET_BRIDGES,
				  (unsigned long)ifindices, MAX_BRIDGES };
	if ((num = ioctl(cfg->g_sock, SIOCGIFBR, args)) < 0) {
		if (errno != ENOPKG)
			LLOG_INFO("unable to get available bridges");
		return 0;
	}
	for (i = 0; i < num; i++) {
		if (if_indextoname(ifindices[i], ifname) == NULL)
			LLOG_INFO("unable to get name of interface %d",
			    ifindices[i]);
		else if (strncmp(name, ifname, IFNAMSIZ) == 0)
			return 1;
	}
	return 0;
}

int
iface_is_bridge(struct lldpd *cfg, const char *name)
{
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
}

int
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

int
iface_is_wireless(struct lldpd *cfg, const char *name)
{
	struct iwreq iwr;
	strlcpy(iwr.ifr_name, name, IFNAMSIZ);
	if (ioctl(cfg->g_sock, SIOCGIWNAME, &iwr) >= 0)
		return 1;
	return 0;
}

int
iface_is_bond(struct lldpd *cfg, const char *name)
{
	struct ifreq ifr;
	struct ifbond ifb;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifb, 0, sizeof(ifb));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_data = &ifb;
	if (ioctl(cfg->g_sock, SIOCBONDINFOQUERY, &ifr) >= 0)
		return 1;
	return 0;
}

int
iface_is_bond_slave(struct lldpd *cfg, const char *slave, const char *master,
    int *active)
{
	struct ifreq ifr;
	struct ifbond ifb;
	struct ifslave ifs;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifb, 0, sizeof(ifb));
	strlcpy(ifr.ifr_name, master, sizeof(ifr.ifr_name));
	ifr.ifr_data = &ifb;
	if (ioctl(cfg->g_sock, SIOCBONDINFOQUERY, &ifr) >= 0) {
		while (ifb.num_slaves--) {
			memset(&ifr, 0, sizeof(ifr));
			memset(&ifs, 0, sizeof(ifs));
			strlcpy(ifr.ifr_name, master, sizeof(ifr.ifr_name));
			ifr.ifr_data = &ifs;
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

int
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

int
iface_is_slave_active(struct lldpd *cfg, int master, const char *slave)
{
	char mastername[IFNAMSIZ];
	int active;
	if (if_indextoname(master, mastername) == NULL) {
		LLOG_WARNX("unable to get master name for %s",
		    slave);
		return 0;	/* Safest choice */
	}
	if (!iface_is_bond_slave(cfg, slave, mastername, &active)) {
		LLOG_WARNX("unable to get slave status for %s",
		    slave);
		return 0;		/* Safest choice */
	}
	return (active == BOND_STATE_ACTIVE);
}

void
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


#ifdef ENABLE_LLDPMED
	/* Fill in inventory stuff:
	    - hardware version: /sys/class/dmi/id/product_version
	    - firmware version: /sys/class/dmi/id/bios_version
	    - software version: `uname -r`
	    - serial number: /sys/class/dmi/id/product_serial
	    - manufacturer: /sys/class/dmi/id/sys_vendor
	    - model: /sys/class/dmi/id/product_name
	    - asset: /sys/class/dmi/id/chassis_asset_tag
	*/

char*
dmi_get(char *file)
{
	int dmi, s;
	char buffer[100];
	
	if ((dmi = priv_open(file)) < 0) {
		LLOG_DEBUG("cannot get DMI file %s", file);
		return NULL;
	}
	memset(buffer, 0, sizeof(buffer));
	if ((s = read(dmi, buffer, sizeof(buffer))) == -1) {
		LLOG_DEBUG("cannot read DMI file %s", file);
		close(dmi);
		return NULL;
	}
	close(dmi);
	buffer[sizeof(buffer) - 1] = '\0';
	if ((s > 0) && (buffer[s-1] == '\n'))
		buffer[s-1] = '\0';
	if (strlen(buffer))
		return strdup(buffer);
	return NULL;
}

char*
dmi_hw()
{
	return dmi_get(SYSFS_CLASS_DMI "product_version");
}

char*
dmi_fw()
{
	return dmi_get(SYSFS_CLASS_DMI "bios_version");
}

char*
dmi_sn()
{
	return dmi_get(SYSFS_CLASS_DMI "product_serial");
}

char*
dmi_manuf()
{
	return dmi_get(SYSFS_CLASS_DMI "sys_vendor");
}

char*
dmi_model()
{
	return dmi_get(SYSFS_CLASS_DMI "product_name");
}

char*
dmi_asset()
{
	return dmi_get(SYSFS_CLASS_DMI "chassis_asset_tag");
}
#endif
