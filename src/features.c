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
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/if_bonding.h>
#include <linux/if_bridge.h>
#include <linux/wireless.h>
#include <linux/sockios.h>

#define SYSFS_PATH_MAX 256
#define MAX_PORTS 1024

/* net/if.h */
extern unsigned int if_nametoindex (__const char *__ifname) __THROW;

int
old_iface_is_bridge(struct lldpd *cfg, const char *name)
{
	struct ifreq ifr;
	struct __bridge_info i;
	unsigned long args[4] = { BRCTL_GET_BRIDGE_INFO,
				  (unsigned long) &i, 0, 0 };
	strlcpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_data = (char *) &args;

	if (ioctl(cfg->g_sock, SIOCDEVPRIVATE, &ifr) < 0)
		return 0;
	return 1;
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
old_iface_is_bridged(struct lldpd *cfg, const char *name)
{
	int i;
	int ifindex = if_nametoindex(name);
	int ifindices[MAX_PORTS];
	unsigned long args[4] = { BRCTL_GET_PORT_LIST,
				  (unsigned long)ifindices, MAX_PORTS, 0 };
	struct ifreq ifr;
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap) != 0) {
		LLOG_WARN("unable to get interface list");
		return 0;
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		memset(ifindices, 0, sizeof(ifindices));
		strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ);
		ifr.ifr_data = (char *)&args;
		
		if (ioctl(cfg->g_sock, SIOCDEVPRIVATE, &ifr) < 0)
			/* Not a bridge */
			continue;

		for (i = 0; i < MAX_PORTS; i++) {
			if (ifindices[i] == ifindex) {
				freeifaddrs(ifap);
				return 1;
			}
		}
	}

	return 0;
}

int
iface_is_bridged(struct lldpd *cfg, const char *name)
{
	char path[SYSFS_PATH_MAX];
	int f;

	if ((snprintf(path, SYSFS_PATH_MAX,
		    SYSFS_CLASS_NET "%s/" SYSFS_BRIDGE_PORT_ATTR,
		    name)) >= SYSFS_PATH_MAX)
		LLOG_WARNX("path truncated");
	if ((f = priv_open(path)) < 0) {
		return old_iface_is_bridged(cfg, name);
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
iface_is_bond_slave(struct lldpd *cfg, const char *slave, const char *master)
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
			    (strncmp(ifs.slave_name, slave, sizeof(ifs.slave_name)) == 0))
				return 1;
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
		if (iface_is_bond_slave(cfg, name, ifa->ifa_name)) {
			master = if_nametoindex(ifa->ifa_name);
			freeifaddrs(ifap);
			return master;
		}
	}
	freeifaddrs(ifap);
	return -1;
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
