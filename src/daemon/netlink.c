/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2012 Vincent Bernat <bernat@luffy.cx>
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

/* Grabbing interfaces information with netlink only. */

#include "lldpd.h"

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <net/if_arp.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/vlan.h>

struct lldpd_netlink {
	struct nl_cache_mngr *mngr;
	struct nl_cache *addr;
	struct nl_cache *link;
};

/**
 * Callback when we get netlink updates.
 */
static void
netlink_change_cb(struct lldpd *cfg)
{
	int err;
	log_debug("netlink", "netlink update received");
	if ((err = nl_cache_mngr_data_ready(cfg->g_netlink->mngr)) < 0) {
		log_warn("netlink", "unable to parse incoming netlink messages: %s",
		    nl_geterror(err));
	}
}

/**
 * Initialize netlink subsystem.
 *
 * This can be called several times but will have effect only the first time.
 *
 * @return 0 on success, -1 otherwise
 */
static int
netlink_initialize(struct lldpd *cfg)
{
	int err;
	if (cfg->g_netlink) return 0;

	log_debug("netlink", "initialize netlink subsystem");
	if ((cfg->g_netlink = calloc(sizeof(struct lldpd_netlink), 1)) == NULL) {
		log_warn("netlink", "unable to allocate memory for netlink subsystem");
		goto end;
	}

	if ((err = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE,
		    &cfg->g_netlink->mngr)) < 0) {
		log_warn("netlink", "unable to allocate cache manager: %s",
		    nl_geterror(err));
		goto end;
	}

	if ((err = nl_cache_mngr_add(cfg->g_netlink->mngr,
		    "route/link", NULL, NULL, &cfg->g_netlink->link)) < 0) {
		log_warn("netlink", "unable to allocate route/link cache");
		goto end;
	}
	if ((err = nl_cache_mngr_add(cfg->g_netlink->mngr,
		    "route/addr", NULL, NULL, &cfg->g_netlink->addr)) < 0) {
		log_warn("netlink", "unable to allocate route/addr cache");
		goto end;
	}

	cfg->g_iface_cb = netlink_change_cb;
	if (levent_iface_subscribe(cfg, nl_cache_mngr_get_fd(cfg->g_netlink->mngr)) == -1) {
		goto end;
	}

	return 0;
end:
	netlink_cleanup(cfg);
	return -1;
}

/**
 * Cleanup netlink subsystem.
 */
void
netlink_cleanup(struct lldpd *cfg)
{
	if (cfg->g_netlink == NULL) return;
	if (cfg->g_netlink->mngr != NULL) nl_cache_mngr_free(cfg->g_netlink->mngr);

	free(cfg->g_netlink);
	cfg->g_netlink = NULL;
}

/**
 * Parse a `link` netlink message.
 *
 * @param link link object from cache
 * @return parsed interface
 */
static struct interfaces_device *
netlink_parse_link(struct rtnl_link *link)
{
	const char *name = rtnl_link_get_name(link);
	if (name == NULL) {
		log_debug("netlink", "skip unnamed interface");
		return NULL;
	}

	unsigned int flags = rtnl_link_get_flags(link);
	if (!((flags & IFF_UP) && (flags & IFF_RUNNING))) {
		log_debug("netlink", "skip down interface %s", name);
		return NULL;
	}
	if (rtnl_link_get_arptype(link) != ARPHRD_ETHER) {
		log_debug("netlink", "skip non Ethernet interface %s", name);
		return NULL;
	}

	struct interfaces_device *iff = calloc(1, sizeof(struct interfaces_device));
	if (iff == NULL) {
		log_warn("netlink", "no memory for a new interface");
		return NULL;
	}
	iff->index = rtnl_link_get_ifindex(link);;
	iff->flags = flags;
	iff->lower_idx = rtnl_link_get_link(link);
	iff->upper_idx = rtnl_link_get_master(link);
	iff->name = strdup(name);
	if (rtnl_link_get_ifalias(link) != NULL)
		iff->alias = strdup(rtnl_link_get_ifalias(link));

	struct nl_addr *mac = rtnl_link_get_addr(link);
	if (mac) {
		iff->address = malloc(nl_addr_get_len(mac));
		if (iff->address)
			memcpy(iff->address,
			    nl_addr_get_binary_addr(mac),
			    nl_addr_get_len(mac));
	}
	if (!iff->address) {
		log_info("netlink", "interface %d does not have a name or an address, skip",
		    iff->index);
		interfaces_free_device(iff);
		return NULL;
	}
	iff->txqueue = rtnl_link_get_txqlen(link);
	iff->mtu = rtnl_link_get_mtu(link);

	const char *kind = rtnl_link_get_type(link);
	if (kind) {
		if (!strcmp(kind, "vlan")) {
			iff->type |= IFACE_VLAN_T;
			iff->vlanid = rtnl_link_vlan_get_id(link);
			log_debug("netlink", "interface %s is a VLAN (id=%d)",
			    name, iff->vlanid);
		} else if (!strcmp(kind, "bridge")) {
			iff->type |= IFACE_BRIDGE_T;
			log_debug("netlink", "interface %s is a bridge",
			    name);
		} else if (!strcmp(kind, "bond")) {
			iff->type |= IFACE_BOND_T;
			log_debug("netlink", "interface %s is a bond",
			    name);
		}
	}

	return iff;
}

/**
 * Parse a `address` netlink message.
 *
 * @param addr address object from cache
 * @return parsed address
 */
static struct interfaces_address *
netlink_parse_address(struct rtnl_addr *addr)
{
	int family = rtnl_addr_get_family(addr);
	switch (family) {
	case AF_INET:
	case AF_INET6: break;
	default:
		log_debug("netlink", "got a non IP address on if %d (family: %d)",
		    rtnl_addr_get_ifindex(addr), family);
		return NULL;
	}

	struct interfaces_address *ifa = calloc(1, sizeof(struct interfaces_address));
	if (ifa == NULL) {
		log_warn("netlink", "no memory for a new address");
		return NULL;
	}
	ifa->index = rtnl_addr_get_ifindex(addr);
	ifa->flags = rtnl_addr_get_flags(addr);

	socklen_t len = sizeof(ifa->address);
	int err = nl_addr_fill_sockaddr(rtnl_addr_get_local(addr),
	    (struct sockaddr *)&ifa->address, &len);
	if (err < 0 || ifa->address.ss_family == AF_UNSPEC) {
		log_debug("netlink", "no IP for interface %d",
		    ifa->index);
		interfaces_free_address(ifa);
		return NULL;
	}
	return ifa;
}

/**
 * Receive the list of interfaces.
 *
 * @return a list of interfaces.
 */
struct interfaces_device_list*
netlink_get_interfaces(struct lldpd *cfg)
{
	if (netlink_initialize(cfg) == -1) return NULL;

	struct interfaces_device_list *ifs;

	log_debug("netlink", "get the list of available interfaces");
	ifs = malloc(sizeof(struct interfaces_device_list));
	if (ifs == NULL) {
		log_warn("netlink", "not enough memory for interface list");
		return NULL;
	}
	TAILQ_INIT(ifs);

	for (struct nl_object *link = nl_cache_get_first(cfg->g_netlink->link);
	     link != NULL;
	     link = nl_cache_get_next(link)) {
		nl_object_get(link);
		struct interfaces_device *iff = netlink_parse_link((struct rtnl_link *)link);
		if (iff) TAILQ_INSERT_TAIL(ifs, iff, next);
		nl_object_put(link);
	}

	struct interfaces_device *iface1, *iface2;
	TAILQ_FOREACH(iface1, ifs, next) {
		if (iface1->upper_idx != 0 && iface1->upper_idx != iface1->index)
			TAILQ_FOREACH(iface2, ifs, next) {
				if (iface1->upper_idx == iface2->index) {
					log_debug("netlink", "%s is upper iface for %s",
					    iface2->name, iface1->name);
					iface1->upper = iface2;
					break;
				}
			}
		if (iface1->lower_idx != 0 && iface1->lower_idx != iface1->index)
			TAILQ_FOREACH(iface2, ifs, next) {
				if (iface1->lower_idx == iface2->index) {
					if (iface2->lower_idx == iface1->index) {
						log_debug("netlink", "%s and %s are peered together",
						    iface1->name, iface2->name);
						/* Workaround a bug introduced in Linux 4.1 */
						iface2->lower_idx = iface2->index;
						iface1->lower_idx = iface1->index;
					} else {
						log_debug("netlink", "%s is lower iface for %s",
						    iface2->name, iface1->name);
						iface1->lower = iface2;
					}
					break;
				}
			}
	}

	return ifs;
}

/**
 * Receive the list of addresses.
 *
 * @return a list of addresses.
 */
struct interfaces_address_list*
netlink_get_addresses(struct lldpd *cfg)
{
	if (netlink_initialize(cfg) == -1) return NULL;

	struct interfaces_address_list *ifaddrs;

	log_debug("netlink", "get the list of available addresses");
	ifaddrs = malloc(sizeof(struct interfaces_address_list));
	if (ifaddrs == NULL) {
		log_warn("netlink", "not enough memory for address list");
		return NULL;
	}
	TAILQ_INIT(ifaddrs);

	for (struct nl_object *addr = nl_cache_get_first(cfg->g_netlink->addr);
	     addr != NULL;
	     addr = nl_cache_get_next(addr)) {
		nl_object_get(addr);
		struct interfaces_address *ifa = netlink_parse_address((struct rtnl_addr *)addr);
		if (ifa) TAILQ_INSERT_TAIL(ifaddrs, ifa, next);
		nl_object_put(addr);
	}

	return ifaddrs;
}
