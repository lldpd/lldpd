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
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

/* This implementation uses ioctl and not netlink. This should work with many
 * earlier Linux. However, because we use an AF_INET socket, we only get IPv4
 * addresses. Since lldpd only handles IPv4 for now, this is not a
 * problem. Moreover, IPv6 + libc not having getifaddrs should be pretty
 * rare. */
int
getifaddrs(struct ifaddrs **ifap)
{
	int sock, n, i;
	struct ifconf ifc;
	struct ifreq *ifr;
	char buffer[8192];
	struct ifaddrs *ifa = NULL, *lifa = NULL;

	*ifap = NULL;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -1;

	ifc.ifc_len = sizeof(buffer);
	ifc.ifc_buf = buffer;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
		goto fault;
	ifr = ifc.ifc_req;
	n = ifc.ifc_len / sizeof(struct ifreq);
	for (i = 0; i < n; i++) {
		if (ioctl(sock, SIOCGIFFLAGS, &ifr[i]) == -1)
			goto fault;
		ifa = (struct ifaddrs*)calloc(1, sizeof(struct ifaddrs));
		if ((ifa->ifa_name = strdup(ifr[i].ifr_name)) == NULL)
			goto fault;
		ifa->ifa_flags = ifr[i].ifr_flags;
		/* Address */
		if (ioctl(sock, SIOCGIFADDR, &ifr[i]) != -1) {
			if ((ifa->ifa_addr =
				(struct  sockaddr *)malloc(
				    sizeof(struct sockaddr_storage))) == NULL)
				goto fault;
			memcpy(ifa->ifa_addr, &ifr[i].ifr_addr,
			    sizeof(struct sockaddr_storage));
		}
		/* Netmask */
		if (ioctl(sock, SIOCGIFNETMASK, &ifr[i]) != -1) {
			if ((ifa->ifa_netmask =
				(struct sockaddr *)malloc(
				    sizeof(struct sockaddr_storage))) == NULL)
				goto fault;
			memcpy(ifa->ifa_netmask, &ifr[i].ifr_addr,
			    sizeof(struct sockaddr_storage));
		}
		/* Broadcast or point to point */
		if (ifr[i].ifr_flags & IFF_BROADCAST) {
			if (ioctl(sock, SIOCGIFBRDADDR, &ifr[i]) != -1) {
				if ((ifa->ifa_ifu.ifu_broadaddr =
					(struct sockaddr *)malloc(
						sizeof(struct sockaddr_storage))) == NULL)
					goto fault;
				memcpy(ifa->ifa_ifu.ifu_broadaddr,
				    &ifr[i].ifr_addr,
				    sizeof(struct sockaddr_storage));
			}
		} else if (ifr[i].ifr_flags & IFF_POINTOPOINT) {
			if (ioctl(sock, SIOCGIFDSTADDR, &ifr[i]) != -1) {
				if ((ifa->ifa_ifu.ifu_dstaddr =
					(struct sockaddr *)malloc(
						sizeof(struct sockaddr_storage))) == NULL)
					goto fault;
				memcpy(ifa->ifa_ifu.ifu_dstaddr,
				    &ifr[i].ifr_addr,
				    sizeof(struct sockaddr_storage));
			}
		}
		/* Link them together */
		if (lifa)
			lifa->ifa_next = ifa;
		else
			*ifap = ifa;
		lifa = ifa;
		ifa = NULL;
	}
	return 0;
fault:
	freeifaddrs(ifa);	/* It is not linked at anything if not NULL */
	freeifaddrs(*ifap);
	close(sock);
	return -1;
}

void
freeifaddrs(struct ifaddrs *ifa)
{
	struct ifaddrs *pifa;
	while (ifa) {
		pifa = ifa;
		ifa = ifa->ifa_next;
		free(pifa->ifa_name);
		free(pifa->ifa_netmask);
		free(pifa->ifa_addr);
		if (pifa->ifa_flags & IFF_BROADCAST)
			free(pifa->ifa_ifu.ifu_broadaddr);
		else if (pifa->ifa_flags & IFF_POINTOPOINT)
			free(pifa->ifa_ifu.ifu_dstaddr);
		free(pifa->ifa_data);
		free(pifa);
	}
}
