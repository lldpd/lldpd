/*
 * Copyright (c) 2009 Vincent Bernat <bernat@luffy.cx>
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
#include <sys/uio.h>

#define DSA_MAX_PORTS 11
#define DSA_CPU_PORT "chan0"
#define DSA_MTU 1506		/* TODO: Including DSA tag */

static int	 dsa_cpu_if(struct lldpd *, const char *);
static char 	*dsa_port_name(struct lldpd *, int);
static int	 dsa_init(struct lldpd *, struct lldpd_hardware *);
static void	 dsa_callback(struct lldpd*, struct lldpd_callback*);

static int	 dsa_send(struct lldpd *, struct lldpd_hardware*, char *, size_t);
static int	 dsa_recv(struct lldpd *, struct lldpd_hardware*, int, char*, size_t);
static int	 dsa_close(struct lldpd *, struct lldpd_hardware *);
struct lldpd_ops dsa_ops = {
	.send = dsa_send,
	.recv = dsa_recv,
	.cleanup = dsa_close,
};

static int
dsa_cpu_if(struct lldpd *cfg, const char *name)
{
	/* TODO: check that this is a CPU interface for DSA */
	if (strncmp(DSA_CPU_PORT, name, IFNAMSIZ) == 0)
		return 1;
	return 0;
}

static char *
dsa_port_name(struct lldpd *cfg, int i)
{
	/* TODO: return the name of port `i' or NULL if it is not enabled. */
	return NULL;
}

/* This function receives frame for all ports. It should then find the
 * appropriate port for dispatch. */
static void
dsa_callback(struct lldpd *cfg, struct lldpd_callback *callback)
{
	struct lldpd_hardware *hardware;
	char *buffer;
	int n;

	if ((buffer = (char *)malloc(DSA_MTU)) ==
	    NULL) {
		LLOG_WARN("failed to alloc reception buffer");
		return;
	}
	if ((n = recv(callback->fd, buffer,
		    DSA_MTU, 0)) == -1) {
		LLOG_WARN("error while receiving message");
		free(buffer);
		return;
	}
	/* We need to know which port this frame is for. */
	if (n < ETH_ALEN*2 + 4) {
		LLOG_WARNX("frame too short to contain a DSA tag");
		free(buffer);
		return;
	}
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if (hardware->h_ops != &dsa_ops)
			continue;
		/* TODO: check if it is the right port */
		/* We shortcut the reception and decode the frame. We just need
		 * to strip out DSA tag */
		hardware->h_rx_cnt++;
		memmove(buffer + 2*ETH_ALEN, buffer + 2*ETH_ALEN + 4,
		    n - 2*ETH_ALEN - 4);
		lldpd_decode(cfg, buffer, n, hardware);
		break;
	}
	free(buffer);
}

static int
dsa_init(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	/* We open only one socket! */
	static int socket = -1;

	if (socket == -1) {
		    if ((socket = priv_iface_init(DSA_CPU_PORT)) == -1)
			    return -1;
		    /* TODO: set BPF filter, like iface_set_filter */
		    /* TODO: ask to receive LLDP frames */
		    /* We register our callback to handle any frame received on
		     * this socket */
		    if (lldpd_callback_add(cfg, socket,
			    dsa_callback, NULL) == -1) {
			    LLOG_WARNX("unable to set callback for DSA");
			    close(socket); socket = -1;
			    return -1;
		    }
	}

	hardware->h_sendfd = socket;

	/* We won't receive anything directly! Don't set h_recvfds. */

	LLOG_DEBUG("DSA interface %s initialized", hardware->h_ifname);
	return 0;
}

static int
dsa_send(struct lldpd *cfg, struct lldpd_hardware *hardware,
    char *buffer, size_t size)
{
	struct iovec iov[3];
	
	/* We need to modify the ethernet frame to include DSA header. */
	iov[0].iov_base = buffer;
	iov[0].iov_len = 2*ETH_ALEN;
	/* TODO: in iov[1], put the buffer containing DSA tag */
	iov[2].iov_base = buffer + 2*ETH_ALEN;
	iov[2].iov_len = size - 2*ETH_ALEN;
	return writev(hardware->h_sendfd, iov, 3);
}

static int
dsa_recv(struct lldpd *cfg, struct lldpd_hardware *hardware,
    int fd, char *buffer, size_t size)
{
	LLOG_WARN("this function should not have been called!");
	return 0;
}

static int
dsa_close(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	/* TODO: any cleanup needed. I think nothing is needed */
	return 0;
}

void
lldpd_ifh_dsa(struct lldpd *cfg, struct ifaddrs *ifap)
{
	struct ifaddrs *ifa;
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
	struct lldpd_vlan *vlan;
	char *name;
	int i;
	
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_flags)
			continue;
		if (!dsa_cpu_if(cfg, ifa->ifa_name))
			continue;

		/* Iterate through all possible ports */
		for (i = 0; i < DSA_MAX_PORTS; i++) {
			if ((name = dsa_port_name(cfg, i)) == NULL)
				/* This port is disabled */
				continue;

			if ((hardware =
				lldpd_get_hardware(cfg, name, i, &dsa_ops)) == NULL) {
				if  ((hardware = lldpd_alloc_hardware(cfg,
					    name)) == NULL) {
					LLOG_WARNX(
						"Unable to allocate space for DSA port %s",
					    name);
					continue;
				}
				if (dsa_init(cfg, hardware) != 0) {
					LLOG_WARN("unable to initialize DSA port %s",
					    hardware->h_ifname);
					lldpd_hardware_cleanup(cfg, hardware);
					continue;
				}
				hardware->h_ifindex = i;
				hardware->h_ops = &dsa_ops;
				TAILQ_INSERT_TAIL(&cfg->g_hardware, hardware, h_entries);
			} else {
				if (hardware->h_flags) continue;
				lldpd_port_cleanup(cfg, &hardware->h_lport, 0);
			}

			port = &hardware->h_lport;
			hardware->h_flags = ifa->ifa_flags;
			hardware->h_mtu = DSA_MTU;
			ifa->ifa_flags = 0;

			/* TODO: get MAC address in hardware->h_lladdr */
			/* TODO: copy MAC address in hardware->h_portid, like in
			 * iface_portid or put an hardware->h_ifname if we have a
			 * description. */
			/* TODO: set port description */
			port->p_descr = strdup(hardware->h_ifname);
			
			/* TODO: Fill additional info, like MAC/PHY */
			/* TODO: add VLAN if possible */
			for (;0;) {
				if ((vlan = (struct lldpd_vlan *)
					calloc(1, sizeof(struct lldpd_vlan))) == NULL)
					return;
				vlan->v_name = "VLAN 7547";
				vlan->v_vid = 7547;
				TAILQ_INSERT_TAIL(&port->p_vlans, vlan, v_entries);
			}
		}
	}
}
