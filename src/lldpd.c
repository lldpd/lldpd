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
#include <time.h>
#include <libgen.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#ifdef USE_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#endif /* USE_SNMP */

static void		 usage(void);

static struct protocol protos[] =
{
	{ LLDPD_MODE_LLDP, 1, "LLDP", ' ', lldp_send, lldp_decode, NULL,
	  LLDP_MULTICAST_ADDR },
#ifdef ENABLE_CDP
	{ LLDPD_MODE_CDPV1, 0, "CDPv1", 'c', cdpv1_send, cdp_decode, cdpv1_guess,
	  CDP_MULTICAST_ADDR },
	{ LLDPD_MODE_CDPV2, 0, "CDPv2", 'c', cdpv2_send, cdp_decode, cdpv2_guess,
	  CDP_MULTICAST_ADDR },
#endif
#ifdef ENABLE_SONMP
	{ LLDPD_MODE_SONMP, 0, "SONMP", 's', sonmp_send, sonmp_decode, NULL,
	  SONMP_MULTICAST_ADDR },
#endif
#ifdef ENABLE_EDP
	{ LLDPD_MODE_EDP, 0, "EDP", 'e', edp_send, edp_decode, NULL,
	  EDP_MULTICAST_ADDR },
#endif
#ifdef ENABLE_FDP
	{ LLDPD_MODE_FDP, 0, "FDP", 'f', fdp_send, cdp_decode, NULL,
	  FDP_MULTICAST_ADDR },
#endif
	{ 0, 0, "any", ' ', NULL, NULL, NULL,
	  {0,0,0,0,0,0} }
};

static void		 lldpd_update_localchassis(struct lldpd *);
static void		 lldpd_update_localports(struct lldpd *);
static void		 lldpd_cleanup(struct lldpd *);
static void		 lldpd_loop(struct lldpd *);
static void		 lldpd_shutdown(int);
static void		 lldpd_exit();
static void		 lldpd_send_all(struct lldpd *);
static void		 lldpd_recv_all(struct lldpd *);
static int		 lldpd_guess_type(struct lldpd *, char *, int);
static void		 lldpd_decode(struct lldpd *, char *, int,
			    struct lldpd_hardware *);
static void		 lldpd_update_chassis(struct lldpd_chassis *,
			    const struct lldpd_chassis *);
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

struct lldpd_hardware *
lldpd_get_hardware(struct lldpd *cfg, char *name, struct lldpd_ops *ops)
{
	struct lldpd_hardware *hardware;
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if ((strcmp(hardware->h_ifname, name) == 0) &&
		    ((!ops) || (ops == hardware->h_ops)))
			break;
	}
	return hardware;
}

struct lldpd_hardware *
lldpd_alloc_hardware(struct lldpd *cfg, char *name)
{
	struct lldpd_hardware *hardware;

	if ((hardware = (struct lldpd_hardware *)
		calloc(1, sizeof(struct lldpd_hardware))) == NULL)
		return NULL;

	strlcpy(hardware->h_ifname, name, sizeof(hardware->h_ifname));
	hardware->h_lport.p_chassis = LOCAL_CHASSIS(cfg);
	TAILQ_INIT(&hardware->h_rports);

#ifdef ENABLE_LLDPMED
	if (LOCAL_CHASSIS(cfg)->c_med_cap_available) {
		hardware->h_lport.p_med_cap_enabled = LLDPMED_CAP_CAP;
		if (!cfg->g_noinventory)
			hardware->h_lport.p_med_cap_enabled |= LLDPMED_CAP_IV;
	}
#endif
#ifdef ENABLE_DOT1
	TAILQ_INIT(&hardware->h_lport.p_vlans);
#endif
	return hardware;
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
   are not refreshed periodically. Port should be freed manually. */
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
	if (all) {
		free(port->p_lastframe);
		if (port->p_chassis) /* chassis may not have been attributed, yet */
			port->p_chassis->c_refcount--;
	}
}

void
lldpd_chassis_cleanup(struct lldpd_chassis *chassis, int all)
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
	if (all)
		free(chassis);
}

void
lldpd_remote_cleanup(struct lldpd *cfg, struct lldpd_hardware *hardware, int all)
{
	struct lldpd_port *port, *port_next;
	int del;
	for (port = TAILQ_FIRST(&hardware->h_rports);
	     port != NULL;
	     port = port_next) {
		port_next = TAILQ_NEXT(port, p_entries);
		del = all;
		if (!del &&
		    (time(NULL) - port->p_lastupdate > port->p_chassis->c_ttl)) {
			hardware->h_rx_ageout_cnt++;
			del = 1;
		}
		if (del) {
			TAILQ_REMOVE(&hardware->h_rports, port, p_entries);
			lldpd_port_cleanup(port, 1);
			free(port);
		}
	}
}

void
lldpd_hardware_cleanup(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	int i;
	lldpd_port_cleanup(&hardware->h_lport, 1);
	/* If we have a dedicated cleanup function, use it. Otherwise,
	   we just free the hardware-dependent data and close all FD
	   in h_recvfds and h_sendfd. */
	if (hardware->h_ops->cleanup)
		hardware->h_ops->cleanup(cfg, hardware);
	else {
		free(hardware->h_data);
		for (i=0; i < FD_SETSIZE; i++)
			if (FD_ISSET(i, &hardware->h_recvfds))
				close(i);
		if (hardware->h_sendfd) close(hardware->h_sendfd);
	}
	free(hardware);
}

static void
lldpd_cleanup(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware, *hardware_next;

	for (hardware = TAILQ_FIRST(&cfg->g_hardware); hardware != NULL;
	     hardware = hardware_next) {
		hardware_next = TAILQ_NEXT(hardware, h_entries);
		if (!hardware->h_flags) {
			TAILQ_REMOVE(&cfg->g_hardware, hardware, h_entries);
			lldpd_remote_cleanup(cfg, hardware, 1);
			lldpd_hardware_cleanup(cfg, hardware);
		} else
			lldpd_remote_cleanup(cfg, hardware, 0);
	}
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
    struct lldpd_hardware *hardware)
{
	int i, result;
	struct lldpd_chassis *chassis, *ochassis = NULL;
	struct lldpd_port *port, *oport = NULL;
	int guess = LLDPD_MODE_LLDP;

	/* Discard VLAN frames */
	if ((s >= sizeof(struct ethhdr)) &&
	    (((struct ethhdr*)frame)->h_proto == htons(ETHERTYPE_VLAN)))
		return;

	TAILQ_FOREACH(oport, &hardware->h_rports, p_entries) {
		if ((oport->p_lastframe != NULL) &&
		    (oport->p_lastframe->size == s) &&
		    (memcmp(oport->p_lastframe->frame, frame, s) == 0)) {
			/* Already received the same frame */
			oport->p_lastupdate = time(NULL);
			return;
		}
	}

	guess = lldpd_guess_type(cfg, frame, s);
	for (i=0; cfg->g_protocols[i].mode != 0; i++) {
		if (!cfg->g_protocols[i].enabled)
			continue;
		if (cfg->g_protocols[i].mode == guess) {
			if ((result = cfg->g_protocols[i].decode(cfg, frame,
				    s, hardware, &chassis, &port)) == -1)
				return;
			chassis->c_protocol = port->p_protocol =
			    cfg->g_protocols[i].mode;
			break;
			}
	}
	if (cfg->g_protocols[i].mode == 0) {
		LLOG_INFO("unable to guess frame type");
		return;
	}

	/* Do we already have the same MSAP somewhere? */
	TAILQ_FOREACH(oport, &hardware->h_rports, p_entries) {
		if ((port->p_protocol == oport->p_protocol) &&
		    (port->p_id_subtype == oport->p_id_subtype) &&
		    (port->p_id_len == oport->p_id_len) &&
		    (memcmp(port->p_id, oport->p_id, port->p_id_len) == 0) &&
		    (chassis->c_id_subtype == oport->p_chassis->c_id_subtype) &&
		    (chassis->c_id_len == oport->p_chassis->c_id_len) &&
		    (memcmp(chassis->c_id, oport->p_chassis->c_id,
			chassis->c_id_len) == 0)) {
			ochassis = oport->p_chassis;
			break;
		}
	}
	/* No, but do we already know the system? */
	if (!oport) {
		TAILQ_FOREACH(ochassis, &cfg->g_chassis, c_entries) {
			if ((chassis->c_protocol == ochassis->c_protocol) &&
			    (chassis->c_id_subtype == ochassis->c_id_subtype) &&
			    (chassis->c_id_len == ochassis->c_id_len) &&
			    (memcmp(chassis->c_id, ochassis->c_id,
				chassis->c_id_len) == 0))
			break;
		}
	}

	if (oport) {
		/* The port is known, remove it before adding it back */
		TAILQ_REMOVE(&hardware->h_rports, oport, p_entries);
		lldpd_port_cleanup(oport, 1);
		free(oport);
	}
	if (ochassis) {
		lldpd_update_chassis(ochassis, chassis);
		free(chassis);
		chassis = ochassis;
	} else {
		/* Chassis not known, add it */
		chassis->c_index = ++cfg->g_lastrid;
		port->p_chassis = chassis;
		chassis->c_refcount = 0;
		TAILQ_INSERT_TAIL(&cfg->g_chassis, chassis, c_entries);
		i = 0; TAILQ_FOREACH(ochassis, &cfg->g_chassis, c_entries) i++;
		LLOG_DEBUG("Currently, we know %d different systems", i);
	}
	/* Add port */
	port->p_lastchange = port->p_lastupdate = time(NULL);
	if ((port->p_lastframe = (struct lldpd_frame *)malloc(s +
		    sizeof(int))) != NULL) {
		port->p_lastframe->size = s;
		memcpy(port->p_lastframe->frame, frame, s);
	}
	TAILQ_INSERT_TAIL(&hardware->h_rports, port, p_entries);
	port->p_chassis = chassis;
	port->p_chassis->c_refcount++;
	i = 0; TAILQ_FOREACH(oport, &hardware->h_rports, p_entries) i++;
	LLOG_DEBUG("Currently, %s known %d neighbors",
	    hardware->h_ifname, i);
	return;
}

/* Update chassis `ochassis' with values from `chassis'. */
static void
lldpd_update_chassis(struct lldpd_chassis *ochassis,
    const struct lldpd_chassis *chassis) {
	TAILQ_ENTRY(lldpd_chassis) entries;
	/* We want to keep refcount, index and list stuff from the current
	 * chassis */
	int refcount = ochassis->c_refcount;
	int index = ochassis->c_index;
	memcpy(&entries, &ochassis->c_entries,
	    sizeof(entries));
	/* Make the copy */
	lldpd_chassis_cleanup(ochassis, 0);
	memcpy(ochassis, chassis, sizeof(struct lldpd_chassis));
	/* Restore saved values */
	ochassis->c_refcount = refcount;
	ochassis->c_index = index;
	memcpy(&ochassis->c_entries, &entries, sizeof(entries));
}


static void
lldpd_recv_all(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
	struct lldpd_client *client, *client_next;
	fd_set rfds;
	struct timeval tv;
#ifdef USE_SNMP
	int fakeblock = 0;
	struct timeval *tvp = &tv;
#endif
	int rc, nfds, n;
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
			if ((hardware->h_flags & IFF_RUNNING) == 0)
				continue;
			/* This is quite expensive but we don't rely on internal
			 * structure of fd_set. */
			for (n = 0; n < FD_SETSIZE; n++)
				if (FD_ISSET(n, &hardware->h_recvfds)) {
					FD_SET(n, &rfds);
					if (nfds < n)
						nfds = n;
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
			for (n = 0; n < FD_SETSIZE; n++)
				if ((FD_ISSET(n, &hardware->h_recvfds)) &&
				    (FD_ISSET(n, &rfds))) break;
			if (n == FD_SETSIZE) continue;
			if ((buffer = (char *)malloc(
					hardware->h_mtu)) == NULL) {
				LLOG_WARN("failed to alloc reception buffer");
				continue;
			}
			if ((n = hardware->h_ops->recv(cfg, hardware,
				    n, buffer, hardware->h_mtu)) == -1) {
				free(buffer);
				continue;
			}
			hardware->h_rx_cnt++;
			lldpd_decode(cfg, buffer, n, hardware);
			free(buffer);
			break;
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
	struct lldpd_port *port;
	int i, sent = 0;

	cfg->g_lastsent = time(NULL);
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		/* Ignore if interface is down */
		if ((hardware->h_flags & IFF_RUNNING) == 0)
			continue;

		for (i=0; cfg->g_protocols[i].mode != 0; i++) {
			if (!cfg->g_protocols[i].enabled)
				continue;
			/* We send only if we have at least one remote system
			 * speaking this protocol */
			TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
				if (port->p_protocol ==
				    cfg->g_protocols[i].mode) {
					cfg->g_protocols[i].send(cfg,
					    hardware);
					sent = 1;
					break;
				}
			}
		}

		if (!sent)
			/* Nothing was sent for this port, let's speak LLDP */
			cfg->g_protocols[0].send(cfg,
			    hardware);
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
lldpd_update_localchassis(struct lldpd *cfg)
{
	struct utsname un;
	char *hp;
	int f;
	char status;
	struct lldpd_hardware *hardware;

	/* Set system name and description */
	if (uname(&un) != 0)
		fatal("failed to get system information");
	if ((hp = priv_gethostbyname()) == NULL)
		fatal("failed to get system name");
	free(LOCAL_CHASSIS(cfg)->c_name);
	free(LOCAL_CHASSIS(cfg)->c_descr);
	if ((LOCAL_CHASSIS(cfg)->c_name = strdup(hp)) == NULL)
		fatal(NULL);
	if (asprintf(&LOCAL_CHASSIS(cfg)->c_descr, "%s %s %s %s",
		un.sysname, un.release, un.version, un.machine) == -1)
		fatal("failed to set system description");

	/* Check forwarding */
	if ((f = priv_open("/proc/sys/net/ipv4/ip_forward")) >= 0) {
		if ((read(f, &status, 1) == 1) && (status == '1')) {
			LOCAL_CHASSIS(cfg)->c_cap_enabled = LLDP_CAP_ROUTER;
		}
		close(f);
	}
#ifdef ENABLE_LLDPMED
	if (LOCAL_CHASSIS(cfg)->c_cap_available & LLDP_CAP_TELEPHONE)
		LOCAL_CHASSIS(cfg)->c_cap_enabled |= LLDP_CAP_TELEPHONE;
	lldpd_med(LOCAL_CHASSIS(cfg));
	free(LOCAL_CHASSIS(cfg)->c_med_sw);
	LOCAL_CHASSIS(cfg)->c_med_sw = strdup(un.release);
#endif

	/* Set chassis ID if needed */
	if ((LOCAL_CHASSIS(cfg)->c_id == NULL) &&
	    (hardware = TAILQ_FIRST(&cfg->g_hardware))) {
		if ((LOCAL_CHASSIS(cfg)->c_id =
			malloc(sizeof(hardware->h_lladdr))) == NULL)
			fatal(NULL);
		LOCAL_CHASSIS(cfg)->c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
		LOCAL_CHASSIS(cfg)->c_id_len = sizeof(hardware->h_lladdr);
		memcpy(LOCAL_CHASSIS(cfg)->c_id,
		    hardware->h_lladdr, sizeof(hardware->h_lladdr));
	}
}

static void
lldpd_update_localports(struct lldpd *cfg)
{
	struct ifaddrs *ifap;
	struct lldpd_hardware *hardware;
	lldpd_ifhandlers ifhs[] = {
		lldpd_ifh_bond,	/* Handle bond */
		lldpd_ifh_eth,	/* Handle classic ethernet interfaces */
#ifdef ENABLE_DOT1
		lldpd_ifh_vlan,	/* Handle VLAN */
#endif
		lldpd_ifh_mgmt,	/* Handle management address (if not already handled) */
		NULL
	};
	lldpd_ifhandlers *ifh;

	/* h_flags is set to 0 for each port. If the port is updated, h_flags
	 * will be set to a non-zero value. This will allow us to clean up any
	 * non up-to-date port */
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries)
	    hardware->h_flags = 0;

	LOCAL_CHASSIS(cfg)->c_mgmt.s_addr = INADDR_ANY;
	if (getifaddrs(&ifap) != 0)
		fatal("lldpd_update_localports: failed to get interface list");

	/* We will run the list of interfaces through a list of interface
	 * handlers. Each handler will create or update some hardware port (and
	 * will set h_flags to a non zero value. The handler can use the list of
	 * interfaces but this is not mandatory. If the interface handler
	 * handles an interface from the list, it should set ifa_flags to 0 to
	 * let know the other handlers that it took care of this interface. This
	 * means that more specific handlers should be before less specific
	 * ones. */
	for (ifh = ifhs; *ifh != NULL; ifh++)
		(*ifh)(cfg, ifap);
	freeifaddrs(ifap);
}

static void
lldpd_loop(struct lldpd *cfg)
{
	/* Main loop.
	   
	   1. Update local ports information
	   2. Clean unwanted (removed) local ports
	   3. Update local chassis information
	   4. Send packets
	   5. Receive packets
	*/
	LOCAL_CHASSIS(cfg)->c_cap_enabled = 0;
	lldpd_update_localports(cfg);
	lldpd_cleanup(cfg);
	lldpd_update_localchassis(cfg);
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
	struct lldpd_hardware *hardware, *hardware_next;
	close(gcfg->g_ctl);
	priv_ctl_cleanup();
	for (hardware = TAILQ_FIRST(&gcfg->g_hardware); hardware != NULL;
	     hardware = hardware_next) {
		hardware_next = TAILQ_NEXT(hardware, h_entries);
		lldpd_hardware_cleanup(gcfg, hardware);
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
	struct lldpd_chassis *lchassis;
	int ch, debug = 0;
#ifdef USE_SNMP
	int snmp = 0;
#endif
	char *mgmtp = NULL;
	char *popt, opts[] = "vdxm:p:M:i@                    ";
	int i, found, vlan = 0;
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
		case 'v':
			vlan = 1;
			break;
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
	if ((lchassis = (struct lldpd_chassis*)
		calloc(1, sizeof(struct lldpd_chassis))) == NULL)
		fatal(NULL);
	lchassis->c_cap_available = LLDP_CAP_BRIDGE | LLDP_CAP_WLAN |
	    LLDP_CAP_ROUTER;
#ifdef ENABLE_LLDPMED
	if (lldpmed > 0) {
		if (lldpmed == LLDPMED_CLASS_III)
			lchassis->c_cap_available |= LLDP_CAP_TELEPHONE;
		lchassis->c_med_type = lldpmed;
		lchassis->c_med_cap_available = LLDPMED_CAP_CAP |
		    LLDPMED_CAP_IV | LLDPMED_CAP_LOCATION;
		cfg->g_noinventory = noinventory;
	} else
		cfg->g_noinventory = 1;
#endif

	/* Set TTL */
	lchassis->c_ttl = LLDPD_TTL;

	cfg->g_protocols = protos;
	for (i=0; protos[i].mode != 0; i++)
		if (protos[i].enabled) {
			LLOG_INFO("protocol %s enabled", protos[i].name);
		} else
			LLOG_INFO("protocol %s disabled", protos[i].name);

	TAILQ_INIT(&cfg->g_hardware);
	TAILQ_INIT(&cfg->g_chassis);
	TAILQ_INSERT_TAIL(&cfg->g_chassis, lchassis, c_entries);
	lchassis->c_refcount++;

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
