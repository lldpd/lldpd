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
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#if LLDPD_FD_SETSIZE != FD_SETSIZE
# warning "FD_SETSIZE is set to an inconsistent value."
#endif

#ifdef USE_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#endif /* USE_SNMP */

static void		 usage(void);

static struct protocol protos[] =
{
	{ LLDPD_MODE_LLDP, 1, "LLDP", 'l', lldp_send, lldp_decode, NULL,
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
static void		 lldpd_exit(void);
static void		 lldpd_send_all(struct lldpd *);
static void		 lldpd_recv_all(struct lldpd *);
static void		 lldpd_hide_all(struct lldpd *);
static int		 lldpd_guess_type(struct lldpd *, char *, int);
static void		 lldpd_decode(struct lldpd *, char *, int,
			    struct lldpd_hardware *);
static void		 lldpd_update_chassis(struct lldpd_chassis *,
			    const struct lldpd_chassis *);
static char 		*lldpd_get_lsb_release(void);
#ifdef ENABLE_LLDPMED
static void		 lldpd_med(struct lldpd_chassis *);
#endif

static char		**saved_argv;
#ifdef HAVE___PROGNAME
extern const char	*__progname;
#else
# define __progname "lldpd"
#endif

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [OPTIONS ...]\n", __progname);

	fprintf(stderr, "\n");

	fprintf(stderr, "-d       Do not daemonize.\n");
	fprintf(stderr, "-i       Disable LLDP-MED inventory TLV transmission.\n");
	fprintf(stderr, "-k       Disable advertising of kernel release, version, machine.\n");
	fprintf(stderr, "-S descr Override the default system description.\n");
	fprintf(stderr, "-m IP    Specify the management address of this system.\n");
	fprintf(stderr, "-H mode  Specify the behaviour when detecting multiple neighbors.\n");
#ifdef ENABLE_LLDPMED
	fprintf(stderr, "-M class Enable emission of LLDP-MED frame. 'class' should be one of:\n");
	fprintf(stderr, "             1 Generic Endpoint (Class I)\n");
	fprintf(stderr, "             2 Media Endpoint (Class II)\n");
	fprintf(stderr, "             3 Communication Device Endpoints (Class III)\n");
	fprintf(stderr, "             4 Network Connectivity Device\n");
#endif
#ifdef USE_SNMP
	fprintf(stderr, "-x       Enable SNMP subagent.\n");
#endif
	fprintf(stderr, "\n");

#if defined ENABLE_CDP || defined ENABLE_EDP || defined ENABLE_FDP || defined ENABLE_SONMP
	fprintf(stderr, "Additional protocol support.\n");
#ifdef ENABLE_CDP
	fprintf(stderr, "-c       Enable the support of CDP protocol. (Cisco)\n");
#endif
#ifdef ENABLE_EDP
	fprintf(stderr, "-e       Enable the support of EDP protocol. (Extreme)\n");
#endif
#ifdef ENABLE_FDP
	fprintf(stderr, "-f       Enable the support of FDP protocol. (Foundry)\n");
#endif
#ifdef ENABLE_SONMP
	fprintf(stderr, "-s       Enable the support of SONMP protocol. (Nortel)\n");
#endif

	fprintf(stderr, "\n");
#endif

	fprintf(stderr, "see manual page lldpd(8) for more information\n");
	exit(1);
}

struct lldpd_hardware *
lldpd_get_hardware(struct lldpd *cfg, char *name, int index, struct lldpd_ops *ops)
{
	struct lldpd_hardware *hardware;
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if ((strcmp(hardware->h_ifname, name) == 0) &&
		    (hardware->h_ifindex == index) &&
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
	hardware->h_lport.p_chassis->c_refcount++;
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
lldpd_port_cleanup(struct lldpd *cfg, struct lldpd_port *port, int all)
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
		if (port->p_chassis) { /* chassis may not have been attributed, yet */
			port->p_chassis->c_refcount--;
			port->p_chassis = NULL;
		}
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
			lldpd_port_cleanup(cfg, port, 1);
			free(port);
		}
	}
}

void
lldpd_hardware_cleanup(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	int i;
	lldpd_port_cleanup(cfg, &hardware->h_lport, 1);
	/* If we have a dedicated cleanup function, use it. Otherwise,
	   we just free the hardware-dependent data and close all FD
	   in h_recvfds and h_sendfd. */
	if (hardware->h_ops->cleanup)
		hardware->h_ops->cleanup(cfg, hardware);
	else {
		free(hardware->h_data);
		for (i=0; i < LLDPD_FD_SETSIZE; i++)
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
	struct lldpd_chassis *chassis, *chassis_next;

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

	for (chassis = TAILQ_FIRST(&cfg->g_chassis); chassis;
	     chassis = chassis_next) {
		chassis_next = TAILQ_NEXT(chassis, c_entries);
		if (chassis->c_refcount == 0) {
			TAILQ_REMOVE(&cfg->g_chassis, chassis, c_entries);
			lldpd_chassis_cleanup(chassis, 1);
		}
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

	if (s < sizeof(struct ethhdr) + 4)
		/* Too short, just discard it */
		return;
	/* Decapsulate VLAN frames */
	if (((struct ethhdr*)frame)->h_proto == htons(ETHERTYPE_VLAN)) {
		/* VLAN decapsulation means to shift 4 bytes left the frame from
		 * offset 2*ETH_ALEN */
		memmove(frame + 2*ETH_ALEN, frame + 2*ETH_ALEN + 4, s - 2*ETH_ALEN);
		s -= 4;
	}

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
		lldpd_port_cleanup(cfg, oport, 1);
		free(oport);
	}
	if (ochassis) {
		lldpd_update_chassis(ochassis, chassis);
		free(chassis);
		chassis = ochassis;
	} else {
		/* Chassis not known, add it */
		chassis->c_index = ++cfg->g_lastrid;
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
	/* Several cases are possible :
	     1. chassis is new, its refcount was 0. It is now attached
	        to this port, its refcount is 1.
	     2. chassis already exists and was attached to another
	        port, we increase its refcount accordingly.
	     3. chassis already exists and was attached to the same
	        port, its refcount was decreased with
	        lldpd_port_cleanup() and is now increased again.

	   In all cases, if the port already existed, it has been
	   freed with lldpd_port_cleanup() and therefore, the refcount
	   of the chassis that was attached to it is decreased.
	*/
	i = 0; TAILQ_FOREACH(oport, &hardware->h_rports, p_entries)
		i++;
	LLOG_DEBUG("Currently, %s knows %d neighbors",
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

/* Get the output of lsb_release -s -d.  This is a slow function. It should be
   called once. It return NULL if any problem happens. Otherwise, this is a
   statically allocated buffer. The result includes the trailing \n  */
static char *
lldpd_get_lsb_release() {
	static char release[1024];
	char *const command[] = { "lsb_release", "-s", "-d", NULL };
	int pid, status, devnull, count;
	int pipefd[2];

	if (pipe(pipefd)) {
		LLOG_WARN("unable to get a pair of pipes");
		return NULL;
	}

	if ((pid = fork()) < 0) {
		LLOG_WARN("unable to fork");
		return NULL;
	}
	switch (pid) {
	case 0:
		/* Child, exec lsb_release */
		close(pipefd[0]);
		if ((devnull = open("/dev/null", O_RDWR, 0)) != -1) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDERR_FILENO);
			dup2(pipefd[1], STDOUT_FILENO);
			if (devnull > 2) close(devnull);
			if (pipefd[1] > 2) close(pipefd[1]);
			execvp("lsb_release", command);
		}
		exit(127);
		break;
	default:
		/* Father, read the output from the children */
		close(pipefd[1]);
		count = 0;
		do {
			status = read(pipefd[0], release+count, sizeof(release)-count);
			if ((status == -1) && (errno == EINTR)) continue;
			if (status > 0)
				count += status;
		} while (count < sizeof(release) && (status > 0));
		if (status < 0) {
			LLOG_WARN("unable to read from lsb_release");
			close(pipefd[0]);
			waitpid(pid, &status, 0);
			return NULL;
		}
		close(pipefd[0]);
		if (count >= sizeof(release)) {
			LLOG_INFO("output of lsb_release is too large");
			waitpid(pid, &status, 0);
			return NULL;
		}
		status = -1;
		if (waitpid(pid, &status, 0) != pid)
			return NULL;
		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
			LLOG_INFO("lsb_release information not available");
			return NULL;
		}
		if (!count) {
			LLOG_INFO("lsb_release returned an empty string");
			return NULL;
		}
		release[count] = '\0';
		return release;
	}
	/* Should not be here */
	return NULL;
}

int
lldpd_callback_add(struct lldpd *cfg, int fd, void(*fn)(CALLBACK_SIG), void *data)
{
	struct lldpd_callback *callback;
	if ((callback = (struct lldpd_callback *)
		malloc(sizeof(struct lldpd_callback))) == NULL)
		return -1;
	callback->fd = fd;
	callback->function = fn;
	callback->data = data;
	TAILQ_INSERT_TAIL(&cfg->g_callbacks, callback, next);
	return 0;
}

void
lldpd_callback_del(struct lldpd *cfg, int fd, void(*fn)(CALLBACK_SIG))
{
	struct lldpd_callback *callback, *callback_next;
	for (callback = TAILQ_FIRST(&cfg->g_callbacks);
	     callback;
	     callback = callback_next) {
		callback_next = TAILQ_NEXT(callback, next);
		if ((callback->fd == fd) &&
		    (callback->function = fn)) {
			free(callback->data);
			TAILQ_REMOVE(&cfg->g_callbacks, callback, next);
			free(callback);
		}
	}
}

/* Hide unwanted ports depending on smart mode set by the user */
static void
lldpd_hide_all(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
	int protocols[LLDPD_MODE_MAX+1];
	int i, j, found;
	unsigned int min;

	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		/* Compute the number of occurrences of each protocol */
		for (i = 0; i <= LLDPD_MODE_MAX; i++)
			protocols[i] = 0;
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries)
			protocols[port->p_protocol]++;

		/* Turn the protocols[] array into an array of
		   enabled/disabled protocols. 1 means enabled, 0
		   means disabled. */
		min = (unsigned int)-1;
		for (i = 0; i <= LLDPD_MODE_MAX; i++)
			if (protocols[i] && (protocols[i] < min))
				min = protocols[i];
		found = 0;
		for (i = 0; i <= LLDPD_MODE_MAX; i++)
			if ((protocols[i] == min) && !found) {
				/* If we need a tie breaker, we take
				   the first protocol only */
				if (cfg->g_smart & SMART_FILTER_NO_TIE)
					found = 1;
				protocols[i] = 1;
			} else protocols[i] = 0;

		/* We set the p_hidden flag to 1 if the protocol is disabled */
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries)
			port->p_hidden = protocols[port->p_protocol]?0:1;

		/* If we want only one neighbor, we take the first one */
		if (cfg->g_smart & SMART_FILTER_ONE_NEIGH) {
			found = 0;
			TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
				if (!port->p_hidden) {
					if (found)
						port->p_hidden = 1;
					else
						found = 1;
				}
			}
		}

		/* Print a debug message summarizing the operation */
		i = j = 0;
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
		    if (port->p_hidden) i++;
		    j++;
		}
		if (i) {
			LLOG_DEBUG("On %s, out of %d neighbors, %d are hidden",
			    hardware->h_ifname, j, i);
			for (i=0; protos[i].mode != 0; i++) {
				if (protos[i].enabled)
					LLOG_DEBUG("On %s, %s is %s",
					    hardware->h_ifname, protos[i].name,
					    protocols[protos[i].mode]?"enabled":"disabled");
			}
		}
	}
}

static void
lldpd_recv_all(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
	struct lldpd_callback *callback, *callback_next;
	fd_set rfds;
	struct timeval tv;
#ifdef USE_SNMP
	struct timeval snmptv;
	int snmpblock = 0;
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
			for (n = 0; n < LLDPD_FD_SETSIZE; n++)
				if (FD_ISSET(n, &hardware->h_recvfds)) {
					FD_SET(n, &rfds);
					if (nfds < n)
						nfds = n;
				}
		}
		TAILQ_FOREACH(callback, &cfg->g_callbacks, next) {
			FD_SET(callback->fd, &rfds);
			if (nfds < callback->fd)
				nfds = callback->fd;
		}
		
#ifdef USE_SNMP
		if (cfg->g_snmp) {
			snmpblock = 0;
			memcpy(&snmptv, &tv, sizeof(struct timeval));
			snmp_select_info(&nfds, &rfds, &snmptv, &snmpblock);
			if (snmpblock == 0)
				memcpy(&tv, &snmptv, sizeof(struct timeval));
		}
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
			for (n = 0; n < LLDPD_FD_SETSIZE; n++)
				if ((FD_ISSET(n, &hardware->h_recvfds)) &&
				    (FD_ISSET(n, &rfds))) break;
			if (n == LLDPD_FD_SETSIZE) continue;
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
		for (callback = TAILQ_FIRST(&cfg->g_callbacks);
		     callback;
		     callback = callback_next) {
			/* Callback function can use TAILQ_REMOVE */
			callback_next = TAILQ_NEXT(callback, next);
			if (FD_ISSET(callback->fd, &rfds))
				callback->function(cfg, callback);
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
	int i, sent;

	cfg->g_lastsent = time(NULL);
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		/* Ignore if interface is down */
		if ((hardware->h_flags & IFF_RUNNING) == 0)
			continue;

		sent = 0;
		for (i=0; cfg->g_protocols[i].mode != 0; i++) {
			if (!cfg->g_protocols[i].enabled)
				continue;
			/* We send only if we have at least one remote system
			 * speaking this protocol or if the protocol is forced */
			if (cfg->g_protocols[i].enabled > 1) {
				cfg->g_protocols[i].send(cfg, hardware);
				sent++;
				continue;
			}
			TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
				/* If this remote port is disabled, we don't
				 * consider it */
				if (port->p_hidden &&
				    (cfg->g_smart & SMART_FILTER_EMISSION))
					continue;
				if (port->p_protocol ==
				    cfg->g_protocols[i].mode) {
					cfg->g_protocols[i].send(cfg,
					    hardware);
					sent++;
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
        if (cfg->g_descr_override) {
                if (asprintf(&LOCAL_CHASSIS(cfg)->c_descr, "%s",
			cfg->g_descr_override) == -1)
			fatal("failed to set full system description");
        } else {
	        if (cfg->g_advertise_version) {
		        if (asprintf(&LOCAL_CHASSIS(cfg)->c_descr, "%s%s %s %s",
			        cfg->g_lsb_release?cfg->g_lsb_release:"",
				un.sysname, un.release, un.machine)
                                == -1)
			        fatal("failed to set full system description");
	        } else {
		        if (asprintf(&LOCAL_CHASSIS(cfg)->c_descr, "%s",
                                cfg->g_lsb_release?cfg->g_lsb_release:un.sysname) == -1)
			        fatal("failed to set minimal system description");
	        }
        }

	/* Check forwarding */
	if ((f = priv_open("/proc/sys/net/ipv4/ip_forward")) >= 0) {
		if ((read(f, &status, 1) == 1) && (status == '1'))
			LOCAL_CHASSIS(cfg)->c_cap_enabled |= LLDP_CAP_ROUTER;
		else
			LOCAL_CHASSIS(cfg)->c_cap_enabled &= ~LLDP_CAP_ROUTER;
		close(f);
	}
#ifdef ENABLE_LLDPMED
	if (LOCAL_CHASSIS(cfg)->c_cap_available & LLDP_CAP_TELEPHONE)
		LOCAL_CHASSIS(cfg)->c_cap_enabled |= LLDP_CAP_TELEPHONE;
	lldpd_med(LOCAL_CHASSIS(cfg));
	free(LOCAL_CHASSIS(cfg)->c_med_sw);
	if (cfg->g_advertise_version)
		LOCAL_CHASSIS(cfg)->c_med_sw = strdup(un.release);
	else
		LOCAL_CHASSIS(cfg)->c_med_sw = strdup("Unknown");
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
	   6. Update smart mode
	*/
	LOCAL_CHASSIS(cfg)->c_cap_enabled = 0;
	lldpd_update_localports(cfg);
	lldpd_cleanup(cfg);
	lldpd_update_localchassis(cfg);
	lldpd_send_all(cfg);
	lldpd_recv_all(cfg);
	if (cfg->g_smart != SMART_NOFILTER)
		lldpd_hide_all(cfg);
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
lldpd_main(int argc, char *argv[])
{
	struct lldpd *cfg;
	struct lldpd_chassis *lchassis;
	int ch, debug = 0;
#ifdef USE_SNMP
	int snmp = 0;
	char *agentx = NULL;	/* AgentX socket */
#endif
	char *mgmtp = NULL;
	char *popt, opts[] = 
		"H:hkdxX:m:p:M:S:i@                    ";
	int i, found, advertise_version = 1;
#ifdef ENABLE_LLDPMED
	int lldpmed = 0, noinventory = 0;
#endif
        char *descr_override = NULL;
	char *lsb_release = NULL;
	int smart = SMART_FILTER_NO_TIE | SMART_FILTER_EMISSION | SMART_FILTER_RECEPTION;

	saved_argv = argv;

	/*
	 * Get and parse command line options
	 */
	popt = strchr(opts, '@');
	for (i=0; protos[i].mode != 0; i++)
		*(popt++) = protos[i].arg;
	*popt = '\0';
	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'h':
			usage();
			break;
		case 'd':
			debug++;
			break;
		case 'm':
			mgmtp = optarg;
			break;
		case 'k':
			advertise_version = 0;
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
#ifdef USE_SNMP
		case 'x':
			snmp = 1;
			break;
		case 'X':
			snmp = 1;
			agentx = optarg;
			break;
#else
		case 'x':
		case 'X':
			fprintf(stderr, "SNMP support is not built-in\n");
			usage();
#endif
			break;
                case 'S':
                        descr_override = strdup(optarg);
                        break;
		case 'H':
			smart = SMART_NOFILTER;
			i = atoi(optarg);
			if (i == 0) break;
			if ((i < 0) || (i > 9)) {
				fprintf(stderr, "Incorrect mode for -H\n");
				usage();
			}
			if (i%3 != 0)
				smart |= SMART_FILTER_RECEPTION;
			if ((i + 1)%3 != 0)
				smart |= SMART_FILTER_EMISSION;
			if (i > 6)
				smart |= SMART_FILTER_ONE_NEIGH | SMART_FILTER_NO_TIE;
			if (i < 4)
				smart |= SMART_FILTER_NO_TIE;
			break;
		default:
			found = 0;
			for (i=0; protos[i].mode != 0; i++) {
				if (ch == protos[i].arg) {
					protos[i].enabled++;
					/* When an argument enable
					   several protocols, only the
					   first one can be forced. */
					if (found && protos[i].enabled > 1)
						protos[i].enabled = 1;
					found = 1;
				}
			}
			if (!found)
				usage();
		}
	}
	
	log_init(debug, __progname);
	tzset();		/* Get timezone info before chroot */

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

	lsb_release = lldpd_get_lsb_release();

	priv_init(PRIVSEP_CHROOT);

	if ((cfg = (struct lldpd *)
	    calloc(1, sizeof(struct lldpd))) == NULL)
		fatal(NULL);

	cfg->g_mgmt_pattern = mgmtp;
	cfg->g_smart = smart;

	/* Get ioctl socket */
	if ((cfg->g_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("failed to get ioctl socket");
	cfg->g_delay = LLDPD_TX_DELAY;

	/* Description */
	if (!(cfg->g_advertise_version = advertise_version))
		/* Remove the \n */
		lsb_release[strlen(lsb_release) - 1] = '\0';
	cfg->g_lsb_release = lsb_release;
        if (descr_override)
           cfg->g_descr_override = descr_override;

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
		    LLDPMED_CAP_IV | LLDPMED_CAP_LOCATION |
		    LLDPMED_CAP_POLICY | LLDPMED_CAP_MDI_PSE | LLDPMED_CAP_MDI_PD;
		cfg->g_noinventory = noinventory;
	} else
		cfg->g_noinventory = 1;
#endif

	/* Set TTL */
	lchassis->c_ttl = LLDPD_TTL;

	cfg->g_protocols = protos;
	for (i=0; protos[i].mode != 0; i++)
		if (protos[i].enabled > 1)
			LLOG_INFO("protocol %s enabled and forced", protos[i].name);
		else if (protos[i].enabled)
			LLOG_INFO("protocol %s enabled", protos[i].name);
		else
			LLOG_INFO("protocol %s disabled", protos[i].name);

	TAILQ_INIT(&cfg->g_hardware);
	TAILQ_INIT(&cfg->g_chassis);
	TAILQ_INSERT_TAIL(&cfg->g_chassis, lchassis, c_entries);
	lchassis->c_refcount++; /* We should always keep a reference to local chassis */

	TAILQ_INIT(&cfg->g_callbacks);

#ifdef USE_SNMP
	if (snmp) {
		cfg->g_snmp = 1;
		agent_init(cfg, agentx, debug);
	}
#endif /* USE_SNMP */

	/* Create socket */
	if ((cfg->g_ctl = priv_ctl_create()) == -1)
		fatalx("unable to create control socket " LLDPD_CTL_SOCKET);
	if (lldpd_callback_add(cfg, cfg->g_ctl, ctl_accept, NULL) != 0)
		fatalx("unable to add callback for control socket");

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
