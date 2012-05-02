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

#include "lldpd.h"

#include <unistd.h>
#include <signal.h>
#include <event2/event.h>

static void
levent_log_cb(int severity, const char *msg)
{
	switch (severity) {
	case _EVENT_LOG_DEBUG: log_debug("libevent[debug]: %s", msg); break;
	case _EVENT_LOG_MSG:   log_info ("libevent[info]: %s", msg);  break;
	case _EVENT_LOG_WARN:  log_warnx("libevent[warn]: %s", msg);  break;
	case _EVENT_LOG_ERR:   log_warnx("libevent[error]: %s", msg); break;
	}
}

struct lldpd_events {
	TAILQ_ENTRY(lldpd_events) next;
	struct event *ev;
};
TAILQ_HEAD(ev_l, lldpd_events);

#define levent_snmp_fds(cfg)   ((struct ev_l*)(cfg)->g_snmp_fds)
#define levent_hardware_fds(hardware) ((struct ev_l*)(hardware)->h_recv)

#ifdef USE_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>

static void levent_snmp_update(struct lldpd *);

/*
 * Callback function when we have something to read from SNMP.
 *
 * This function is called because we have a read event on one SNMP
 * file descriptor. When need to call snmp_read() on it.
 */
static void
levent_snmp_read(evutil_socket_t fd, short what, void *arg)
{
	(void)what;
	struct lldpd *cfg = arg;
	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	snmp_read(&fdset);
	levent_snmp_update(cfg);
}

/*
 * Callback function for a SNMP timeout.
 *
 * A SNMP timeout has occurred. Call `snmp_timeout()` to handle it.
 */
static void
levent_snmp_timeout(evutil_socket_t fd, short what, void *arg)
{
	(void)what; (void)fd;
	struct lldpd *cfg = arg;
	snmp_timeout();
	levent_snmp_update(cfg);
}

/*
 * Watch a new SNMP FD.
 *
 * @param base The libevent base we are working on.
 * @param fd The file descriptor we want to watch.
 *
 * The file descriptor is appended to the list of file descriptors we
 * want to watch.
 */
static void
levent_snmp_add_fd(struct lldpd *cfg, int fd)
{
	struct event_base *base = cfg->g_base;
	struct lldpd_events *snmpfd = calloc(1, sizeof(struct lldpd_events));
	if (!snmpfd) {
		LLOG_WARN("unable to allocate memory for new SNMP event");
		return;
	}
	evutil_make_socket_nonblocking(fd);
	if ((snmpfd->ev = event_new(base, fd,
				    EV_READ | EV_PERSIST,
				    levent_snmp_read,
				    cfg)) == NULL) {
		LLOG_WARNX("unable to allocate a new SNMP event for FD %d", fd);
		free(snmpfd);
		return;
	}
	if (event_add(snmpfd->ev, NULL) == -1) {
		LLOG_WARNX("unable to schedule new SNMP event for FD %d", fd);
		event_free(snmpfd->ev);
		free(snmpfd);
		return;
	}
	TAILQ_INSERT_TAIL(levent_snmp_fds(cfg), snmpfd, next);
}

/*
 * Update SNMP event loop.
 *
 * New events are added and some other are removed. This function
 * should be called every time a SNMP event happens: either when
 * handling a SNMP packet, a SNMP timeout or when sending a SNMP
 * packet. This function will keep libevent in sync with NetSNMP.
 *
 * @param base The libevent base we are working on.
 */
static void
levent_snmp_update(struct lldpd *cfg)
{
	int maxfd = 0;
	int block = 1;
	fd_set fdset;
	struct timeval timeout;
	static int howmany = 0;

	/* snmp_select_info() can be tricky to understand. We set `block` to
	   1 to means that we don't request a timeout. snmp_select_info()
	   will reset `block` to 0 if it wants us to setup a timeout. In
	   this timeout, `snmp_timeout()` should be invoked.
	   
	   Each FD in `fdset` will need to be watched for reading. If one of
	   them become active, `snmp_read()` should be called on it.
	*/
	
	FD_ZERO(&fdset);
	snmp_select_info(&maxfd, &fdset, &timeout, &block);
	
	/* We need to untrack any event whose FD is not in `fdset`
	   anymore */
	int added = 0, removed = 0, current = 0;
	struct lldpd_events *snmpfd, *snmpfd_next;
	for (snmpfd = TAILQ_FIRST(levent_snmp_fds(cfg));
	     snmpfd;
	     snmpfd = snmpfd_next) {
		snmpfd_next = TAILQ_NEXT(snmpfd, next);
		if (event_get_fd(snmpfd->ev) >= maxfd ||
		    (!FD_ISSET(event_get_fd(snmpfd->ev), &fdset))) {
			event_free(snmpfd->ev);
			TAILQ_REMOVE(levent_snmp_fds(cfg), snmpfd, next);
			free(snmpfd);
			removed++;
		} else {
			FD_CLR(event_get_fd(snmpfd->ev), &fdset);
			current++;
		}
	}
	
	/* Invariant: FD in `fdset` are not in list of FD */
	for (int fd = 0; fd < maxfd; fd++) {
		if (FD_ISSET(fd, &fdset)) {
			levent_snmp_add_fd(cfg, fd);
			added++;
		}
	}
	current += added;
	if (howmany != current) {
		LLOG_DEBUG("added %d events, removed %d events, total of %d events",
			   added, removed, current);
		howmany = current;
	}

	/* If needed, handle timeout */
	if (evtimer_add(cfg->g_snmp_timeout, block?NULL:&timeout) == -1)
		LLOG_WARNX("unable to schedule timeout function for SNMP");
}
#endif /* USE_SNMP */

struct lldpd_one_client {
	struct lldpd *cfg;
	struct event *ev;
};

static void
levent_ctl_recv(evutil_socket_t fd, short what, void *arg)
{
	(void)what;
	struct lldpd_one_client *client = arg;
	enum hmsg_type type;
	void          *buffer = NULL;
	int            n;

	if ((n = ctl_msg_recv(fd, &type, &buffer)) == -1 ||
	    client_handle_client(client->cfg, fd, type, buffer, n) == -1) {
		close(fd);
		event_free(client->ev);
		free(client);
	}
	free(buffer);
}

static void
levent_ctl_accept(evutil_socket_t fd, short what, void *arg)
{
	(void)what;
	struct lldpd *cfg = arg;
	struct lldpd_one_client *client = NULL;
	int s;
	if ((s = accept(fd, NULL, NULL)) == -1) {
		LLOG_WARN("unable to accept connection from socket");
		return;
	}
	client = calloc(1, sizeof(struct lldpd_one_client));
	if (!client) {
		LLOG_WARNX("unable to allocate memory for new client");
		goto accept_failed;
	}
	client->cfg = cfg;
	evutil_make_socket_nonblocking(s);
	if ((client->ev = event_new(cfg->g_base, s,
		    EV_READ | EV_PERSIST,
		    levent_ctl_recv,
		    client)) == NULL) {
		LLOG_WARNX("unable to allocate a new event for new client");
		goto accept_failed;
	}
	if (event_add(client->ev, NULL) == -1) {
		LLOG_WARNX("unable to schedule new event for new client");
		goto accept_failed;
	}
	return;
accept_failed:
	if (client && client->ev) event_free(client->ev);
	free(client);
	close(s);
}

static void
levent_dump(evutil_socket_t fd, short what, void *arg)
{
	(void)fd; (void)what;
	struct event_base *base = arg;
	event_base_dump_events(base, stderr);
}
static void
levent_stop(evutil_socket_t fd, short what, void *arg)
{
	(void)fd; (void)what;
	struct event_base *base = arg;
	event_base_loopbreak(base);
}

static void
levent_update_and_send(evutil_socket_t fd, short what, void *arg)
{
	(void)fd; (void)what;
	struct lldpd *cfg = arg;
	struct timeval tv = {cfg->g_delay, 0};
	lldpd_loop(cfg);
	event_add(cfg->g_main_loop, &tv);
}

static void
levent_init(struct lldpd *cfg)
{
	/* Setup libevent */
	event_set_log_callback(levent_log_cb);
	if (!(cfg->g_base = event_base_new()))
		fatalx("unable to create a new libevent base");
	LLOG_INFO("libevent %s initialized with %s method",
		  event_get_version(),
		  event_base_get_method(cfg->g_base));

	/* Setup SNMP */
#ifdef USE_SNMP
	if (cfg->g_snmp) {
		agent_init(cfg, cfg->g_snmp_agentx);
		cfg->g_snmp_timeout = evtimer_new(cfg->g_base,
		    levent_snmp_timeout,
		    cfg);
		if (!cfg->g_snmp_timeout)
			fatalx("unable to setup timeout function for SNMP");
		if ((cfg->g_snmp_fds =
			malloc(sizeof(struct ev_l))) == NULL)
			fatalx("unable to allocate memory for SNMP events");
		TAILQ_INIT(levent_snmp_fds(cfg));
	}
#endif
	
	/* Setup loop that will run every 30 seconds. */
	if (!(cfg->g_main_loop = event_new(cfg->g_base, -1, 0,
					   levent_update_and_send,
					   cfg)))
		fatalx("unable to setup main timer");
	event_active(cfg->g_main_loop, EV_TIMEOUT, 1);

	/* Setup unix socket */
	evutil_make_socket_nonblocking(cfg->g_ctl);
	if ((cfg->g_ctl_event = event_new(cfg->g_base, cfg->g_ctl,
		    EV_READ|EV_PERSIST, levent_ctl_accept, cfg)) == NULL)
		fatalx("unable to setup control socket event");
	event_add(cfg->g_ctl_event, NULL);

	/* Signals */
	evsignal_add(evsignal_new(cfg->g_base, SIGUSR1,
		levent_dump, cfg->g_base),
	    NULL);
	evsignal_add(evsignal_new(cfg->g_base, SIGHUP,
		levent_stop, cfg->g_base),
	    NULL);
	evsignal_add(evsignal_new(cfg->g_base, SIGINT,
		levent_stop, cfg->g_base),
	    NULL);
	evsignal_add(evsignal_new(cfg->g_base, SIGTERM,
		levent_stop, cfg->g_base),
	    NULL);
}

/* Initialize libevent and start the event loop */
void
levent_loop(struct lldpd *cfg)
{
	levent_init(cfg);

	/* libevent loop */
	do {
		if (event_base_got_break(cfg->g_base) ||
		    event_base_got_exit(cfg->g_base))
			break;
#ifdef USE_SNMP
		if (cfg->g_snmp) {
			run_alarms();
			netsnmp_check_outstanding_agent_requests();
			/* run_alarms() may establish new connections and then
			   synchronously modify the set of SNMP FD. We need to
			   update them. */
			levent_snmp_update(cfg);
		}
#endif
	} while (event_base_loop(cfg->g_base, EVLOOP_ONCE) == 0);

#ifdef USE_SNMP
	if (cfg->g_snmp)
		agent_shutdown();
#endif /* USE_SNMP */

}

static void
levent_hardware_recv(evutil_socket_t fd, short what, void *arg)
{
	(void)what;
	struct lldpd_hardware *hardware = arg;
	struct lldpd *cfg = hardware->h_cfg;
	lldpd_recv(cfg, hardware, fd);
}

void
levent_hardware_init(struct lldpd_hardware *hardware)
{
	if ((hardware->h_recv =
		malloc(sizeof(struct ev_l))) == NULL) {
		LLOG_WARNX("unable to allocate memory for %s",
		    hardware->h_ifname);
		return;
	}
	TAILQ_INIT(levent_hardware_fds(hardware));
}

void
levent_hardware_add_fd(struct lldpd_hardware *hardware, int fd)
{
	if (!hardware->h_recv) return;

	struct lldpd_events *hfd = calloc(1, sizeof(struct lldpd_events));
	if (!hfd) {
		LLOG_WARNX("unable to allocate new event for %s",
		    hardware->h_ifname);
		return;
	}
	evutil_make_socket_nonblocking(fd);
	if ((hfd->ev = event_new(hardware->h_cfg->g_base, fd,
		    EV_READ | EV_PERSIST,
		    levent_hardware_recv,
		    hardware)) == NULL) {
		LLOG_WARNX("unable to allocate a new event for %s",
			hardware->h_ifname);
		free(hfd);
		return;
	}
	if (event_add(hfd->ev, NULL) == -1) {
		LLOG_WARNX("unable to schedule new event for %s",
			hardware->h_ifname);
		event_free(hfd->ev);
		free(hfd);
		return;
	}
	TAILQ_INSERT_TAIL(levent_hardware_fds(hardware), hfd, next);
}

void
levent_hardware_release(struct lldpd_hardware *hardware)
{
	if (!hardware->h_recv) return;

	struct lldpd_events *ev, *ev_next;
	for (ev = TAILQ_FIRST(levent_hardware_fds(hardware));
	     ev;
	     ev = ev_next) {
		ev_next = TAILQ_NEXT(ev, next);
		/* We may close several time the same FD. This is harmless. */
		close(event_get_fd(ev->ev));
		event_free(ev->ev);
		TAILQ_REMOVE(levent_hardware_fds(hardware), ev, next);
		free(ev);
	}
	free(levent_hardware_fds(hardware));
}
