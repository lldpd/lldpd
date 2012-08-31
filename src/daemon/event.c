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

#include "lldpd.h"

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

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
	struct lldpd *cfg = arg;
	fd_set fdset;
	(void)what;
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
	struct lldpd *cfg = arg;
	(void)what; (void)fd;
	snmp_timeout();
	run_alarms();
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
	int added = 0, removed = 0, current = 0;
	struct lldpd_events *snmpfd, *snmpfd_next;

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
	TAILQ_ENTRY(lldpd_one_client) next;
	struct lldpd *cfg;
	struct bufferevent *bev;
	int    subscribed;	/* Is this client subscribed to changes? */
};
TAILQ_HEAD(, lldpd_one_client) lldpd_clients;

static void
levent_ctl_free_client(struct lldpd_one_client *client)
{
	if (client && client->bev) bufferevent_free(client->bev);
	if (client) {
		TAILQ_REMOVE(&lldpd_clients, client, next);
		free(client);
	}
}

static ssize_t
levent_ctl_send(struct lldpd_one_client *client, int type, void *data, size_t len)
{
	struct bufferevent *bev = client->bev;
	struct hmsg_header hdr = { .len = len, .type = type };
	bufferevent_disable(bev, EV_WRITE);
	if (bufferevent_write(bev, &hdr, sizeof(struct hmsg_header)) == -1 ||
	    (len > 0 && bufferevent_write(bev, data, len) == -1)) {
		LLOG_WARNX("unable to create answer to client");
		levent_ctl_free_client(client);
		return -1;
	}
	bufferevent_enable(bev, EV_WRITE);
	return len;
}

void
levent_ctl_notify(char *ifname, int state, struct lldpd_port *neighbor)
{
	struct lldpd_one_client *client, *client_next;
	struct lldpd_neighbor_change neigh = {
		.ifname = ifname,
		.state  = state,
		.neighbor = neighbor
	};
	void *output = NULL;
	ssize_t output_len = 0;

	/* Don't use TAILQ_FOREACH, the client may be deleted in case of errors. */
	for (client = TAILQ_FIRST(&lldpd_clients);
	     client;
	     client = client_next) {
		client_next = TAILQ_NEXT(client, next);
		if (!client->subscribed) continue;

		if (output == NULL) {
			/* Ugly hack: we don't want to transmit a list of
			 * ports. We patch the port to avoid this. */
			TAILQ_ENTRY(lldpd_port) backup_p_entries;
			memcpy(&backup_p_entries, &neighbor->p_entries,
			    sizeof(backup_p_entries));
			memset(&neighbor->p_entries, 0,
			    sizeof(backup_p_entries));
			output_len = marshal_serialize(lldpd_neighbor_change,
			    &neigh, &output);
			memcpy(&neighbor->p_entries, &backup_p_entries,
			    sizeof(backup_p_entries));

			if (output_len <= 0) {
				LLOG_WARNX("unable to serialize changed neighbor");
				return;
			}
		}

		levent_ctl_send(client, NOTIFICATION, output, output_len);
	}

	free(output);
}

static ssize_t
levent_ctl_send_cb(void *out, int type, void *data, size_t len)
{
	struct lldpd_one_client *client = out;
	return levent_ctl_send(client, type, data, len);
}

static void
levent_ctl_recv(struct bufferevent *bev, void *ptr)
{
	struct lldpd_one_client *client = ptr;
	struct evbuffer *buffer = bufferevent_get_input(bev);
	size_t buffer_len       = evbuffer_get_length(buffer);
	struct hmsg_header hdr;
	void *data = NULL;

	if (buffer_len < sizeof(struct hmsg_header))
		return;		/* Not enough data yet */
	if (evbuffer_copyout(buffer, &hdr,
		sizeof(struct hmsg_header)) != sizeof(struct hmsg_header)) {
		LLOG_WARNX("not able to read header");
		return;
	}
	if (hdr.len > HMSG_MAX_SIZE) {
		LLOG_WARNX("message received is too large");
		goto recv_error;
	}

	if (buffer_len < hdr.len + sizeof(struct hmsg_header))
		return;		/* Not enough data yet */
	if (hdr.len > 0 && (data = malloc(hdr.len)) == NULL) {
		LLOG_WARNX("not enough memory");
		goto recv_error;
	}
	evbuffer_drain(buffer, sizeof(struct hmsg_header));
	if (hdr.len > 0) evbuffer_remove(buffer, data, hdr.len);

	/* Currently, we should not receive notification acknowledgment. But if
	 * we receive one, we can discard it. */
	if (hdr.len == 0 && hdr.type == NOTIFICATION) return;
	if (client_handle_client(client->cfg,
		levent_ctl_send_cb, client,
		hdr.type, data, hdr.len,
		&client->subscribed) == -1) goto recv_error;
	free(data);
	return;

recv_error:
	free(data);
	levent_ctl_free_client(client);
}

static void
levent_ctl_event(struct bufferevent *bev, short events, void *ptr)
{
	struct lldpd_one_client *client = ptr;
	if (events & BEV_EVENT_ERROR) {
		LLOG_WARNX("an error occurred with client: %s",
		    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		levent_ctl_free_client(client);
	} else if (events & BEV_EVENT_EOF) {
		LLOG_DEBUG("client has been disconnected");
		levent_ctl_free_client(client);
	}
}

static void
levent_ctl_accept(evutil_socket_t fd, short what, void *arg)
{
	struct lldpd *cfg = arg;
	struct lldpd_one_client *client = NULL;
	int s;
	(void)what;

	if ((s = accept(fd, NULL, NULL)) == -1) {
		LLOG_WARN("unable to accept connection from socket");
		return;
	}
	client = calloc(1, sizeof(struct lldpd_one_client));
	if (!client) {
		LLOG_WARNX("unable to allocate memory for new client");
		close(s);
		goto accept_failed;
	}
	client->cfg = cfg;
	evutil_make_socket_nonblocking(s);
	if ((client->bev = bufferevent_socket_new(cfg->g_base, s,
		    BEV_OPT_CLOSE_ON_FREE)) == NULL) {
		LLOG_WARNX("unable to allocate a new buffer event for new client");
		close(s);
		goto accept_failed;
	}
	bufferevent_setcb(client->bev,
	    levent_ctl_recv, NULL, levent_ctl_event,
	    client);
	bufferevent_enable(client->bev, EV_READ | EV_WRITE);
	LLOG_DEBUG("new client accepted");
	TAILQ_INSERT_TAIL(&lldpd_clients, client, next);
	return;
accept_failed:
	levent_ctl_free_client(client);
}

static void
levent_dump(evutil_socket_t fd, short what, void *arg)
{
	struct event_base *base = arg;
	(void)fd; (void)what;
	event_base_dump_events(base, stderr);
}
static void
levent_stop(evutil_socket_t fd, short what, void *arg)
{
	struct event_base *base = arg;
	(void)fd; (void)what;
	event_base_loopbreak(base);
}

static void
levent_update_and_send(evutil_socket_t fd, short what, void *arg)
{
	struct lldpd *cfg = arg;
	struct timeval tv = {cfg->g_config.c_delay, 0};
	(void)fd; (void)what;
	lldpd_loop(cfg);
	event_add(cfg->g_main_loop, &tv);
}

void
levent_send_now(struct lldpd *cfg)
{
	event_active(cfg->g_main_loop, EV_TIMEOUT, 1);
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
	levent_send_now(cfg);

	/* Setup unix socket */
	TAILQ_INIT(&lldpd_clients);
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
			/* We don't use delegated requests (request
			   whose answer is delayed). However, we keep
			   the call here in case we use it some
			   day. We don't call run_alarms() here. We do
			   it on timeout only. */
			netsnmp_check_outstanding_agent_requests();
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
	struct lldpd_hardware *hardware = arg;
	struct lldpd *cfg = hardware->h_cfg;
	(void)what;
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
	struct lldpd_events *hfd = NULL;
	if (!hardware->h_recv) return;

	hfd = calloc(1, sizeof(struct lldpd_events));
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
	struct lldpd_events *ev, *ev_next;
	if (!hardware->h_recv) return;

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
