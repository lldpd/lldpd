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

struct client_handle client_handles[] = {
	{ HMSG_NONE, client_handle_none },
	{ HMSG_GET_INTERFACES, client_handle_get_interfaces },
	{ HMSG_GET_CHASSIS, client_handle_get_port_related },
	{ HMSG_GET_PORT, client_handle_get_port_related },
#ifdef ENABLE_DOT1
	{ HMSG_GET_VLANS, client_handle_get_port_related },
#endif
	{ HMSG_SHUTDOWN, client_handle_shutdown },
	{ 0, NULL } };

void
client_handle_client(struct lldpd *cfg, struct lldpd_client *client,
    char *buffer, int n)
{
	struct hmsg *h;		/* Reception */
	struct hmsg *t;		/* Sending */
	struct client_handle *ch;

	if (n < sizeof(struct hmsg_hdr)) {
		LLOG_WARNX("too short message request received");
		return;
	}
	h = (struct hmsg *)buffer;
	n -= sizeof(struct hmsg_hdr);
	if (n != h->hdr.len) {
		LLOG_WARNX("incorrect message size received from %d",
		    h->hdr.pid);
		return;
	}

	if ((t = (struct hmsg*)calloc(1, MAX_HMSGSIZE)) == NULL) {
		LLOG_WARNX("unable to allocate memory to answer to %d",
		    h->hdr.pid);
		return;
	}
	ctl_msg_init(t, h->hdr.type);
	for (ch = client_handles; ch->handle != NULL; ch++) {
		if (ch->type == h->hdr.type) {
			ch->handle(cfg, h, t);
			if (t->hdr.len == -1) {
				t->hdr.len = 0;
				t->hdr.type = HMSG_NONE;
			}
			if (ctl_msg_send(client->fd, t) == -1)
				LLOG_WARN("unable to send answer to client %d",
				    h->hdr.pid);
			free(t);
			return;
		}
	}
		
	LLOG_WARNX("unknown message request (%d) received from %d",
	    h->hdr.type, h->hdr.pid);
	free(t);
	return;
}

void
client_handle_shutdown(struct lldpd *cfg, struct hmsg *r, struct hmsg *s)
{
	LLOG_INFO("received shutdown request from client %d",
	    r->hdr.pid);
	exit(0);
}

void
client_handle_none(struct lldpd *cfg, struct hmsg *r, struct hmsg *s)
{
	LLOG_INFO("received noop request from client %d",
	    r->hdr.pid);
	s->hdr.len = -1;
}

void
client_handle_get_interfaces(struct lldpd *cfg, struct hmsg *r, struct hmsg *s)
{
	struct lldpd_interface *iff, *iff_next;
	struct lldpd_hardware *hardware;
	void *p;

	/* Build the list of interfaces */
	TAILQ_HEAD(, lldpd_interface) ifs;
	TAILQ_INIT(&ifs);
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if ((iff = (struct lldpd_interface*)malloc(sizeof(
			    struct lldpd_interface))) == NULL)
			fatal(NULL);
		iff->name = hardware->h_ifname;
		TAILQ_INSERT_TAIL(&ifs, iff, next);
	}

	p = &s->data;
	if (ctl_msg_pack_list(STRUCT_LLDPD_INTERFACE, &ifs,
		sizeof(struct lldpd_interface), s, &p) == -1) {
		LLOG_WARNX("unable to pack list of interfaces");
		s->hdr.len = -1;
	}

	/* Free the temporary list */
	for (iff = TAILQ_FIRST(&ifs);
	    iff != NULL;
	    iff = iff_next) {
		iff_next = TAILQ_NEXT(iff, next);
		TAILQ_REMOVE(&ifs, iff, next);
		free(iff);
	}
}

void
client_handle_get_port_related(struct lldpd *cfg, struct hmsg *r, struct hmsg *s)
{
	char *ifname;
	struct lldpd_hardware *hardware;
	void *p;

	ifname = (char*)(&r->data);
	if (ifname[r->hdr.len - 1] != 0) {
		LLOG_WARNX("bad message format for get port related message");
		s->hdr.len = -1;
		return;
	}
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if (strncmp(ifname, hardware->h_ifname, IFNAMSIZ) == 0) {
			if ((hardware->h_rport == NULL) ||
			    (hardware->h_rchassis == NULL)) {
				s->hdr.len = 0;
				s->hdr.type = HMSG_NONE;
				return;
			}
			p = &s->data;
			switch (r->hdr.type) {
#ifdef ENABLE_DOT1
			case HMSG_GET_VLANS:
				if (ctl_msg_pack_list(STRUCT_LLDPD_VLAN,
					&hardware->h_rport->p_vlans,
					sizeof(struct lldpd_vlan), s, &p) == -1) {
					LLOG_WARNX("unable to send vlans information for "
					    "interface %s for %d", ifname, r->hdr.pid);
					s->hdr.len = -1;
					return;
				}
				break;
#endif
			case HMSG_GET_PORT:
				if (ctl_msg_pack_structure(STRUCT_LLDPD_PORT,
					hardware->h_rport,
					sizeof(struct lldpd_port), s, &p) == -1) {
					LLOG_WARNX("unable to send port information for "
					    "interface %s for %d", ifname, r->hdr.pid);
					s->hdr.len = -1;
					return;
				}
				break;
			case HMSG_GET_CHASSIS:
				if (ctl_msg_pack_structure(STRUCT_LLDPD_CHASSIS,
					hardware->h_rchassis,
					sizeof(struct lldpd_chassis), s, &p) == -1) {
					LLOG_WARNX("unable to send chassis information for "
					    "interface %s for %d", ifname, r->hdr.pid);
					s->hdr.len = -1;
					return;
				}
				break;
			default:
				LLOG_WARNX("don't know what to do");
				s->hdr.len = -1;
				return;
			}
			return;
		}
	}
	LLOG_WARNX("requested interface %s by %d was not found",
	    ifname, r->hdr.pid);
	s->hdr.len = -1;
	return;
}
