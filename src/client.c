/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
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

static struct client_handle client_handles[] = {
	{ HMSG_NONE, client_handle_none },
	{ HMSG_GET_INTERFACES, client_handle_get_interfaces },
	{ HMSG_GET_NB_PORTS, client_handle_port_related },
	{ HMSG_GET_PORT, client_handle_port_related },
	{ HMSG_GET_CHASSIS, client_handle_port_related },
#ifdef ENABLE_LLDPMED
	{ HMSG_SET_LOCATION, client_handle_port_related },
	{ HMSG_SET_POLICY, client_handle_port_related },
	{ HMSG_SET_POWER, client_handle_port_related },
#endif
#ifdef ENABLE_DOT3
	{ HMSG_SET_DOT3_POWER, client_handle_port_related },
#endif
#ifdef ENABLE_DOT1
	{ HMSG_GET_VLANS, client_handle_port_related },
	{ HMSG_GET_PPVIDS, client_handle_port_related },
	{ HMSG_GET_PIDS, client_handle_port_related },
#endif
	{ HMSG_SHUTDOWN, client_handle_shutdown },
	{ 0, NULL } };

void
client_handle_client(struct lldpd *cfg, struct lldpd_callback *callback,
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

	if ((t = (struct hmsg*)malloc(MAX_HMSGSIZE)) == NULL) {
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
			if (ctl_msg_send(callback->fd, t) == -1)
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
client_handle_port_related(struct lldpd *cfg, struct hmsg *r, struct hmsg *s)
{
	char *ifname;
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
	void *p;
	int i;

	ifname = (char*)(&r->data);
	if ((r->hdr.len < IFNAMSIZ) || (ifname[IFNAMSIZ - 1] != 0)) {
		LLOG_WARNX("bad message format for get port related message (%d)",
			r->hdr.type);
		s->hdr.len = -1;
		return;
	}
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if (strncmp(ifname, hardware->h_ifname, IFNAMSIZ) == 0) {
			switch (r->hdr.type) {
#ifdef ENABLE_LLDPMED
			case HMSG_SET_LOCATION:
				p = (char*)&r->data + IFNAMSIZ;
				for (i=0; i < LLDPMED_LOCFORMAT_LAST; i++) {
					free(hardware->h_lport.p_med_location[i].data);
					hardware->h_lport.p_med_location[i].data = NULL;
					hardware->h_lport.p_med_location[i].format = 0;
				}
				if (ctl_msg_unpack_structure(STRUCT_LLDPD_MED_LOC
					STRUCT_LLDPD_MED_LOC STRUCT_LLDPD_MED_LOC,
					hardware->h_lport.p_med_location,
					3*sizeof(struct lldpd_med_loc), r, &p) == -1) {
					LLOG_WARNX("unable to set location for %s", ifname);
					s->hdr.len = -1;
					return;
				}
				hardware->h_lport.p_med_cap_enabled |= LLDPMED_CAP_LOCATION;
				break;
			case HMSG_SET_POLICY:
				p = (char*)&r->data + IFNAMSIZ;
				for (i=0; i < LLDPMED_APPTYPE_LAST; i++) {
					hardware->h_lport.p_med_policy[i].type     = 0;
					hardware->h_lport.p_med_policy[i].unknown  = 0;
					hardware->h_lport.p_med_policy[i].tagged   = 0;
					hardware->h_lport.p_med_policy[i].vid      = 0;
					hardware->h_lport.p_med_policy[i].priority = 0;
					hardware->h_lport.p_med_policy[i].dscp     = 0;
				}
				if (ctl_msg_unpack_structure(
					STRUCT_LLDPD_MED_POLICY
					STRUCT_LLDPD_MED_POLICY
					STRUCT_LLDPD_MED_POLICY
					STRUCT_LLDPD_MED_POLICY
					STRUCT_LLDPD_MED_POLICY
					STRUCT_LLDPD_MED_POLICY
					STRUCT_LLDPD_MED_POLICY
					STRUCT_LLDPD_MED_POLICY,
					hardware->h_lport.p_med_policy,
					8*sizeof(struct lldpd_med_policy),
					r, &p) == -1) {
					LLOG_WARNX("unable to set network policy for %s", ifname);
					s->hdr.len = -1;
					return;
				}
				hardware->h_lport.p_med_cap_enabled |=
					LLDPMED_CAP_POLICY;
				break;
			case HMSG_SET_POWER:
				p = (char*)&r->data + IFNAMSIZ;
				memset(&hardware->h_lport.p_med_power, 0,
				       sizeof(struct lldpd_med_power));
				if (ctl_msg_unpack_structure(STRUCT_LLDPD_MED_POWER,
						&hardware->h_lport.p_med_power,
						sizeof(struct lldpd_med_power),
						r, &p) == -1) {
					LLOG_WARNX("unable to set POE-MDI for %s",
						   ifname);
					s->hdr.len = -1;
					return;
				}
				hardware->h_lport.p_med_cap_enabled &= ~(
					LLDPMED_CAP_MDI_PD | LLDPMED_CAP_MDI_PSE);
				switch (hardware->h_lport.p_med_power.devicetype)
				{
				case LLDPMED_POW_TYPE_PSE:
					hardware->h_lport.p_med_cap_enabled |=
					    LLDPMED_CAP_MDI_PSE;
					break;
				case LLDPMED_POW_TYPE_PD:
					hardware->h_lport.p_med_cap_enabled |=
					    LLDPMED_CAP_MDI_PD;
					break;
				}
				break;
#endif
#ifdef ENABLE_DOT3
			case HMSG_SET_DOT3_POWER:
				p = (char*)&r->data + IFNAMSIZ;
				memset(&hardware->h_lport.p_power, 0,
				       sizeof(struct lldpd_dot3_power));
				if (ctl_msg_unpack_structure(STRUCT_LLDPD_DOT3_POWER,
						&hardware->h_lport.p_power,
						sizeof(struct lldpd_dot3_power),
						r, &p) == -1) {
					LLOG_WARNX("unable to set POE-MDI for %s",
						   ifname);
					s->hdr.len = -1;
					return;
				}
				break;
#endif
			case HMSG_GET_NB_PORTS:
				p = &s->data;
				i = 0;
				TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
					if (SMART_HIDDEN(cfg, port)) continue;
					i++;
				}
				memcpy(p, &i, sizeof(int));
				s->hdr.len = sizeof(int);
				break;
			case HMSG_GET_VLANS:
			case HMSG_GET_PPVIDS:
			case HMSG_GET_PIDS:
			case HMSG_GET_PORT:
			case HMSG_GET_CHASSIS:
				/* We read the index which is right after the interface name */
				if (r->hdr.len < IFNAMSIZ + sizeof(int)) {
					LLOG_WARNX("too short message format for get "
					    "port related message (%d)", r->hdr.type);
					s->hdr.len = -1;
					return;
				}
				p = (char*)&r->data + IFNAMSIZ;
				memcpy(&i, p, sizeof(int));
				p = &s->data;
				TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
					if (SMART_HIDDEN(cfg, port)) continue;
					if (i-- == 0) break;
				}
				if (!port) {
					LLOG_INFO("out of range index requested for port "
					    "related information on interface %s for %d",
					    ifname, r->hdr.pid);
					s->hdr.len = -1;
					return;
				}
				p = (char*)&s->data;
				switch (r->hdr.type) {
#ifdef ENABLE_DOT1
				case HMSG_GET_VLANS:
					if (ctl_msg_pack_list(STRUCT_LLDPD_VLAN,
						&port->p_vlans,
						sizeof(struct lldpd_vlan), s, &p) == -1) {
						LLOG_WARNX("unable to send vlans information for "
						    "interface %s for %d", ifname, r->hdr.pid);
						s->hdr.len = -1;
						return;
					}
					break;
				case HMSG_GET_PPVIDS:
					if (ctl_msg_pack_list(
						STRUCT_LLDPD_PPVID,
						&port->p_ppvids,
						sizeof(struct lldpd_ppvid), s, &p) == -1) {
						LLOG_WARNX("unable to send ppvids information for "
						    "interface %s for %d", ifname, r->hdr.pid);
						s->hdr.len = -1;
						return;
					}
					break;
				case HMSG_GET_PIDS:
					if (ctl_msg_pack_list(
						STRUCT_LLDPD_PI,
						&port->p_pids,
						sizeof(struct lldpd_pi), s, &p) == -1) {
						LLOG_WARNX("unable to send PI's information for "
						    "interface %s for %d", ifname, r->hdr.pid);
						s->hdr.len = -1;
						return;
					}
					break;
#endif
				case HMSG_GET_PORT:
					if (ctl_msg_pack_structure(STRUCT_LLDPD_PORT,
						port,
						sizeof(struct lldpd_port), s, &p) == -1) {
						LLOG_WARNX("unable to send port information for "
						    "interface %s for %d", ifname, r->hdr.pid);
						s->hdr.len = -1;
						return;
					}
					break;
				case HMSG_GET_CHASSIS:
					if (ctl_msg_pack_structure(STRUCT_LLDPD_CHASSIS,
						port->p_chassis,
						sizeof(struct lldpd_chassis), s, &p) == -1) {
						LLOG_WARNX("unable to send chassis information "
						    "for interface %s for %d",
						    ifname, r->hdr.pid);
						s->hdr.len = -1;
						return;
					}
					break;
				default:
					LLOG_WARNX("don't know what to do");
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
