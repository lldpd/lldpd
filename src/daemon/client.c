/* -*- mode: c; c-file-style: "openbsd" -*- */
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

static int
client_handle_none(struct lldpd *cfg, enum hmsg_type *type,
    void *input, int input_len, void **output, int *subscribed)
{
	LLOG_INFO("received noop request from client");
	*type = NONE;
	return 0;
}

/* Return the global configuration */
static int
client_handle_get_configuration(struct lldpd *cfg, enum hmsg_type *type,
    void *input, int input_len, void **output, int *subscribed)
{
	ssize_t output_len;
	output_len = marshal_serialize(lldpd_config, &cfg->g_config, output);
	if (output_len <= 0) {
		output_len = 0;
		*type = NONE;
	}
	return output_len;
}

/* Change the global configuration */
static int
client_handle_set_configuration(struct lldpd *cfg, enum hmsg_type *type,
    void *input, int input_len, void **output, int *subscribed)
{
	struct lldpd_config *config;

	/* Get the proposed configuration. */
	if (marshal_unserialize(lldpd_config, input, input_len, &config) <= 0) {
		*type = NONE;
		return 0;
	}

	/* What needs to be done? Currently, we only support setting the
	 * transmit delay. */
	if (config->c_delay > 0) {
		cfg->g_config.c_delay = config->c_delay;
	}
	if (config->c_delay < 0) {
		LLOG_DEBUG("client asked for immediate retransmission");
		levent_send_now(cfg);
	}

	lldpd_config_cleanup(config);

	return 0;
}

/* Return the list of interfaces.
   Input:  nothing.
   Output: list of interface names (lldpd_interface_list)
*/
static int
client_handle_get_interfaces(struct lldpd *cfg, enum hmsg_type *type,
    void *input, int input_len, void **output, int *subscribed)
{
	struct lldpd_interface *iff, *iff_next;
	struct lldpd_hardware *hardware;
	int output_len;

	/* Build the list of interfaces */
	struct lldpd_interface_list ifs;
	TAILQ_INIT(&ifs);
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if ((iff = (struct lldpd_interface*)malloc(sizeof(
			    struct lldpd_interface))) == NULL)
			fatal(NULL);
		iff->name = hardware->h_ifname;
		TAILQ_INSERT_TAIL(&ifs, iff, next);
	}

	output_len = marshal_serialize(lldpd_interface_list, &ifs, output);
	if (output_len <= 0) {
		output_len = 0;
		*type = NONE;
	}

	/* Free the temporary list */
	for (iff = TAILQ_FIRST(&ifs);
	    iff != NULL;
	    iff = iff_next) {
		iff_next = TAILQ_NEXT(iff, next);
		TAILQ_REMOVE(&ifs, iff, next);
		free(iff);
	}

	return output_len;
}

/* Return all available information related to an interface
   Input:  name of the interface (serialized)
   Output: Information about the interface (lldpd_hardware)
*/
static int
client_handle_get_interface(struct lldpd *cfg, enum hmsg_type *type,
    void *input, int input_len, void **output, int *subscribed)
{
	char *name;
	struct lldpd_hardware *hardware;

	/* Get name of the interface */
	if (marshal_unserialize(string, input, input_len, &name) <= 0) {
		*type = NONE;
		return 0;
	}

	/* Search appropriate hardware */
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries)
		if (!strcmp(hardware->h_ifname, name)) {
			int output_len = marshal_serialize(lldpd_hardware, hardware, output);
			free(name);
			if (output_len <= 0) {
				*type = NONE;
				free(name);
				return 0;
			}
			return output_len;
		}

	free(name);
	LLOG_WARNX("no interface %s found", name);
	*type = NONE;
	return 0;
}

/* Set some port related settings (policy, location, power)
   Input: name of the interface, policy/location/power setting to be modified
   Output: nothing
*/
static int
client_handle_set_port(struct lldpd *cfg, enum hmsg_type *type,
    void *input, int input_len, void **output, int *subscribed)
{
	int ret = 0;
	struct lldpd_port_set *set = NULL;
	struct lldpd_hardware *hardware = NULL;
#ifdef ENABLE_LLDPMED
	struct lldpd_med_loc *loc = NULL;
#endif

	if (marshal_unserialize(lldpd_port_set, input, input_len, &set) <= 0) {
		*type = NONE;
		return 0;
	}
	if (!set->ifname) {
		LLOG_WARNX("no interface provided");
		goto set_port_finished;
	}

	/* Search the appropriate hardware */
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries)
	    if (!strcmp(hardware->h_ifname, set->ifname)) {
		    struct lldpd_port *port = &hardware->h_lport;
		    (void)port;
#ifdef ENABLE_LLDPMED
		    if (set->med_policy && set->med_policy->type > 0) {
			    if (set->med_policy->type > LLDP_MED_APPTYPE_LAST) {
				    LLOG_WARNX("invalid policy provided: %d",
					set->med_policy->type);
				    goto set_port_finished;
			    }
			    memcpy(&port->p_med_policy[set->med_policy->type - 1],
				set->med_policy, sizeof(struct lldpd_med_policy));
			    port->p_med_cap_enabled |= LLDP_MED_CAP_POLICY;
		    }
		    if (set->med_location && set->med_location->format > 0) {
			    char *newdata = NULL;
			    if (set->med_location->format > LLDP_MED_LOCFORMAT_LAST) {
				    LLOG_WARNX("invalid location format provided: %d",
					set->med_location->format);
				    goto set_port_finished;
			    }
			    loc = \
				&port->p_med_location[set->med_location->format - 1];
			    free(loc->data);
			    memcpy(loc, set->med_location, sizeof(struct lldpd_med_loc));
			    if (!loc->data || !(newdata = malloc(loc->data_len))) loc->data_len = 0;
			    if (newdata) memcpy(newdata, loc->data, loc->data_len);
			    loc->data = newdata;
			    port->p_med_cap_enabled |= LLDP_MED_CAP_LOCATION;
		    }
		    if (set->med_power) {
			    memcpy(&port->p_med_power, set->med_power,
				sizeof(struct lldpd_med_power));
			    switch (set->med_power->devicetype) {
			    case LLDP_MED_POW_TYPE_PD:
				    port->p_med_cap_enabled |= LLDP_MED_CAP_MDI_PD;
				    port->p_med_cap_enabled &= ~LLDP_MED_CAP_MDI_PSE;
				    break;
			    case LLDP_MED_POW_TYPE_PSE:
				    port->p_med_cap_enabled |= LLDP_MED_CAP_MDI_PSE;
				    port->p_med_cap_enabled &= ~LLDP_MED_CAP_MDI_PD;
				    break;
			    }
		    }
#endif
#ifdef ENABLE_DOT3
		    if (set->dot3_power)
			    memcpy(&port->p_power, set->dot3_power,
				sizeof(struct lldpd_dot3_power));
#endif
		    ret = 1;
		    break;
	    }

	if (ret == 0)
		LLOG_WARN("no interface %s found", set->ifname);

set_port_finished:
	if (!ret) *type = NONE;
	free(set->ifname);
#ifdef ENABLE_LLDPMED
	free(set->med_policy);
	if (set->med_location) free(set->med_location->data);
	free(set->med_location);
	free(set->med_power);
#endif
#ifdef ENABLE_DOT3
	free(set->dot3_power);
#endif
	return 0;
}

/* Register subscribtion to neighbor changes */
static int
client_handle_subscribe(struct lldpd *cfg, enum hmsg_type *type,
    void *input, int input_len, void **output, int *subscribed)
{
	*subscribed = 1;
	return 0;
}

struct client_handle {
	enum hmsg_type type;
	int (*handle)(struct lldpd*, enum hmsg_type *,
	    void *, int, void **, int *);
};

static struct client_handle client_handles[] = {
	{ NONE,			client_handle_none },
	{ GET_CONFIG,		client_handle_get_configuration },
	{ SET_CONFIG,		client_handle_set_configuration },
	{ GET_INTERFACES,	client_handle_get_interfaces },
	{ GET_INTERFACE,	client_handle_get_interface },
	{ SET_PORT,		client_handle_set_port },
	{ SUBSCRIBE,		client_handle_subscribe },
	{ 0,			NULL } };

int
client_handle_client(struct lldpd *cfg,
    ssize_t(*send)(void *, int, void *, size_t),
    void *out,
    enum hmsg_type type, void *buffer, size_t n,
    int *subscribed)
{
	struct client_handle *ch;
	void *answer; size_t len, sent;
	for (ch = client_handles; ch->handle != NULL; ch++) {
		if (ch->type == type) {
			answer = NULL; len = 0;
			len  = ch->handle(cfg, &type, buffer, n, &answer,
			    subscribed);
			sent = send(out, type, answer, len);
			free(answer);
			return sent;
		}
	}

	LLOG_WARNX("unknown message request (%d) received",
	    type);
	return -1;
}
