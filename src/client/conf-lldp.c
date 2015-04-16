/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2013 Vincent Bernat <bernat@luffy.cx>
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

#include <unistd.h>
#include <string.h>

#include "client.h"
#include "../log.h"

static int
cmd_txdelay(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set transmit delay");

	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}
	if (lldpctl_atom_set_str(config,
		lldpctl_k_config_tx_interval, cmdenv_get(env, "tx-interval")) == NULL) {
		log_warnx("lldpctl", "unable to set transmit delay. %s",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}
	log_info("lldpctl", "transmit delay set to new value");
	lldpctl_atom_dec_ref(config);
	return 1;
}

static int
cmd_txhold(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set transmit hold");

	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}
	if (lldpctl_atom_set_str(config,
		lldpctl_k_config_tx_hold, cmdenv_get(env, "tx-hold")) == NULL) {
		log_warnx("lldpctl", "unable to set transmit hold. %s",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}
	log_info("lldpctl", "transmit hold set to new value %s", cmdenv_get(env, "tx-hold"));
	lldpctl_atom_dec_ref(config);
	return 1;
}

static int
cmd_portid_type_local(struct lldpctl_conn_t *conn, struct writer *w,
		struct cmd_env *env, void *arg)
{
	lldpctl_atom_t *iface;
	const char *id = cmdenv_get(env, "port-id");
	const char *descr = cmdenv_get(env, "port-descr");

	log_debug("lldpctl", "lldp PortID TLV Subtype Local port-id '%s' port-descr '%s'", id, descr);

	if (!id || !strlen(id)) {
		log_warnx("lldpctl", "no id speficied");
		return 0;
	}

	while ((iface = cmd_iterate_on_interfaces(conn, env))) {
		lldpctl_atom_t *port = lldpctl_get_port(iface);
		if (lldpctl_atom_set_str(port, lldpctl_k_port_id, id) == NULL) {
			log_warnx("lldpctl", "unable to set LLDP PortID."
			  " %s", lldpctl_last_strerror(conn));
		}
		if (descr && lldpctl_atom_set_str(port, lldpctl_k_port_descr, descr) == NULL) {
			log_warnx("lldpctl", "unable to set LLDP Port Description."
			  " %s", lldpctl_last_strerror(conn));
		}
		lldpctl_atom_dec_ref(port);
	}

	return 1;
}

static int
cmd_portid_type(struct lldpctl_conn_t *conn, struct writer *w,
		struct cmd_env *env, void *arg)
{
	char *value_str;
	int value = -1;

	log_debug("lldpctl", "lldp PortID TLV Subtype");

	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl",
			  "unable to get configuration from lldpd. %s",
			  lldpctl_last_strerror(conn));
		return 0;
	}

	value_str = arg;
	for (lldpctl_map_t *b_map =
		     lldpctl_key_get_map(lldpctl_k_config_lldp_portid_type);
	     b_map->string; b_map++) {
		if (!strcmp(b_map->string, value_str)) {
			value = b_map->value;
			break;
		}
	}

	if (value == -1) {
		log_warnx("lldpctl", "invalid value");
		lldpctl_atom_dec_ref(config);
		return 0;
	}

	if (lldpctl_atom_set_int(config,
				 lldpctl_k_config_lldp_portid_type, value) == NULL) {
		log_warnx("lldpctl", "unable to set LLDP PortID type."
			  " %s", lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}

	log_info("lldpctl", "LLDP PortID TLV type set to new value : %s", value_str);
	lldpctl_atom_dec_ref(config);

	return 1;
}

static int
cmd_chassis_cap_advertise(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "lldp capabilities-advertisements %s", arg?"enable":"disable");

	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}
	if (lldpctl_atom_set_int(config,
		lldpctl_k_config_chassis_cap_advertise,
		arg?1:0) == NULL) {
		log_warnx("lldpctl", "unable to %s chassis capabilities advertisement: %s",
		    arg?"enable":"disable",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}
	log_info("lldpctl", "chassis capabilities advertisement %s",
	    arg?"enabled":"disabled");
	lldpctl_atom_dec_ref(config);
	return 1;
}

/* FIXME: see about compressing this with other functions */
static int
cmd_chassis_mgmt_advertise(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "lldp management-addresses-advertisements %s", arg?"enable":"disable");

	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}
	if (lldpctl_atom_set_int(config,
		lldpctl_k_config_chassis_mgmt_advertise,
		arg?1:0) == NULL) {
		log_warnx("lldpctl", "unable to %s management addresses advertisement: %s",
		    arg?"enable":"disable",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}
	log_info("lldpctl", "management addresses advertisement %s",
	    arg?"enabled":"disabled");
	lldpctl_atom_dec_ref(config);
	return 1;
}

/**
 * Register `configure lldp` commands.
 *
 * Those are the commands that are related to the LLDP protocol but not
 * Dot1/Dot3/MED. Commands not related to LLDP should go in system instead.
 */
void
register_commands_configure_lldp(struct cmd_node *configure,
    struct cmd_node *unconfigure)
{
	struct cmd_node *configure_lldp = commands_new(
		configure,
		"lldp", "LLDP configuration",
		NULL, NULL, NULL);
	struct cmd_node *unconfigure_lldp = commands_new(
		unconfigure,
		"lldp", "LLDP configuration",
		NULL, NULL, NULL);

        commands_new(
		commands_new(
			commands_new(configure_lldp,
			    "tx-interval", "Set LLDP transmit delay",
			    cmd_check_no_env, NULL, "ports"),
			NULL, "LLDP transmit delay in seconds",
			NULL, cmd_store_env_value, "tx-interval"),
		NEWLINE, "Set LLDP transmit delay",
		NULL, cmd_txdelay, NULL);

        commands_new(
		commands_new(
			commands_new(configure_lldp,
			    "tx-hold", "Set LLDP transmit hold",
			    cmd_check_no_env, NULL, "ports"),
			NULL, "LLDP transmit hold in seconds",
			NULL, cmd_store_env_value, "tx-hold"),
		NEWLINE, "Set LLDP transmit hold",
		NULL, cmd_txhold, NULL);

	/* Now handle the various portid subtypes we can configure. */
	struct cmd_node *configure_lldp_portid_type = commands_new(
		configure_lldp,
		"portidsubtype", "LLDP PortID TLV Subtype ",
		NULL, NULL, NULL);

	for (lldpctl_map_t *b_map =
		     lldpctl_key_get_map(lldpctl_k_config_lldp_portid_type);
	     b_map->string; b_map++) {
		if (!strcmp(b_map->string, "ifname")) {
			commands_new(
				commands_new(configure_lldp_portid_type,
					     b_map->string, "Interface Name",
					     NULL, NULL, NULL),
				NEWLINE, NULL,
				NULL, cmd_portid_type,
				b_map->string);
		} else if (!strcmp(b_map->string, "local")) {
			struct cmd_node *port_id = commands_new(
				commands_new(configure_lldp_portid_type,
					     b_map->string, "Local",
					     NULL, NULL, NULL),
				NULL, "Port ID",
				NULL, cmd_store_env_value, "port-id");
			commands_new(port_id,
				NEWLINE, "Set local port ID",
				NULL, cmd_portid_type_local,
				b_map->string);
			commands_new(
				commands_new(
					commands_new(port_id,
					    "description",
					    "Also set port description",
					    NULL, NULL, NULL),
					NULL, "Port description",
					NULL, cmd_store_env_value, "port-descr"),
				NEWLINE, "Set local port ID and description",
				NULL, cmd_portid_type_local, NULL);
		} else if (!strcmp(b_map->string, "macaddress")) {
			commands_new(
				commands_new(configure_lldp_portid_type,
					     b_map->string, "MAC Address",
					     NULL, NULL, NULL),
				NEWLINE, NULL,
				NULL, cmd_portid_type,
				b_map->string);
		}
	}

	commands_new(
		commands_new(configure_lldp,
		    "capabilities-advertisements",
		    "Enable chassis capabilities advertisement",
		    NULL, NULL, NULL),
		NEWLINE, "Enable chassis capabilities advertisement",
		NULL, cmd_chassis_cap_advertise, "enable");
	commands_new(
		commands_new(unconfigure_lldp,
		    "capabilities-advertisements",
		    "Don't enable chassis capabilities advertisement",
		    NULL, NULL, NULL),
		NEWLINE, "Don't enable chassis capabilities advertisement",
		NULL, cmd_chassis_cap_advertise, NULL);

	commands_new(
		commands_new(configure_lldp,
		    "management-addresses-advertisements",
		    "Enable management addresses advertisement",
		    NULL, NULL, NULL),
		NEWLINE, "Enable management addresses advertisement",
		NULL, cmd_chassis_mgmt_advertise, "enable");
	commands_new(
		commands_new(unconfigure_lldp,
		    "management-addresses-advertisements",
		    "Don't enable management addresses advertisement",
		    NULL, NULL, NULL),
		NEWLINE, "Don't enable management addresses advertisement",
		NULL, cmd_chassis_mgmt_advertise, NULL);
}
