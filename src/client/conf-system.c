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
cmd_iface_pattern(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set iface pattern");

	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}
	if (lldpctl_atom_set_str(config,
		lldpctl_k_config_iface_pattern, cmdenv_get(env, "iface-pattern")) == NULL) {
		log_warnx("lldpctl", "unable to set iface-pattern. %s",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}
	log_info("lldpctl", "iface-pattern set to new value %s", cmdenv_get(env, "iface-pattern"));
	lldpctl_atom_dec_ref(config);
	return 1;
}

static int
cmd_system_description(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	int platform = 0;
	const char *value = cmdenv_get(env, "description");
	if (!value) {
		platform = 1;
		value = cmdenv_get(env, "platform");
	}
	log_debug("lldpctl", "set %s description", platform?"platform":"system");
	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}
	if (lldpctl_atom_set_str(config,
		platform?lldpctl_k_config_platform:lldpctl_k_config_description,
		value) == NULL) {
		log_warnx("lldpctl", "unable to set description. %s",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}
	log_info("lldpctl", "description set to new value %s",
	    value);
	lldpctl_atom_dec_ref(config);
	return 1;
}

static int
cmd_update_descriptions(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}
	if (lldpctl_atom_set_int(config,
		lldpctl_k_config_ifdescr_update,
		arg?1:0) == NULL) {
		log_warnx("lldpctl", "unable to %s interface description update: %s",
		    arg?"enable":"disable",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}
	log_info("lldpctl", "interface description update %s",
	    arg?"enabled":"disabled");
	lldpctl_atom_dec_ref(config);
	return 1;
}

/**
 * Register `configure system` commands.
 *
 * Those are the commands to configure protocol-independant stuff.
 */
void
register_commands_configure_system(struct cmd_node *configure,
    struct cmd_node *unconfigure)
{
	struct cmd_node *configure_system = commands_new(
		configure,
		"system", "System configuration",
		cmd_check_no_env, NULL, "ports");
	struct cmd_node *unconfigure_system = commands_new(
		unconfigure,
		"system", "System configuration",
		cmd_check_no_env, NULL, "ports");
	struct cmd_node *configure_interface = commands_new(
		configure_system,
		"interface", "Interface related items",
		NULL, NULL, NULL);
	struct cmd_node *unconfigure_interface = commands_new(
		unconfigure_system,
		"interface", "Interface related items",
		NULL, NULL, NULL);

	commands_new(
		commands_new(
			commands_new(configure_system,
			    "description", "Override chassis description",
			    NULL, NULL, NULL),
			NULL, "Chassis description",
			NULL, cmd_store_env_value, "description"),
		NEWLINE, "Override chassis description",
		NULL, cmd_system_description, NULL);

	commands_new(
		commands_new(
			commands_new(configure_system,
			    "platform", "Override platform description",
			    NULL, NULL, NULL),
			NULL, "Platform description (CDP)",
			NULL, cmd_store_env_value, "platform"),
		NEWLINE, "Override platform description",
		NULL, cmd_system_description, NULL);

        commands_new(
		commands_new(
			commands_new(configure_interface,
			    "pattern", "Set active interface pattern",
			    NULL, NULL, NULL),
			NULL, "Interface pattern (comma separated list of wildcards)",
			NULL, cmd_store_env_value, "iface-pattern"),
		NEWLINE, "Set active interface pattern",
		NULL, cmd_iface_pattern, NULL);

	commands_new(
		commands_new(configure_interface,
		    "description", "Update interface descriptions with neighbor name",
		    NULL, NULL, NULL),
		NEWLINE, "Update interface descriptions with neighbor name",
		NULL, cmd_update_descriptions, "enable");
	commands_new(
		commands_new(unconfigure_interface,
		    "description", "Don't update interface descriptions with neighbor name",
		    NULL, NULL, NULL),
		NEWLINE, "Don't update interface descriptions with neighbor name",
		NULL, cmd_update_descriptions, NULL);
}

