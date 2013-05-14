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

/**
 * Register `configure lldp` commands.
 */
void
register_commands_configure_lldp(struct cmd_node *configure)
{
	struct cmd_node *configure_lldp = commands_new(
		configure,
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
}

/**
 * Register `configure` and `no configure` commands.
 */
void
register_commands_configure(struct cmd_node *root)
{
	struct cmd_node *configure = commands_new(
		root,
		"configure",
		"Change system settings",
		NULL, NULL, NULL);
	struct cmd_node *unconfigure = commands_new(
		root,
		"unconfigure",
		"Unconfigure system settings",
		NULL, NULL, NULL);
	cmd_restrict_ports(configure);
	cmd_restrict_ports(unconfigure);

        register_commands_configure_lldp(configure);
        register_commands_configure_med(configure, unconfigure);
        register_commands_configure_dot3(configure);
}
