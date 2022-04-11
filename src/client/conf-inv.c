/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * SPDX-FileCopyrightText: 2022 Koninklijke Philips N.V.
 * SPDX-License-Identifier: ISC
 */

#include <unistd.h>
#include <string.h>

#include "client.h"
#include "../log.h"

static int
cmd_inventory(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "configure inventory information");

	lldpctl_atom_t *chassis = lldpctl_get_local_chassis(conn);

	if (chassis == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}

	char *action = arg;
	if ((!strcmp(action, "hardware-revision") &&
		(lldpctl_atom_set_str(chassis,
		    lldpctl_k_chassis_med_inventory_hw,
		    cmdenv_get(env, "hardware-revision")) == NULL)) ||
	    (!strcmp(action, "software-revision") &&
		(lldpctl_atom_set_str(chassis,
		    lldpctl_k_chassis_med_inventory_sw,
		    cmdenv_get(env, "software-revision")) == NULL)) ||
	    (!strcmp(action, "firmware-revision") &&
		(lldpctl_atom_set_str(chassis,
		    lldpctl_k_chassis_med_inventory_fw,
		    cmdenv_get(env, "firmware-revision")) == NULL)) ||
	    (!strcmp(action, "serial-number") &&
		(lldpctl_atom_set_str(chassis,
		    lldpctl_k_chassis_med_inventory_sn,
		    cmdenv_get(env, "serial-number")) == NULL)) ||
	    (!strcmp(action, "manufacturer") &&
		(lldpctl_atom_set_str(chassis,
		    lldpctl_k_chassis_med_inventory_manuf,
		    cmdenv_get(env, "manufacturer")) == NULL)) ||
	    (!strcmp(action, "model") &&
		(lldpctl_atom_set_str(chassis,
		    lldpctl_k_chassis_med_inventory_model,
		    cmdenv_get(env, "model")) == NULL)) ||
	    (!strcmp(action, "asset") &&
		(lldpctl_atom_set_str(chassis,
		    lldpctl_k_chassis_med_inventory_asset,
		    cmdenv_get(env, "asset")) == NULL))) {
		log_warnx("lldpctl", "Unable to setup inventory. %s",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(chassis);
		return 0;
	}

	log_info("lldpctl", "Configuration for inventory is applied");
	lldpctl_atom_dec_ref(chassis);
	return 1;
}

/**
 * Register `configure inventory *` commands
 *
 */
static void
register_commands_inv(struct cmd_node *configure_inv, struct cmd_node *unconfigure_inv)
{
	commands_new(
		commands_new(
			commands_new(configure_inv,
			    "hardware-revision", "Set hardware-revision string",
			    NULL, NULL, NULL),
			NULL, "Inventory hardware-revision string",
			NULL, cmd_store_env_value, "hardware-revision"),
		NEWLINE, "Set hardware-revision string",
		NULL, cmd_inventory, "hardware-revision");

	commands_new(
		commands_new(unconfigure_inv,
		    "hardware-revision", "Unset hardware-revision string",
		    NULL, NULL, NULL),
		NEWLINE, "Unset hardware-revision string",
		NULL, cmd_inventory, "hardware-revision");

	commands_new(
		commands_new(
			commands_new(configure_inv,
			    "software-revision", "Set software-revision string",
			    NULL, NULL, NULL),
			NULL, "Inventory software-revision string",
			NULL, cmd_store_env_value, "software-revision"),
		NEWLINE, "Set software-revision string",
		NULL, cmd_inventory, "software-revision");

	commands_new(
		commands_new(unconfigure_inv,
		    "software-revision", "Unset software-revision string",
		    NULL, NULL, NULL),
		NEWLINE, "Unset software-revision string",
		NULL, cmd_inventory, "software-revision");

	commands_new(
		commands_new(
			commands_new(configure_inv,
			    "firmware-revision", "Set firmware-revision string",
			    NULL, NULL, NULL),
			NULL, "Inventory firmware-revision string",
			NULL, cmd_store_env_value, "firmware-revision"),
		NEWLINE, "Set firmware-revision string",
		NULL, cmd_inventory, "firmware-revision");

	commands_new(
		commands_new(unconfigure_inv,
		    "firmware-revision", "Unset firmware-revision string",
		    NULL, NULL, NULL),
		NEWLINE, "Unset firmware-revision string",
		NULL, cmd_inventory, "firmware-revision");

	commands_new(
		commands_new(
			commands_new(configure_inv,
			    "serial-number", "Set serial-number string",
			    NULL, NULL, NULL),
			NULL, "Inventory serial-number string",
			NULL, cmd_store_env_value, "serial-number"),
		NEWLINE, "Set serial-number string",
		NULL, cmd_inventory, "serial-number");

	commands_new(
		commands_new(unconfigure_inv,
		    "serial-number", "Unset serial-number string",
		    NULL, NULL, NULL),
		NEWLINE, "Unset serial-number string",
		NULL, cmd_inventory, "serial-number");

	commands_new(
		commands_new(
			commands_new(configure_inv,
			    "manufacturer", "Set manufacturer string",
			    NULL, NULL, NULL),
			NULL, "Inventory manufacturer string",
			NULL, cmd_store_env_value, "manufacturer"),
		NEWLINE, "Set manufacturer string",
		NULL, cmd_inventory, "manufacturer");

	commands_new(
		commands_new(unconfigure_inv,
		    "manufacturer", "Unset manufacturer string",
		    NULL, NULL, NULL),
		NEWLINE, "Unset manufacturer string",
		NULL, cmd_inventory, "manufacturer");

	commands_new(
		commands_new(
			commands_new(configure_inv,
			    "model", "Set model string",
			    NULL, NULL, NULL),
			NULL, "Inventory model string",
			NULL, cmd_store_env_value, "model"),
		NEWLINE, "Set model string",
		NULL, cmd_inventory, "model");

	commands_new(
		commands_new(unconfigure_inv,
		    "model", "Unset model string",
		    NULL, NULL, NULL),
		NEWLINE, "Unset model string",
		NULL, cmd_inventory, "model");

	commands_new(
		commands_new(
			commands_new(configure_inv,
			    "asset", "Set asset string",
			    NULL, NULL, NULL),
			NULL, "Inventory asset string",
			NULL, cmd_store_env_value, "asset"),
		NEWLINE, "Set asset string",
		NULL, cmd_inventory, "asset");

	commands_new(
		commands_new(unconfigure_inv,
		    "asset", "Unset asset string",
		    NULL, NULL, NULL),
		NEWLINE, "Unset asset string",
		NULL, cmd_inventory, "asset");
}

/**
 * Register `configure inventory *`
 *
 */
void
register_commands_configure_inventory(struct cmd_node *configure, struct cmd_node *unconfigure) {
	if(lldpctl_key_get_map(
		    lldpctl_k_med_policy_type)[0].value <= 0)
		return;

	struct cmd_node *configure_inv = commands_new(
		configure,
		"inventory", "Inventory configuration",
		NULL, NULL, NULL);
	struct cmd_node *unconfigure_inv = commands_new(
		unconfigure,
		"inventory", "Inventory configuration",
		NULL, NULL, NULL);

	register_commands_inv(configure_inv, unconfigure_inv);
}

