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

#include <unistd.h>
#include <string.h>

#include "client.h"
#include "../log.h"

static int
_cmd_medlocation(struct lldpctl_conn_t *conn,
    struct cmd_env *env, int format)
{
	lldpctl_atom_t *iface;
	while ((iface = cmd_iterate_on_interfaces(conn, env))) {
		const char *name = lldpctl_atom_get_str(iface, lldpctl_k_interface_name);
		lldpctl_atom_t *port = lldpctl_get_port(iface);
		lldpctl_atom_t *med_location = NULL, *med_locations = NULL;
		const char *what = NULL;
		int ok = 0;

		med_locations = lldpctl_atom_get(port, lldpctl_k_port_med_locations);
		if (med_locations == NULL) {
			log_warnx("lldpctl", "unable to set LLDP-MED location: support seems unavailable");
			goto end;
		}

		med_location = lldpctl_atom_iter_value(med_locations,
		    lldpctl_atom_iter_next(med_locations,
			lldpctl_atom_iter(med_locations)));

		switch (format) {
		case LLDP_MED_LOCFORMAT_COORD:
			if ((what = "format", lldpctl_atom_set_int(med_location,
				    lldpctl_k_med_location_format,
				    format)) == NULL ||
			    (what = "latitude", lldpctl_atom_set_str(med_location,
				lldpctl_k_med_location_latitude,
				cmdenv_get(env, "latitude"))) == NULL ||
			    (what = "longitude", lldpctl_atom_set_str(med_location,
				lldpctl_k_med_location_longitude,
				cmdenv_get(env, "longitude"))) == NULL ||
			    (what = "altitude", lldpctl_atom_set_str(med_location,
				lldpctl_k_med_location_altitude,
				cmdenv_get(env, "altitude"))) == NULL ||
			    (what = "altitude unit", lldpctl_atom_set_str(med_location,
				lldpctl_k_med_location_altitude_unit,
				cmdenv_get(env, "altitude-unit"))) == NULL ||
			    (what = "datum", lldpctl_atom_set_str(med_location,
				lldpctl_k_med_location_geoid,
				cmdenv_get(env, "datum"))) == NULL)
				log_warnx("lldpctl",
				    "unable to set LLDP MED location value for %s on %s. %s.",
				    what, name, lldpctl_last_strerror(conn));
			else ok = 1;
			break;
		case LLDP_MED_LOCFORMAT_CIVIC:
			if ((what = "format", lldpctl_atom_set_int(med_location,
				    lldpctl_k_med_location_format,
				    format)) == NULL ||
			    (what = "country", lldpctl_atom_set_str(med_location,
				lldpctl_k_med_location_country,
				cmdenv_get(env, "country"))) == NULL) {
				log_warnx("lldpctl",
				    "unable to set LLDP MED location value for %s on %s. %s.",
				    what, name, lldpctl_last_strerror(conn));
				break;
			}
			ok = 1;
			for (lldpctl_map_t *addr_map =
				 lldpctl_key_get_map(lldpctl_k_med_civicaddress_type);
			     addr_map->string;
			     addr_map++) {
				lldpctl_atom_t *cael, *caels;
				const char *value = cmdenv_get(env, addr_map->string);
				if (!value) continue;

				caels = lldpctl_atom_get(med_location, lldpctl_k_med_location_ca_elements);
				cael = lldpctl_atom_create(caels);

				if (lldpctl_atom_set_str(cael, lldpctl_k_med_civicaddress_type,
					addr_map->string) == NULL ||
				    lldpctl_atom_set_str(cael, lldpctl_k_med_civicaddress_value,
					value) == NULL ||
				    lldpctl_atom_set(med_location,
					lldpctl_k_med_location_ca_elements,
					cael) == NULL) {
						log_warnx("lldpctl",
						    "unable to add a civic address element `%s`. %s",
						    addr_map->string,
						    lldpctl_last_strerror(conn));
						ok = 0;
				}

				lldpctl_atom_dec_ref(cael);
				lldpctl_atom_dec_ref(caels);
				if (!ok) break;
			}
			break;
		case LLDP_MED_LOCFORMAT_ELIN:
			if (lldpctl_atom_set_int(med_location,
				lldpctl_k_med_location_format, format) == NULL ||
			    lldpctl_atom_set_str(med_location,
				lldpctl_k_med_location_elin, cmdenv_get(env, "elin")) == NULL)
				log_warnx("lldpctl", "unable to set LLDP MED location on %s. %s",
				    name, lldpctl_last_strerror(conn));
			else ok = 1;
			break;
		}
		if (ok) {
			if (lldpctl_atom_set(port, lldpctl_k_port_med_locations,
				med_location) == NULL) {
				log_warnx("lldpctl", "unable to set LLDP MED location on %s. %s.",
				    name, lldpctl_last_strerror(conn));
			} else
				log_info("lldpctl", "LLDP-MED location has been set for port %s",
				    name);
		}

	end:
		lldpctl_atom_dec_ref(med_location);
		lldpctl_atom_dec_ref(med_locations);
		lldpctl_atom_dec_ref(port);
	}
	return 1;
}

static int
cmd_medlocation_coordinate(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set MED location coordinate");
	return _cmd_medlocation(conn, env, LLDP_MED_LOCFORMAT_COORD);
}

static int
cmd_medlocation_address(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set MED location address");
	return _cmd_medlocation(conn, env, LLDP_MED_LOCFORMAT_CIVIC);
}

static int
cmd_medlocation_elin(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set MED location ELIN");
	return _cmd_medlocation(conn, env, LLDP_MED_LOCFORMAT_ELIN);
}

static int
cmd_medpolicy(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set MED policy");
	lldpctl_atom_t *iface;
	while ((iface = cmd_iterate_on_interfaces(conn, env))) {
		const char *name = lldpctl_atom_get_str(iface, lldpctl_k_interface_name);
		lldpctl_atom_t *port = lldpctl_get_port(iface);
		lldpctl_atom_t *med_policy = NULL, *med_policies = NULL;
		const char *what = NULL;

		med_policies = lldpctl_atom_get(port, lldpctl_k_port_med_policies);
		if (med_policies == NULL) {
			log_warnx("lldpctl", "unable to set LLDP-MED policies: support seems unavailable");
			goto end;
		}

		med_policy = lldpctl_atom_iter_value(med_policies,
		    lldpctl_atom_iter_next(med_policies,
			lldpctl_atom_iter(med_policies)));

		if ((what = "application", lldpctl_atom_set_str(med_policy,
			    lldpctl_k_med_policy_type,
			    cmdenv_get(env, "application"))) == NULL ||
		    (what = "unknown flag", lldpctl_atom_set_int(med_policy,
			lldpctl_k_med_policy_unknown,
			cmdenv_get(env, "unknown")?1:0)) == NULL ||
		    (what = "vlan",
			cmdenv_get(env, "vlan")?
			lldpctl_atom_set_str(med_policy,
			    lldpctl_k_med_policy_vid,
			    cmdenv_get(env, "vlan")):
			lldpctl_atom_set_int(med_policy,
			    lldpctl_k_med_policy_vid, 0)) == NULL ||
		    (what = "priority",
			cmdenv_get(env, "priority")?
			lldpctl_atom_set_str(med_policy,
			    lldpctl_k_med_policy_priority,
			    cmdenv_get(env, "priority")):
			lldpctl_atom_set_int(med_policy,
			    lldpctl_k_med_policy_priority,
			    0)) == NULL ||
		    (what = "dscp",
			cmdenv_get(env, "dscp")?
			lldpctl_atom_set_str(med_policy,
			    lldpctl_k_med_policy_dscp,
			    cmdenv_get(env, "dscp")):
			lldpctl_atom_set_int(med_policy,
			    lldpctl_k_med_policy_dscp,
			    0)) == NULL)
			log_warnx("lldpctl",
			    "unable to set LLDP MED policy value for %s on %s. %s.",
			    what, name, lldpctl_last_strerror(conn));
		else {
			if (lldpctl_atom_set(port, lldpctl_k_port_med_policies,
				med_policy) == NULL) {
				log_warnx("lldpctl", "unable to set LLDP MED policy on %s. %s.",
				    name, lldpctl_last_strerror(conn));
			} else
				log_info("lldpctl", "LLDP-MED policy has been set for port %s",
				    name);
		}

	end:
		lldpctl_atom_dec_ref(med_policy);
		lldpctl_atom_dec_ref(med_policies);
		lldpctl_atom_dec_ref(port);
	}
	return 1;
}

static int
cmd_medpower(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set MED power");
	lldpctl_atom_t *iface;
	while ((iface = cmd_iterate_on_interfaces(conn, env))) {
		const char *name = lldpctl_atom_get_str(iface, lldpctl_k_interface_name);
		lldpctl_atom_t *port = lldpctl_get_port(iface);
		lldpctl_atom_t *med_power;
		const char *what = NULL;

		med_power = lldpctl_atom_get(port, lldpctl_k_port_med_power);
		if (med_power == NULL) {
			log_warnx("lldpctl", "unable to set LLDP-MED power: support seems unavailable");
			goto end;
		}

		if ((what = "device type", lldpctl_atom_set_str(med_power,
			    lldpctl_k_med_power_type,
			    cmdenv_get(env, "device-type"))) == NULL ||
		    (what = "power source", lldpctl_atom_set_str(med_power,
			lldpctl_k_med_power_source,
			cmdenv_get(env, "source"))) == NULL ||
		    (what = "power priority", lldpctl_atom_set_str(med_power,
			lldpctl_k_med_power_priority,
			cmdenv_get(env, "priority"))) == NULL ||
		    (what = "power value", lldpctl_atom_set_str(med_power,
			lldpctl_k_med_power_val,
			cmdenv_get(env, "value"))) == NULL)
			log_warnx("lldpctl",
			    "unable to set LLDP MED power value for %s on %s. %s.",
			    what, name, lldpctl_last_strerror(conn));
		else {
			if (lldpctl_atom_set(port, lldpctl_k_port_med_power,
				med_power) == NULL) {
				log_warnx("lldpctl", "unable to set LLDP MED power on %s. %s.",
				    name, lldpctl_last_strerror(conn));
			} else
				log_info("lldpctl", "LLDP-MED power has been set for port %s",
				    name);
		}

	end:
		lldpctl_atom_dec_ref(med_power);
		lldpctl_atom_dec_ref(port);
	}
	return 1;
}

static int
cmd_dot3power(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_debug("lldpctl", "set dot3 power");
	lldpctl_atom_t *iface;
	while ((iface = cmd_iterate_on_interfaces(conn, env))) {
		const char *name = lldpctl_atom_get_str(iface, lldpctl_k_interface_name);
		lldpctl_atom_t *port = lldpctl_get_port(iface);
		lldpctl_atom_t *dot3_power;
		const char *what = NULL;
		int ok = 1;

		dot3_power = lldpctl_atom_get(port, lldpctl_k_port_dot3_power);
		if (dot3_power == NULL) {
			log_warnx("lldpctl", "unable to set Dot3 power: support seems unavailable");
			goto end;
		}

		if ((what = "device type", lldpctl_atom_set_str(dot3_power,
			    lldpctl_k_dot3_power_devicetype,
			    cmdenv_get(env, "device-type"))) == NULL ||
		    /* Flags */
		    (what = "supported flag", lldpctl_atom_set_int(dot3_power,
			lldpctl_k_dot3_power_supported,
			cmdenv_get(env, "supported")?1:0)) == NULL ||
		    (what = "enabled flag", lldpctl_atom_set_int(dot3_power,
			lldpctl_k_dot3_power_enabled,
			cmdenv_get(env, "enabled")?1:0)) == NULL ||
		    (what = "paircontrol flag", lldpctl_atom_set_int(dot3_power,
			lldpctl_k_dot3_power_paircontrol,
			cmdenv_get(env, "paircontrol")?1:0)) == NULL ||
		    /* Powerpairs */
		    (what = "power pairs", lldpctl_atom_set_str(dot3_power,
			lldpctl_k_dot3_power_pairs,
			cmdenv_get(env, "powerpairs"))) == NULL ||
		    /* Class */
		    (what = "power class", cmdenv_get(env, "class")?
			lldpctl_atom_set_str(dot3_power,
			    lldpctl_k_dot3_power_class,
			    cmdenv_get(env, "class")):
			lldpctl_atom_set_int(dot3_power,
			    lldpctl_k_dot3_power_class, 0)) == NULL ||
		    (what = "802.3at type", lldpctl_atom_set_int(dot3_power,
			lldpctl_k_dot3_power_type, 0)) == NULL) {
			log_warnx("lldpctl",
			    "unable to set LLDP Dot3 power value for %s on %s. %s.",
			    what, name, lldpctl_last_strerror(conn));
			ok = 0;
		} else if (cmdenv_get(env, "typeat")) {
			int typeat = cmdenv_get(env, "typeat")[0] - '0';
			const char *source = cmdenv_get(env, "source");
			if ((what = "802.3at type", lldpctl_atom_set_int(dot3_power,
				    lldpctl_k_dot3_power_type,
				    typeat)) == NULL ||
			    (what = "source", lldpctl_atom_set_int(dot3_power,
				lldpctl_k_dot3_power_source,
				(!strcmp(source, "primary"))?LLDP_DOT3_POWER_SOURCE_PRIMARY:
				(!strcmp(source, "backup"))? LLDP_DOT3_POWER_SOURCE_BACKUP:
				(!strcmp(source, "pse"))?    LLDP_DOT3_POWER_SOURCE_PSE:
				(!strcmp(source, "local"))?  LLDP_DOT3_POWER_SOURCE_LOCAL:
				(!strcmp(source, "both"))?   LLDP_DOT3_POWER_SOURCE_BOTH:
				LLDP_DOT3_POWER_SOURCE_UNKNOWN)) == NULL ||
			    (what = "priority", lldpctl_atom_set_str(dot3_power,
				lldpctl_k_dot3_power_priority,
				cmdenv_get(env, "priority"))) == NULL ||
			    (what = "requested power", lldpctl_atom_set_str(dot3_power,
				lldpctl_k_dot3_power_requested,
				cmdenv_get(env, "requested"))) == NULL ||
			    (what = "allocated power", lldpctl_atom_set_str(dot3_power,
				lldpctl_k_dot3_power_allocated,
				cmdenv_get(env, "allocated"))) == NULL) {
				log_warnx("lldpctl", "unable to set LLDP Dot3 power value for %s on %s. %s.",
				    what, name, lldpctl_last_strerror(conn));
				ok = 0;
			}
		}
		if (ok) {
			if (lldpctl_atom_set(port, lldpctl_k_port_dot3_power,
				dot3_power) == NULL) {
				log_warnx("lldpctl", "unable to set LLDP Dot3 power on %s. %s.",
				    name, lldpctl_last_strerror(conn));
			} else
				log_info("lldpctl", "LLDP Dot3 power has been set for port %s",
				    name);
		}

	end:
		lldpctl_atom_dec_ref(dot3_power);
		lldpctl_atom_dec_ref(port);
	}
	return 1;
}

#define cmd_no_medlocation_coordinate cmd_not_implemented
#define cmd_no_medlocation_address    cmd_not_implemented
#define cmd_no_medlocation_elin       cmd_not_implemented
#define cmd_no_medpolicy              cmd_not_implemented
#define cmd_no_medpower               cmd_not_implemented
#define cmd_no_dot3power              cmd_not_implemented

/**
 * Restrict the command to some ports.
 */
static void
restrict_ports(struct cmd_node *root)
{
	/* Restrict to some ports. */
	commands_new(
		commands_new(root,
		    "ports",
		    "Restrict configuration to some ports",
		    cmd_check_no_env, NULL, "ports"),
		NULL,
		"Restrict configuration to the specified ports (comma-separated list)",
		NULL, cmd_store_env_value_and_pop2, "ports");
}

/**
 * Register `configure med location coordinate` commands.
 */
static void
register_commands_medloc_coord(struct cmd_node *configure_medlocation)
{
	/* MED location coordinate (set) */
	struct cmd_node *configure_medloc_coord = commands_new(
		configure_medlocation,
		"coordinate", "MED location coordinate configuration",
		NULL, NULL, NULL);
	commands_new(configure_medloc_coord,
	    NEWLINE, "Configure MED location coordinates",
	    cmd_check_env, cmd_medlocation_coordinate,
	    "latitude,longitude,altitude,altitude-unit,datum");
	commands_new(
		commands_new(
			configure_medloc_coord,
			"latitude", "Specify latitude",
			cmd_check_no_env, NULL, "latitude"),
		NULL, "Latitude as xx.yyyyN or xx.yyyyS",
		NULL, cmd_store_env_value_and_pop2, "latitude");
	commands_new(
		commands_new(
			configure_medloc_coord,
			"longitude", "Specify longitude",
			cmd_check_no_env, NULL, "longitude"),
		NULL, "Longitude as xx.yyyyE or xx.yyyyW",
		NULL, cmd_store_env_value_and_pop2, "longitude");
	struct cmd_node *altitude = commands_new(
		commands_new(
			configure_medloc_coord,
			"altitude", "Specify altitude",
			cmd_check_no_env, NULL, "altitude"),
		NULL, "Altitude",
		NULL, cmd_store_env_value, "altitude");
	commands_new(altitude,
	    "m", "meters",
	    NULL, cmd_store_env_value_and_pop3, "altitude-unit");
	commands_new(altitude,
	    "f", "floors",
	    NULL, cmd_store_env_value_and_pop3, "altitude-unit");

	struct cmd_node *datum = commands_new(configure_medloc_coord,
	    "datum", "Specify datum",
	    cmd_check_no_env, NULL, "datum");
	for (lldpctl_map_t *datum_map =
		 lldpctl_key_get_map(lldpctl_k_med_location_geoid);
	     datum_map->string;
	     datum_map++)
		commands_new(datum, datum_map->string, NULL,
		    NULL, cmd_store_env_value_and_pop2, "datum");
}

/**
 * Register `configure med location address` commands.
 */
static void
register_commands_medloc_addr(struct cmd_node *configure_medlocation)
{
	/* MED location address (set) */
	struct cmd_node *configure_medloc_addr = commands_new(
		configure_medlocation,
		"address", "MED location address configuration",
		NULL, NULL, NULL);
	commands_new(configure_medloc_addr,
	    NEWLINE, "Configure MED location address",
	    cmd_check_env, cmd_medlocation_address,
	    "country");

	/* Country */
	commands_new(
		commands_new(
			configure_medloc_addr,
			"country", "Specify country (mandatory)",
			cmd_check_no_env, NULL, "country"),
		NULL, "Country as a two-letter code",
		NULL, cmd_store_env_value_and_pop2, "country");

	/* Other fields */
	for (lldpctl_map_t *addr_map =
		 lldpctl_key_get_map(lldpctl_k_med_civicaddress_type);
	     addr_map->string;
	     addr_map++)
		commands_new(
			commands_new(
				configure_medloc_addr,
				strdup(totag(addr_map->string)), /* TODO: memory leak, happens once */
				addr_map->string,
				cmd_check_no_env, NULL, addr_map->string),
			NULL, addr_map->string,
			NULL, cmd_store_env_value_and_pop2, addr_map->string);
}

/**
 * Register `configure med location elin` commands.
 */
static void
register_commands_medloc_elin(struct cmd_node *configure_medlocation)
{
	/* MED location elin (set) */
	commands_new(
		commands_new(
			commands_new(
				configure_medlocation,
				"elin", "MED location ELIN configuration",
				NULL, NULL, NULL),
			NULL, "ELIN number",
			NULL, cmd_store_env_value, "elin"),
		NEWLINE, "Set MED location ELIN number",
		NULL, cmd_medlocation_elin, NULL);
}

/**
 * Register `configure med location` commands.
 */
static void
register_commands_medloc(struct cmd_node *configure_med, struct cmd_node *unconfigure_med)
{
	struct cmd_node *configure_medlocation = commands_new(
		configure_med,
		"location", "MED location configuration",
		NULL, NULL, NULL);

	register_commands_medloc_coord(configure_medlocation);
	register_commands_medloc_addr(configure_medlocation);
	register_commands_medloc_elin(configure_medlocation);

	/* MED location (unset) */
	struct cmd_node *unconfigure_medlocation = commands_new(
		unconfigure_med,
		"location", "MED location configuration",
		NULL, NULL, NULL);
	commands_new(
		commands_new(
			unconfigure_medlocation,
			"coordinate", "Unconfigure MED location coordinate",
			NULL, NULL, NULL),
		NEWLINE, "Unconfigure MED location coordinate",
		NULL, cmd_no_medlocation_coordinate, NULL);
	commands_new(
		commands_new(
			unconfigure_medlocation,
			"coordinate", "Unconfigure MED location address",
			NULL, NULL, NULL),
		NEWLINE, "Unconfigure MED location address",
		NULL, cmd_no_medlocation_address, NULL);
	commands_new(
		commands_new(
			unconfigure_medlocation,
			"coordinate", "Unconfigure MED location ELIN",
			NULL, NULL, NULL),
		NEWLINE, "Unconfigure MED location ELIN",
		NULL, cmd_no_medlocation_elin, NULL);
}

static int
cmd_check_application_but_no(struct cmd_env *env, void *arg)
{
	const char *what = arg;
	if (!cmdenv_get(env, "application")) return 0;
	if (cmdenv_get(env, what)) return 0;
	return 1;
}
static int
cmd_store_something_env_value_and_pop2(const char *what,
    struct cmd_env *env, void *value)
{
	return (cmdenv_put(env, what, value) != -1 &&
	    cmdenv_pop(env, 2) != -1);
}
static int
cmd_store_app_env_value_and_pop2(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *value)
{
	return cmd_store_something_env_value_and_pop2("application", env, value);
}
static int
cmd_store_powerpairs_env_value_and_pop2(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *value)
{
	return cmd_store_something_env_value_and_pop2("powerpairs", env, value);
}
static int
cmd_store_class_env_value_and_pop2(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *value)
{
	return cmd_store_something_env_value_and_pop2("class", env, value);
}
static int
cmd_store_prio_env_value_and_pop2(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *value)
{
	return cmd_store_something_env_value_and_pop2("priority", env, value);
}
static int
cmd_store_app_env_value(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *value)
{
	return (cmdenv_put(env, "application", value) != -1);
}

/**
 * Register `configure med policy` commands.
 */
static void
register_commands_medpol(struct cmd_node *configure_med, struct cmd_node *unconfigure_med)
{
	struct cmd_node *configure_medpolicy = commands_new(
		configure_med,
		"policy", "MED policy configuration",
		NULL, NULL, NULL);

	/* MED policy (un set) */
	struct cmd_node *unconfigure_application =
	    commands_new(
		    commands_new(
			    unconfigure_med,
			    "policy", "MED policy configuration",
			    NULL, NULL, NULL),
		    "application", "MED policy application",
		    NULL, NULL, NULL);

	commands_new(
		configure_medpolicy,
		NEWLINE, "Apply new MED policy",
		cmd_check_env, cmd_medpolicy, "application");

	/* Application */
	struct cmd_node *configure_application =
	    commands_new(
		    configure_medpolicy,
		    "application", "MED policy application",
		    cmd_check_no_env, NULL, "application");

	for (lldpctl_map_t *pol_map =
		 lldpctl_key_get_map(lldpctl_k_med_policy_type);
	     pol_map->string;
	     pol_map++) {
		char *tag = strdup(totag(pol_map->string)); /* TODO: memory leak, happens once */
		commands_new(
			commands_new(
				unconfigure_application,
				tag,
				pol_map->string,
				NULL, cmd_store_app_env_value, pol_map->string),
			NEWLINE, "Remove specified MED policy",
			NULL, cmd_no_medpolicy, NULL);
		commands_new(
			configure_application,
			tag,
			pol_map->string,
			NULL, cmd_store_app_env_value_and_pop2, pol_map->string);
	}

	/* Remaining keywords */
	commands_new(
		configure_medpolicy,
		"unknown", "Set unknown flag",
		cmd_check_application_but_no, cmd_store_env_and_pop, "unknown");
	commands_new(
		commands_new(
			configure_medpolicy,
			"vlan", "VLAN advertising",
			cmd_check_application_but_no, NULL, "vlan"),
		NULL, "VLAN ID to advertise",
		NULL, cmd_store_env_value_and_pop2, "vlan");
	commands_new(
		commands_new(
			configure_medpolicy,
			"dscp", "DiffServ advertising",
			cmd_check_application_but_no, NULL, "dscp"),
		NULL, "DSCP value to advertise (between 0 and 63)",
		NULL, cmd_store_env_value_and_pop2, "dscp");
	struct cmd_node *priority =
	    commands_new(
		    configure_medpolicy,
		    "priority", "MED policy priority",
		    cmd_check_application_but_no, NULL, "priority");
	for (lldpctl_map_t *prio_map =
		 lldpctl_key_get_map(lldpctl_k_med_policy_priority);
	     prio_map->string;
	     prio_map++) {
		char *tag = strdup(totag(prio_map->string)); /* TODO: memory leak, happens once */
		commands_new(
			priority,
			tag, prio_map->string,
			NULL, cmd_store_prio_env_value_and_pop2, prio_map->string);
	}
}

static int
cmd_check_type_but_no(struct cmd_env *env, void *arg)
{
	const char *what = arg;
	if (!cmdenv_get(env, "device-type")) return 0;
	if (cmdenv_get(env, what)) return 0;
	return 1;
}
static int
cmd_check_typeat_but_no(struct cmd_env *env, void *arg)
{
	const char *what = arg;
	if (!cmdenv_get(env, "typeat")) return 0;
	if (cmdenv_get(env, what)) return 0;
	return 1;
}
static int
cmd_check_type(struct cmd_env *env, const char *type)
{
	const char *etype = cmdenv_get(env, "device-type");
	if (!etype) return 0;
	return (!strcmp(type, etype));
}
static int
cmd_check_pse(struct cmd_env *env, void *arg)
{
	return cmd_check_type(env, "pse");
}
static int
cmd_check_pd(struct cmd_env *env, void *arg)
{
	return cmd_check_type(env, "pd");
}

static void
register_commands_pow_source(struct cmd_node *source)
{
	commands_new(source,
	    "unknown", "Unknown power source",
	    NULL, cmd_store_env_and_pop, "source");
	commands_new(source,
	    "primary", "Primary power source",
	    cmd_check_pse, cmd_store_env_value_and_pop2, "source");
	commands_new(source,
	    "backup", "Backup power source",
	    cmd_check_pse, cmd_store_env_value_and_pop2, "source");
	commands_new(source,
	    "pse", "Power source is PSE",
	    cmd_check_pd, cmd_store_env_value_and_pop2, "source");
	commands_new(source,
	    "local", "Local power source",
	    cmd_check_pd, cmd_store_env_value_and_pop2, "source");
	commands_new(source,
	    "both", "Both PSE and local source available",
	    cmd_check_pd, cmd_store_env_value_and_pop2, "source");
}

static void
register_commands_pow_priority(struct cmd_node *priority, int key)
{
	for (lldpctl_map_t *prio_map =
		 lldpctl_key_get_map(key);
	     prio_map->string;
	     prio_map++) {
		char *tag = strdup(totag(prio_map->string)); /* TODO: memory leak, happens once */
		commands_new(
			priority,
			tag,
			prio_map->string,
			NULL, cmd_store_prio_env_value_and_pop2, prio_map->string);
	}
}

/**
 * Register `configure med power` commands.
 */
static void
register_commands_medpow(struct cmd_node *configure_med, struct cmd_node *unconfigure_med)
{
	commands_new(
		commands_new(unconfigure_med,
		    "power", "MED power configuration",
		    NULL, NULL, NULL),
		NEWLINE, "Disable advertising of LLDP-MED POE-MDI TLV",
		NULL, cmd_no_medpower, NULL);

	struct cmd_node *configure_medpower = commands_new(
		configure_med,
		"power", "MED power configuration",
		NULL, NULL, NULL);

	commands_new(
		configure_medpower,
		NEWLINE, "Apply new MED power configuration",
		cmd_check_env, cmd_medpower, "device-type,source,priority,value");

	/* Type: PSE or PD */
	commands_new(
		configure_medpower,
		"pd", "MED power consumer",
		cmd_check_no_env, cmd_store_env_value_and_pop, "device-type");
	commands_new(
		configure_medpower,
		"pse", "MED power provider",
		cmd_check_no_env, cmd_store_env_value_and_pop, "device-type");

	/* Source */
	struct cmd_node *source = commands_new(
		configure_medpower,
		"source", "MED power source",
		cmd_check_type_but_no, NULL, "source");
	register_commands_pow_source(source);

	/* Priority */
	struct cmd_node *priority = commands_new(
		configure_medpower,
		"priority", "MED power priority",
		cmd_check_type_but_no, NULL, "priority");
	register_commands_pow_priority(priority, lldpctl_k_med_power_priority);

	/* Value */
	commands_new(
		commands_new(configure_medpower,
		    "value", "MED power value",
		    cmd_check_type_but_no, NULL, "value"),
		NULL, "MED power value in milliwatts",
		NULL, cmd_store_env_value_and_pop2, "value");
}

static int
cmd_check_env_power(struct cmd_env *env, void *nothing)
{
	/* We need type and powerpair but if we have typeat, we also request
	 * source, priority, requested and allocated. */
	if (!cmdenv_get(env, "device-type")) return 0;
	if (!cmdenv_get(env, "powerpairs")) return 0;
	if (cmdenv_get(env, "typeat")) {
		return (!!cmdenv_get(env, "source") &&
		    !!cmdenv_get(env, "priority") &&
		    !!cmdenv_get(env, "requested") &&
		    !!cmdenv_get(env, "allocated"));
	}
	return 1;
}

/**
 * Register `configure med dot3` commands.
 */
static void
register_commands_dot3pow(struct cmd_node *configure_dot3, struct cmd_node *unconfigure_dot3)
{
	commands_new(
		commands_new(unconfigure_dot3,
		    "power", "Dot3 power configuration",
		    NULL, NULL, NULL),
		NEWLINE, "Disable advertising of Dot3 POE-MDI TLV",
		NULL, cmd_no_dot3power, NULL);

	struct cmd_node *configure_dot3power = commands_new(
		configure_dot3,
		"power", "Dot3 power configuration",
		NULL, NULL, NULL);

	commands_new(
		configure_dot3power,
		NEWLINE, "Apply new Dot3 power configuration",
		cmd_check_env_power, cmd_dot3power, NULL);

	/* Type: PSE or PD */
	commands_new(
		configure_dot3power,
		"pd", "Dot3 power consumer",
		cmd_check_no_env, cmd_store_env_value_and_pop, "device-type");
	commands_new(
		configure_dot3power,
		"pse", "Dot3 power provider",
		cmd_check_no_env, cmd_store_env_value_and_pop, "device-type");

	/* Flags */
	commands_new(
		configure_dot3power,
		"supported", "MDI power support present",
		cmd_check_type_but_no, cmd_store_env_and_pop, "supported");
	commands_new(
		configure_dot3power,
		"enabled", "MDI power support enabled",
		cmd_check_type_but_no, cmd_store_env_and_pop, "enabled");
	commands_new(
		configure_dot3power,
		"paircontrol", "MDI power pair can be selected",
		cmd_check_type_but_no, cmd_store_env_and_pop, "paircontrol");

	/* Power pairs */
	struct cmd_node *powerpairs = commands_new(
		configure_dot3power,
		"powerpairs", "Which pairs are currently used for power (mandatory)",
		cmd_check_type_but_no, NULL, "powerpairs");
	for (lldpctl_map_t *pp_map =
		 lldpctl_key_get_map(lldpctl_k_dot3_power_pairs);
	     pp_map->string;
	     pp_map++) {
		commands_new(
			powerpairs,
			pp_map->string,
			pp_map->string,
			NULL, cmd_store_powerpairs_env_value_and_pop2, pp_map->string);
	}

	/* Class */
	struct cmd_node *class = commands_new(
		configure_dot3power,
		"class", "Power class",
		cmd_check_type_but_no, NULL, "class");
	for (lldpctl_map_t *class_map =
		 lldpctl_key_get_map(lldpctl_k_dot3_power_class);
	     class_map->string;
	     class_map++) {
		const char *tag = strdup(totag(class_map->string));
		commands_new(
			class,
			tag,
			class_map->string,
			NULL, cmd_store_class_env_value_and_pop2, class_map->string);
	}

	/* 802.3at type */
	struct cmd_node *typeat = commands_new(
		configure_dot3power,
		"type", "802.3at device type",
		cmd_check_type_but_no, NULL, "typeat");
	commands_new(typeat,
	    "1", "802.3at type 1",
	    NULL, cmd_store_env_value_and_pop2, "typeat");
	commands_new(typeat,
	    "2", "802.3at type 2",
	    NULL, cmd_store_env_value_and_pop2, "typeat");

	/* Source */
	struct cmd_node *source = commands_new(
		configure_dot3power,
		"source", "802.3at dot3 power source (mandatory)",
		cmd_check_typeat_but_no, NULL, "source");
	register_commands_pow_source(source);

	/* Priority */
	struct cmd_node *priority = commands_new(
		configure_dot3power,
		"priority", "802.3at dot3 power priority (mandatory)",
		cmd_check_typeat_but_no, NULL, "priority");
	register_commands_pow_priority(priority, lldpctl_k_dot3_power_priority);

	/* Values */
	commands_new(
		commands_new(configure_dot3power,
		    "requested", "802.3at dot3 power value requested (mandatory)",
		    cmd_check_typeat_but_no, NULL, "requested"),
		NULL, "802.3at power value requested in milliwatts",
		NULL, cmd_store_env_value_and_pop2, "requested");
	commands_new(
		commands_new(configure_dot3power,
		    "allocated", "802.3at dot3 power value allocated (mandatory)",
		    cmd_check_typeat_but_no, NULL, "allocated"),
		NULL, "802.3at power value allocated in milliwatts",
		NULL, cmd_store_env_value_and_pop2, "allocated");
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
		"Unset configuration option",
		NULL, NULL, NULL);
	restrict_ports(configure);
	restrict_ports(unconfigure);

	struct cmd_node *configure_med = commands_new(
		configure,
		"med", "MED configuration",
		NULL, NULL, NULL);
	struct cmd_node *unconfigure_med = commands_new(
		unconfigure,
		"med", "MED configuration",
		NULL, NULL, NULL);

	register_commands_medloc(configure_med, unconfigure_med);
	register_commands_medpol(configure_med, unconfigure_med);
	register_commands_medpow(configure_med, unconfigure_med);

	struct cmd_node *configure_dot3 = commands_new(
		configure,
		"dot3", "Dot3 configuration",
		NULL, NULL, NULL);
	struct cmd_node *unconfigure_dot3 = commands_new(
		unconfigure,
		"dot3", "Dot3 configuration",
		NULL, NULL, NULL);

	register_commands_dot3pow(configure_dot3, unconfigure_dot3);
}
