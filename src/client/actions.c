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

/* Helpers to parse a ':'-separated string. */
static char*
get_next(lldpctl_atom_t *atom, char *string,
    const char *what, int mandatory)
{
	static char *e2 = NULL;
	static char *e1 = NULL;
	static char *saved_string = NULL;
	static int pos;
	if (e2 != NULL) {
		*e2 = ':';
		e1 = e2 + 1;
	} else if (e1 != NULL) e1 = "";
	if (e1 == NULL || (saved_string != string)) {
		e1 = saved_string = string;
		pos = 1;
		e2 = NULL;
	}


	if (*e1 == '\0') {
		if (mandatory)
			LLOG_WARNX("unable to find %s in `%s' at pos %d",
			    what, string, pos);
		return NULL;
	}
	e2 = strchr(e1, ':');
	if (e2 != NULL) *e2 = '\0';
	pos++;
	return e1;
}

static int
get_next_and_set(lldpctl_atom_t *atom, char *string,
    const char *what, lldpctl_key_t key, int mandatory)
{
	char *e1 = get_next(atom, string, what, mandatory);
	if (e1 == NULL) return -1;
	if (lldpctl_atom_set_str(atom, key, e1) == NULL) {
		LLOG_WARNX("unable to set %s. %s.", what,
			lldpctl_last_strerror(lldpctl_atom_get_connection(atom)));
		return 0;
	}
	return 1;
}

/**
 * Parse dot3 power string.
 *
 * @param value String describing the new value.
 * @param power Atom to use to insert new values.
 * @return 1 on success, 0 otherwise.
 */
static int
parse_dot3_power(char *value, lldpctl_atom_t *power)
{
	int rc = 0;

	if (get_next_and_set(power, value, "device type", lldpctl_k_dot3_power_devicetype, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power support", lldpctl_k_dot3_power_supported, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power enableness", lldpctl_k_dot3_power_enabled, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "pair control ability", lldpctl_k_dot3_power_paircontrol, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power pairs", lldpctl_k_dot3_power_pairs, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "class", lldpctl_k_dot3_power_class, 1) != 1)
		return 0;
	rc = get_next_and_set(power, value, "power type", lldpctl_k_dot3_power_type, 0);
	if (rc == 0) return 0;
	if (rc == -1) return 1;

	if (get_next_and_set(power, value, "power source", lldpctl_k_dot3_power_source, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power priority", lldpctl_k_dot3_power_priority, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power requested", lldpctl_k_dot3_power_requested, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power allocated", lldpctl_k_dot3_power_allocated, 1) != 1)
		return 0;

	return 1;
}

/**
 * Parse LLDP-MED power string.
 *
 * @param value String describing the new value.
 * @param power Atom to use to insert new values.
 * @return 1 on success, 0 otherwise.
 */
static int
parse_med_power(char *value, lldpctl_atom_t *power)
{
	if (get_next_and_set(power, value, "device type", lldpctl_k_med_power_type, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power source", lldpctl_k_med_power_source, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power priority", lldpctl_k_med_power_priority, 1) != 1)
		return 0;
	if (get_next_and_set(power, value, "power value", lldpctl_k_med_power_val, 1) != 1)
		return 0;

	return 1;
}

/**
 * Parse LLDP-MED policy string.
 *
 * @param value String describing the new value.
 * @param power Atom to use to insert new values.
 * @return 1 on success, 0 otherwise.
 */
static int
parse_med_policy(char *value, lldpctl_atom_t *policy)
{
	if (get_next_and_set(policy, value, "application type", lldpctl_k_med_policy_type, 1) != 1)
		return 0;
	if (get_next_and_set(policy, value, "unknown flag", lldpctl_k_med_policy_unknown, 1) != 1)
		return 0;
	if (get_next_and_set(policy, value, "tagged flag", lldpctl_k_med_policy_tagged, 1) != 1)
		return 0;
	if (get_next_and_set(policy, value, "VLAN ID", lldpctl_k_med_policy_vid, 1) != 1)
		return 0;
	if (get_next_and_set(policy, value, "Layer 2 priority", lldpctl_k_med_policy_priority, 1) != 1)
		return 0;
	if (get_next_and_set(policy, value, "DSCP", lldpctl_k_med_policy_dscp, 1) != 1)
		return 0;

	return 1;
}

/**
 * Parse LLDP-MED location string.
 *
 * @param value String describing the new value.
 * @param power Atom to use to insert new values.
 * @return 1 on success, 0 otherwise.
 */
static int
parse_med_location(char *value, lldpctl_atom_t *location)
{
	int format, stop = 0;
	lldpctl_atom_t *cael, *caels;
	char *type;

	if (get_next_and_set(location, value, "location format", lldpctl_k_med_location_format, 1) != 1)
		return 0;
	format = lldpctl_atom_get_int(location, lldpctl_k_med_location_format);
	switch (format) {
	case LLDP_MED_LOCFORMAT_COORD:
		if (get_next_and_set(location, value, "latitude", lldpctl_k_med_location_latitude, 1) != 1)
			return 0;
		if (get_next_and_set(location, value, "longitude", lldpctl_k_med_location_longitude, 1) != 1)
			return 0;
		if (get_next_and_set(location, value, "altitude", lldpctl_k_med_location_altitude, 1) != 1)
			return 0;
		if (get_next_and_set(location, value, "altitude unit", lldpctl_k_med_location_altitude_unit, 1) != 1)
			return 0;
		if (get_next_and_set(location, value, "datum", lldpctl_k_med_location_geoid, 1) != 1)
			return 0;
		return 1;
	case LLDP_MED_LOCFORMAT_CIVIC:
		if (get_next_and_set(location, value, "country", lldpctl_k_med_location_country, 1) != 1)
			return 0;
		while ((type = get_next(location, value, "civic address type", 0)) != NULL &&
		    !stop) {
			/* Next we have the element addresses */
			caels = lldpctl_atom_get(location, lldpctl_k_med_location_ca_elements);
			cael = lldpctl_atom_create(caels);

			if (lldpctl_atom_set_str(cael, lldpctl_k_med_civicaddress_type, type) != NULL) {
				if (get_next_and_set(cael, value, "civic address value",
					lldpctl_k_med_civicaddress_value, 1) == 1) {
					if (lldpctl_atom_set(location, lldpctl_k_med_location_ca_elements,
						cael) == NULL) {
						LLOG_WARNX("unable to add a civic address element. %s",
						    lldpctl_last_strerror(lldpctl_atom_get_connection(location)));
						stop = 1;
					}
				} else stop = 1;
			} else {
				LLOG_WARNX("unable to set civic address type. %s.",
				    lldpctl_last_strerror(lldpctl_atom_get_connection(cael)));
				stop = 1;
			}

			lldpctl_atom_dec_ref(cael);
			lldpctl_atom_dec_ref(caels);
		}
		if (stop) return 0;
		return 1;
	case LLDP_MED_LOCFORMAT_ELIN:
		if (get_next_and_set(location, value, "ELIN number", lldpctl_k_med_location_elin, 1) != 1)
			return 0;
		return 1;
	default:
		LLOG_WARNX("unable to determine the requested location format");
		return 0;
	}

	return 1;
}

/**
 * Modify the interfaces specified on the command line.
 *
 * @param conn    Connection to lldpd.
 * @param argc    Number of arguments.
 * @param argv    Array of arguments.
 * @param ifindex Index of the first non optional argument
 */
void
modify_interfaces(lldpctl_conn_t *conn,
    int argc, char **argv, int ifindex)
{
	int i, ch;
	const char *iface_name;
	lldpctl_atom_t *ifaces, *iface;
	lldpctl_atom_t *port;

	ifaces = lldpctl_get_interfaces(conn);
	if (!ifaces) {
		LLOG_WARNX("not able to get the list of interfaces: %s", lldpctl_strerror(lldpctl_last_error(conn)));
		return;
	}

	lldpctl_atom_foreach(ifaces, iface) {
		/* Only process specified interfaces or all interfaces if none
		 * is specified. */
		iface_name = lldpctl_atom_get_str(iface,
		    lldpctl_k_interface_name);
		if (ifindex < argc) {
			for (i = ifindex; i < argc; i++)
				if (strcmp(argv[i],
					iface_name) == 0)
					break;
			if (i == argc)
				continue;
		}

		port      = lldpctl_get_port(iface);

		optind = 1;
		while ((ch = getopt(argc, argv, LLDPCTL_ARGS)) != -1) {
			lldpctl_atom_t *dot3_power;
			lldpctl_atom_t *med_power;
			lldpctl_atom_t *med_policy, *med_policies;
			lldpctl_atom_t *med_location, *med_locations;

			switch (ch) {
			case 'o':
				/* Dot3 power */
				dot3_power = lldpctl_atom_get(port, lldpctl_k_port_dot3_power);
				if (dot3_power == NULL) {
					LLOG_WARNX("unable to set Dot3 power: support seems unavailable");
					break;
				}
				if (parse_dot3_power(optarg, dot3_power)) {
					if (lldpctl_atom_set(port, lldpctl_k_port_dot3_power,
						dot3_power) == NULL)
						LLOG_WARNX("unable to set Dot3 power. %s",
						    lldpctl_strerror(lldpctl_last_error(conn)));
					else
						LLOG_INFO("Dot3 power has been set for port %s",
						    iface_name);
				}
				lldpctl_atom_dec_ref(dot3_power);
				break;
			case 'O':
				/* LLDP-MED power */
				med_power = lldpctl_atom_get(port, lldpctl_k_port_med_power);
				if (med_power == NULL) {
					LLOG_WARNX("unable to set LLDP-MED power: support seems unavailable");
					break;
				}
				if (parse_med_power(optarg, med_power)) {
					if (lldpctl_atom_set(port, lldpctl_k_port_med_power,
						med_power) == NULL)
						LLOG_WARNX("unable to set LLDP-MED power. %s",
						    lldpctl_strerror(lldpctl_last_error(conn)));
					else
						LLOG_INFO("LLDP-MED power has been set for port %s",
						    iface_name);
				}
				lldpctl_atom_dec_ref(med_power);
				break;
			case 'P':
				/* LLDP-MED network policy */
				med_policies = lldpctl_atom_get(port, lldpctl_k_port_med_policies);
				if (med_policies == NULL) {
					LLOG_WARNX("unable to set LLDP-MED policy: support seems unavailable");
					break;
				}
				/* We select the first policy. Since we will
				 * modify the application type, it is not
				 * necessary to select the one with the
				 * appropriate index. */
				med_policy = lldpctl_atom_iter_value(med_policies,
					lldpctl_atom_iter_next(med_policies,
					    lldpctl_atom_iter(med_policies)));
				if (parse_med_policy(optarg, med_policy)) {
					if (lldpctl_atom_set(port, lldpctl_k_port_med_policies,
						med_policy) == NULL)
						LLOG_WARNX("unable to set LLDP-MED policy. %s",
						    lldpctl_strerror(lldpctl_last_error(conn)));
					else
						LLOG_INFO("LLDP-MED policy has been set for port %s",
						    iface_name);
				}
				lldpctl_atom_dec_ref(med_policy);
				lldpctl_atom_dec_ref(med_policies);
				break;
			case 'L':
				/* LLDP-MED location */
				med_locations = lldpctl_atom_get(port, lldpctl_k_port_med_locations);
				if (med_locations == NULL) {
					LLOG_WARNX("unable to set LLDP-MED location: support seems unavailable");
					break;
				}
				/* As for policy, we pick the first and it will
				 * be reset when setting the format. No need to
				 * pick the one with the appropriate index. */
				med_location = lldpctl_atom_iter_value(med_locations,
				    lldpctl_atom_iter_next(med_locations,
					lldpctl_atom_iter(med_locations)));
				if (parse_med_location(optarg, med_location)) {
					if (lldpctl_atom_set(port, lldpctl_k_port_med_locations,
						med_location) == NULL)
						LLOG_WARNX("unable to set LLDP-MED location. %s",
							lldpctl_strerror(lldpctl_last_error(conn)));
					else
						LLOG_INFO("LLDP-MED location has been set for port %s",
						    iface_name);
				}
				lldpctl_atom_dec_ref(med_location);
				lldpctl_atom_dec_ref(med_locations);
				break;
			default:
				/* We shouldn't be here... */
				break;
			}
		}

		lldpctl_atom_dec_ref(port);
	}

	lldpctl_atom_dec_ref(ifaces);
}
