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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>

#include "lldpctl.h"
#include "../lldpd-structs.h"
#include "../log.h"
#include "private.h"

#define ntohll(x)						\
	(((u_int64_t)(ntohl((int)(((x) << 32) >> 32))) << 32) |	\
	    (unsigned int)ntohl(((int)((x) >> 32))))

/* Translation from constants to string */

struct value_string {
	int value;
	char *string;
};

static const struct value_string lldpd_protocol_map[] = {
	{ LLDPD_MODE_LLDP,	"LLDP" },
	{ LLDPD_MODE_CDPV1,	"CDPv1"},
	{ LLDPD_MODE_CDPV2,	"CDPv2"},
	{ LLDPD_MODE_EDP,	"EDP" },
	{ LLDPD_MODE_FDP,	"FDP"},
	{ LLDPD_MODE_SONMP,	"SONMP"},
        { 0, NULL }
};

static const struct value_string chassis_id_subtype_map[] = {
	{ LLDP_CHASSISID_SUBTYPE_IFNAME,  "ifname"},
	{ LLDP_CHASSISID_SUBTYPE_IFALIAS, "ifalias" },
	{ LLDP_CHASSISID_SUBTYPE_LOCAL,   "local" },
	{ LLDP_CHASSISID_SUBTYPE_LLADDR,  "mac" },
	{ LLDP_CHASSISID_SUBTYPE_ADDR,    "ip" },
	{ LLDP_CHASSISID_SUBTYPE_PORT,    "unhandled" },
	{ LLDP_CHASSISID_SUBTYPE_CHASSIS, "unhandled" },
	{ 0, NULL},
};

static const struct value_string port_id_subtype_map[] = {
	{ LLDP_PORTID_SUBTYPE_IFNAME,   "ifname"},
	{ LLDP_PORTID_SUBTYPE_IFALIAS,  "ifalias" },
	{ LLDP_PORTID_SUBTYPE_LOCAL,    "local" },
	{ LLDP_PORTID_SUBTYPE_LLADDR,   "mac" },
	{ LLDP_PORTID_SUBTYPE_ADDR,     "ip" },
	{ LLDP_PORTID_SUBTYPE_PORT,     "unhandled" },
	{ LLDP_PORTID_SUBTYPE_AGENTCID, "unhandled" },
	{ 0, NULL},
};

#ifdef ENABLE_DOT3
static const struct value_string operational_mau_type_values[] = {
	{ 1,	"AUI - no internal MAU, view from AUI" },
	{ 2,	"10Base5 - thick coax MAU" },
	{ 3,	"Foirl - FOIRL MAU" },
	{ 4,	"10Base2 - thin coax MAU" },
	{ 5,	"10BaseT - UTP MAU" },
	{ 6,	"10BaseFP - passive fiber MAU" },
	{ 7,	"10BaseFB - sync fiber MAU" },
	{ 8,	"10BaseFL - async fiber MAU" },
	{ 9,	"10Broad36 - broadband DTE MAU" },
	{ 10,	"10BaseTHD - UTP MAU, half duplex mode" },
	{ 11,	"10BaseTFD - UTP MAU, full duplex mode" },
	{ 12,	"10BaseFLHD - async fiber MAU, half duplex mode" },
	{ 13,	"10BaseFLDF - async fiber MAU, full duplex mode" },
	{ 14,	"10BaseT4 - 4 pair category 3 UTP" },
	{ 15,	"100BaseTXHD - 2 pair category 5 UTP, half duplex mode" },
	{ 16,	"100BaseTXFD - 2 pair category 5 UTP, full duplex mode" },
	{ 17,	"100BaseFXHD - X fiber over PMT, half duplex mode" },
	{ 18,	"100BaseFXFD - X fiber over PMT, full duplex mode" },
	{ 19,	"100BaseT2HD - 2 pair category 3 UTP, half duplex mode" },
	{ 20,	"100BaseT2DF - 2 pair category 3 UTP, full duplex mode" },
	{ 21,	"1000BaseXHD - PCS/PMA, unknown PMD, half duplex mode" },
	{ 22,	"1000BaseXFD - PCS/PMA, unknown PMD, full duplex mode" },
	{ 23,	"1000BaseLXHD - Fiber over long-wavelength laser, half duplex mode" },
	{ 24,	"1000BaseLXFD - Fiber over long-wavelength laser, full duplex mode" },
	{ 25,	"1000BaseSXHD - Fiber over short-wavelength laser, half duplex mode" },
	{ 26,	"1000BaseSXFD - Fiber over short-wavelength laser, full duplex mode" },
	{ 27,	"1000BaseCXHD - Copper over 150-Ohm balanced cable, half duplex mode" },
	{ 28,	"1000BaseCXFD - Copper over 150-Ohm balanced cable, full duplex mode" },
	{ 29,	"1000BaseTHD - Four-pair Category 5 UTP, half duplex mode" },
	{ 30,	"1000BaseTFD - Four-pair Category 5 UTP, full duplex mode" },
	{ 31,	"10GigBaseX - X PCS/PMA, unknown PMD." },
	{ 32,	"10GigBaseLX4 - X fiber over WWDM optics" },
	{ 33,	"10GigBaseR - R PCS/PMA, unknown PMD." },
	{ 34,	"10GigBaseER - R fiber over 1550 nm optics" },
	{ 35,	"10GigBaseLR - R fiber over 1310 nm optics" },
	{ 36,	"10GigBaseSR - R fiber over 850 nm optics" },
	{ 37,	"10GigBaseW - W PCS/PMA, unknown PMD." },
	{ 38,	"10GigBaseEW - W fiber over 1550 nm optics" },
	{ 39,	"10GigBaseLW - W fiber over 1310 nm optics" },
	{ 40,	"10GigBaseSW - W fiber over 850 nm optics" },
	{ 41,	"10GigBaseCX4 - X copper over 8 pair 100-Ohm balanced cable" },
	{ 42,	"2BaseTL - Voice grade UTP copper, up to 2700m, optional PAF" },
	{ 43,	"10PassTS - Voice grade UTP copper, up to 750m, optional PAF" },
	{ 44,	"100BaseBX10D - One single-mode fiber OLT, long wavelength, 10km" },
	{ 45,	"100BaseBX10U - One single-mode fiber ONU, long wavelength, 10km" },
	{ 46,	"100BaseLX10 - Two single-mode fibers, long wavelength, 10km" },
	{ 47,	"1000BaseBX10D - One single-mode fiber OLT, long wavelength, 10km" },
	{ 48,	"1000BaseBX10U - One single-mode fiber ONU, long wavelength, 10km" },
	{ 49,	"1000BaseLX10 - Two sigle-mode fiber, long wavelength, 10km" },
	{ 50,	"1000BasePX10D - One single-mode fiber EPON OLT, 10km" },
	{ 51,	"1000BasePX10U - One single-mode fiber EPON ONU, 10km" },
	{ 52,	"1000BasePX20D - One single-mode fiber EPON OLT, 20km" },
	{ 53,	"1000BasePX20U - One single-mode fiber EPON ONU, 20km" },
	{ 0, NULL }
};

static const struct value_string port_dot3_power_devicetype_map[] = {
	{ LLDP_DOT3_POWER_PSE, "PSE" },
	{ LLDP_DOT3_POWER_PD,  "PD" },
	{ 0, NULL }
};

static const struct value_string port_dot3_power_pairs_map[] = {
	{ LLDP_DOT3_POWERPAIRS_SIGNAL, "signal" },
	{ LLDP_DOT3_POWERPAIRS_SPARE,  "spare" },
	{ 0, NULL }
};

static const struct value_string port_dot3_power_class_map[] = {
	{ 1, "class 0" },
	{ 2, "class 1" },
	{ 3, "class 2" },
	{ 4, "class 3" },
	{ 5, "class 4" },
	{ 0, NULL }
};

static const struct value_string port_dot3_power_pse_source_map[] = {
	{ LLDP_DOT3_POWER_SOURCE_BOTH, "PSE + Local" },
	{ LLDP_DOT3_POWER_SOURCE_PSE, "PSE" },
	{ 0, NULL }
};

static const struct value_string port_dot3_power_pd_source_map[] = {
	{ LLDP_DOT3_POWER_SOURCE_BACKUP, "Backup source" },
	{ LLDP_DOT3_POWER_SOURCE_PRIMARY, "Primary power source" },
	{ 0, NULL }
};

static const struct value_string port_dot3_power_priority_map[] = {
	{ 0,                          "unknown" },
	{ LLDP_MED_POW_PRIO_CRITICAL, "critical" },
	{ LLDP_MED_POW_PRIO_HIGH,     "high" },
	{ LLDP_MED_POW_PRIO_LOW,      "low" },
	{ 0, NULL },
};
#endif

#ifdef ENABLE_LLDPMED
static const struct value_string chassis_med_type_map[] = {
	{ LLDP_MED_CLASS_I,        "Generic Endpoint (Class I)" },
	{ LLDP_MED_CLASS_II,       "Media Endpoint (Class II)" },
	{ LLDP_MED_CLASS_III,      "Communication Device Endpoint (Class III)" },
	{ LLDP_MED_NETWORK_DEVICE, "Network Connectivity Device" },
	{ 0, NULL },
};

static const struct value_string port_med_policy_map[] = {
	{ LLDP_MED_APPTYPE_VOICE ,           "Voice"},
	{ LLDP_MED_APPTYPE_VOICESIGNAL,      "Voice Signaling"},
	{ LLDP_MED_APPTYPE_GUESTVOICE,       "Guest Voice"},
	{ LLDP_MED_APPTYPE_GUESTVOICESIGNAL, "Guest Voice Signaling"},
	{ LLDP_MED_APPTYPE_SOFTPHONEVOICE,   "Softphone Voice"},
	{ LLDP_MED_APPTYPE_VIDEOCONFERENCE,  "Video Conferencing"},
	{ LLDP_MED_APPTYPE_VIDEOSTREAM,      "Streaming Video"},
	{ LLDP_MED_APPTYPE_VIDEOSIGNAL,      "Video Signaling"},
	{ 0, NULL },
};

static const struct value_string port_med_location_map[] = {
	{ LLDP_MED_LOCFORMAT_COORD, "Coordinates" },
	{ LLDP_MED_LOCFORMAT_CIVIC, "Civic address" },
	{ LLDP_MED_LOCFORMAT_ELIN, "ELIN" },
	{ 0, NULL },
};

static const struct value_string civic_address_type_map[] = {
        { 0,    "Language" },
        { 1,    "Country subdivision" },
        { 2,    "County" },
        { 3,    "City" },
        { 4,    "City division" },
        { 5,    "Block" },
        { 6,    "Street" },
        { 16,   "Direction" },
        { 17,   "Trailing street suffix" },
        { 18,   "Street suffix" },
        { 19,   "Number" },
        { 20,   "Number suffix" },
        { 21,   "Landmark" },
        { 22,   "Additional" },
        { 23,   "Name" },
        { 24,   "ZIP" },
        { 25,   "Building" },
        { 26,   "Unit" },
        { 27,   "Floor" },
        { 28,   "Room" },
        { 29,   "Place type" },
        { 128,  "Script" },
        { 0, NULL }
};

static const struct value_string port_med_geoid_map[] = {
	{ LLDP_MED_LOCATION_GEOID_WGS84, "WGS84" },
	{ LLDP_MED_LOCATION_GEOID_NAD83, "NAD83" },
	{ LLDP_MED_LOCATION_GEOID_NAD83_MLLW, "NAD83/MLLW" },
	{ 0, NULL },
};

static const struct value_string port_med_pow_devicetype_map[] = {
	{ LLDP_MED_POW_TYPE_PSE, "PSE" },
	{ LLDP_MED_POW_TYPE_PD,  "PD" },
	{ 0, NULL },
};

static const struct value_string port_med_pow_source_map[] = {
	{ LLDP_MED_POW_SOURCE_PRIMARY, "Primary Power Source" },
	{ LLDP_MED_POW_SOURCE_BACKUP,  "Backup Power Source / Power Conservation Mode" },
	{ LLDP_MED_POW_SOURCE_PSE,     "PSE" },
	{ LLDP_MED_POW_SOURCE_LOCAL,   "Local"},
	{ LLDP_MED_POW_SOURCE_BOTH,    "PSE + Local"},
	{ 0, NULL },
};

static const struct value_string port_med_pow_source_map2[] = {
	{ 0,                           "unknown" },
	{ LLDP_MED_POW_SOURCE_PRIMARY, "primary" },
	{ LLDP_MED_POW_SOURCE_BACKUP,  "backup" },
	{ LLDP_MED_POW_SOURCE_PSE,     "pse" },
	{ LLDP_MED_POW_SOURCE_LOCAL,   "local" },
	{ LLDP_MED_POW_SOURCE_BOTH,    "both" },
	{ 0, NULL }
};

static const struct value_string port_med_pow_priority_map[] = {
	{ 0,                          "unknown" },
	{ LLDP_MED_POW_PRIO_CRITICAL, "critical" },
	{ LLDP_MED_POW_PRIO_HIGH,     "high" },
	{ LLDP_MED_POW_PRIO_LOW,      "low" },
	{ 0, NULL },
};
#endif

static const char*
map_lookup(const struct value_string *list, int n)
{

	unsigned int i;

	for (i = 0; list[i].string != NULL; i++) {
		if (list[i].value == n) {
			return list[i].string;
		}
	}

	return "unknown";
}

#if defined ENABLE_LLDPMED || defined ENABLE_DOT3
static int
map_reverse_lookup(const struct value_string *list, const char *string)
{
	unsigned int i;

	for (i = 0; list[i].string != NULL; i++) {
		if (!strcasecmp(list[i].string, string))
			return list[i].value;
	}

	return -1;
}
#endif

/* Atom methods */

static int
_lldpctl_atom_new_interfaces_list(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_interfaces_list_t *iflist =
	    (struct _lldpctl_atom_interfaces_list_t *)atom;
	iflist->ifs = va_arg(ap, struct lldpd_interface_list *);
	return 1;
}

static void
_lldpctl_atom_free_interfaces_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_interfaces_list_t *iflist =
	    (struct _lldpctl_atom_interfaces_list_t *)atom;
	struct lldpd_interface *iface, *iface_next;
	for (iface = TAILQ_FIRST(iflist->ifs);
	     iface != NULL;
	     iface = iface_next) {
		/* Don't TAILQ_REMOVE, this is not a real list! */
		iface_next = TAILQ_NEXT(iface, next);
		free(iface->name);
		free(iface);
	}
	free(iflist->ifs);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_iter_interfaces_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_interfaces_list_t *iflist =
	    (struct _lldpctl_atom_interfaces_list_t *)atom;
	return (lldpctl_atom_iter_t*)TAILQ_FIRST(iflist->ifs);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_interfaces_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	return (lldpctl_atom_iter_t*)TAILQ_NEXT((struct lldpd_interface *)iter, next);
}

static lldpctl_atom_t*
_lldpctl_atom_value_interfaces_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_interface *iface = (struct lldpd_interface *)iter;
	return _lldpctl_new_atom(atom->conn, atom_interface, iface->name);
}

static int
_lldpctl_atom_new_interface(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_interface_t *port =
	    (struct _lldpctl_atom_interface_t *)atom;
	port->name = strdup(va_arg(ap, char *));
	return (port->name != NULL);
}

static void
_lldpctl_atom_free_interface(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_interface_t *port =
	    (struct _lldpctl_atom_interface_t *)atom;
	free(port->name);
}

static const char*
_lldpctl_atom_get_str_interface(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_interface_t *port =
	    (struct _lldpctl_atom_interface_t *)atom;
	switch (key) {
	case lldpctl_k_interface_name:
		return port->name;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static int
_lldpctl_atom_new_any_list(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_any_list_t *plist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	plist->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)plist->parent);
	return 1;
}

static void
_lldpctl_atom_free_any_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_any_list_t *plist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)plist->parent);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_iter_ports_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_any_list_t *plist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	return (lldpctl_atom_iter_t*)TAILQ_FIRST(&plist->parent->hardware->h_rports);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_ports_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_port *port = (struct lldpd_port *)iter;
	return (lldpctl_atom_iter_t*)TAILQ_NEXT(port, p_entries);
}

static lldpctl_atom_t*
_lldpctl_atom_value_ports_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_port *port = (struct lldpd_port *)iter;
	return _lldpctl_new_atom(atom->conn, atom_port, NULL, port,
	    ((struct _lldpctl_atom_any_list_t *)atom)->parent);
}

static int
_lldpctl_atom_new_port(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_port_t *port =
	    (struct _lldpctl_atom_port_t *)atom;
	port->hardware = va_arg(ap, struct lldpd_hardware*);
	port->port = va_arg(ap, struct lldpd_port*);
	port->parent = va_arg(ap, struct _lldpctl_atom_port_t*);
	if (port->parent)
		lldpctl_atom_inc_ref((lldpctl_atom_t*)port->parent);
	return 1;
}

TAILQ_HEAD(chassis_list, lldpd_chassis);

static void
add_chassis(struct chassis_list *chassis_list,
	struct lldpd_chassis *chassis)
{
	struct lldpd_chassis *one_chassis;
	TAILQ_FOREACH(one_chassis, chassis_list, c_entries) {
		if (one_chassis == chassis) return;
	}
	TAILQ_INSERT_TAIL(chassis_list,
	    chassis, c_entries);
}

static void
_lldpctl_atom_free_port(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_port_t *port =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_hardware *hardware = port->hardware;
	struct lldpd_chassis  *one_chassis, *one_chassis_next;
	struct lldpd_port     *one_port;

	/* We need to free the whole struct lldpd_hardware: local port, local
	 * chassis and remote ports... The same chassis may be present several
	 * times. We build a list of chassis (we don't use reference count). */
	struct chassis_list chassis_list;
	TAILQ_INIT(&chassis_list);

	if (port->parent) lldpctl_atom_dec_ref((lldpctl_atom_t*)port->parent);
	else if (!hardware) {
		/* No parent, no hardware, we assume a single neighbor: one
		 * port, one chassis. */
		lldpd_chassis_cleanup(port->port->p_chassis, 1);
		port->port->p_chassis = NULL;
		lldpd_port_cleanup(port->port, 1);
		free(port->port);
	}
	if (!hardware) return;

	add_chassis(&chassis_list, port->port->p_chassis);
	TAILQ_FOREACH(one_port, &hardware->h_rports, p_entries)
		add_chassis(&chassis_list, one_port->p_chassis);

	/* Free hardware port */
	lldpd_remote_cleanup(hardware, NULL);
	lldpd_port_cleanup(port->port, 1);
	free(port->hardware);

	/* Free list of chassis */
	for (one_chassis = TAILQ_FIRST(&chassis_list);
	     one_chassis != NULL;
	     one_chassis = one_chassis_next) {
		one_chassis_next = TAILQ_NEXT(one_chassis, c_entries);
		lldpd_chassis_cleanup(one_chassis, 1);
	}
}

static lldpctl_atom_t*
_lldpctl_atom_get_atom_port(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;
	struct lldpd_hardware *hardware = p->hardware;

	/* Local port only */
	if (hardware != NULL) {
		switch (key) {
		case lldpctl_k_port_neighbors:
			return _lldpctl_new_atom(atom->conn, atom_ports_list, p);
		default: break;
		}
	}

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_chassis_mgmt:
		return _lldpctl_new_atom(atom->conn, atom_mgmts_list,
		    p, port->p_chassis);
#ifdef ENABLE_DOT3
	case lldpctl_k_port_dot3_power:
		return _lldpctl_new_atom(atom->conn, atom_dot3_power,
		    p);
#endif
#ifdef ENABLE_DOT1
	case lldpctl_k_port_vlans:
		return _lldpctl_new_atom(atom->conn, atom_vlans_list,
		    p);
	case lldpctl_k_port_ppvids:
		return _lldpctl_new_atom(atom->conn, atom_ppvids_list,
		    p);
	case lldpctl_k_port_pis:
		return _lldpctl_new_atom(atom->conn, atom_pis_list,
		    p);
#endif
#ifdef ENABLE_LLDPMED
	case lldpctl_k_port_med_policies:
		return _lldpctl_new_atom(atom->conn, atom_med_policies_list,
		    p);
	case lldpctl_k_port_med_locations:
		return _lldpctl_new_atom(atom->conn, atom_med_locations_list,
		    p);
	case lldpctl_k_port_med_power:
		return _lldpctl_new_atom(atom->conn, atom_med_power, p);
#endif
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_atom_port(lldpctl_atom_t *atom, lldpctl_key_t key, lldpctl_atom_t *value)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_hardware *hardware = p->hardware;
	struct lldpd_port_set set;
	int rc;

#ifdef ENABLE_DOT3
	struct _lldpctl_atom_dot3_power_t *dpow;
#endif
#ifdef ENABLE_LLDPMED
	struct _lldpctl_atom_med_power_t *mpow;
	struct _lldpctl_atom_med_policy_t *mpol;
	struct _lldpctl_atom_med_location_t *mloc;
#endif

	/* Local port only */
	if (hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	memset(&set, 0, sizeof(struct lldpd_port_set));

	switch (key) {
#ifdef ENABLE_DOT3
	case lldpctl_k_port_dot3_power:
		if (value->type != atom_dot3_power) {
			SET_ERROR(atom->conn, LLDPCTL_ERR_INCORRECT_ATOM_TYPE);
			return NULL;
		}

		dpow = (struct _lldpctl_atom_dot3_power_t *)value;
		set.dot3_power = &dpow->parent->port->p_power;
		break;
#endif
#ifdef ENABLE_LLDPMED
	case lldpctl_k_port_med_power:
		if (value->type != atom_med_power) {
			SET_ERROR(atom->conn, LLDPCTL_ERR_INCORRECT_ATOM_TYPE);
			return NULL;
		}

		mpow = (struct _lldpctl_atom_med_power_t *)value;
		set.med_power = &mpow->parent->port->p_med_power;
		break;
	case lldpctl_k_port_med_policies:
		if (value->type != atom_med_policy) {
			SET_ERROR(atom->conn, LLDPCTL_ERR_INCORRECT_ATOM_TYPE);
			return NULL;
		}
		mpol = (struct _lldpctl_atom_med_policy_t *)value;
		set.med_policy = mpol->policy;
		break;
	case lldpctl_k_port_med_locations:
		if (value->type != atom_med_location) {
			SET_ERROR(atom->conn, LLDPCTL_ERR_INCORRECT_ATOM_TYPE);
			return NULL;
		}
		mloc = (struct _lldpctl_atom_med_location_t *)value;
		set.med_location = mloc->location;
		break;
#endif
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	set.ifname = hardware->h_ifname;
	rc = _lldpctl_do_something(atom->conn,
	    CONN_STATE_SET_PORT_SEND, CONN_STATE_SET_PORT_RECV,
	    value,
	    SET_PORT, &set, &MARSHAL_INFO(lldpd_port_set),
	    NULL, NULL);
	if (rc == 0) return atom;
	return NULL;
}

static const char*
_lldpctl_atom_get_str_port(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;
	struct lldpd_hardware *hardware = p->hardware;
	struct lldpd_chassis  *chassis  = port->p_chassis;
	char *ipaddress = NULL; size_t len;

	/* Local port only */
	if (hardware != NULL) {
		switch (key) {
		case lldpctl_k_port_name:
			return hardware->h_ifname;
		default: break;
		}
	}

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_port_protocol:
		return map_lookup(lldpd_protocol_map, port->p_protocol);
	case lldpctl_k_port_id_subtype:
		return map_lookup(port_id_subtype_map, port->p_id_subtype);
	case lldpctl_k_port_id:
		switch (port->p_id_subtype) {
		case LLDP_PORTID_SUBTYPE_IFNAME:
		case LLDP_PORTID_SUBTYPE_IFALIAS:
		case LLDP_PORTID_SUBTYPE_LOCAL:
			return port->p_id;
		case LLDP_PORTID_SUBTYPE_LLADDR:
			return _lldpctl_dump_in_atom(atom,
			    (uint8_t*)port->p_id, port->p_id_len,
			    ':', 0);
		case LLDP_PORTID_SUBTYPE_ADDR:
			switch (port->p_id[0]) {
			case LLDP_MGMT_ADDR_IP4: len = INET_ADDRSTRLEN + 1; break;
			case LLDP_MGMT_ADDR_IP6: len = INET6_ADDRSTRLEN + 1; break;
			default: len = 0;
			}
			if (len > 0) {
				ipaddress = _lldpctl_alloc_in_atom(atom, len);
				if (!ipaddress) return NULL;
				if (inet_ntop((port->p_id[0] == LLDP_MGMT_ADDR_IP4)?
					AF_INET:AF_INET6,
					&port->p_id[1], ipaddress, len) == NULL)
					break;
				return ipaddress;
			}
			break;
		}
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	case lldpctl_k_port_descr:
		return port->p_descr;

#ifdef ENABLE_DOT3
	case lldpctl_k_port_dot3_mautype:
		return map_lookup(operational_mau_type_values,
		    port->p_macphy.mau_type);
#endif

	case lldpctl_k_chassis_id_subtype:
		return map_lookup(chassis_id_subtype_map, chassis->c_id_subtype);
	case lldpctl_k_chassis_id:
		switch (chassis->c_id_subtype) {
		case LLDP_CHASSISID_SUBTYPE_IFNAME:
		case LLDP_CHASSISID_SUBTYPE_IFALIAS:
		case LLDP_CHASSISID_SUBTYPE_LOCAL:
			return chassis->c_id;
		case LLDP_CHASSISID_SUBTYPE_LLADDR:
			return _lldpctl_dump_in_atom(atom,
			    (uint8_t*)chassis->c_id, chassis->c_id_len,
			    ':', 0);
		case LLDP_CHASSISID_SUBTYPE_ADDR:
			switch (chassis->c_id[0]) {
			case LLDP_MGMT_ADDR_IP4: len = INET_ADDRSTRLEN + 1; break;
			case LLDP_MGMT_ADDR_IP6: len = INET6_ADDRSTRLEN + 1; break;
			default: len = 0;
			}
			if (len > 0) {
				ipaddress = _lldpctl_alloc_in_atom(atom, len);
				if (!ipaddress) return NULL;
				if (inet_ntop((chassis->c_id[0] == LLDP_MGMT_ADDR_IP4)?
					AF_INET:AF_INET6,
					&chassis->c_id[1], ipaddress, len) == NULL)
					break;
				return ipaddress;
			}
			break;
		}
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	case lldpctl_k_chassis_name: return chassis->c_name;
	case lldpctl_k_chassis_descr: return chassis->c_descr;

#ifdef ENABLE_LLDPMED
	case lldpctl_k_chassis_med_type:
		return map_lookup(chassis_med_type_map, chassis->c_med_type);
	case lldpctl_k_chassis_med_inventory_hw:
		return chassis->c_med_hw;
	case lldpctl_k_chassis_med_inventory_sw:
		return chassis->c_med_sw;
	case lldpctl_k_chassis_med_inventory_fw:
		return chassis->c_med_fw;
	case lldpctl_k_chassis_med_inventory_sn:
		return chassis->c_med_sn;
	case lldpctl_k_chassis_med_inventory_manuf:
		return chassis->c_med_manuf;
	case lldpctl_k_chassis_med_inventory_model:
		return chassis->c_med_model;
	case lldpctl_k_chassis_med_inventory_asset:
		return chassis->c_med_asset;
#endif

	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static long int
_lldpctl_atom_get_int_port(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;
	struct lldpd_hardware *hardware = p->hardware;
	struct lldpd_chassis  *chassis  = port->p_chassis;

	/* Local port only */
	if (hardware != NULL) {
		switch (key) {
		case lldpctl_k_port_index:
			return hardware->h_ifindex;
		default: break;
		}
	}

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_port_protocol:
		return port->p_protocol;
	case lldpctl_k_port_age:
		return port->p_lastchange;
	case lldpctl_k_port_id_subtype:
		return port->p_id_subtype;
	case lldpctl_k_port_hidden:
		return port->p_hidden_in;
#ifdef ENABLE_DOT3
	case lldpctl_k_port_dot3_mfs:
		if (port->p_mfs > 0)
			return port->p_mfs;
		break;
	case lldpctl_k_port_dot3_aggregid:
		if (port->p_aggregid > 0)
			return port->p_aggregid;
		break;
	case lldpctl_k_port_dot3_autoneg_support:
		return port->p_macphy.autoneg_support;
	case lldpctl_k_port_dot3_autoneg_enabled:
		return port->p_macphy.autoneg_enabled;
	case lldpctl_k_port_dot3_autoneg_advertised:
		return port->p_macphy.autoneg_advertised;
	case lldpctl_k_port_dot3_mautype:
		return port->p_macphy.mau_type;
#endif
#ifdef ENABLE_DOT1
	case lldpctl_k_port_vlan_pvid:
		return port->p_pvid;
#endif
	case lldpctl_k_chassis_index:
		return chassis->c_index;
	case lldpctl_k_chassis_id_subtype:
		return chassis->c_id_subtype;
	case lldpctl_k_chassis_cap_available:
		return chassis->c_cap_available;
	case lldpctl_k_chassis_cap_enabled:
		return chassis->c_cap_enabled;
#ifdef ENABLE_LLDPMED
	case lldpctl_k_chassis_med_type:
		return chassis->c_med_type;
	case lldpctl_k_chassis_med_cap:
		return chassis->c_med_cap_available;
#endif
	default:
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	}
	return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
}

static const uint8_t*
_lldpctl_atom_get_buf_port(lldpctl_atom_t *atom, lldpctl_key_t key, size_t *n)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;
	struct lldpd_chassis  *chassis  = port->p_chassis;

	switch (key) {
	case lldpctl_k_port_id:
		*n = port->p_id_len;
		return (uint8_t*)port->p_id;
	case lldpctl_k_chassis_id:
		*n = chassis->c_id_len;
		return (uint8_t*)chassis->c_id;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static int
_lldpctl_atom_new_mgmts_list(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_mgmts_list_t *plist =
	    (struct _lldpctl_atom_mgmts_list_t *)atom;
	plist->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	plist->chassis = va_arg(ap, struct lldpd_chassis *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)plist->parent);
	return 1;
}

static void
_lldpctl_atom_free_mgmts_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_mgmts_list_t *plist =
	    (struct _lldpctl_atom_mgmts_list_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)plist->parent);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_iter_mgmts_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_mgmts_list_t *plist =
	    (struct _lldpctl_atom_mgmts_list_t *)atom;
	return (lldpctl_atom_iter_t*)TAILQ_FIRST(&plist->chassis->c_mgmt);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_mgmts_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_mgmt *mgmt = (struct lldpd_mgmt *)iter;
	return (lldpctl_atom_iter_t*)TAILQ_NEXT(mgmt, m_entries);
}

static lldpctl_atom_t*
_lldpctl_atom_value_mgmts_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct _lldpctl_atom_mgmts_list_t *plist =
	    (struct _lldpctl_atom_mgmts_list_t *)atom;
	struct lldpd_mgmt *mgmt = (struct lldpd_mgmt *)iter;
	return _lldpctl_new_atom(atom->conn, atom_mgmt, plist->parent, mgmt);
}

static int
_lldpctl_atom_new_mgmt(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_mgmt_t *mgmt =
	    (struct _lldpctl_atom_mgmt_t *)atom;
	mgmt->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	mgmt->mgmt = va_arg(ap, struct lldpd_mgmt *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)mgmt->parent);
	return 1;
}

static void
_lldpctl_atom_free_mgmt(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_mgmt_t *mgmt =
	    (struct _lldpctl_atom_mgmt_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)mgmt->parent);
}

static const char*
_lldpctl_atom_get_str_mgmt(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	char *ipaddress = NULL;
	size_t len; int af;
	struct _lldpctl_atom_mgmt_t *m =
	    (struct _lldpctl_atom_mgmt_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_mgmt_ip:
		switch (m->mgmt->m_family) {
		case LLDPD_AF_IPV4:
			len = INET_ADDRSTRLEN + 1;
			af  = AF_INET;
			break;
		case LLDPD_AF_IPV6:
			len = INET6_ADDRSTRLEN + 1;
			af = AF_INET6;
			break;
		default:
			len = 0;
		}
		if (len == 0) break;
		ipaddress = _lldpctl_alloc_in_atom(atom, len);
		if (!ipaddress) return NULL;
		if (inet_ntop(af, &m->mgmt->m_addr, ipaddress, len) == NULL)
			break;
		return ipaddress;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
	SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	return NULL;
}

#ifdef ENABLE_DOT3
static int
_lldpctl_atom_new_dot3_power(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_dot3_power_t *dpow =
	    (struct _lldpctl_atom_dot3_power_t *)atom;
	dpow->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)dpow->parent);
	return 1;
}

static void
_lldpctl_atom_free_dot3_power(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_dot3_power_t *dpow =
	    (struct _lldpctl_atom_dot3_power_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)dpow->parent);
}

static const char*
_lldpctl_atom_get_str_dot3_power(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_dot3_power_t *dpow =
	    (struct _lldpctl_atom_dot3_power_t *)atom;
	struct lldpd_port     *port     = dpow->parent->port;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_dot3_power_devicetype:
		return map_lookup(port_dot3_power_devicetype_map,
		    port->p_power.devicetype);
	case lldpctl_k_dot3_power_pairs:
		return map_lookup(port_dot3_power_pairs_map,
		    port->p_power.pairs);
	case lldpctl_k_dot3_power_class:
		return map_lookup(port_dot3_power_class_map,
		    port->p_power.class);
	case lldpctl_k_dot3_power_source:
		return map_lookup((port->p_power.devicetype == LLDP_DOT3_POWER_PSE)?
		    port_dot3_power_pse_source_map:
		    port_dot3_power_pd_source_map,
		    port->p_power.source);
	case lldpctl_k_dot3_power_priority:
		return map_lookup(port_dot3_power_priority_map,
		    port->p_power.priority);
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static long int
_lldpctl_atom_get_int_dot3_power(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_dot3_power_t *dpow =
	    (struct _lldpctl_atom_dot3_power_t *)atom;
	struct lldpd_port     *port     = dpow->parent->port;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_dot3_power_devicetype:
		return port->p_power.devicetype;
	case lldpctl_k_dot3_power_supported:
		return port->p_power.supported;
	case lldpctl_k_dot3_power_enabled:
		return port->p_power.enabled;
	case lldpctl_k_dot3_power_paircontrol:
		return port->p_power.paircontrol;
	case lldpctl_k_dot3_power_pairs:
		return port->p_power.pairs;
	case lldpctl_k_dot3_power_class:
		return port->p_power.class;
	case lldpctl_k_dot3_power_type:
		return port->p_power.powertype;
	case lldpctl_k_dot3_power_source:
		return port->p_power.source;
	case lldpctl_k_dot3_power_priority:
		return port->p_power.priority;
	case lldpctl_k_dot3_power_requested:
		return port->p_power.requested * 100;
	case lldpctl_k_dot3_power_allocated:
		return port->p_power.allocated * 100;
	default:
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_int_dot3_power(lldpctl_atom_t *atom, lldpctl_key_t key,
    long int value)
{
	struct _lldpctl_atom_dot3_power_t *dpow =
	    (struct _lldpctl_atom_dot3_power_t *)atom;
	struct lldpd_port *port = dpow->parent->port;

	/* Only local port can be modified */
	if (dpow->parent->hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_dot3_power_devicetype:
		switch (value) {
		case 0:		/* Disabling */
		case LLDP_DOT3_POWER_PSE:
		case LLDP_DOT3_POWER_PD:
			port->p_power.devicetype = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_dot3_power_supported:
		switch (value) {
		case 0:
		case 1:
			port->p_power.supported = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_dot3_power_enabled:
		switch (value) {
		case 0:
		case 1:
			port->p_power.enabled = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_dot3_power_paircontrol:
		switch (value) {
		case 0:
		case 1:
			port->p_power.paircontrol = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_dot3_power_pairs:
		switch (value) {
		case 1:
		case 2:
			port->p_power.pairs = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_dot3_power_class:
		if (value < 0 || value > 5)
			goto bad;
		port->p_power.class = value;
		return atom;
	case lldpctl_k_dot3_power_type:
		switch (value) {
		case LLDP_DOT3_POWER_8023AT_TYPE1:
		case LLDP_DOT3_POWER_8023AT_TYPE2:
		case LLDP_DOT3_POWER_8023AT_OFF:
			port->p_power.powertype = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_dot3_power_source:
		if (value < 0 || value > 3)
			goto bad;
		port->p_power.source = value;
		return atom;
	case lldpctl_k_dot3_power_priority:
		switch (value) {
		case LLDP_DOT3_POWER_PRIO_UNKNOWN:
		case LLDP_DOT3_POWER_PRIO_CRITICAL:
		case LLDP_DOT3_POWER_PRIO_HIGH:
		case LLDP_DOT3_POWER_PRIO_LOW:
			port->p_power.priority = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_dot3_power_allocated:
		if (value < 0) goto bad;
		port->p_power.allocated = value / 100;
		return atom;
	case lldpctl_k_dot3_power_requested:
		if (value < 0) goto bad;
		port->p_power.requested = value / 100;
		return atom;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return atom;
bad:
	SET_ERROR(atom->conn, LLDPCTL_ERR_BAD_VALUE);
	return NULL;
}

static lldpctl_atom_t*
_lldpctl_atom_set_str_dot3_power(lldpctl_atom_t *atom, lldpctl_key_t key,
    const char *value)
{
	switch (key) {
	case lldpctl_k_dot3_power_devicetype:
		return _lldpctl_atom_set_int_dot3_power(atom, key,
		    map_reverse_lookup(port_dot3_power_devicetype_map, value));
	case lldpctl_k_dot3_power_pairs:
		return _lldpctl_atom_set_int_dot3_power(atom, key,
		    map_reverse_lookup(port_dot3_power_pairs_map, value));
	case lldpctl_k_dot3_power_priority:
		return _lldpctl_atom_set_int_dot3_power(atom, key,
		    map_reverse_lookup(port_dot3_power_priority_map, value));
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}
#endif

#ifdef ENABLE_DOT1
static lldpctl_atom_iter_t*
_lldpctl_atom_iter_vlans_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	return (lldpctl_atom_iter_t*)TAILQ_FIRST(&vlist->parent->port->p_vlans);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_vlans_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_vlan *vlan = (struct lldpd_vlan *)iter;
	return (lldpctl_atom_iter_t*)TAILQ_NEXT(vlan, v_entries);
}

static lldpctl_atom_t*
_lldpctl_atom_value_vlans_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	struct lldpd_vlan *vlan = (struct lldpd_vlan *)iter;
	return _lldpctl_new_atom(atom->conn, atom_vlan, vlist->parent, vlan);
}

static int
_lldpctl_atom_new_vlan(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_vlan_t *vlan =
	    (struct _lldpctl_atom_vlan_t *)atom;
	vlan->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	vlan->vlan = va_arg(ap, struct lldpd_vlan *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)vlan->parent);
	return 1;
}

static void
_lldpctl_atom_free_vlan(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_vlan_t *vlan =
	    (struct _lldpctl_atom_vlan_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)vlan->parent);
}

static const char*
_lldpctl_atom_get_str_vlan(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_vlan_t *m =
	    (struct _lldpctl_atom_vlan_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_vlan_name:
		return m->vlan->v_name;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static long int
_lldpctl_atom_get_int_vlan(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_vlan_t *m =
	    (struct _lldpctl_atom_vlan_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_vlan_id:
		return m->vlan->v_vid;
	default:
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	}
}

static lldpctl_atom_iter_t*
_lldpctl_atom_iter_ppvids_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	return (lldpctl_atom_iter_t*)TAILQ_FIRST(&vlist->parent->port->p_ppvids);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_ppvids_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_ppvid *ppvid = (struct lldpd_ppvid *)iter;
	return (lldpctl_atom_iter_t*)TAILQ_NEXT(ppvid, p_entries);
}

static lldpctl_atom_t*
_lldpctl_atom_value_ppvids_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	struct lldpd_ppvid *ppvid = (struct lldpd_ppvid *)iter;
	return _lldpctl_new_atom(atom->conn, atom_ppvid, vlist->parent, ppvid);
}

static int
_lldpctl_atom_new_ppvid(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_ppvid_t *ppvid =
	    (struct _lldpctl_atom_ppvid_t *)atom;
	ppvid->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	ppvid->ppvid = va_arg(ap, struct lldpd_ppvid *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)ppvid->parent);
	return 1;
}

static void
_lldpctl_atom_free_ppvid(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_ppvid_t *ppvid =
	    (struct _lldpctl_atom_ppvid_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)ppvid->parent);
}

static long int
_lldpctl_atom_get_int_ppvid(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_ppvid_t *m =
	    (struct _lldpctl_atom_ppvid_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_ppvid_id:
		return m->ppvid->p_ppvid;
	case lldpctl_k_ppvid_status:
		return m->ppvid->p_cap_status;
	default:
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	}
}

static lldpctl_atom_iter_t*
_lldpctl_atom_iter_pis_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	return (lldpctl_atom_iter_t*)TAILQ_FIRST(&vlist->parent->port->p_pids);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_pis_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_pi *pi = (struct lldpd_pi *)iter;
	return (lldpctl_atom_iter_t*)TAILQ_NEXT(pi, p_entries);
}

static lldpctl_atom_t*
_lldpctl_atom_value_pis_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	struct lldpd_pi *pi = (struct lldpd_pi *)iter;
	return _lldpctl_new_atom(atom->conn, atom_pi, vlist->parent, pi);
}

static int
_lldpctl_atom_new_pi(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_pi_t *pi =
	    (struct _lldpctl_atom_pi_t *)atom;
	pi->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	pi->pi = va_arg(ap, struct lldpd_pi *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)pi->parent);
	return 1;
}

static void
_lldpctl_atom_free_pi(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_pi_t *pi =
	    (struct _lldpctl_atom_pi_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)pi->parent);
}

static const uint8_t*
_lldpctl_atom_get_buf_pi(lldpctl_atom_t *atom, lldpctl_key_t key, size_t *n)
{
	struct _lldpctl_atom_pi_t *m =
	    (struct _lldpctl_atom_pi_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_pi_id:
		*n = m->pi->p_pi_len;
		return (const uint8_t*)m->pi->p_pi;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}
#endif

#ifdef ENABLE_LLDPMED
static lldpctl_atom_iter_t*
_lldpctl_atom_iter_med_policies_list(lldpctl_atom_t *atom)
{
	int i;
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	for (i = 0; i < LLDP_MED_APPTYPE_LAST; i++)
		vlist->parent->port->p_med_policy[i].index = i;
	return (lldpctl_atom_iter_t*)&vlist->parent->port->p_med_policy[0];
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_med_policies_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_med_policy *policy = (struct lldpd_med_policy *)iter;
	if (policy->index == LLDP_MED_APPTYPE_LAST - 1) return NULL;
	return (lldpctl_atom_iter_t*)(++policy);
}

static lldpctl_atom_t*
_lldpctl_atom_value_med_policies_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	struct lldpd_med_policy *policy = (struct lldpd_med_policy *)iter;
	return _lldpctl_new_atom(atom->conn, atom_med_policy, vlist->parent, policy);
}

static int
_lldpctl_atom_new_med_policy(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_med_policy_t *policy =
	    (struct _lldpctl_atom_med_policy_t *)atom;
	policy->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	policy->policy = va_arg(ap, struct lldpd_med_policy *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)policy->parent);
	return 1;
}

static void
_lldpctl_atom_free_med_policy(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_med_policy_t *policy =
	    (struct _lldpctl_atom_med_policy_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)policy->parent);
}

static long int
_lldpctl_atom_get_int_med_policy(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_med_policy_t *m =
	    (struct _lldpctl_atom_med_policy_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_med_policy_type:
		return m->policy->type;
	case lldpctl_k_med_policy_unknown:
		return m->policy->unknown;
	case lldpctl_k_med_policy_tagged:
		return m->policy->tagged;
	case lldpctl_k_med_policy_vid:
		return m->policy->vid;
	case lldpctl_k_med_policy_dscp:
		return m->policy->dscp;
	case lldpctl_k_med_policy_priority:
		return m->policy->priority;
	default:
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_int_med_policy(lldpctl_atom_t *atom, lldpctl_key_t key,
    long int value)
{
	struct _lldpctl_atom_med_policy_t *m =
	    (struct _lldpctl_atom_med_policy_t *)atom;

	/* Only local port can be modified */
	if (m->parent->hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_med_policy_type:
		/* We let set any policy type, including one whose are not
		 * compatible with the index. If a policy type is set, the index
		 * will be ignored. If a policy type is 0, the index will be
		 * used to know which policy to "erase". */
		if (value < 0 || value > LLDP_MED_APPTYPE_LAST) goto bad;
		m->policy->type = value;
		return atom;
	case lldpctl_k_med_policy_unknown:
		if (value != 0 && value != 1) goto bad;
		m->policy->unknown = value;
		return atom;
	case lldpctl_k_med_policy_tagged:
		if (value != 0 && value != 1) goto bad;
		m->policy->tagged = value;
		return atom;
	case lldpctl_k_med_policy_vid:
		if (value < 0 || value > 4094) goto bad;
		m->policy->vid = value;
		return atom;
	case lldpctl_k_med_policy_dscp:
		if (value < 0 || value > 63) goto bad;
		m->policy->dscp = value;
		return atom;
	case lldpctl_k_med_policy_priority:
		if (value < 0 || value > 7) goto bad;
		m->policy->priority = value;
		return atom;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return atom;
bad:
	SET_ERROR(atom->conn, LLDPCTL_ERR_BAD_VALUE);
	return NULL;
}

static const char*
_lldpctl_atom_get_str_med_policy(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_med_policy_t *m =
	    (struct _lldpctl_atom_med_policy_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_med_policy_type:
		return map_lookup(port_med_policy_map, m->policy->type);
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static lldpctl_atom_iter_t*
_lldpctl_atom_iter_med_locations_list(lldpctl_atom_t *atom)
{
	int i;
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	for (i = 0; i < LLDP_MED_LOCFORMAT_LAST; i++)
		vlist->parent->port->p_med_location[i].index = i;
	return (lldpctl_atom_iter_t*)&vlist->parent->port->p_med_location[0];
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_med_locations_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_med_loc *location = (struct lldpd_med_loc *)iter;
	if (location->index == LLDP_MED_LOCFORMAT_LAST - 1) return NULL;
	return (lldpctl_atom_iter_t*)(++location);
}

static lldpctl_atom_t*
_lldpctl_atom_value_med_locations_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct _lldpctl_atom_any_list_t *vlist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	struct lldpd_med_loc *location = (struct lldpd_med_loc *)iter;
	return _lldpctl_new_atom(atom->conn, atom_med_location, vlist->parent, location);
}

static int
_lldpctl_atom_new_med_location(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_med_location_t *location =
	    (struct _lldpctl_atom_med_location_t *)atom;
	location->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	location->location = va_arg(ap, struct lldpd_med_loc *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)location->parent);
	return 1;
}

static void
_lldpctl_atom_free_med_location(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_med_location_t *location =
	    (struct _lldpctl_atom_med_location_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)location->parent);
}

static long int
_lldpctl_atom_get_int_med_location(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_med_location_t *m =
	    (struct _lldpctl_atom_med_location_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_med_location_format:
		switch (m->location->format) {
		case LLDP_MED_LOCFORMAT_COORD:
			if (m->location->data_len != 16) break;
			return LLDP_MED_LOCFORMAT_COORD;
		case LLDP_MED_LOCFORMAT_CIVIC:
			if ((m->location->data_len < 3) ||
			    (m->location->data_len - 1 !=
				m->location->data[0])) break;
			return LLDP_MED_LOCFORMAT_CIVIC;
		case LLDP_MED_LOCFORMAT_ELIN:
			return LLDP_MED_LOCFORMAT_ELIN;
		default:
			return 0;
		}
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	case lldpctl_k_med_location_geoid:
		if (m->location->format != LLDP_MED_LOCFORMAT_COORD)
			return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return m->location->data[15];
	case lldpctl_k_med_location_altitude_unit:
		if (m->location->format != LLDP_MED_LOCFORMAT_COORD)
			return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return (m->location->data[10] & 0xf0) >> 4;
	default:
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_int_med_location(lldpctl_atom_t *atom, lldpctl_key_t key,
    long int value)
{
	struct _lldpctl_atom_med_location_t *mloc =
	    (struct _lldpctl_atom_med_location_t *)atom;

	/* Only local port can be modified */
	if (mloc->parent->hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_med_location_format:
		switch (value) {
		case 0:		/* Disabling */
		case LLDP_MED_LOCFORMAT_COORD:
			mloc->location->format = value;
			if (mloc->location->data) free(mloc->location->data);
			mloc->location->data = calloc(1, 16);
			if (mloc->location->data == NULL) {
				mloc->location->data_len = 0;
				SET_ERROR(atom->conn, LLDPCTL_ERR_NOMEM);
				return NULL;
			}
			mloc->location->data_len = 16;
			return atom;
		case LLDP_MED_LOCFORMAT_CIVIC:
			mloc->location->format = value;
			if (mloc->location->data) free(mloc->location->data);
			mloc->location->data = calloc(1, 4);
			if (mloc->location->data == NULL) {
				mloc->location->data_len = 0;
				SET_ERROR(atom->conn, LLDPCTL_ERR_NOMEM);
				return NULL;
			}
			mloc->location->data_len = 4;
			mloc->location->data[0] = 3;
			mloc->location->data[1] = 2; /* Client */
			mloc->location->data[2] = 'U';
			mloc->location->data[3] = 'S';
			return atom;
		case LLDP_MED_LOCFORMAT_ELIN:
			mloc->location->format = value;
			mloc->location->data = NULL;
			mloc->location->data_len = 0;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_med_location_geoid:
		if (mloc->location->format != LLDP_MED_LOCFORMAT_COORD) goto bad;
		if (mloc->location->data == NULL || mloc->location->data_len != 16) goto bad;
		switch (value) {
		case 0:
		case LLDP_MED_LOCATION_GEOID_WGS84:
		case LLDP_MED_LOCATION_GEOID_NAD83:
		case LLDP_MED_LOCATION_GEOID_NAD83_MLLW:
			mloc->location->data[15] = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_med_location_altitude_unit:
		if (mloc->location->format != LLDP_MED_LOCFORMAT_COORD) goto bad;
		if (mloc->location->data == NULL || mloc->location->data_len != 16) goto bad;
		switch (value) {
		case 0:
		case LLDP_MED_LOCATION_ALTITUDE_UNIT_METER:
		case LLDP_MED_LOCATION_ALTITUDE_UNIT_FLOOR:
			mloc->location->data[10] = value << 4;
			return atom;
		default: goto bad;
		}
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return atom;
bad:
	SET_ERROR(atom->conn, LLDPCTL_ERR_BAD_VALUE);
	return NULL;

}

static const char*
fixed_precision(lldpctl_atom_t *atom,
    u_int64_t value, int intpart, int floatpart, int displaysign,
    const char *negsuffix, const char *possuffix)
{
	char *buf;
	u_int64_t tmp = value;
	int negative = 0, n;
	u_int32_t integer = 0;
	if (value & (1ULL << (intpart + floatpart - 1))) {
		negative = 1;
		tmp = ~value;
		tmp += 1;
	}
	integer = (u_int32_t)((tmp &
		(((1ULL << intpart)-1) << floatpart)) >> floatpart);
	tmp = (tmp & ((1<< floatpart) - 1))*10000/(1ULL << floatpart);

	if ((buf = _lldpctl_alloc_in_atom(atom, 64)) == NULL)
		return NULL;
	n = snprintf(buf, 64, "%s%u.%04llu%s",
	    displaysign?(negative?"-":"+"):"",
	    integer, (unsigned long long int)tmp,
	    (negative && negsuffix)?negsuffix:
	    (!negative && possuffix)?possuffix:"");
	if (n > -1 && n < 64)
		return buf;
	SET_ERROR(atom->conn, LLDPCTL_ERR_NOMEM);
	return NULL;
}

static const char*
_lldpctl_atom_get_str_med_location(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_med_location_t *m =
	    (struct _lldpctl_atom_med_location_t *)atom;
	char *value;
	u_int64_t l;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_med_location_format:
		return map_lookup(port_med_location_map, m->location->format);
	case lldpctl_k_med_location_geoid:
		if (m->location->format != LLDP_MED_LOCFORMAT_COORD) break;
		return map_lookup(port_med_geoid_map,
		    m->location->data[15]);
	case lldpctl_k_med_location_latitude:
		if (m->location->format != LLDP_MED_LOCFORMAT_COORD) break;
		memcpy(&l, m->location->data, sizeof(u_int64_t));
		l = (ntohll(l) & 0x03FFFFFFFF000000ULL) >> 24;
		return fixed_precision(atom, l, 9, 25, 0, " S", " N");
	case lldpctl_k_med_location_longitude:
		if (m->location->format != LLDP_MED_LOCFORMAT_COORD) break;
		memcpy(&l, m->location->data + 5, sizeof(u_int64_t));
		l = (ntohll(l) & 0x03FFFFFFFF000000ULL) >> 24;
		return fixed_precision(atom, l, 9, 25, 0, " W", " E");
	case lldpctl_k_med_location_altitude:
		if (m->location->format != LLDP_MED_LOCFORMAT_COORD) break;
		memset(&l, 0, sizeof(u_int64_t));
		memcpy(&l, m->location->data + 10, 5);
		l = (ntohll(l) & 0x3FFFFFFF000000ULL) >> 24;
		return fixed_precision(atom, l, 22, 8, 1, NULL, NULL);
	case lldpctl_k_med_location_altitude_unit:
		if (m->location->format != LLDP_MED_LOCFORMAT_COORD) break;
		switch (m->location->data[10] & 0xf0) {
		case (LLDP_MED_LOCATION_ALTITUDE_UNIT_METER << 4):
			return "m";
		case (LLDP_MED_LOCATION_ALTITUDE_UNIT_FLOOR << 4):
			return "floor";
		}
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	case lldpctl_k_med_location_country:
		if (m->location->format != LLDP_MED_LOCFORMAT_CIVIC) break;
		value = _lldpctl_alloc_in_atom(atom, 3);
		if (!value) return NULL;
		memcpy(value, m->location->data + 2, 2);
		return value;
	case lldpctl_k_med_location_elin:
		if (m->location->format != LLDP_MED_LOCFORMAT_ELIN) break;
		value = _lldpctl_alloc_in_atom(atom, m->location->data_len + 1);
		if (!value) return NULL;
		memcpy(value, m->location->data, m->location->data_len);
		return value;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
	SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	return NULL;
}

static void
write_fixed_precision(uint8_t *where, double l,
    int precisionnb, int intnb, int floatnb)
{
	int intpart, floatpart, precision = 6;
	if (l > 0) {
		intpart = (int)l;
		floatpart = (l - intpart) * (1 << floatnb);
	} else {
		intpart = -(int)l;
		floatpart = (-(l + intpart)) * (1 << floatnb);
		intpart = ~intpart; intpart += 1;
		floatpart = ~floatpart; floatpart += 1;
	}
	if ((1 << precisionnb) - 1 < precision)
		precision = (1 << precisionnb) - 1;
	/* We need to write precision, int part and float part. */
	do {
		int obit, i, o;
		unsigned int ints[3] = { precision, intpart, floatpart };
		unsigned int bits[3] = { precisionnb, intnb, floatnb };
		for (i = 0, obit = 8, o = 0; i < 3;) {
			if (obit > bits[i]) {
				where[o] = where[o] |
				    ((ints[i] & ((1 << bits[i]) - 1)) << (obit - bits[i]));
				obit -= bits[i];
				i++;
			} else {
				where[o] = where[o] |
				    ((ints[i] >> (bits[i] - obit)) & ((1 << obit) - 1));
				bits[i] -= obit;
				obit = 8;
				o++;
			}
		}
	} while(0);
}

static lldpctl_atom_t*
_lldpctl_atom_set_str_med_location(lldpctl_atom_t *atom, lldpctl_key_t key,
    const char *value)
{
	struct _lldpctl_atom_med_location_t *mloc =
	    (struct _lldpctl_atom_med_location_t *)atom;
	double l;
	char *end;

	/* Only local port can be modified */
	if (mloc->parent->hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_med_location_latitude:
		if (mloc->location->format != LLDP_MED_LOCFORMAT_COORD) goto bad;
		if (mloc->location->data == NULL || mloc->location->data_len != 16) goto bad;
		l = strtod(value, &end);
		if (!end) goto bad;
		if (end && *end != '\0') {
			if (*(end+1) != '\0') goto bad;
			if (*end == 'S') l = -l;
			else if (*end != 'N') goto bad;
		}
		write_fixed_precision((uint8_t*)mloc->location->data, l, 6, 9, 25);
		return atom;
	case lldpctl_k_med_location_longitude:
		if (mloc->location->format != LLDP_MED_LOCFORMAT_COORD) goto bad;
		if (mloc->location->data == NULL || mloc->location->data_len != 16) goto bad;
		l = strtod(value, &end);
		if (!end) goto bad;
		if (end && *end != '\0') {
			if (*(end+1) != '\0') goto bad;
			if (*end == 'W') l = -l;
			else if (*end != 'E') goto bad;
		}
		write_fixed_precision((uint8_t*)mloc->location->data + 5, l, 6, 9, 25);
		return atom;
	case lldpctl_k_med_location_altitude:
		if (mloc->location->format != LLDP_MED_LOCFORMAT_COORD) goto bad;
		if (mloc->location->data == NULL || mloc->location->data_len != 16) goto bad;
		l = strtod(value, &end);
		if (!end || *end != '\0') goto bad;
		write_fixed_precision((uint8_t*)mloc->location->data + 11, l, 2, 22, 8);
		return atom;
	case lldpctl_k_med_location_altitude_unit:
		if (mloc->location->format != LLDP_MED_LOCFORMAT_COORD) goto bad;
		if (mloc->location->data == NULL || mloc->location->data_len != 16) goto bad;
		if (!strcmp(value, "m"))
			return _lldpctl_atom_set_int_med_location(atom, key,
			    LLDP_MED_LOCATION_ALTITUDE_UNIT_METER);
		if (!strcmp(value, "f") ||
		    (!strcmp(value, "floor")))
			return _lldpctl_atom_set_int_med_location(atom, key,
			    LLDP_MED_LOCATION_ALTITUDE_UNIT_FLOOR);
		goto bad;
	case lldpctl_k_med_location_country:
		if (mloc->location->format != LLDP_MED_LOCFORMAT_CIVIC) goto bad;
		if (mloc->location->data == NULL || mloc->location->data_len < 3) goto bad;
		if (strlen(value) != 2) goto bad;
		memcpy(mloc->location->data + 2, value, 2);
		return atom;
	case lldpctl_k_med_location_elin:
		if (mloc->location->format != LLDP_MED_LOCFORMAT_ELIN) goto bad;
		if (mloc->location->data) free(mloc->location->data);
		mloc->location->data = calloc(1, strlen(value));
		if (mloc->location->data == NULL) {
			mloc->location->data_len = 0;
			SET_ERROR(atom->conn, LLDPCTL_ERR_NOMEM);
			return NULL;
		}
		mloc->location->data_len = strlen(value);
		memcpy(mloc->location->data, value,
		    mloc->location->data_len);
		return atom;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return atom;
bad:
	SET_ERROR(atom->conn, LLDPCTL_ERR_BAD_VALUE);
	return NULL;

}

static lldpctl_atom_t*
_lldpctl_atom_get_atom_med_location(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_med_location_t *m =
	    (struct _lldpctl_atom_med_location_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_med_location_ca_elements:
		if (m->location->format != LLDP_MED_LOCFORMAT_CIVIC) {
			SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
			return NULL;
		}
		return _lldpctl_new_atom(atom->conn, atom_med_caelements_list, m);
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_atom_med_location(lldpctl_atom_t *atom, lldpctl_key_t key,
    lldpctl_atom_t *value)
{
	struct _lldpctl_atom_med_location_t *m =
	    (struct _lldpctl_atom_med_location_t *)atom;
	struct _lldpctl_atom_med_caelement_t *el;
	uint8_t *new;

	/* Only local port can be modified */
	if (m->parent->hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_med_location_ca_elements:
		if (value->type != atom_med_caelement) {
			SET_ERROR(atom->conn, LLDPCTL_ERR_INCORRECT_ATOM_TYPE);
			return NULL;
		}
		if (m->location->format != LLDP_MED_LOCFORMAT_CIVIC) goto bad;
		if (m->location->data == NULL || m->location->data_len < 3) goto bad;

		/* We append this element. */
		el = (struct _lldpctl_atom_med_caelement_t *)value;
		new = malloc(m->location->data_len + 2 + el->len);
		if (new == NULL) {
			SET_ERROR(atom->conn, LLDPCTL_ERR_NOMEM);
			return NULL;
		}
		memcpy(new, m->location->data, m->location->data_len);
		new[m->location->data_len] = el->type;
		new[m->location->data_len + 1] = el->len;
		memcpy(new + m->location->data_len + 2, el->value, el->len);
		new[0] += 2 + el->len;
		free(m->location->data);
		m->location->data = (char*)new;
		m->location->data_len += 2 + el->len;
		return atom;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
bad:
	SET_ERROR(atom->conn, LLDPCTL_ERR_BAD_VALUE);
	return NULL;
}

struct ca_iter {
	uint8_t *data;
	size_t data_len;
};

static lldpctl_atom_iter_t*
_lldpctl_atom_iter_med_caelements_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_med_caelements_list_t *plist =
	    (struct _lldpctl_atom_med_caelements_list_t *)atom;
	struct ca_iter *iter = _lldpctl_alloc_in_atom(atom, sizeof(struct ca_iter));
	if (!iter) return NULL;
	iter->data = (uint8_t*)plist->parent->location->data + 4;
	iter->data_len = plist->parent->location->data_len - 4;
	return (lldpctl_atom_iter_t*)iter;
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_med_caelements_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct ca_iter *cai = (struct ca_iter *)iter;
	int len;
	if (cai->data_len < 2) return NULL;
	len = *((uint8_t *)cai->data + 1);
	if (cai->data_len < 2 + len) return NULL;
	cai->data += 2 + len;
	cai->data_len -= 2 + len;
	return (lldpctl_atom_iter_t*)cai;
}

static lldpctl_atom_t*
_lldpctl_atom_value_med_caelements_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct _lldpctl_atom_med_caelements_list_t *plist =
	    (struct _lldpctl_atom_med_caelements_list_t *)atom;
	struct ca_iter *cai = (struct ca_iter *)iter;
	size_t len;
	if (cai->data_len < 2) return NULL;
	len = *((uint8_t *)cai->data + 1);
	if (cai->data_len < 2 + len) return NULL;
	return _lldpctl_new_atom(atom->conn, atom_med_caelement, plist->parent,
	    (int)*cai->data, cai->data + 2, len);
}

static lldpctl_atom_t*
_lldpctl_atom_create_med_caelements_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_med_caelements_list_t *plist =
	    (struct _lldpctl_atom_med_caelements_list_t *)atom;
	return _lldpctl_new_atom(atom->conn, atom_med_caelement, plist->parent,
	    -1, NULL, 0);
}

static int
_lldpctl_atom_new_med_caelement(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_med_caelement_t *el =
	    (struct _lldpctl_atom_med_caelement_t *)atom;
	el->parent = va_arg(ap, struct _lldpctl_atom_med_location_t *);
	el->type   = va_arg(ap, int);
	el->value  = va_arg(ap, uint8_t*);
	el->len    = va_arg(ap, size_t);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)el->parent);
	return 1;
}

static void
_lldpctl_atom_free_med_caelement(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_med_caelement_t *el =
	    (struct _lldpctl_atom_med_caelement_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)el->parent);
}

static const char*
_lldpctl_atom_get_str_med_caelement(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	char *value = NULL;
	struct _lldpctl_atom_med_caelement_t *m =
	    (struct _lldpctl_atom_med_caelement_t *)atom;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_med_civicaddress_type:
		return map_lookup(civic_address_type_map, m->type);
	case lldpctl_k_med_civicaddress_value:
		value = _lldpctl_alloc_in_atom(atom, m->len + 1);
		if (!value) return NULL;
		memcpy(value, m->value, m->len);
		return value;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_str_med_caelement(lldpctl_atom_t *atom, lldpctl_key_t key,
    const char *value)
{
	struct _lldpctl_atom_med_caelement_t *el =
	    (struct _lldpctl_atom_med_caelement_t *)atom;

	/* Only local port can be modified */
	if (el->parent->parent->hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_med_civicaddress_value:
		if (strlen(value) > 250) goto bad;
		el->value = _lldpctl_alloc_in_atom(atom, strlen(value) + 1);
		if (el->value == NULL) return NULL;
		strcpy((char*)el->value, value);
		el->len = strlen(value);
		return atom;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return atom;
bad:
	SET_ERROR(atom->conn, LLDPCTL_ERR_BAD_VALUE);
	return NULL;
}

static long int
_lldpctl_atom_get_int_med_caelement(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_med_caelement_t *m =
	    (struct _lldpctl_atom_med_caelement_t *)atom;

	switch (key) {
	case lldpctl_k_med_civicaddress_type:
		return m->type;
	default:
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_int_med_caelement(lldpctl_atom_t *atom, lldpctl_key_t key,
    long int value)
{
	struct _lldpctl_atom_med_caelement_t *el =
	    (struct _lldpctl_atom_med_caelement_t *)atom;

	/* Only local port can be modified */
	if (el->parent->parent->hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_med_civicaddress_type:
		if (value <= 0 || value > 128) goto bad;
		el->type = value;
		return atom;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return atom;
bad:
	SET_ERROR(atom->conn, LLDPCTL_ERR_BAD_VALUE);
	return NULL;
}

static int
_lldpctl_atom_new_med_power(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_med_power_t *mpow =
	    (struct _lldpctl_atom_med_power_t *)atom;
	mpow->parent = va_arg(ap, struct _lldpctl_atom_port_t *);
	lldpctl_atom_inc_ref((lldpctl_atom_t *)mpow->parent);
	return 1;
}

static void
_lldpctl_atom_free_med_power(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_med_power_t *mpow =
	    (struct _lldpctl_atom_med_power_t *)atom;
	lldpctl_atom_dec_ref((lldpctl_atom_t *)mpow->parent);
}

static const char*
_lldpctl_atom_get_str_med_power(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_med_power_t *mpow =
	    (struct _lldpctl_atom_med_power_t *)atom;
	struct lldpd_port *port = mpow->parent->port;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_med_power_type:
		return map_lookup(port_med_pow_devicetype_map,
		    port->p_med_power.devicetype);
	case lldpctl_k_med_power_source:
		return map_lookup(port_med_pow_source_map,
		    port->p_med_power.source);
	case lldpctl_k_med_power_priority:
		return map_lookup(port_med_pow_priority_map,
		    port->p_med_power.priority);
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static long int
_lldpctl_atom_get_int_med_power(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_med_power_t *dpow =
	    (struct _lldpctl_atom_med_power_t *)atom;
	struct lldpd_port     *port     = dpow->parent->port;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_med_power_type:
		return port->p_med_power.devicetype;
	case lldpctl_k_med_power_source:
		return port->p_med_power.source;
	case lldpctl_k_med_power_priority:
		return port->p_med_power.priority;
	case lldpctl_k_med_power_val:
		return port->p_med_power.val * 100;
	default:
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_int_med_power(lldpctl_atom_t *atom, lldpctl_key_t key,
    long int value)
{
	struct _lldpctl_atom_med_power_t *dpow =
	    (struct _lldpctl_atom_med_power_t *)atom;
	struct lldpd_port *port = dpow->parent->port;

	/* Only local port can be modified */
	if (dpow->parent->hardware == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_med_power_type:
		switch (value) {
		case 0:
		case LLDP_MED_POW_TYPE_PSE:
		case LLDP_MED_POW_TYPE_PD:
			port->p_med_power.devicetype = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_med_power_source:
		switch (value) {
		case LLDP_MED_POW_SOURCE_PRIMARY:
		case LLDP_MED_POW_SOURCE_BACKUP:
			if (port->p_med_power.devicetype != LLDP_MED_POW_TYPE_PSE)
				goto bad;
			port->p_med_power.source = value;
			return atom;
		case LLDP_MED_POW_SOURCE_PSE:
		case LLDP_MED_POW_SOURCE_LOCAL:
		case LLDP_MED_POW_SOURCE_BOTH:
			if (port->p_med_power.devicetype != LLDP_MED_POW_TYPE_PD)
				goto bad;
			port->p_med_power.source = value;
			return atom;
		case LLDP_MED_POW_SOURCE_UNKNOWN:
			port->p_med_power.source = value;
			return atom;
		default: goto bad;
		}
	case lldpctl_k_med_power_priority:
		if (value < 0 || value > 3) goto bad;
		port->p_med_power.priority = value;
		return atom;
	case lldpctl_k_med_power_val:
		if (value < 0) goto bad;
		port->p_med_power.val = value / 100;
		return atom;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return atom;
bad:
	SET_ERROR(atom->conn, LLDPCTL_ERR_BAD_VALUE);
	return NULL;
}

static lldpctl_atom_t*
_lldpctl_atom_set_str_med_power(lldpctl_atom_t *atom, lldpctl_key_t key,
    const char *value)
{
	switch (key) {
	case lldpctl_k_med_power_type:
		return _lldpctl_atom_set_int_med_power(atom, key,
		    map_reverse_lookup(port_med_pow_devicetype_map, value));
	case lldpctl_k_med_power_source:
		return _lldpctl_atom_set_int_med_power(atom, key,
		    map_reverse_lookup(port_med_pow_source_map2, value));
	case lldpctl_k_med_power_priority:
		return _lldpctl_atom_set_int_med_power(atom, key,
		    map_reverse_lookup(port_med_pow_priority_map, value));
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}
#endif

struct atom_builder {
	atom_t type;	/* Atom type */
	size_t size;	/* Size of structure to allocate */
	int  (*init)(lldpctl_atom_t *, va_list); /* Optional additional init steps */
	void (*free)(lldpctl_atom_t *); /* Optional deallocation steps */

	lldpctl_atom_iter_t* (*iter)(lldpctl_atom_t *); /* Optional, return an iterator for this object */
	lldpctl_atom_iter_t* (*next)(lldpctl_atom_t *,  lldpctl_atom_iter_t *); /* Return the next object for the provided iterator */
	lldpctl_atom_t*      (*value)(lldpctl_atom_t *, lldpctl_atom_iter_t *); /* Return the current object for the provided iterator */

	lldpctl_atom_t*      (*get)(lldpctl_atom_t *,        lldpctl_key_t);
	const char*          (*get_str)(lldpctl_atom_t *,    lldpctl_key_t);
	const u_int8_t*      (*get_buffer)(lldpctl_atom_t *, lldpctl_key_t, size_t *);
	long int             (*get_int)(lldpctl_atom_t *,    lldpctl_key_t);

	lldpctl_atom_t*      (*set)(lldpctl_atom_t *, lldpctl_key_t, lldpctl_atom_t *);
	lldpctl_atom_t*      (*set_str)(lldpctl_atom_t *, lldpctl_key_t, const char *);
	lldpctl_atom_t*      (*set_buffer)(lldpctl_atom_t *, lldpctl_key_t, const u_int8_t *, size_t);
	lldpctl_atom_t*      (*set_int)(lldpctl_atom_t *, lldpctl_key_t, long int);
	lldpctl_atom_t*      (*create)(lldpctl_atom_t *);
};

struct atom_builder builders[] = {
	{ atom_interfaces_list, sizeof(struct _lldpctl_atom_interfaces_list_t),
	  .init  = _lldpctl_atom_new_interfaces_list,
	  .free  = _lldpctl_atom_free_interfaces_list,
	  .iter  = _lldpctl_atom_iter_interfaces_list,
	  .next  = _lldpctl_atom_next_interfaces_list,
	  .value = _lldpctl_atom_value_interfaces_list },
	{ atom_interface, sizeof(struct _lldpctl_atom_interface_t),
	  .init = _lldpctl_atom_new_interface,
	  .free = _lldpctl_atom_free_interface,
	  .get_str = _lldpctl_atom_get_str_interface },
	{ atom_ports_list, sizeof(struct _lldpctl_atom_any_list_t),
	  .init = _lldpctl_atom_new_any_list,
	  .free = _lldpctl_atom_free_any_list,
	  .iter = _lldpctl_atom_iter_ports_list,
	  .next = _lldpctl_atom_next_ports_list,
	  .value = _lldpctl_atom_value_ports_list },
	{ atom_port, sizeof(struct _lldpctl_atom_port_t),
	  .init = _lldpctl_atom_new_port,
	  .free = _lldpctl_atom_free_port,
	  .get  = _lldpctl_atom_get_atom_port,
	  .set  = _lldpctl_atom_set_atom_port,
	  .get_str = _lldpctl_atom_get_str_port,
	  .get_int = _lldpctl_atom_get_int_port,
	  .get_buffer = _lldpctl_atom_get_buf_port },
	{ atom_mgmts_list, sizeof(struct _lldpctl_atom_mgmts_list_t),
	  .init = _lldpctl_atom_new_mgmts_list,
	  .free = _lldpctl_atom_free_mgmts_list,
	  .iter = _lldpctl_atom_iter_mgmts_list,
	  .next = _lldpctl_atom_next_mgmts_list,
	  .value = _lldpctl_atom_value_mgmts_list },
	{ atom_mgmt, sizeof(struct _lldpctl_atom_mgmt_t),
	  .init = _lldpctl_atom_new_mgmt,
	  .free = _lldpctl_atom_free_mgmt,
	  .get_str = _lldpctl_atom_get_str_mgmt },
#ifdef ENABLE_DOT3
	{ atom_dot3_power, sizeof(struct _lldpctl_atom_dot3_power_t),
	  .init = _lldpctl_atom_new_dot3_power,
	  .free = _lldpctl_atom_free_dot3_power,
	  .get_int = _lldpctl_atom_get_int_dot3_power,
	  .set_int = _lldpctl_atom_set_int_dot3_power,
	  .get_str = _lldpctl_atom_get_str_dot3_power,
	  .set_str = _lldpctl_atom_set_str_dot3_power },
#endif
#ifdef ENABLE_DOT1
	{ atom_vlans_list, sizeof(struct _lldpctl_atom_any_list_t),
	  .init = _lldpctl_atom_new_any_list,
	  .free = _lldpctl_atom_free_any_list,
	  .iter = _lldpctl_atom_iter_vlans_list,
	  .next = _lldpctl_atom_next_vlans_list,
	  .value = _lldpctl_atom_value_vlans_list },
	{ atom_vlan, sizeof(struct _lldpctl_atom_vlan_t),
	  .init = _lldpctl_atom_new_vlan,
	  .free = _lldpctl_atom_free_vlan,
	  .get_str = _lldpctl_atom_get_str_vlan,
	  .get_int = _lldpctl_atom_get_int_vlan },
	{ atom_ppvids_list, sizeof(struct _lldpctl_atom_any_list_t),
	  .init = _lldpctl_atom_new_any_list,
	  .free = _lldpctl_atom_free_any_list,
	  .iter = _lldpctl_atom_iter_ppvids_list,
	  .next = _lldpctl_atom_next_ppvids_list,
	  .value = _lldpctl_atom_value_ppvids_list },
	{ atom_ppvid, sizeof(struct _lldpctl_atom_ppvid_t),
	  .init = _lldpctl_atom_new_ppvid,
	  .free = _lldpctl_atom_free_ppvid,
	  .get_int = _lldpctl_atom_get_int_ppvid },
	{ atom_pis_list, sizeof(struct _lldpctl_atom_any_list_t),
	  .init = _lldpctl_atom_new_any_list,
	  .free = _lldpctl_atom_free_any_list,
	  .iter = _lldpctl_atom_iter_pis_list,
	  .next = _lldpctl_atom_next_pis_list,
	  .value = _lldpctl_atom_value_pis_list },
	{ atom_pi, sizeof(struct _lldpctl_atom_pi_t),
	  .init = _lldpctl_atom_new_pi,
	  .free = _lldpctl_atom_free_pi,
	  .get_buffer = _lldpctl_atom_get_buf_pi },
#endif
#ifdef ENABLE_LLDPMED
	{ atom_med_policies_list, sizeof(struct _lldpctl_atom_any_list_t),
	  .init = _lldpctl_atom_new_any_list,
	  .free = _lldpctl_atom_free_any_list,
	  .iter = _lldpctl_atom_iter_med_policies_list,
	  .next = _lldpctl_atom_next_med_policies_list,
	  .value = _lldpctl_atom_value_med_policies_list },
	{ atom_med_policy, sizeof(struct _lldpctl_atom_med_policy_t),
	  .init = _lldpctl_atom_new_med_policy,
	  .free = _lldpctl_atom_free_med_policy,
	  .get_int = _lldpctl_atom_get_int_med_policy,
	  .set_int = _lldpctl_atom_set_int_med_policy,
	  .get_str = _lldpctl_atom_get_str_med_policy },
	{ atom_med_locations_list, sizeof(struct _lldpctl_atom_any_list_t),
	  .init = _lldpctl_atom_new_any_list,
	  .free = _lldpctl_atom_free_any_list,
	  .iter = _lldpctl_atom_iter_med_locations_list,
	  .next = _lldpctl_atom_next_med_locations_list,
	  .value = _lldpctl_atom_value_med_locations_list },
	{ atom_med_location, sizeof(struct _lldpctl_atom_med_location_t),
	  .init = _lldpctl_atom_new_med_location,
	  .free = _lldpctl_atom_free_med_location,
	  .get     = _lldpctl_atom_get_atom_med_location,
	  .set     = _lldpctl_atom_set_atom_med_location,
	  .get_int = _lldpctl_atom_get_int_med_location,
	  .set_int = _lldpctl_atom_set_int_med_location,
	  .get_str = _lldpctl_atom_get_str_med_location,
	  .set_str = _lldpctl_atom_set_str_med_location },
	{ atom_med_caelements_list, sizeof(struct _lldpctl_atom_med_caelements_list_t),
	  .init = _lldpctl_atom_new_any_list,
	  .free = _lldpctl_atom_free_any_list,
	  .iter = _lldpctl_atom_iter_med_caelements_list,
	  .next = _lldpctl_atom_next_med_caelements_list,
	  .value = _lldpctl_atom_value_med_caelements_list,
	  .create = _lldpctl_atom_create_med_caelements_list },
	{ atom_med_caelement, sizeof(struct _lldpctl_atom_med_caelement_t),
	  .init = _lldpctl_atom_new_med_caelement,
	  .free = _lldpctl_atom_free_med_caelement,
	  .get_int = _lldpctl_atom_get_int_med_caelement,
	  .set_int = _lldpctl_atom_set_int_med_caelement,
	  .get_str = _lldpctl_atom_get_str_med_caelement,
	  .set_str = _lldpctl_atom_set_str_med_caelement },
	{ atom_med_power, sizeof(struct _lldpctl_atom_med_power_t),
	  .init = _lldpctl_atom_new_med_power,
	  .free = _lldpctl_atom_free_med_power,
	  .get_int = _lldpctl_atom_get_int_med_power,
	  .set_int = _lldpctl_atom_set_int_med_power,
	  .get_str = _lldpctl_atom_get_str_med_power,
	  .set_str = _lldpctl_atom_set_str_med_power },
#endif
	{ 0 }
};

lldpctl_atom_t*
_lldpctl_new_atom(lldpctl_conn_t *conn, atom_t type, ...)
{
	struct atom_builder *builder;
	struct lldpctl_atom_t *atom;
	va_list(ap);
	for (builder = builders; builder->size > 0; builder++) {
		if (builder->type != type) continue;
		atom = calloc(1, builder->size);
		if (atom == NULL) {
			SET_ERROR(conn, LLDPCTL_ERR_NOMEM);
			return NULL;
		}
		atom->count = 1;
		atom->type  = type;
		atom->conn  = conn;
		TAILQ_INIT(&atom->buffers);
		atom->free  = builder->free;

		atom->iter  = builder->iter;
		atom->next  = builder->next;
		atom->value = builder->value;

		atom->get       = builder->get;
		atom->get_str   = builder->get_str;
		atom->get_buffer= builder->get_buffer;
		atom->get_int   = builder->get_int;

		atom->set       = builder->set;
		atom->set_str   = builder->set_str;
		atom->set_buffer= builder->set_buffer;
		atom->set_int   = builder->set_int;
		atom->create    = builder->create;

		va_start(ap, type);
		if (builder->init && builder->init(atom, ap) == 0) {
			free(atom);
			va_end(ap);
			/* Error to be set in init() */
			return NULL;
		}
		va_end(ap);
		return atom;
	}
	LLOG_WARNX("unknown atom type: %d", type);
	SET_ERROR(conn, LLDPCTL_ERR_FATAL);
	return NULL;
}

/**
 * Allocate a buffer inside an atom.
 *
 * It will be freed automatically when the atom is released. This buffer cannot
 * be reallocated and should not be freed!
 *
 * @param atom Atom which will be used as a container.
 * @param size Size of the allocated area.
 * @return Pointer to the buffer or @c NULL if allocation fails.
 */
void*
_lldpctl_alloc_in_atom(lldpctl_atom_t *atom, size_t size)
{
	struct atom_buffer *buffer;

	if ((buffer = calloc(1, size + sizeof(struct atom_buffer))) == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOMEM);
		return NULL;
	}
	TAILQ_INSERT_TAIL(&atom->buffers, buffer, next);
	return &buffer->data[0];
}

/**
 * Allocate a buffer inside an atom and dump another buffer in it.
 *
 * The dump is done in hexadecimal with the provided separator.
 *
 * @param atom   Atom which will be used as a container.
 * @param input  Buffer we want to dump.
 * @param size   Size of the buffer
 * @param sep    Separator to use.
 * @param max    Maximum number of bytes to dump. Can be 0 if no maximum.
 * @return A string representing the dump of the buffer or @c NULL if error.
 */
const char*
_lldpctl_dump_in_atom(lldpctl_atom_t *atom,
    const uint8_t *input, size_t size,
    char sep, size_t max)
{
	static const char truncation[] = "[...]";
	size_t i, len;
	char *buffer = NULL;

	if (max > 0 && size > max)
		len = max * 3 + sizeof(truncation) + 1;
	else
		len = size * 3 + 1;

	if ((buffer = _lldpctl_alloc_in_atom(atom, len)) == NULL)
		return NULL;

	for (i = 0; (i < size) && (max == 0 || i < max); i++)
		sprintf(buffer + i * 3, "%02x%c", *(u_int8_t*)(input + i), sep);
	if (max > 0 && size > max)
		sprintf(buffer + i * 3, "%s", truncation);
	else
		*(buffer + i*3 - 1) = 0;
	return buffer;
}
