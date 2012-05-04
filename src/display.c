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

#include "lldpctl.h"

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

TAILQ_HEAD(interfaces, lldpd_interface);

#define ntohll(x) (((u_int64_t)(ntohl((int)((x << 32) >> 32))) << 32) |	\
	    (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)

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

#ifdef ENABLE_LLDPMED
static const struct value_string chassis_med_type_map[] = {
	{ LLDPMED_CLASS_I,        "Generic Endpoint (Class I)" },
	{ LLDPMED_CLASS_II,       "Media Endpoint (Class II)" },
	{ LLDPMED_CLASS_III,      "Communication Device Endpoint (Class III)" },
	{ LLDPMED_NETWORK_DEVICE, "Network Connectivity Device" },
	{ 0, NULL },
};

static const struct value_string lldpmed_capabilit_map[] = {
	{LLDPMED_CAP_CAP,	"Capabilities"},
	{LLDPMED_CAP_POLICY,	"Policy"},
	{LLDPMED_CAP_LOCATION,	"Location"},
	{LLDPMED_CAP_MDI_PSE,	"MDI/PSE"},
	{LLDPMED_CAP_MDI_PD,	"MDI/PD"},
	{LLDPMED_CAP_IV,	"Inventory"},
	{ 0, NULL },
};

static const struct value_string port_med_policy_map[] = {
	{ LLDPMED_APPTYPE_VOICE ,           "Voice"},
	{ LLDPMED_APPTYPE_VOICESIGNAL,      "Voice Signaling"},
	{ LLDPMED_APPTYPE_GUESTVOICE,       "Guest Voice"},
	{ LLDPMED_APPTYPE_GUESTVOICESIGNAL, "Guest Voice Signaling"},
	{ LLDPMED_APPTYPE_SOFTPHONEVOICE,   "Softphone Voice"},
	{ LLDPMED_APPTYPE_VIDEOCONFERENCE,  "Video Conferencing"},
	{ LLDPMED_APPTYPE_VIDEOSTREAM,      "Streaming Video"},
	{ LLDPMED_APPTYPE_VIDEOSIGNAL,      "Video Signaling"},
	{ 0, NULL },
};

static const struct value_string civic_address_type_values[] = {
        { 0,    "Language" },
        { 1,    "National subdivisions" },
        { 2,    "County, parish, district" },
        { 3,    "City, township" },
        { 4,    "City division, borough, ward" },
        { 5,    "Neighborhood, block" },
        { 6,    "Street" },
        { 16,   "Leading street direction" },
        { 17,   "Trailing street suffix" },
        { 18,   "Street suffix" },
        { 19,   "House number" },
        { 20,   "House number suffix" },
        { 21,   "Landmark or vanity address" },
        { 22,   "Additional location info" },
        { 23,   "Name" },
        { 24,   "Postal/ZIP code" },
        { 25,   "Building" },
        { 26,   "Unit" },
        { 27,   "Floor" },
        { 28,   "Room number" },
        { 29,   "Place type" },
        { 128,  "Script" },
        { 0, NULL }
};

static const struct value_string civic_address_type_tags[] = {
        { 0,    "language" },
        { 1,    "country-subdivision" },
        { 2,    "county" },
        { 3,    "city" },
        { 4,    "city-division" },
        { 5,    "block" },
        { 6,    "street" },
        { 16,   "direction" },
        { 17,   "street-suffix" },
        { 18,   "street-suffix" },
        { 19,   "number" },
        { 20,   "number-suffix" },
        { 21,   "landmark" },
        { 22,   "additional" },
        { 23,   "name" },
        { 24,   "zip" },
        { 25,   "building" },
        { 26,   "unit" },
        { 27,   "floor" },
        { 28,   "room" },
        { 29,   "place-type" },
        { 128,  "Script" },
        { 0, NULL }
};

static const struct value_string port_med_geoid_map[] = {
	{ 1, "WGS84" },
	{ 2, "NAD83" },
	{ 3, "NAD83/MLLW" },
	{ 0, NULL },
};

static const struct value_string port_med_pow_devicetype_map[] = {
	{ LLDPMED_POW_TYPE_PSE, "PSE Device" },
	{ LLDPMED_POW_TYPE_PD,  "PD Device" },
	{ 0, NULL },
};

static const struct value_string port_med_pow_source_map[] = {
	{ LLDPMED_POW_SOURCE_PRIMARY, "Primary Power Source" },
	{ LLDPMED_POW_SOURCE_BACKUP,  "Backup Power Source / Power Conservation Mode" },
	{ LLDPMED_POW_SOURCE_PSE,     "PSE" },
	{ LLDPMED_POW_SOURCE_LOCAL,   "Local"},
	{ LLDPMED_POW_SOURCE_BOTH,    "PSE + Local"},
	{ 0, NULL },
};

static const struct value_string port_med_pow_priority_map[] = {
	{ LLDPMED_POW_PRIO_CRITICAL, "critical" },
	{ LLDPMED_POW_PRIO_HIGH,     "high" },
	{ LLDPMED_POW_PRIO_LOW,      "low" },
	{ 0, NULL },
};
#endif

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
	{ LLDPMED_POW_PRIO_CRITICAL, "critical" },
	{ LLDPMED_POW_PRIO_HIGH,     "high" },
	{ LLDPMED_POW_PRIO_LOW,      "low" },
	{ 0, NULL },
};
#endif

static const struct value_string chassis_capability_map[] = {
	{ LLDP_CAP_OTHER,    "Other" },
	{ LLDP_CAP_REPEATER, "Repeater"},
	{ LLDP_CAP_BRIDGE,   "Bridge"},
	{ LLDP_CAP_ROUTER,   "Router"},
	{ LLDP_CAP_WLAN,     "Wlan"},
	{ LLDP_CAP_TELEPHONE,"Telephone"},
	{ LLDP_CAP_DOCSIS,   "Docsis"},
	{ LLDP_CAP_STATION,  "Station"},
	{ 0, NULL},
};


static const char*
map_lookup(const struct value_string * list, int n)
{

	unsigned int i;

	for( i = 0; list[i].string != NULL; i ++ ) {
		if( list[i].value == n ) {
			return list[i].string;
		}
	}

	return "unknown";
}

static char*
u2str(unsigned n)
{
	static char buf[21];
	snprintf(buf, sizeof(buf), "%u", n);
	return buf;
}

static char*
dump(void *data, int size, int max, char sep)
{
	int			 i;
	size_t			 len;
	static char		*buffer = NULL;
	static char		 truncation[] = "[...]";

	free(buffer);
	if (size > max)
		len = max * 3 + sizeof(truncation) + 1;
	else
		len = size * 3;

	if ((buffer = (char *)malloc(len)) == NULL)
		fatal(NULL);

	for (i = 0; (i < size) && (i < max); i++)
		sprintf(buffer + i * 3, "%02x%c", *(u_int8_t*)(data + i), sep);
	if (size > max)
		sprintf(buffer + i * 3, "%s", truncation);
	else
		*(buffer + i*3 - 1) = 0;
	return buffer;
}

static void
display_cap(struct writer * w, struct lldpd_chassis *chassis, u_int8_t bit, char *symbol)
{
	if (chassis->c_cap_available & bit) {
		tag_start(w, "capability", "Capability");
		tag_attr (w, "type", "", symbol );
		tag_attr (w, "enabled", "", (chassis->c_cap_enabled & bit)?"on":"off"); 
		tag_end  (w);
	}
}

#ifdef ENABLE_LLDPMED
static int
display_fixed_precision(u_int64_t value, int intpart, int floatpart, int displaysign, char ** res)
{
	static char buf[64]; 
	u_int64_t tmp = value;
	int negative = 0;
	u_int32_t integer = 0;
	if (value & (1ULL<<(intpart + floatpart - 1))) {
		negative = 1;
		tmp = ~value;
		tmp += 1;
	}
	integer = (u_int32_t)((tmp &
		(((1ULL << intpart)-1) << floatpart)) >> floatpart);
	tmp = (tmp & ((1<< floatpart) - 1))*10000/(1ULL << floatpart);
	snprintf(buf, sizeof(buf),"%s%u.%04llu", displaysign?(negative?"-":"+"):"",
	    integer, (unsigned long long int)tmp);

	*res = buf;

	return negative;
}

static void
display_latitude_or_longitude(struct writer *w, int option, u_int64_t value)
{
	static char buf[70]; 
	int negative;
	char * str;

	if ( option == 0 ) {
		tag_start(w, "lat", "Latitude");
	} else {
		tag_start(w, "lon", "Longitude");
	}
	negative = display_fixed_precision(value, 9, 25, 0, &str);
	if (option == 0)
		snprintf(buf, sizeof(buf), "%s %s", str, negative?" S":" N");
	else
		snprintf(buf, sizeof(buf), "%s %s", str, negative?" W":" E");

	tag_data(w, buf);
	tag_end(w);
}

static void
display_med_capability(struct writer *w, struct lldpd_chassis *chassis, int cap)
{
	if (chassis->c_med_cap_available & cap) {
		tag_start(w, "capability", "Capability");
		tag_attr(w, "type", "",
			map_lookup(lldpmed_capabilit_map, cap));
		tag_end(w);
	}
}

static void
display_med(struct writer *w, struct lldpd_chassis *chassis, struct lldpd_port *port)
{
	int i;
	char *value;

	tag_start(w, "lldp-med", "LLDP-MED");

	tag_datatag(w, "device-type", "Device Type",
		map_lookup(chassis_med_type_map, chassis->c_med_type));

	display_med_capability(w, chassis, LLDPMED_CAP_CAP);
	display_med_capability(w, chassis, LLDPMED_CAP_POLICY);
	display_med_capability(w, chassis, LLDPMED_CAP_LOCATION);
	display_med_capability(w, chassis, LLDPMED_CAP_MDI_PSE);
	display_med_capability(w, chassis, LLDPMED_CAP_MDI_PD);
	display_med_capability(w, chassis, LLDPMED_CAP_IV);

	for (i = 0; i < LLDPMED_APPTYPE_LAST; i++) {
		if (i+1 == port->p_med_policy[i].type) {
			tag_start(w, "policy", "LLDP-MED Network Policy for");
			tag_attr(w, "apptype", "AppType",
				 u2str(port->p_med_policy[i].type));
			tag_attr(w, "defined", "Defined",
			         (port->p_med_policy[i].unknown)?"no":"yes");

			tag_datatag(w, "descr", "",
			    map_lookup(port_med_policy_map, port->p_med_policy[i].type));

			if (port->p_med_policy[i].tagged) {
				tag_start(w, "vlan", "VLAN");
				if (port->p_med_policy[i].vid == 0) {
					tag_attr(w, "vid", "", "priority");
				} else if (port->p_med_policy[i].vid == 4095) {
					tag_attr(w, "vid", "", "reserved");
				} else {
					tag_attr(w, "vid", "",
						 u2str(port->p_med_policy[i].vid));
				}
				tag_end(w);
			}

			tag_datatag(w, "priority", "Layer 2 Priority",
				    u2str(port->p_med_policy[i].priority));

			tag_datatag(w, "dscp", "DSCP Value",
				    u2str(port->p_med_policy[i].dscp));

			tag_end(w);
		}
	}
	for (i = 0; i < LLDPMED_LOCFORMAT_LAST; i++) {
		if (i+1 == port->p_med_location[i].format) {
			tag_start(w, "location", "LLDP-MED Location Identification");

			switch(port->p_med_location[i].format) {
			case LLDPMED_LOCFORMAT_COORD:
				tag_attr(w, "type", "Type", "coordinates");

				if (port->p_med_location[i].data_len != 16) {
					tag_datatag(w, "error", "Error", "bad data length");
				} else {
					u_int64_t l;
					u_int8_t  v;
					char *    s;

					v = *(u_int8_t*)(port->p_med_location[i].data + 15);
					tag_attr(w, "geoid", "Geoid",
						 map_lookup(port_med_geoid_map,v));

					/* Latitude and longitude */
					memcpy(&l, port->p_med_location[i].data,
					    sizeof(u_int64_t));
					l = (ntohll(l) &
					    0x03FFFFFFFF000000ULL) >> 24;
					display_latitude_or_longitude(w,0, l);
					memcpy(&l, port->p_med_location[i].data + 5,
					    sizeof(u_int64_t));
					l = (ntohll(l) &
					    0x03FFFFFFFF000000ULL) >> 24;
					display_latitude_or_longitude(w,1, l);

					/* Altitude */
					memcpy(&l, port->p_med_location[i].data + 10,
					    sizeof(u_int64_t));
					l = (ntohll(l) &
					    0x3FFFFFFF000000ULL) >> 24;
					display_fixed_precision(l, 22, 8, 1, &s);

					tag_start(w, "altitude", "Altitude");
					switch ((*(u_int8_t*)(port->p_med_location[i].data +
						    10)) & 0xf0) {
					case (1 << 4):
						tag_attr(w, "unit", "", "m");
						break;
					case (2 << 4):
						tag_attr(w, "unit", "", "floor");
						break;
					default:
						tag_attr(w, "unit", "", "unknown");
					}
					tag_data(w,s);
					tag_end(w);

				}
				break;
			case LLDPMED_LOCFORMAT_CIVIC:
				tag_attr(w, "type", "Type", "address");

				if ((port->p_med_location[i].data_len < 3) ||
				    (port->p_med_location[i].data_len - 1 !=
					*(u_int8_t*)port->p_med_location[i].data)) {
					tag_datatag(w, "error", "Error", "bad data length");
				} else {
					int l = 4, n, catype, calength; 
					char country[3];
					country[0] = ((char *)port->p_med_location[i].data)[2];
					country[1] = ((char *)port->p_med_location[i].data)[3];
					country[2] = 0;

					tag_datatag(w, "country", "Country", country);

					while ((n = (port->
						    p_med_location[i].data_len - l)) >= 2) {
						catype = *(u_int8_t*)(port->
						    p_med_location[i].data + l);
						calength = *(u_int8_t*)(port->
						    p_med_location[i].data + l + 1);
						if (n < 2 + calength) {
							tag_datatag(w, "error", "Error", "bad data length");
							break;
						}

						if ((value = strndup((char *)(port->
							p_med_location[i].data + l + 2),
							    calength)) == NULL) {
							fatalx("not enough memory");
							break;
						}
						tag_datatag(w,
							map_lookup(civic_address_type_tags,catype),
							map_lookup(civic_address_type_values,catype),
							value);
						free(value);
						l += 2 + calength;
					}
				}
				break;
			case LLDPMED_LOCFORMAT_ELIN:
				if ((value = strndup((char *)(port->
						p_med_location[i].data),
					    port->p_med_location[i].data_len)) == NULL) {
					fatalx( "not enough memory");
					break;
				}
				tag_attr(w, "type", "Type", "elin");
				tag_datatag(w, "ecs", "ECS ELIN", value);
				free(value);
				break;
			default:
				tag_attr(w, "type", "", "unknown");
				tag_datatag(w, "unknown", "Data",
					dump(port->p_med_location[i].data,
				             port->p_med_location[i].data_len, 20, ' '));
			}
			tag_end(w);
		}
	}
	if (port->p_med_power.devicetype) {
		tag_start(w, "poe", "Extended Power-over-Ethernet");

		tag_start(w, "device-type", "Power Type & Source");
		tag_data(w, map_lookup(port_med_pow_devicetype_map, port->p_med_power.devicetype));
		tag_end(w);

		tag_start(w, "source", "Power Source");
		tag_data(w, map_lookup(port_med_pow_source_map, port->p_med_power.source));
		tag_end(w);
		
		tag_start(w, "priority", "Power Priority");
		tag_data(w, map_lookup(port_med_pow_priority_map, port->p_med_power.priority));
		tag_end(w);

		if(port->p_med_power.val < 1024) {
			tag_start(w, "power", "Power Value");
			tag_data(w, u2str(port->p_med_power.val * 100));
			tag_end(w);
		}
		tag_end(w);
	}
	if (chassis->c_med_hw ||
	    chassis->c_med_sw ||
	    chassis->c_med_fw ||
	    chassis->c_med_sn ||
	    chassis->c_med_manuf ||
	    chassis->c_med_model ||
	    chassis->c_med_asset) {
		tag_start(w, "inventory", "Inventory");

		if (chassis->c_med_hw)
			tag_datatag(w, "hardware", "Hardware Revision",
					chassis->c_med_hw);
		if (chassis->c_med_sw)
			tag_datatag(w, "software", "Software Revision",
					chassis->c_med_sw);
		if (chassis->c_med_fw)
			tag_datatag(w, "firmware", "Firmware Revision",
					chassis->c_med_fw);
		if (chassis->c_med_sn)
			tag_datatag(w, "serial", "Serial Number",
					chassis->c_med_sn);
		if (chassis->c_med_manuf)
			tag_datatag(w, "manufacturer", "Manufacturer",
					chassis->c_med_manuf);
		if (chassis->c_med_model)
			tag_datatag(w, "model", "Model",
					chassis->c_med_model);
		if (chassis->c_med_asset)
			tag_datatag(w, "asset", "Asset ID",
					chassis->c_med_asset);

		tag_end(w);
	}

	tag_end(w);
}
#endif

static void
display_chassis(struct writer * w, struct lldpd_chassis *chassis)
{
	char *cid;
	struct in_addr ip;
	struct lldpd_mgmt *mgmt;
	char addrbuf[INET6_ADDRSTRLEN];

	if ((cid = (char *)malloc(chassis->c_id_len + 1)) == NULL)
		fatal(NULL);
	memcpy(cid, chassis->c_id, chassis->c_id_len);
	cid[chassis->c_id_len] = 0;

	tag_start(w, "chassis", "Chassis");
	tag_start(w, "id", "ChassisID");
	tag_attr (w, "type", "", map_lookup(chassis_id_subtype_map, chassis->c_id_subtype));

	switch (chassis->c_id_subtype) {
	case LLDP_CHASSISID_SUBTYPE_IFNAME:
	case LLDP_CHASSISID_SUBTYPE_IFALIAS:
	case LLDP_CHASSISID_SUBTYPE_LOCAL:
		tag_data (w, cid);
		break;
	case LLDP_CHASSISID_SUBTYPE_LLADDR:
		tag_data(w, dump(chassis->c_id, chassis->c_id_len, ETH_ALEN, ':'));
		break;
	case LLDP_CHASSISID_SUBTYPE_ADDR:
		if (*(u_int8_t*)chassis->c_id == 1) {
			memcpy(&ip, chassis->c_id + 1, sizeof(struct in_addr));
			tag_data(w, inet_ntoa(ip));
			break;
		}
	case LLDP_CHASSISID_SUBTYPE_PORT:
	case LLDP_CHASSISID_SUBTYPE_CHASSIS:
	default:
		tag_data(w, dump(chassis->c_id, chassis->c_id_len, 16, ' '));
	}

	tag_end(w);
	
	tag_datatag(w, "name", "SysName", chassis->c_name);
	tag_datatag(w, "descr", "SysDescr", chassis->c_descr);

	TAILQ_FOREACH(mgmt, &chassis->c_mgmt, m_entries) {
		memset(addrbuf, 0, sizeof(addrbuf));
		inet_ntop(lldpd_af(mgmt->m_family), &mgmt->m_addr, addrbuf, sizeof(addrbuf));
		switch (mgmt->m_family) {
		case LLDPD_AF_IPV4:
			tag_datatag(w, "mgmt-ip", "MgmtIP", addrbuf);
			break;
		case LLDPD_AF_IPV6:
			tag_datatag(w, "mgmt-ip6", "MgmtIPv6", addrbuf);
			break;
		}
	}

	display_cap(w, chassis, LLDP_CAP_OTHER, "Other");
	display_cap(w, chassis, LLDP_CAP_REPEATER, "Repeater");
	display_cap(w, chassis, LLDP_CAP_BRIDGE, "Bridge");
	display_cap(w, chassis, LLDP_CAP_ROUTER, "Router");
	display_cap(w, chassis, LLDP_CAP_WLAN, "Wlan");
	display_cap(w, chassis, LLDP_CAP_TELEPHONE, "Tel");
	display_cap(w, chassis, LLDP_CAP_DOCSIS, "Docsis");
	display_cap(w, chassis, LLDP_CAP_STATION, "Station");

	tag_end(w);
}

#ifdef ENABLE_DOT3
static void
display_autoneg(struct writer * w, struct lldpd_port *port, int bithd, int bitfd, char *desc)
{
	if (!((port->p_macphy.autoneg_advertised & bithd) ||
		(port->p_macphy.autoneg_advertised & bitfd)))
		return;

	tag_start(w, "advertised", "Adv");
	tag_attr(w, "type", "", desc);
	tag_attr(w, "hd", "HD", (port->p_macphy.autoneg_advertised & bithd)?"yes":"no");
	tag_attr(w, "fd", "FD", (port->p_macphy.autoneg_advertised)?"yes":"no");
	tag_end (w);
}
#endif

static void
display_port(struct writer * w, struct lldpd_port *port)
{
	char *pid;
	struct in_addr address;

	if ((pid = (char *)malloc(port->p_id_len + 1)) == NULL)
		fatal(NULL);
	memcpy(pid, port->p_id, port->p_id_len);
	pid[port->p_id_len] = 0;

	tag_start(w, "port", "Port");
	tag_start(w, "id", "PortID");
	tag_attr (w, "type", "", map_lookup(port_id_subtype_map, port->p_id_subtype));

	switch (port->p_id_subtype) {
	case LLDP_PORTID_SUBTYPE_IFNAME:
	case LLDP_PORTID_SUBTYPE_IFALIAS:
	case LLDP_PORTID_SUBTYPE_LOCAL:
		tag_data (w, pid);
		break;
	case LLDP_PORTID_SUBTYPE_LLADDR:
		tag_data(w, dump(port->p_id, port->p_id_len, ETH_ALEN, ':'));
		break;
	case LLDP_PORTID_SUBTYPE_ADDR:
		if (*(u_int8_t*)port->p_id == 1) {
			memcpy(&address, port->p_id + 1,
			    sizeof(struct in_addr));
			tag_data(w, inet_ntoa(address));
			break;
		}
	case LLDP_PORTID_SUBTYPE_PORT:
	case LLDP_PORTID_SUBTYPE_AGENTCID:
	default:
		tag_data(w, dump(port->p_id, port->p_id_len, 16, ' '));
	}

	tag_end(w);

	tag_datatag(w, "descr", "PortDescr", port->p_descr);

#ifdef ENABLE_DOT3
	if (port->p_mfs)
		tag_datatag(w, "mfs", "MFS", u2str(port->p_mfs));

	if (port->p_aggregid)
		tag_datatag(w, "aggregation", " Port is aggregated. PortAggregID",
		            u2str(port->p_aggregid));

	if (port->p_macphy.autoneg_support || port->p_macphy.autoneg_enabled ||
	    port->p_macphy.mau_type) {
		tag_start(w, "auto-negotiation", "PMD autoneg");
		tag_attr (w, "supported", "supported",
		    port->p_macphy.autoneg_support?"yes":"no");
		tag_attr (w, "enabled", "enabled",
		    port->p_macphy.autoneg_enabled?"yes":"no");

		if (port->p_macphy.autoneg_enabled) {
			display_autoneg(w, port, LLDP_DOT3_LINK_AUTONEG_10BASE_T,
			    LLDP_DOT3_LINK_AUTONEG_10BASET_FD,
			    "10Base-T");
			display_autoneg(w, port, LLDP_DOT3_LINK_AUTONEG_100BASE_TX,
			    LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD,
			    "100Base-T");
			display_autoneg(w, port, LLDP_DOT3_LINK_AUTONEG_100BASE_T2,
			    LLDP_DOT3_LINK_AUTONEG_100BASE_T2FD,
			    "100Base-T2");
			display_autoneg(w, port, LLDP_DOT3_LINK_AUTONEG_1000BASE_X,
			    LLDP_DOT3_LINK_AUTONEG_1000BASE_XFD,
			    "100Base-X");
			display_autoneg(w, port, LLDP_DOT3_LINK_AUTONEG_1000BASE_T,
			    LLDP_DOT3_LINK_AUTONEG_1000BASE_TFD,
			    "1000Base-T");
		}
		tag_datatag(w, "current", "MAU oper type",
			map_lookup(operational_mau_type_values, port->p_macphy.mau_type));
		tag_end(w);
	}
	if (port->p_power.devicetype) {
		tag_start(w, "power", "MDI Power");
		tag_attr(w, "supported", "supported",
		    port->p_power.supported?"yes":"no");
		tag_attr(w, "enabled", "enabled",
		    port->p_power.enabled?"yes":"no");
		tag_attr(w, "paircontrol", "pair control",
		    port->p_power.paircontrol?"yes":"no");
		tag_start(w, "device-type", "Device type");
		tag_data(w, map_lookup(port_dot3_power_devicetype_map,
			port->p_power.devicetype));
		tag_end(w);
		tag_start(w, "pairs", "Power pairs");
		tag_data(w, map_lookup(port_dot3_power_pairs_map,
			port->p_power.pairs));
		tag_end(w);
		tag_start(w, "class", "Class");
		tag_data(w, map_lookup(port_dot3_power_class_map,
			port->p_power.class));
		tag_end(w);

		/* 802.3at */
		if (port->p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			tag_start(w, "power-type", "Power type");
			tag_data(w, u2str(port->p_power.powertype));
			tag_end(w);

			tag_start(w, "source", "Power Source");
			tag_data(w, map_lookup(
				    (port->p_power.devicetype == LLDP_DOT3_POWER_PSE)?
					port_dot3_power_pse_source_map:
					port_dot3_power_pd_source_map,
					port->p_power.source));
			tag_end(w);

			tag_start(w, "priority", "Power Priority");
			tag_data(w, map_lookup(port_dot3_power_priority_map,
				port->p_power.priority));
			tag_end(w);

			tag_start(w, "requested", "PD requested power Value");
			tag_data(w, u2str(port->p_power.requested * 100));
			tag_end(w);

			tag_start(w, "allocated", "PSE allocated power Value");
			tag_data(w, u2str(port->p_power.allocated * 100));
			tag_end(w);
		}

		tag_end(w);
	}
#endif
	tag_end(w);
}

#ifdef ENABLE_DOT1
static void
display_vlans(struct writer *w, struct lldpd_port *port)
{
	int foundpvid = 0;
	struct lldpd_vlan *vlan;
	TAILQ_FOREACH(vlan, &port->p_vlans, v_entries) {
		if (port->p_pvid == vlan->v_vid)
			foundpvid = 1;

		tag_start(w, "vlan", "VLAN");
		tag_attr(w, "vlan-id", "", u2str(vlan->v_vid));
		if (port->p_pvid == vlan->v_vid)
			tag_attr(w, "pvid", "pvid", "yes");
		tag_data(w, vlan->v_name);
		tag_end(w);
	}
	if (!foundpvid && port->p_pvid) {
		tag_start(w, "vlan", "VLAN");
		tag_attr(w, "vlan-id", "", u2str(port->p_pvid));
		tag_attr(w, "pvid", "pvid", "yes");
		tag_end(w);
	}
}

static void
display_ppvids(struct writer *w, struct lldpd_port *port)
{
	struct lldpd_ppvid *ppvid;
	TAILQ_FOREACH(ppvid, &port->p_ppvids, p_entries) {
		tag_start(w, "ppvid", "PPVID");
		if (ppvid->p_ppvid)
			tag_attr(w, "value", "", u2str(ppvid->p_ppvid));
		tag_attr(w, "supported", "supported",
			 (ppvid->p_cap_status & LLDPD_PPVID_CAP_SUPPORTED)?"yes":"no");
		tag_attr(w, "enabled", "enabled",
			 (ppvid->p_cap_status & LLDPD_PPVID_CAP_ENABLED)?"yes":"no");
		tag_end(w);
	}
}

static void
display_pids(struct writer *w, struct lldpd_port *port)
{
	struct lldpd_pi *pi;
	char *hex;
	TAILQ_FOREACH(pi, &port->p_pids, p_entries) {
		if (!pi->p_pi_len) continue;
		tag_start(w, "pi", "PI");
		/* Convert to hex for display */
		if ((hex = malloc(pi->p_pi_len * 2 + 1)) == NULL)
			fatal(NULL);
		for (int i = 0; i < pi->p_pi_len; i++)
			snprintf(hex + 2*i, 3, "%02X", (unsigned char)pi->p_pi[i]);
		tag_data(w, hex);
		tag_end(w);
		free(hex);
	}
}
#endif

static const char*
display_age(struct lldpd_port *port)
{
	static char sage[30];
	int age = (int)(time(NULL) - port->p_lastchange);
	if (snprintf(sage, sizeof(sage),
		"%d day%s, %02d:%02d:%02d",
		age / (60*60*24),
		(age / (60*60*24) > 1)?"s":"",
		(age / (60*60)) % 24,
		(age / 60) % 60,
		age % 60) >= sizeof(sage))
		return "too much";
	else
		return sage;
}

void
display_interfaces(int s, const char * fmt, int hidden, int argc, char *argv[])
{
	int i;
	struct writer * w;
	char sep[80];
	struct lldpd_interface *iff;
	struct lldpd_interface_list *ifs;
	struct lldpd_port *port;
	struct lldpd_chassis *chassis;
	struct lldpd_hardware *hardware;

	if ( strcmp(fmt,"plain") == 0 ) {
		w = txt_init( stdout );
	} else if (strcmp(fmt, "keyvalue") == 0) {
		w = kv_init( stdout );
	}
#ifdef USE_XML
	else if ( strcmp(fmt,"xml") == 0 ) {
		w = xml_init( stdout );
	}
#endif
	else {
		w = txt_init( stdout );
	}

	memset(sep, '-', 79);
	sep[79] = 0;

	ifs = get_interfaces(s);
	tag_start(w, "lldp", "LLDP neighbors");
	
	TAILQ_FOREACH(iff, ifs, next) {
		if (optind < argc) {
			for (i = optind; i < argc; i++)
				if (strncmp(argv[i], iff->name, IFNAMSIZ) == 0)
					break;
			if (i == argc)
				continue;
		}
		
		hardware = get_interface(s, iff->name);
		if (TAILQ_EMPTY(&hardware->h_rports))
			continue;
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
			if (!hidden && SMART_HIDDEN(port)) continue;
			chassis = port->p_chassis;

			tag_start(w, "interface", "Interface");
			tag_attr(w, "name", "", iff->name );
			tag_attr(w, "via" , "via", map_lookup(lldpd_protocol_map, port->p_protocol));
			tag_attr(w, "rid" , "RID", u2str(chassis->c_index));
			tag_attr(w, "age" , "Time", display_age(port));

			display_chassis(w,chassis);
			display_port(w, port);
#ifdef ENABLE_DOT1
			if (!TAILQ_EMPTY(&port->p_vlans) || port->p_pvid) {
				display_vlans(w, port);
			}
			if (!TAILQ_EMPTY(&port->p_ppvids)) {
				display_ppvids(w, port);
			}
			if (!TAILQ_EMPTY(&port->p_pids)) {
				display_pids(w, port);
			}
#endif
#ifdef ENABLE_LLDPMED
			if (port->p_med_cap_enabled) {
				display_med(w, chassis, port);
			}
#endif
			tag_end(w); /* interface */
		}
	}

	tag_end(w);
	w->finish(w);
}
