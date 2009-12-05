/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

static void		 usage(void);

TAILQ_HEAD(interfaces, lldpd_interface);
#ifdef ENABLE_DOT1
TAILQ_HEAD(vlans, lldpd_vlan);
#endif

#define ntohll(x) (((u_int64_t)(ntohl((int)((x << 32) >> 32))) << 32) |	\
	    (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)

#ifdef HAVE___PROGNAME
extern const char	*__progname;
#else
# define __progname "lldpctl"
#endif


struct value_string {
	int value;
	char *string;
};

#ifdef ENABLE_LLDPMED
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
#endif

static void
usage(void)
{
	fprintf(stderr, "usage: %s [options]\n", __progname);
	fprintf(stderr, "see manual page lldpctl(8) for more information\n");
	exit(1);
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
get_interfaces(int s, struct interfaces *ifs)
{
	void *p;
	struct hmsg *h;

	if ((h = (struct hmsg *)malloc(MAX_HMSGSIZE)) == NULL)
		fatal(NULL);
	ctl_msg_init(h, HMSG_GET_INTERFACES);
	if (ctl_msg_send(s, h) == -1)
		fatalx("get_interfaces: unable to send request");
	if (ctl_msg_recv(s, h) == -1)
		fatalx("get_interfaces: unable to receive answer");
	if (h->hdr.type != HMSG_GET_INTERFACES)
		fatalx("get_interfaces: unknown answer type received");
	p = &h->data;
	if (ctl_msg_unpack_list(STRUCT_LLDPD_INTERFACE,
		ifs, sizeof(struct lldpd_interface), h, &p) == -1)
		fatalx("get_interfaces: unable to retrieve the list of interfaces");
}

#ifdef ENABLE_DOT1
static int
get_vlans(int s, struct vlans *vls, char *interface, int nb)
{
	void *p;
	struct hmsg *h;

	if ((h = (struct hmsg *)malloc(MAX_HMSGSIZE)) == NULL)
		fatal(NULL);
	ctl_msg_init(h, HMSG_GET_VLANS);
	strlcpy((char *)&h->data, interface, IFNAMSIZ);
	memcpy((char*)&h->data + IFNAMSIZ, &nb, sizeof(int));
	h->hdr.len += IFNAMSIZ + sizeof(int);
	if (ctl_msg_send(s, h) == -1)
		fatalx("get_vlans: unable to send request");
	if (ctl_msg_recv(s, h) == -1)
		fatalx("get_vlans: unable to receive answer");
	if (h->hdr.type != HMSG_GET_VLANS)
		fatalx("get_vlans: unknown answer type received");
	p = &h->data;
	if (ctl_msg_unpack_list(STRUCT_LLDPD_VLAN,
		vls, sizeof(struct lldpd_vlan), h, &p) == -1)
		fatalx("get_vlans: unable to retrieve the list of vlans");
	return 1;
}
#endif

static int
get_chassis(int s, struct lldpd_chassis *chassis, char *interface, int nb)
{
	struct hmsg *h;
	void *p;

	if ((h = (struct hmsg *)malloc(MAX_HMSGSIZE)) == NULL)
		fatal(NULL);
	ctl_msg_init(h, HMSG_GET_CHASSIS);
	strlcpy((char *)&h->data, interface, IFNAMSIZ);
	memcpy((char*)&h->data + IFNAMSIZ, &nb, sizeof(int));
	h->hdr.len += IFNAMSIZ + sizeof(int);
	if (ctl_msg_send(s, h) == -1)
		fatalx("get_chassis: unable to send request to get chassis");
	if (ctl_msg_recv(s, h) == -1)
		fatalx("get_chassis: unable to receive answer to get chassis");
	if (h->hdr.type == HMSG_NONE)
		/* No chassis */
		return -1;
	p = &h->data;
	if (ctl_msg_unpack_structure(STRUCT_LLDPD_CHASSIS,
		chassis, sizeof(struct lldpd_chassis), h, &p) == -1) {
		LLOG_WARNX("unable to retrieve chassis for %s", interface);
		fatalx("get_chassis: abort");
	}
	return 1;
}

static int
get_port(int s, struct lldpd_port *port, char *interface, int nb)
{
	struct hmsg *h;
	void *p;

	if ((h = (struct hmsg *)malloc(MAX_HMSGSIZE)) == NULL)
		fatal(NULL);
	ctl_msg_init(h, HMSG_GET_PORT);
	strlcpy((char *)&h->data, interface, IFNAMSIZ);
	memcpy((char*)&h->data + IFNAMSIZ, &nb, sizeof(int));
	h->hdr.len += IFNAMSIZ + sizeof(int);
	if (ctl_msg_send(s, h) == -1)
		fatalx("get_port: unable to send request to get port");
	if (ctl_msg_recv(s, h) == -1)
		fatalx("get_port: unable to receive answer to get port");
	if (h->hdr.type == HMSG_NONE)
		/* No port */
		return -1;
	p = &h->data;
	if (ctl_msg_unpack_structure(STRUCT_LLDPD_PORT,
		port, sizeof(struct lldpd_port), h, &p) == -1) {
		LLOG_WARNX("unable to retrieve port information for %s",
		    interface);
		fatalx("get_chassis: abort");
	}
	return 1;
}

static int
get_nb_port(int s, char *interface)
{
	struct hmsg *h;
	int nb;

	if ((h = (struct hmsg *)malloc(MAX_HMSGSIZE)) == NULL)
		fatal(NULL);
	ctl_msg_init(h, HMSG_GET_NB_PORTS);
	strlcpy((char *)&h->data, interface, IFNAMSIZ);
	h->hdr.len += IFNAMSIZ;
	if (ctl_msg_send(s, h) == -1)
		fatalx("get_nb_port: unable to send request to get number of ports");
	if (ctl_msg_recv(s, h) == -1)
		fatalx("get_nb_port: unable to receive answer to get number of ports");
	if (h->hdr.type == HMSG_NONE)
		return -1;
	if (h->hdr.len != sizeof(int))
		fatalx("get_nb_port: bad message length");
	memcpy(&nb, &h->data, sizeof(int));
	return nb;
}

static void
display_cap(struct lldpd_chassis *chassis, u_int8_t bit, char *symbol)
{
	if (chassis->c_cap_available & bit)
		printf("%s(%c) ", symbol,
		    (chassis->c_cap_enabled & bit)?'E':'d');
}

static void
pretty_print(char *string)
{
	char *s = NULL;
	if (((s = strchr(string, '\n')) == NULL) && (strlen(string) < 60)) {
		printf("%s\n", string);
		return;
	} else
		printf("\n");
	while (s != NULL) {
		*s = '\0';
		printf("   %s\n", string);
		*s = '\n';
		string = s + 1;
		s = strchr(string, '\n');
	}
	printf("   %s\n", string);
}

#ifdef ENABLE_LLDPMED
static int
display_fixed_precision(u_int64_t value, int intpart, int floatpart, int displaysign)
{
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
	printf("%s%u.%04llu", displaysign?(negative?"-":"+"):"",
	    integer, (unsigned long long int)tmp);
	return negative;
}

static void
display_latitude_or_longitude(int option, u_int64_t value)
{
	int negative;
	negative = display_fixed_precision(value, 9, 25, 0);
	if (option == 0)
		printf("%s", negative?" South":" North");
	else
		printf("%s", negative?" West":" East");
}

static void
display_med(struct lldpd_chassis *chassis, struct lldpd_port *port)
{
	int i;
	char *value;
	printf(" LLDP-MED Device Type: ");
	switch (chassis->c_med_type) {
	case LLDPMED_CLASS_I:
		printf("Generic Endpoint (Class I)");
		break;
	case LLDPMED_CLASS_II:
		printf("Media Endpoint (Class II)");
		break;
	case LLDPMED_CLASS_III:
		printf("Communication Device Endpoint (Class III)");
		break;
	case LLDPMED_NETWORK_DEVICE:
		printf("Network Connectivity Device");
		break;
	default:
		printf("Unknown (%d)", chassis->c_med_type);
		break;
	}
	printf("\n LLDP-MED Capabilities:");
	if (chassis->c_med_cap_available & LLDPMED_CAP_CAP)
		printf(" Capabilities");
	if (chassis->c_med_cap_available & LLDPMED_CAP_POLICY)
		printf(" Policy");
	if (chassis->c_med_cap_available & LLDPMED_CAP_LOCATION)
		printf(" Location");
	if (chassis->c_med_cap_available & LLDPMED_CAP_MDI_PSE)
		printf(" MDI/PSE");
	if (chassis->c_med_cap_available & LLDPMED_CAP_MDI_PD)
		printf(" MDI/PD");
	if (chassis->c_med_cap_available & LLDPMED_CAP_IV)
		printf(" Inventory");
	printf("\n");
	for (i = 0; i < LLDPMED_APPTYPE_LAST; i++) {
		if (i+1 == port->p_med_policy[i].type) {
			printf(" LLDP-MED Network Policy for ");
			switch(port->p_med_policy[i].type) {
			case LLDPMED_APPTYPE_VOICE:
				printf("Voice");
				break;
			case LLDPMED_APPTYPE_VOICESIGNAL:
				printf("Voice Signaling");
				break;
			case LLDPMED_APPTYPE_GUESTVOICE:
				printf("Guest Voice");
				break;
			case LLDPMED_APPTYPE_GUESTVOICESIGNAL:
				printf("Guest Voice Signaling");
				break;
			case LLDPMED_APPTYPE_SOFTPHONEVOICE:
				printf("Softphone Voice");
				break;
			case LLDPMED_APPTYPE_VIDEOCONFERENCE:
				printf("Video Conferencing");
				break;
			case LLDPMED_APPTYPE_VIDEOSTREAM:
				printf("Streaming Video");
				break;
			case LLDPMED_APPTYPE_VIDEOSIGNAL:
				printf("Video Signaling");
				break;
			default:
				printf("Reserved");
			}
			printf(":\n  Policy:           ");
			if (port->p_med_policy[i].unknown) {
				printf("unknown, ");
			} else {
				printf("defined, ");
			}
			if (!port->p_med_policy[i].tagged) {
				printf("un");
			}
			printf("tagged");
			printf("\n  VLAN ID:          ");
			if (port->p_med_policy[i].vid == 0) {
				printf("Priority Tagged");
			} else if (port->p_med_policy[i].vid == 4095) {
				printf("reserved");
			} else {
				printf("%u", port->p_med_policy[i].vid);
			}
			printf("\n  Layer 2 Priority: ");
			printf("%u", port->p_med_policy[i].priority);
			printf("\n  DSCP Value:       ");
			printf("%u\n", port->p_med_policy[i].dscp);
		}
	}
	for (i = 0; i < LLDPMED_LOCFORMAT_LAST; i++) {
		if (i+1 == port->p_med_location[i].format) {
			printf(" LLDP-MED Location Identification: ");
			switch(port->p_med_location[i].format) {
			case LLDPMED_LOCFORMAT_COORD:
				printf("\n   Coordinate-based data: ");
				if (port->p_med_location[i].data_len != 16)
					printf("bad data length");
				else {
					u_int64_t l;

					/* Latitude and longitude */
					memcpy(&l, port->p_med_location[i].data,
					    sizeof(u_int64_t));
					l = (ntohll(l) &
					    0x03FFFFFFFF000000ULL) >> 24;
					display_latitude_or_longitude(0, l);
					printf(", ");
					memcpy(&l, port->p_med_location[i].data + 5,
					    sizeof(u_int64_t));
					l = (ntohll(l) &
					    0x03FFFFFFFF000000ULL) >> 24;
					display_latitude_or_longitude(1, l);

					/* Altitude */
					printf(", ");
					memcpy(&l, port->p_med_location[i].data + 10,
					    sizeof(u_int64_t));
					l = (ntohll(l) &
					    0x3FFFFFFF000000ULL) >> 24;
					display_fixed_precision(l, 22, 8, 1);
					switch ((*(u_int8_t*)(port->p_med_location[i].data +
						    10)) & 0xf0) {
					case (1 << 4):
						printf(" meters"); break;
					case (2 << 4):
						printf(" floors"); break;
					default:
						printf(" (unknown)");
					}

					/* Datum */
					switch (*(u_int8_t*)(port->p_med_location[i].data +
						    15)) {
					case 1:
						printf(", WGS84"); break;
					case 2:
						printf(", NAD83"); break;
					case 3:
						printf(", NAD83/MLLW"); break;
					}
				}
				break;
			case LLDPMED_LOCFORMAT_CIVIC:
				printf("Civic address: ");
				if ((port->p_med_location[i].data_len < 3) ||
				    (port->p_med_location[i].data_len - 1 !=
					*(u_int8_t*)port->p_med_location[i].data))
					printf("bad data length");
				else {
					int l = 4, n, catype, calength, j = 0;
					printf("\n%28s: %c%c", "Country",
					    ((char *)port->p_med_location[i].data)[2],
					    ((char *)port->p_med_location[i].data)[3]);
					while ((n = (port->
						    p_med_location[i].data_len - l)) >= 2) {
						catype = *(u_int8_t*)(port->
						    p_med_location[i].data + l);
						calength = *(u_int8_t*)(port->
						    p_med_location[i].data + l + 1);
						if (n < 2 + calength) {
							printf("bad data length");
							break;
						}
						for (j = 0;
						     civic_address_type_values[j].string != NULL;
						     j++) {
							if (civic_address_type_values[j].value ==
							    catype)
								break;
						}
						if (civic_address_type_values[j].string == NULL) {
							printf("unknown type %d", catype);
							break;
						}
						if ((value = strndup((char *)(port->
							p_med_location[i].data + l + 2),
							    calength)) == NULL) {
							printf("not enough memory");
							break;
						}
						printf("\n%28s: %s",
						    civic_address_type_values[j].string,
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
					printf("not enough memory");
					break;
				}
				printf("ECS ELIN: %s", value);
				free(value);
				break;
			default:
				printf("unknown location data format: \n   %s",
				    dump(port->p_med_location[i].data,
					port->p_med_location[i].data_len, 20, ' '));
			}
			printf("\n");
		}
	}
	if (port->p_med_pow_devicetype) {
		printf(" LLDP-MED Extended Power-over-Ethernet:\n");
		printf("  Power Type & Source: ");
		switch (port->p_med_pow_devicetype) {
		case LLDPMED_POW_TYPE_PSE:
			printf("PSE Device");
			break;
		case LLDPMED_POW_TYPE_PD:
			printf("PD Device");
			break;
		default:
			printf("reserved");
		}
		switch (port->p_med_pow_source) {
		case LLDPMED_POW_SOURCE_UNKNOWN:
		case LLDPMED_POW_SOURCE_RESERVED:
			printf(", unknown"); break;
		case LLDPMED_POW_SOURCE_PRIMARY:
			printf(", Primary Power Source");
			break;
		case LLDPMED_POW_SOURCE_BACKUP:
			printf(", Backup Power Source / Power Conservation Mode");
			break;
		case LLDPMED_POW_SOURCE_PSE:
			printf(", PSE"); break;
		case LLDPMED_POW_SOURCE_LOCAL:
			printf(", local"); break;
		case LLDPMED_POW_SOURCE_BOTH:
			printf(", PSE & local");
			break;
		}
		printf("\n  Power Priority:      ");
		switch (port->p_med_pow_priority) {
		case LLDPMED_POW_PRIO_CRITICAL:
			printf("critical"); break;
		case LLDPMED_POW_PRIO_HIGH:
			printf("high"); break;
		case LLDPMED_POW_PRIO_LOW:
			printf("low"); break;
		default:
			printf("unknown");
		}
		printf("\n  Power Value:         ");
		if(port->p_med_pow_val < 1024) {
			printf("%u mW", port->p_med_pow_val * 100);
		} else {
			printf("reserved");
		}
		printf("\n");
	}
	if (chassis->c_med_hw ||
	    chassis->c_med_sw ||
	    chassis->c_med_fw ||
	    chassis->c_med_sn ||
	    chassis->c_med_manuf ||
	    chassis->c_med_model ||
	    chassis->c_med_asset) {
		printf(" LLDP-MED Inventory:\n");
		if (chassis->c_med_hw)
			printf("   Hardware Revision: %s\n", chassis->c_med_hw);
		if (chassis->c_med_sw)
			printf("   Software Revision: %s\n", chassis->c_med_sw);
		if (chassis->c_med_fw)
			printf("   Firmware Revision: %s\n", chassis->c_med_fw);
		if (chassis->c_med_sn)
			printf("   Serial Number:     %s\n", chassis->c_med_sn);
		if (chassis->c_med_manuf)
			printf("   Manufacturer:      %s\n",
			       chassis->c_med_manuf);
		if (chassis->c_med_model)
			printf("   Model:             %s\n",
			       chassis->c_med_model);
		if (chassis->c_med_asset)
			printf("   Asset ID:          %s\n",
			       chassis->c_med_asset);
	}
}
#endif

static void
display_chassis(struct lldpd_chassis *chassis)
{
	char *cid;
	if ((cid = (char *)malloc(chassis->c_id_len + 1)) == NULL)
		fatal(NULL);
	memcpy(cid, chassis->c_id, chassis->c_id_len);
	cid[chassis->c_id_len] = 0;
	switch (chassis->c_id_subtype) {
	case LLDP_CHASSISID_SUBTYPE_IFNAME:
		printf(" ChassisID: %s (ifName)\n", cid);
		break;
	case LLDP_CHASSISID_SUBTYPE_IFALIAS:
		printf(" ChassisID: %s (ifAlias)\n", cid);
		break;
	case LLDP_CHASSISID_SUBTYPE_LOCAL:
		printf(" ChassisID: %s (local)\n", cid);
		break;
	case LLDP_CHASSISID_SUBTYPE_LLADDR:
		printf(" ChassisID: %s (MAC)\n",
		    dump(chassis->c_id, chassis->c_id_len, ETH_ALEN, ':'));
		break;
	case LLDP_CHASSISID_SUBTYPE_ADDR:
		if (*(u_int8_t*)chassis->c_id == 1) {
			printf(" ChassisID: %s (IP)\n",
			    inet_ntoa(*(struct in_addr*)(chassis->c_id +
				    1)));
			break;
		}
	case LLDP_CHASSISID_SUBTYPE_PORT:
	case LLDP_CHASSISID_SUBTYPE_CHASSIS:
	default:
		printf(" ChassisID: %s (unhandled type)\n",
		    dump(chassis->c_id, chassis->c_id_len, 16, ' '));
	}
	printf(" SysName:   %s\n", chassis->c_name);
	printf(" SysDescr:  "); pretty_print(chassis->c_descr);
	if (chassis->c_mgmt.s_addr != INADDR_ANY)
		printf(" MgmtIP:    %s\n", inet_ntoa(chassis->c_mgmt));
	printf(" Caps:      ");
	display_cap(chassis, LLDP_CAP_OTHER, "Other");
	display_cap(chassis, LLDP_CAP_REPEATER, "Repeater");
	display_cap(chassis, LLDP_CAP_BRIDGE, "Bridge");
	display_cap(chassis, LLDP_CAP_ROUTER, "Router");
	display_cap(chassis, LLDP_CAP_WLAN, "Wlan");
	display_cap(chassis, LLDP_CAP_TELEPHONE, "Tel");
	display_cap(chassis, LLDP_CAP_DOCSIS, "Docsis");
	display_cap(chassis, LLDP_CAP_STATION, "Station");
	printf("\n");
}

#ifdef ENABLE_DOT3
static void
display_autoneg(struct lldpd_port *port, int bithd, int bitfd, char *desc)
{
	if (!((port->p_autoneg_advertised & bithd) ||
		(port->p_autoneg_advertised & bitfd)))
		return;
	printf("%s ", desc);
	if (port->p_autoneg_advertised & bithd) {
		printf("(HD");
		if (port->p_autoneg_advertised & bitfd) {
			printf(", FD) ");
			return;
		}
		printf(") ");
		return;
	}
	printf("(FD) ");
}
#endif

static void
display_port(struct lldpd_port *port)
{
	char *pid;
	struct in_addr address;
#ifdef ENABLE_DOT3
	int i;
#endif

	if ((pid = (char *)malloc(port->p_id_len + 1)) == NULL)
		fatal(NULL);
	memcpy(pid, port->p_id, port->p_id_len);
	pid[port->p_id_len] = 0;
	switch (port->p_id_subtype) {
	case LLDP_PORTID_SUBTYPE_IFNAME:
		printf(" PortID:    %s (ifName)\n", pid);
		break;
	case LLDP_PORTID_SUBTYPE_IFALIAS:
		printf(" PortID:    %s (ifAlias)\n", pid);
		break;
	case LLDP_PORTID_SUBTYPE_LOCAL:
		printf(" PortID:    %s (local)\n", pid);
		break;
	case LLDP_PORTID_SUBTYPE_LLADDR:
		printf(" PortID:    %s (MAC)\n",
		    dump(port->p_id, port->p_id_len, ETH_ALEN, ':'));
		break;
	case LLDP_PORTID_SUBTYPE_ADDR:
		if (*(u_int8_t*)port->p_id == 1) {
			memcpy(&address, port->p_id + 1,
			    sizeof(struct in_addr));
			printf(" PortID:    %s (IP)\n",
			    inet_ntoa(address));
			break;
		}
	case LLDP_PORTID_SUBTYPE_PORT:
	case LLDP_PORTID_SUBTYPE_AGENTCID:
	default:
		printf(" ChassisID: %s (unhandled type)\n",
		    dump(port->p_id, port->p_id_len, 16, ' '));
	}
	printf(" PortDescr: "); pretty_print(port->p_descr);
#ifdef ENABLE_DOT3
	if (port->p_mfs)
		printf(" MFS:       %d bytes\n", port->p_mfs);
	if (port->p_aggregid)
		printf("\n   Port is aggregated. PortAggregID:  %d\n",
		    port->p_aggregid);

	if (port->p_autoneg_support || port->p_autoneg_enabled ||
	    port->p_mau_type) {
		printf("\n   Autoneg: %ssupported/%senabled\n",
		    port->p_autoneg_support?"":"not ",
		    port->p_autoneg_enabled?"":"not ");
		if (port->p_autoneg_enabled) {
			printf("   PMD autoneg: ");
			display_autoneg(port, LLDP_DOT3_LINK_AUTONEG_10BASE_T,
			    LLDP_DOT3_LINK_AUTONEG_10BASET_FD,
			    "10Base-T");
			display_autoneg(port, LLDP_DOT3_LINK_AUTONEG_100BASE_TX,
			    LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD,
			    "100Base-T");
			display_autoneg(port, LLDP_DOT3_LINK_AUTONEG_100BASE_T2,
			    LLDP_DOT3_LINK_AUTONEG_100BASE_T2FD,
			    "100Base-T2");
			display_autoneg(port, LLDP_DOT3_LINK_AUTONEG_1000BASE_X,
			    LLDP_DOT3_LINK_AUTONEG_1000BASE_XFD,
			    "100Base-X");
			display_autoneg(port, LLDP_DOT3_LINK_AUTONEG_1000BASE_T,
			    LLDP_DOT3_LINK_AUTONEG_1000BASE_TFD,
			    "1000Base-T");
			printf("\n");
		}
		printf("   MAU oper type: ");
		for (i = 0; operational_mau_type_values[i].value != 0; i++) {
			if (operational_mau_type_values[i].value ==
			    port->p_mau_type) {
				printf("%s\n", operational_mau_type_values[i].string);
				break;
			}
		}
		if (operational_mau_type_values[i].value == 0)
			printf("unknown (%d)\n", port->p_mau_type);
	}
#endif
}

#ifdef ENABLE_DOT1
static void
display_vlans(struct lldpd_port *port)
{
	int i = 0;
	int foundpvid = 0;
	struct lldpd_vlan *vlan;
	TAILQ_FOREACH(vlan, &port->p_vlans, v_entries) {
		if (port->p_pvid == vlan->v_vid)
			foundpvid = 1;
		printf("  %cVLAN %4d: %-20s%c",
		    (port->p_pvid == vlan->v_vid)?'*':' ',
		    vlan->v_vid, vlan->v_name,
		    (i++ % 2) ? '\n' : ' ');
	}
	if (!foundpvid && port->p_pvid)
		printf("  *VLAN %4d\n", port->p_pvid);
	else if (i % 2)
		printf("\n");
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
		(age / (60*60)) % (60*60*24),
		(age / 60) % (60*60),
		age % 60) >= sizeof(sage))
		return "too much";
	else
		return sage;
}

static void
display_interfaces(int s, int argc, char *argv[])
{
	int i, nb;
	struct interfaces ifs;
#ifdef ENABLE_DOT1
	struct vlans vls;
#endif
	struct lldpd_interface *iff;
	struct lldpd_chassis chassis;
	struct lldpd_port port;
	char sep[80];

	memset(sep, '-', 79);
	sep[79] = 0;
	get_interfaces(s, &ifs);
	
	printf("%s\n", sep);
	printf("    LLDP neighbors\n");
	printf("%s\n", sep);	
	TAILQ_FOREACH(iff, &ifs, next) {
		if (optind < argc) {
			for (i = optind; i < argc; i++)
				if (strncmp(argv[i], iff->name, IFNAMSIZ) == 0)
					break;
			if (i == argc)
				continue;
		}
		nb = get_nb_port(s, iff->name);
		for (i = 0; i < nb; i++) {
			if (!((get_chassis(s, &chassis, iff->name, i) != -1) &&
				(get_port(s, &port, iff->name, i) != -1)))
				continue;
			printf("Interface: %s (via ", iff->name);
			switch (port.p_protocol) {
			case (LLDPD_MODE_LLDP): printf("LLDP"); break;
			case (LLDPD_MODE_CDPV1): printf("CDPv1"); break;
			case (LLDPD_MODE_CDPV2): printf("CDPv2"); break;
			case (LLDPD_MODE_EDP): printf("EDP"); break;
			case (LLDPD_MODE_FDP): printf("FDP"); break;
			case (LLDPD_MODE_SONMP): printf("SONMP"); break;
			default: printf("unknown protocol"); break;
			}
			printf(") - RID: %d", chassis.c_index);
			printf(" - Time: %s\n", display_age(&port));
			display_chassis(&chassis);
			printf("\n");
			display_port(&port);
#ifdef ENABLE_DOT1
			if (get_vlans(s, &vls, iff->name, i) != -1)
				memcpy(&port.p_vlans, &vls, sizeof(struct vlans));
			if (!TAILQ_EMPTY(&port.p_vlans) || port.p_pvid) {
				printf("\n");
				display_vlans(&port);
			}
#endif
#ifdef ENABLE_LLDPMED
			if (port.p_med_cap_enabled) {
				printf("\n");
				display_med(&chassis, &port);
			}
#endif
			printf("%s\n", sep);
		}
	}
}

#ifdef ENABLE_LLDPMED
static int
lldpd_parse_location(struct lldpd_port *port, const char *location)
{
	char *l, *e, *s, *data, *n;
	double ll, altitude;
	u_int32_t intpart, floatpart;
	int type = 0, i;

	if (strlen(location) == 0)
		return 0;
	if ((l = strdup(location)) == NULL)
		fatal(NULL);
	s = l;
	if ((e = strchr(s, ':')) == NULL)
		goto invalid_location;
	*e = '\0';
	type = atoi(s);
	switch (type) {
	case LLDPMED_LOCFORMAT_COORD:
		/* Coordinates */
		if ((port->p_med_location[0].data =
			(char *)malloc(16)) == NULL)
			fatal(NULL);
		port->p_med_location[0].data_len = 16;
		port->p_med_location[0].format = LLDPMED_LOCFORMAT_COORD;
		data = port->p_med_location[0].data;

		/* Latitude and longitude */
		for (i = 0; i < 2; i++) {
			s = e+1;
			if ((e = strchr(s, ':')) == NULL)
				goto invalid_location;
			*e = '\0';
			ll = atof(s);
			s = e + 1;
			if ((e = strchr(s, ':')) == NULL)
				goto invalid_location;
			*e = '\0';
			intpart = (int)ll;
			floatpart = (ll - intpart) * (1 << 25);
			if (((i == 0) && (*s == 'S')) ||
			    ((i == 1) && (*s == 'W'))) {
				intpart = ~intpart;
				intpart += 1;
				floatpart = ~floatpart;
				floatpart += 1;
			} else if (((i == 0) && (*s != 'N')) ||
			    ((i == 1) && (*s != 'E'))) 
				goto invalid_location;
			*(u_int8_t *)data = (6 << 2) |	       /* Precision */
			    ((intpart & 0x180) >> 7);	       /* Int part 2 bits */
			data++;
			*(u_int8_t *)data = (((intpart & 0x7f) << 1) | /* Int part 7 bits */
			    ((floatpart & 0x1000000) >> 24));	/* Float part 1 bit */
			data++;
			*(u_int8_t *)data = (floatpart & 0xff0000) >> 16; /* 8 bits */
			data++;
			*(u_int8_t *)data = (floatpart & 0xff00) >> 8; /* 8 bits */
			data++;
			*(u_int8_t *)data = (floatpart & 0xff); /* 8 bits */
			data++;
		}
		
		/* Altitude */
		s = e+1;
		if ((e = strchr(s, ':')) == NULL)
			goto invalid_location;
		*e = '\0';
		altitude = atof(s);
		s = e+1;
		if ((e = strchr(s, ':')) == NULL)
			goto invalid_location;
		*e = '\0';
		if (altitude < 0) {
			intpart = -(int)altitude;
			floatpart = (-(altitude + intpart)) * (1 << 8);
			intpart = ~intpart; intpart += 1;
			floatpart = ~floatpart; floatpart += 1;
		} else {
			intpart = (int)altitude;
			floatpart = (altitude - intpart) * (1 << 8);
		}
		if ((*s != 'm') && (*s != 'f'))
			goto invalid_location;
		*(u_int8_t *)data = ((((*s == 'm')?1:2) << 4) |	       /* Type 4 bits */
		    0);						       /* Precision 4 bits */
		data++;
		*(u_int8_t *)data = ((6 << 6) |			       /* Precision 2 bits */
		    ((intpart & 0x3f0000) >> 16));		       /* Int 6 bits */
		data++;
		*(u_int8_t *)data = (intpart & 0xff00) >> 8; /* Int 8 bits */
		data++;
		*(u_int8_t *)data = intpart & 0xff; /* Int 8 bits */
		data++;
		*(u_int8_t *)data = floatpart & 0xff; /* Float 8 bits */
		data++;

		/* Datum */
		s = e + 1;
		if (strchr(s, ':') != NULL)
			goto invalid_location;
		*(u_int8_t *)data = atoi(s);
		break;
	case LLDPMED_LOCFORMAT_CIVIC:
		/* Civic address */
		port->p_med_location[1].data_len = 4;
		s = e+1;
		if ((s = strchr(s, ':')) == NULL)
			goto invalid_location;
		s = s+1;
		do {
			if ((s = strchr(s, ':')) == NULL)
				break;
			s = s+1;
			/* s is the beginning of the word */
			if ((n = strchr(s, ':')) == NULL)
				n = s + strlen(s);
			/* n is the end of the word */
			port->p_med_location[1].data_len += (n - s) + 2;
			if ((s = strchr(s, ':')) == NULL)
				break;
			s = s+1;
		} while (1);
		s = e+1;
		if ((port->p_med_location[1].data =
			(char *)malloc(port->p_med_location[1].data_len)) ==
		    NULL)
			fatal(NULL);
		port->p_med_location[1].format = LLDPMED_LOCFORMAT_CIVIC;
		data = port->p_med_location[1].data;
		*(u_int8_t *)data = port->p_med_location[1].data_len - 1;
		data++;
		*(u_int8_t *)data = 2; /* Client location */
		data++;
		if ((e = strchr(s, ':')) == NULL)
			goto invalid_location;
		if ((e - s) != 2)
			goto invalid_location;
		memcpy(data, s, 2); /* Country code */
		data += 2;
		while (*e != '\0') {
			s=e+1;
			if ((e = strchr(s, ':')) == NULL)
				goto invalid_location;
			*e = '\0';
			*(u_int8_t *)data = atoi(s);
			data++;
			s=e+1;
			if ((e = strchr(s, ':')) == NULL)
				e = s + strlen(s);
			*(u_int8_t *)data = e - s;
			data++;
			memcpy(data, s, e-s);
			data += e-s;
		}
		break;
	case LLDPMED_LOCFORMAT_ELIN:
		s = e+1;
		port->p_med_location[2].data_len = strlen(s);
		if ((port->p_med_location[2].data =
			(char *)malloc(strlen(s))) == NULL)
			fatal(NULL);
		port->p_med_location[2].format = LLDPMED_LOCFORMAT_ELIN;
		strcpy(port->p_med_location[2].data, s);
		break;
	default:
		type = 0;
		goto invalid_location;
	}

	port->p_med_cap_enabled |= LLDPMED_CAP_LOCATION;
	return 0;
invalid_location:
	LLOG_WARNX("the format of the location is invalid (%s)",
		location);
	if (type) {
		free(port->p_med_location[type-1].data);
		memset(&port->p_med_location[type-1], 0,
		    sizeof(struct lldpd_med_loc));
	}
	free(l);
	return -1;
}

static void
set_location(int s, int argc, char *argv[])
{
	int i, ch;
	struct interfaces ifs;
	struct lldpd_interface *iff;
	struct lldpd_port port;
	void *p;
	struct hmsg *h;

	if ((h = (struct hmsg *)malloc(MAX_HMSGSIZE)) == NULL)
		fatal(NULL);

	memset(&port, 0, sizeof(struct lldpd_port));
	optind = 1;
	while ((ch = getopt(argc, argv, "dL:")) != -1) {
		switch (ch) {
		case 'L':
			if ((lldpd_parse_location(&port, optarg)) == -1)
				fatalx("incorrect location");
			break;
		}
	}

	get_interfaces(s, &ifs);
	TAILQ_FOREACH(iff, &ifs, next) {
		if (optind < argc) {
			for (i = optind; i < argc; i++)
				if (strncmp(argv[i], iff->name, IFNAMSIZ) == 0)
					break;
			if (i == argc)
				continue;
		}

		ctl_msg_init(h, HMSG_SET_LOCATION);
		strlcpy((char *)&h->data, iff->name, IFNAMSIZ);
		h->hdr.len += IFNAMSIZ;
		p = (char*)&h->data + IFNAMSIZ;
		if (ctl_msg_pack_structure(STRUCT_LLDPD_MED_LOC
			STRUCT_LLDPD_MED_LOC STRUCT_LLDPD_MED_LOC,
			port.p_med_location,
			3*sizeof(struct lldpd_med_loc), h, &p) == -1) {
			LLOG_WARNX("set_location: unable to set location for %s", iff->name);
			fatalx("aborting");
		}
		if (ctl_msg_send(s, h) == -1)
			fatalx("set_location: unable to send request");
		if (ctl_msg_recv(s, h) == -1)
			fatalx("set_location: unable to receive answer");
		if (h->hdr.type != HMSG_SET_LOCATION)
			fatalx("set_location: unknown answer type received");
		LLOG_INFO("Location set succesfully for %s", iff->name);
	}
}
#endif

int
main(int argc, char *argv[])
{
	int ch, s, debug = 1;
#define ACTION_SET_LOCATION 1
	int action = 0;
	
	/*
	 * Get and parse command line options
	 */
	while ((ch = getopt(argc, argv, "dL:")) != -1) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'L':
#ifdef ENABLE_LLDPMED
			action = ACTION_SET_LOCATION;
#else
			fprintf(stderr, "LLDP-MED support is not built-in\n");
			usage();
#endif
			break;
		default:
			usage();
		}
	}		
	
	log_init(debug, __progname);
	
	if ((s = ctl_connect(LLDPD_CTL_SOCKET)) == -1)
		fatalx("unable to connect to socket " LLDPD_CTL_SOCKET);

	switch (action) {
#ifdef ENABLE_LLDPMED
	case ACTION_SET_LOCATION:
		set_location(s, argc, argv);
		break;
#endif
	default:
		display_interfaces(s, argc, argv);
	}
	
	close(s);
	return 0;
}
