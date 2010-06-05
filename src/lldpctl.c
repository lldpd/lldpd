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

#ifdef HAVE___PROGNAME
extern const char	*__progname;
#else
# define __progname "lldpctl"
#endif

extern void
get_interfaces(int s, struct interfaces *ifs);

extern void
display_interfaces(int s, const char * fmt, int argc, char *argv[]);

#define LLDPCTL_ARGS "hdf:L:P:O:o:"

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [OPTIONS ...] [INTERFACES ...]\n", __progname);

	fprintf(stderr, "\n");

	fprintf(stderr, "-d          Enable more debugging information.\n");
	fprintf(stderr, "-f format   Choose output format (plain, keyvalue or xml).\n");
#ifdef ENABLE_LLDPMED
	fprintf(stderr, "-L location Enable the transmission of LLDP-MED location TLV for the\n");
	fprintf(stderr, "            given interfaces. Can be repeated to enable the transmission\n");
	fprintf(stderr, "            of the location in several formats.\n");
	fprintf(stderr, "-P policy   Enable the transmission of LLDP-MED Network Policy TLVs\n");
	fprintf(stderr, "            for the given interfaces. Can be repeated to specify\n");
	fprintf(stderr, "            different policies.\n");
	fprintf(stderr, "-O poe      Enable the trabsmission of LLDP-MED POE-MDI TLV\n");
	fprintf(stderr, "            for the given interfaces.\n");
#endif
#ifdef ENABLE_DOT3
	fprintf(stderr, "-o poe      Enable the trabsmission of Dot3 POE-MDI TLV\n");
	fprintf(stderr, "            for the given interfaces.\n");
#endif

	fprintf(stderr, "\n");

	fprintf(stderr, "see manual page lldpctl(8) for more information\n");
	exit(1);
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

static int
lldpd_parse_policy(struct lldpd_port *port, const char *policy)
{
	const char *e;
	int app_type            = 0;
	int unknown_policy_flag = 0;
	int tagged_flag         = 0;
	int vlan_id             = 0;
	int l2_prio             = 0;
	int dscp                = 0;

	if (strlen(policy) == 0) {
		return 0;
	}

	e = policy;

	/* Application Type: */
	app_type = atoi(e);
	if (app_type < 1 || app_type > LLDPMED_APPTYPE_LAST) {
		LLOG_WARNX("Application Type (%u) out of range.", app_type);
		goto invalid_policy;
	}

	/* Unknown Policy Flag (U): */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected Unknown Policy Flag (U).");
		goto invalid_policy;
	}
	e = e + 1;
	unknown_policy_flag = atoi(e);
	if (unknown_policy_flag < 0 || unknown_policy_flag > 1) {
		LLOG_WARNX("Unknown Policy Flag (%u) out of range.", unknown_policy_flag);
		goto invalid_policy;
	}

	/* Tagged Flag (T): */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected Tagged Flag (T).");
		goto invalid_policy;
	}
	e = e + 1;
	tagged_flag = atoi(e);
	if (tagged_flag < 0 || tagged_flag > 1) {
		LLOG_WARNX("Tagged Flag (%u) out of range.", tagged_flag);
		goto invalid_policy;
	}

	/* VLAN-ID (VID): */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected VLAN ID (VID).");
		goto invalid_policy;
	}
	e = e + 1;
	vlan_id = atoi(e);
	if (vlan_id < 0 || vlan_id > 4094) {
		LLOG_WARNX("VLAN ID (%u) out of range.", vlan_id);
		goto invalid_policy;
	}

	/* Layer 2 Priority: */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected Layer 2 Priority.");
		goto invalid_policy;
	}
	e = e + 1;
	l2_prio = atoi(e);
	if (l2_prio < 0 || l2_prio > 7) {
		LLOG_WARNX("Layer 2 Priority (%u) out of range.", l2_prio);
		goto invalid_policy;
	}

	/* DSCP value: */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected DSCP value.");
		goto invalid_policy;
	}
	e = e + 1;
	dscp = atoi(e);
	if (dscp < 0 || dscp > 63) {
		LLOG_WARNX("DSCP value (%u) out of range.", dscp);
		goto invalid_policy;
	}

	port->p_med_policy[app_type - 1].type     = (u_int8_t)  app_type;
	port->p_med_policy[app_type - 1].unknown  = (u_int8_t)  unknown_policy_flag;
	port->p_med_policy[app_type - 1].tagged   = (u_int8_t)  tagged_flag;
	port->p_med_policy[app_type - 1].vid      = (u_int16_t) vlan_id;
	port->p_med_policy[app_type - 1].priority = (u_int8_t)  l2_prio;
	port->p_med_policy[app_type - 1].dscp     = (u_int8_t)  dscp;

	port->p_med_cap_enabled |= LLDPMED_CAP_POLICY;
	return 0;

invalid_policy:
	LLOG_WARNX("The format of the policy is invalid (%s)",
		policy);
	return -1;
}

static int
lldpd_parse_power(struct lldpd_port *port, const char *poe)
{
	const char *e;
	int device_type = 0;
	int source      = 0;
	int priority    = 0;
	int val         = 0;

	if (strlen(poe) == 0)
		return 0;
	e = poe;

	/* Device type */
	if (!strncmp(e, "PD", 2))
		device_type = LLDPMED_POW_TYPE_PD;
	else if (!strncmp(e, "PSE", 3))
		device_type = LLDPMED_POW_TYPE_PSE;
	else {
		LLOG_WARNX("Device type should be either 'PD' or 'PSE'.");
		goto invalid_poe;
	}

	/* Source */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power source.");
		goto invalid_poe;
	}
	source = atoi(++e);
	if (source < 0 || source > 3) {
		LLOG_WARNX("Power source out of range (%d).", source);
		goto invalid_poe;
	}

	/* Priority */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power priority.");
		goto invalid_poe;
	}
	priority = atoi(++e);
	if (priority < 0 || priority > 3) {
		LLOG_WARNX("Power priority out of range (%d).", priority);
		goto invalid_poe;
	}

	/* Value */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power value.");
		goto invalid_poe;
	}
	val = atoi(++e);
	if (val < 0 || val > 1023) {
		LLOG_WARNX("Power value out of range (%d).", val);
		goto invalid_poe;
	}

	port->p_med_power.devicetype = device_type;
	port->p_med_power.priority = priority;
	port->p_med_power.val = val;

	switch (device_type) {
	case LLDPMED_POW_TYPE_PD:
		switch (source) {
		case 1:
			port->p_med_power.source = LLDPMED_POW_SOURCE_PSE;
			break;
		case 2:
			port->p_med_power.source = LLDPMED_POW_SOURCE_LOCAL;
			break;
		case 3:
			port->p_med_power.source = LLDPMED_POW_SOURCE_BOTH;
			break;
		default:
			port->p_med_power.source = LLDPMED_POW_SOURCE_UNKNOWN;
			break;
		}
		port->p_med_cap_enabled |= LLDPMED_CAP_MDI_PD;
		break;
	case LLDPMED_POW_TYPE_PSE:
		switch (source) {
		case 1:
			port->p_med_power.source = LLDPMED_POW_SOURCE_PRIMARY;
			break;
		case 2:
			port->p_med_power.source = LLDPMED_POW_SOURCE_BACKUP;
			break;
		default:
			port->p_med_power.source = LLDPMED_POW_SOURCE_UNKNOWN;
			break;
		}
		port->p_med_cap_enabled |= LLDPMED_CAP_MDI_PSE;
		break;
	}
	return 0;

 invalid_poe:
	LLOG_WARNX("The format POE-MDI is invalid (%s)", poe);
	return -1;
}
#endif

#ifdef ENABLE_DOT3
static int
lldpd_parse_dot3_power(struct lldpd_port *port, const char *poe)
{
	const char *e;
	struct lldpd_dot3_power target;

	if (strlen(poe) == 0)
		return 0;
	e = poe;
	memset(&target, 0, sizeof(target));

	/* Device type */
	if (!strncmp(e, "PD", 2))
		target.devicetype = LLDP_DOT3_POWER_PD;
	else if (!strncmp(e, "PSE", 3))
		target.devicetype = LLDP_DOT3_POWER_PSE;
	else {
		LLOG_WARNX("Device type should be either 'PD' or 'PSE'.");
		goto invalid_dot3_poe;
	}

	/* Supported */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power support.");
		goto invalid_dot3_poe;
	}
	target.supported = atoi(++e);
	if (target.supported > 1) {
		LLOG_WARNX("Power support should be 1 or 0, not %d", target.supported);
		goto invalid_dot3_poe;
	}

	/* Enabled */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power ability.");
		goto invalid_dot3_poe;
	}
	target.enabled = atoi(++e);
	if (target.enabled > 1) {
		LLOG_WARNX("Power ability should be 1 or 0, not %d", target.enabled);
		goto invalid_dot3_poe;
	}

	/* Pair control */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power pair control ability.");
		goto invalid_dot3_poe;
	}
	target.paircontrol = atoi(++e);
	if (target.paircontrol > 1) {
		LLOG_WARNX("Power pair control ability should be 1 or 0, not %d",
		    target.paircontrol);
		goto invalid_dot3_poe;
	}

	/* Power pairs */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power pairs.");
		goto invalid_dot3_poe;
	}
	target.pairs = atoi(++e);
	if (target.pairs < 1 || target.pairs > 2) {
		LLOG_WARNX("Power pairs should be 1 or 2, not %d.", target.pairs);
		goto invalid_dot3_poe;
	}

	/* Class */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power class.");
		goto invalid_dot3_poe;
	}
	target.class = atoi(++e);
	if (target.class > 5) {
		LLOG_WARNX("Power class out of range (%d).", target.class);
		goto invalid_dot3_poe;
	}
	/* 802.3at */
	if ((e = strchr(e, ':')) == NULL) {
		target.powertype = LLDP_DOT3_POWER_8023AT_OFF;
		goto no8023at;
	}
	/* 802.3at: Power type */
	target.powertype = atoi(++e);
	if ((target.powertype != LLDP_DOT3_POWER_8023AT_TYPE1) &&
	    (target.powertype != LLDP_DOT3_POWER_8023AT_TYPE2)) {
		LLOG_WARNX("Incorrect power type (%d).", target.powertype);
		goto invalid_dot3_poe;
	}
	/* 802.3at: Source */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power source.");
		goto invalid_dot3_poe;
	}
	target.source = atoi(++e);
	if (target.source > 3) {
		LLOG_WARNX("Power source out of range (%d).", target.source);
		goto invalid_dot3_poe;
	}
	/* 802.3at: priority */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power priority.");
		goto invalid_dot3_poe;
	}
	target.priority = atoi(++e);
	if (target.priority > 3) {
		LLOG_WARNX("Power priority out of range (%d).", target.priority);
		goto invalid_dot3_poe;
	}
	/* 802.3at: requested */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected requested power value.");
		goto invalid_dot3_poe;
	}
	target.requested = atoi(++e);
	/* 802.3at: allocated */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected allocated power value.");
		goto invalid_dot3_poe;
	}
	target.allocated = atoi(++e);

 no8023at:
	memcpy(&port->p_power, &target, sizeof(target));
	return 0;

 invalid_dot3_poe:
	LLOG_WARNX("The format POE-MDI is invalid (%s)", poe);
	return -1;
}
#endif

#ifdef ENABLE_LLDPMED
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
	while ((ch = getopt(argc, argv, LLDPCTL_ARGS)) != -1) {
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
		LLOG_INFO("Location set successfully for %s", iff->name);
	}
}

static void
set_policy(int s, int argc, char *argv[])
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
	while ((ch = getopt(argc, argv, LLDPCTL_ARGS)) != -1) {
		switch (ch) {
		case 'P':
			if ((lldpd_parse_policy(&port, optarg)) == -1)
				fatalx("Incorrect Network Policy.");
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

		ctl_msg_init(h, HMSG_SET_POLICY);
		strlcpy((char *)&h->data, iff->name, IFNAMSIZ);
		h->hdr.len += IFNAMSIZ;
		p = (char*)&h->data + IFNAMSIZ;
		if (ctl_msg_pack_structure(
			STRUCT_LLDPD_MED_POLICY
			STRUCT_LLDPD_MED_POLICY
			STRUCT_LLDPD_MED_POLICY
			STRUCT_LLDPD_MED_POLICY
			STRUCT_LLDPD_MED_POLICY
			STRUCT_LLDPD_MED_POLICY
			STRUCT_LLDPD_MED_POLICY
			STRUCT_LLDPD_MED_POLICY,
			port.p_med_policy,
			8*sizeof(struct lldpd_med_policy), h, &p) == -1) {
			LLOG_WARNX("set_policy: Unable to set Network Policy for %s", iff->name);
			fatalx("aborting");
		}
		if (ctl_msg_send(s, h) == -1)
			fatalx("set_policy: unable to send request");
		if (ctl_msg_recv(s, h) == -1)
			fatalx("set_policy: unable to receive answer");
		if (h->hdr.type != HMSG_SET_POLICY)
			fatalx("set_policy: unknown answer type received");
		LLOG_INFO("Network Policy successfully set for %s", iff->name);
	}
}

static void
set_power(int s, int argc, char *argv[])
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
	while ((ch = getopt(argc, argv, LLDPCTL_ARGS)) != -1) {
		switch (ch) {
		case 'O':
			if ((lldpd_parse_power(&port, optarg)) == -1)
				fatalx("Incorrect POE-MDI.");
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

		ctl_msg_init(h, HMSG_SET_POWER);
		strlcpy((char *)&h->data, iff->name, IFNAMSIZ);
		h->hdr.len += IFNAMSIZ;
		p = (char*)&h->data + IFNAMSIZ;
		if (ctl_msg_pack_structure(STRUCT_LLDPD_MED_POWER,
					   &port.p_med_power,
					   sizeof(struct lldpd_med_power), h, &p) == -1) {
			LLOG_WARNX("set_power: Unable to set POE-MDI for %s", iff->name);
			fatalx("aborting");
		}
		if (ctl_msg_send(s, h) == -1)
			fatalx("set_power: unable to send request");
		if (ctl_msg_recv(s, h) == -1)
			fatalx("set_power: unable to receive answer");
		if (h->hdr.type != HMSG_SET_POWER)
			fatalx("set_power: unknown answer type received");
		LLOG_INFO("POE-MDI successfully set for %s", iff->name);
	}
}
#endif

#ifdef ENABLE_DOT3
static void
set_dot3_power(int s, int argc, char *argv[])
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
	while ((ch = getopt(argc, argv, LLDPCTL_ARGS)) != -1) {
		switch (ch) {
		case 'o':
			if ((lldpd_parse_dot3_power(&port, optarg)) == -1)
				fatalx("Incorrect POE-MDI.");
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

		ctl_msg_init(h, HMSG_SET_DOT3_POWER);
		strlcpy((char *)&h->data, iff->name, IFNAMSIZ);
		h->hdr.len += IFNAMSIZ;
		p = (char*)&h->data + IFNAMSIZ;
		if (ctl_msg_pack_structure(STRUCT_LLDPD_DOT3_POWER,
					   &port.p_power,
					   sizeof(struct lldpd_dot3_power), h, &p) == -1) {
			LLOG_WARNX("set_dot3_power: Unable to set POE-MDI for %s", iff->name);
			fatalx("aborting");
		}
		if (ctl_msg_send(s, h) == -1)
			fatalx("set_dot3_power: unable to send request");
		if (ctl_msg_recv(s, h) == -1)
			fatalx("set_dot3_power: unable to receive answer");
		if (h->hdr.type != HMSG_SET_DOT3_POWER)
			fatalx("set_dot3_power: unknown answer type received");
		LLOG_INFO("Dot3 POE-MDI successfully set for %s", iff->name);
	}
}
#endif

int
main(int argc, char *argv[])
{
	int ch, s, debug = 1;
	char * fmt = "plain";
#define ACTION_SET_LOCATION (1 << 0)
#define ACTION_SET_POLICY   (1 << 1)
#define ACTION_SET_POWER    (1 << 2)
#define ACTION_SET_DOT3_POWER    (1 << 3)
	int action = 0;
	
	/*
	 * Get and parse command line options
	 */
	while ((ch = getopt(argc, argv, LLDPCTL_ARGS)) != -1) {
		switch (ch) {
		case 'h':
			usage();
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			fmt = optarg;
			break;
		case 'L':
		case 'P':
		case 'O':
#ifdef ENABLE_LLDPMED
			switch (ch) {
			case 'L': action |= ACTION_SET_LOCATION; break;
			case 'P': action |= ACTION_SET_POLICY; break;
			case 'O': action |= ACTION_SET_POWER; break;
			}
#else
			fprintf(stderr, "LLDP-MED support is not built-in\n");
			usage();
#endif
			break;
		case 'o':
#ifdef ENABLE_DOT3
			action |= ACTION_SET_DOT3_POWER;
#else
			fprintf(stderr, "Dot3 support is not built-in\n");
			usage();
#endif
			break;
		default:
			usage();
		}
	}

	log_init(debug, __progname);

	if ((action != 0) && (getuid() != 0)) {
		fatalx("mere mortals may not do that, 'root' privileges are required.");
	}
	
	if ((s = ctl_connect(LLDPD_CTL_SOCKET)) == -1)
		fatalx("unable to connect to socket " LLDPD_CTL_SOCKET);

#ifdef ENABLE_LLDPMED
	if (action & ACTION_SET_LOCATION)
		set_location(s, argc, argv);
	if (action & ACTION_SET_POLICY)
		set_policy(s, argc, argv);
	if (action & ACTION_SET_POWER)
		set_power(s, argc, argv);
#endif
#ifdef ENABLE_DOT3
	if (action & ACTION_SET_DOT3_POWER)
		set_dot3_power(s, argc, argv);
#endif
	if (!action)
		display_interfaces(s, fmt, argc, argv);
	
	close(s);
	return 0;
}
