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

static void		 usage(void);

#ifdef HAVE___PROGNAME
extern const char	*__progname;
#else
# define __progname "lldpctl"
#endif

#define LLDPCTL_ARGS "hdvaf:L:P:O:o:"

static void
usage(void)
{
	fprintf(stderr, "Usage:   %s [OPTIONS ...] [INTERFACES ...]\n", __progname);
	fprintf(stderr, "Version: %s\n", PACKAGE_STRING);

	fprintf(stderr, "\n");

	fprintf(stderr, "-d          Enable more debugging information.\n");
	fprintf(stderr, "-a          Display all remote ports, including hidden ones.\n");
	fprintf(stderr, "-f format   Choose output format (plain, keyvalue or xml).\n");
#ifdef ENABLE_LLDPMED
	fprintf(stderr, "-L location Enable the transmission of LLDP-MED location TLV for the\n");
	fprintf(stderr, "            given interfaces. Can be repeated to enable the transmission\n");
	fprintf(stderr, "            of the location in several formats.\n");
	fprintf(stderr, "-P policy   Enable the transmission of LLDP-MED Network Policy TLVs\n");
	fprintf(stderr, "            for the given interfaces. Can be repeated to specify\n");
	fprintf(stderr, "            different policies.\n");
	fprintf(stderr, "-O poe      Enable the transmission of LLDP-MED POE-MDI TLV\n");
	fprintf(stderr, "            for the given interfaces.\n");
#endif
#ifdef ENABLE_DOT3
	fprintf(stderr, "-o poe      Enable the transmission of Dot3 POE-MDI TLV\n");
	fprintf(stderr, "            for the given interfaces.\n");
#endif

	fprintf(stderr, "\n");

	fprintf(stderr, "see manual page lldpctl(8) for more information\n");
	exit(1);
}

#ifdef ENABLE_LLDPMED
static int
lldpd_parse_location(struct lldpd_med_loc *medloc, const char *location)
{
	char *l, *e, *s, *data, *n;
	double ll, altitude;
	u_int32_t intpart, floatpart;
	int type = 0, i;

	memset(medloc, 0, sizeof(struct lldpd_med_loc));

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
		if ((medloc->data = (char *)malloc(16)) == NULL)
			fatal(NULL);
		medloc->data_len = 16;
		medloc->format = LLDPMED_LOCFORMAT_COORD;
		data = medloc->data;

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
		medloc->data_len = 4;
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
			medloc->data_len += (n - s) + 2;
			if ((s = strchr(s, ':')) == NULL)
				break;
			s = s+1;
		} while (1);
		s = e+1;
		if ((medloc->data =
		     (char *)malloc(medloc->data_len)) == NULL)
			fatal(NULL);
		medloc->format = LLDPMED_LOCFORMAT_CIVIC;
		data = medloc->data;
		*(u_int8_t *)data = medloc->data_len - 1;
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
		medloc->data_len = strlen(s);
		if ((medloc->data = (char *)malloc(strlen(s))) == NULL)
			fatal(NULL);
		medloc->format = LLDPMED_LOCFORMAT_ELIN;
		strcpy(medloc->data, s);
		break;
	default:
		type = 0;
		goto invalid_location;
	}

	return 0;
invalid_location:
	LLOG_WARNX("the format of the location is invalid (%s)",
		location);
	return -1;
}

static int
lldpd_parse_policy(struct lldpd_med_policy *medpolicy, const char *policy)
{
	const char *e;
	int app_type            = 0;
	int unknown_policy_flag = 0;
	int tagged_flag         = 0;
	int vlan_id             = 0;
	int l2_prio             = 0;
	int dscp                = 0;

	memset(medpolicy, 0, sizeof(struct lldpd_med_policy));

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

	medpolicy->type     = (u_int8_t)  app_type;
	medpolicy->unknown  = (u_int8_t)  unknown_policy_flag;
	medpolicy->tagged   = (u_int8_t)  tagged_flag;
	medpolicy->vid      = (u_int16_t) vlan_id;
	medpolicy->priority = (u_int8_t)  l2_prio;
	medpolicy->dscp     = (u_int8_t)  dscp;

	return 0;

invalid_policy:
	LLOG_WARNX("The format of the policy is invalid (%s)",
		policy);
	return -1;
}

static int
lldpd_parse_power(struct lldpd_med_power *medpower, const char *poe)
{
	const char *e;
	int device_type = 0;
	int source      = 0;
	int priority    = 0;
	int val         = 0;

	memset(medpower, 0, sizeof(struct lldpd_med_power));

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

	medpower->devicetype = device_type;
	medpower->priority = priority;
	medpower->val = val;

	switch (device_type) {
	case LLDPMED_POW_TYPE_PD:
		switch (source) {
		case 1:
			medpower->source = LLDPMED_POW_SOURCE_PSE;
			break;
		case 2:
			medpower->source = LLDPMED_POW_SOURCE_LOCAL;
			break;
		case 3:
			medpower->source = LLDPMED_POW_SOURCE_BOTH;
			break;
		default:
			medpower->source = LLDPMED_POW_SOURCE_UNKNOWN;
			break;
		}
		break;
	case LLDPMED_POW_TYPE_PSE:
		switch (source) {
		case 1:
			medpower->source = LLDPMED_POW_SOURCE_PRIMARY;
			break;
		case 2:
			medpower->source = LLDPMED_POW_SOURCE_BACKUP;
			break;
		default:
			medpower->source = LLDPMED_POW_SOURCE_UNKNOWN;
			break;
		}
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
lldpd_parse_dot3_power(struct lldpd_dot3_power *dot3power, const char *poe)
{
	const char *e;

	memset(dot3power, 0, sizeof(struct lldpd_dot3_power));

	if (strlen(poe) == 0)
		return 0;
	e = poe;

	/* Device type */
	if (!strncmp(e, "PD", 2))
		dot3power->devicetype = LLDP_DOT3_POWER_PD;
	else if (!strncmp(e, "PSE", 3))
		dot3power->devicetype = LLDP_DOT3_POWER_PSE;
	else {
		LLOG_WARNX("Device type should be either 'PD' or 'PSE'.");
		goto invalid_dot3_poe;
	}

	/* Supported */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power support.");
		goto invalid_dot3_poe;
	}
	dot3power->supported = atoi(++e);
	if (dot3power->supported > 1) {
		LLOG_WARNX("Power support should be 1 or 0, not %d", dot3power->supported);
		goto invalid_dot3_poe;
	}

	/* Enabled */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power ability.");
		goto invalid_dot3_poe;
	}
	dot3power->enabled = atoi(++e);
	if (dot3power->enabled > 1) {
		LLOG_WARNX("Power ability should be 1 or 0, not %d", dot3power->enabled);
		goto invalid_dot3_poe;
	}

	/* Pair control */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power pair control ability.");
		goto invalid_dot3_poe;
	}
	dot3power->paircontrol = atoi(++e);
	if (dot3power->paircontrol > 1) {
		LLOG_WARNX("Power pair control ability should be 1 or 0, not %d",
		    dot3power->paircontrol);
		goto invalid_dot3_poe;
	}

	/* Power pairs */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power pairs.");
		goto invalid_dot3_poe;
	}
	dot3power->pairs = atoi(++e);
	if (dot3power->pairs < 1 || dot3power->pairs > 2) {
		LLOG_WARNX("Power pairs should be 1 or 2, not %d.", dot3power->pairs);
		goto invalid_dot3_poe;
	}

	/* Class */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power class.");
		goto invalid_dot3_poe;
	}
	dot3power->class = atoi(++e);
	if (dot3power->class > 5) {
		LLOG_WARNX("Power class out of range (%d).", dot3power->class);
		goto invalid_dot3_poe;
	}
	/* 802.3at */
	if ((e = strchr(e, ':')) == NULL) {
		dot3power->powertype = LLDP_DOT3_POWER_8023AT_OFF;
		return 0;
	}
	/* 802.3at: Power type */
	dot3power->powertype = atoi(++e);
	if ((dot3power->powertype != LLDP_DOT3_POWER_8023AT_TYPE1) &&
	    (dot3power->powertype != LLDP_DOT3_POWER_8023AT_TYPE2)) {
		LLOG_WARNX("Incorrect power type (%d).", dot3power->powertype);
		goto invalid_dot3_poe;
	}
	/* 802.3at: Source */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power source.");
		goto invalid_dot3_poe;
	}
	dot3power->source = atoi(++e);
	if (dot3power->source > 3) {
		LLOG_WARNX("Power source out of range (%d).", dot3power->source);
		goto invalid_dot3_poe;
	}
	/* 802.3at: priority */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected power priority.");
		goto invalid_dot3_poe;
	}
	dot3power->priority = atoi(++e);
	if (dot3power->priority > 3) {
		LLOG_WARNX("Power priority out of range (%d).", dot3power->priority);
		goto invalid_dot3_poe;
	}
	/* 802.3at: requested */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected requested power value.");
		goto invalid_dot3_poe;
	}
	dot3power->requested = atoi(++e);
	/* 802.3at: allocated */
	if ((e = strchr(e, ':')) == NULL) {
		LLOG_WARNX("Expected allocated power value.");
		goto invalid_dot3_poe;
	}
	dot3power->allocated = atoi(++e);
	return 0;

 invalid_dot3_poe:
	LLOG_WARNX("The format POE-MDI is invalid (%s)", poe);
	return -1;
}
#endif

#define ACTION_SET_LOCATION   (1 << 0)
#define ACTION_SET_POLICY     (1 << 1)
#define ACTION_SET_POWER      (1 << 2)
#define ACTION_SET_DOT3_POWER (1 << 3)
static void
set_port(int s, int argc, char *argv[], int action)
{
	int ch;
#ifdef ENABLE_LLDPMED
	struct lldpd_med_loc    location;
	struct lldpd_med_power  medpower;
	struct lldpd_med_policy policy;
#endif
#ifdef ENABLE_DOT3
	struct lldpd_dot3_power dot3power;
#endif
	int done;
	int skip[4] = {0, 0, 0, 0};
	int skip_[4];
	struct lldpd_interface *iff;
	struct lldpd_interface_list *ifs;
	struct lldpd_port_set set;
	int i;

 redo_set_port:
	memcpy(skip_, skip, sizeof(skip));
	done = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, LLDPCTL_ARGS)) != -1) {
		switch (ch) {
#ifdef ENABLE_LLDPMED
		case 'L':
			if (action & ACTION_SET_LOCATION) {
				if (skip_[0]--) break;
				if (lldpd_parse_location(&location, optarg) == -1)
					fatalx("set_port: incorrect location");
				done = 0;
				skip[0]++;
			}
			break;
		case 'P':
			if (action & ACTION_SET_POLICY) {
				if (skip_[1]--) break;
				if (lldpd_parse_policy(&policy, optarg) == -1)
					fatalx("set_port: incorrect network policy.");
				done = 0;
				skip[1]++;
			}
			break;
		case 'O':
			if (action & ACTION_SET_POWER) {
				if (skip_[2]--) break;
				if (lldpd_parse_power(&medpower, optarg) == -1)
					fatalx("set_port: incorrect MED POE-MDI.");
				done = 0;
				skip[2]++;
			}
			break;
#endif
#ifdef ENABLE_DOT3
		case 'o':
			if (action & ACTION_SET_DOT3_POWER) {
				if (skip_[3]--) break;
				if (lldpd_parse_dot3_power(&dot3power, optarg) == -1)
					fatalx("set_port: incorrect DOT3 POE-MDI.");
				done = 0;
				skip[3]++;
			}
			break;
#endif
		}
	}
	if (done) return;

	ifs = get_interfaces(s);
	TAILQ_FOREACH(iff, ifs, next) {
		if (optind < argc) {
			for (i = optind; i < argc; i++)
				if (strncmp(argv[i], iff->name, IFNAMSIZ) == 0)
					break;
			if (i == argc)
				continue;
		}

		memset(&set, 0, sizeof(struct lldpd_port_set));
		set.ifname = iff->name;
#ifdef ENABLE_LLDPMED
		if (action & ACTION_SET_LOCATION)  set.med_location = &location;
		if (action & ACTION_SET_POLICY)    set.med_policy   = &policy;
		if (action & ACTION_SET_POWER)     set.med_power    = &medpower;
#endif
#ifdef ENABLE_DOT3
		if (action & ACTION_SET_DOT3_POWER)set.dot3_power   = &dot3power;
#endif
		if (ctl_msg_send_recv(s, SET_PORT,
				      &set, &MARSHAL_INFO(lldpd_port_set),
				      NULL, NULL) == -1)
			fatalx("set_port: unable to send new location information");
		LLOG_INFO("configuration change for %s", iff->name);
	}
	goto redo_set_port;
}

struct lldpd_interface_list*
get_interfaces(int s)
{
	struct lldpd_interface_list *ifs;
	if (ctl_msg_send_recv(s, GET_INTERFACES, NULL, NULL, (void **)&ifs,
		&MARSHAL_INFO(lldpd_interface_list)) == -1)
		fatalx("get_interfaces: unable to get the list of interfaces");
	return ifs;
}

struct lldpd_hardware*
get_interface(int s, char *name)
{
	struct lldpd_hardware *h;
	if (ctl_msg_send_recv(s, GET_INTERFACE,
		name, &MARSHAL_INFO(string),
		(void **)&h, &MARSHAL_INFO(lldpd_hardware)) == -1)
		fatalx("get_interface: unable to get information for specified interface");
	return h;
}

int
main(int argc, char *argv[])
{
	int ch, s, debug = 1;
	char * fmt = "plain";
	int action = 0, hidden = 0;
	
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
		case 'v':
			fprintf(stdout, "%s\n", PACKAGE_VERSION);
			exit(0);
			break;
		case 'a':
			hidden = 1;
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

	if (!action)
		display_interfaces(s, fmt, hidden, argc, argv);
	else
		set_port(s, argc, argv, action);
	
	close(s);
	return 0;
}
