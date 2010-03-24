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

#define LLDPCTL_ARGS "hdf:L:P:"

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [OPTIONS ...] [INTERFACES ...]\n", __progname);

	fprintf(stderr, "\n");

	fprintf(stderr, "-d          Enable more debugging information.\n");
	fprintf(stderr, "-f format   Choose output format (plain or xml).\n");
#ifdef ENABLE_LLDPMED
	fprintf(stderr, "-L location Enable the transmission of LLDP-MED location TLV for the\n");
	fprintf(stderr, "            given interfaces. Can be repeated to enable the transmission\n");
	fprintf(stderr, "            of the location in several formats.\n");
	fprintf(stderr, "-P policy   Enable the transmission of LLDP-MED Network Policy TLVs\n");
	fprintf(stderr, "            for the given interfaces. Can be repeated to specify\n");
	fprintf(stderr, "            different policies.\n");
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
		LLOG_INFO("Location set succesfully for %s", iff->name);
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
#endif

int
main(int argc, char *argv[])
{
	int ch, s, debug = 1;
	char * fmt = "plain";
#define ACTION_SET_LOCATION (1 << 0)
#define ACTION_SET_POLICY   (1 << 1)
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
#ifdef ENABLE_LLDPMED
			action |= ACTION_SET_LOCATION;
#else
			fprintf(stderr, "LLDP-MED support is not built-in\n");
			usage();
#endif
			break;
		case 'P':
#ifdef ENABLE_LLDPMED
			action |= ACTION_SET_POLICY;
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

	if ( ( action != 0 ) && ( getuid() != geteuid() ) ) {
		fatalx("mere mortals may not do that, 'root' privileges are required.");
	}
	
	if ((s = ctl_connect(LLDPD_CTL_SOCKET)) == -1)
		fatalx("unable to connect to socket " LLDPD_CTL_SOCKET);

#ifdef ENABLE_LLDPMED
	if (action & ACTION_SET_LOCATION)
		set_location(s, argc, argv);
	if (action & ACTION_SET_POLICY)
		set_policy(s, argc, argv);
#endif
	if (!action)
		display_interfaces(s, fmt, argc, argv);
	
	close(s);
	return 0;
}
