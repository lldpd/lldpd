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
display_interfaces(int s, int argc, char *argv[]);

static void
usage(void)
{
	fprintf(stderr, "usage: %s [options]\n", __progname);
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

	if ( ( action != 0 ) && ( getuid() != geteuid() ) ) {
		fatalx("mere mortals may not do that, 'root' privileges are required.");
	}
	
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
