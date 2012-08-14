/* -*- mode: c; c-file-style: "openbsd" -*- */
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "../log.h"
#include "../ctl.h"
#include "client.h"

static void		 usage(void);

#ifdef HAVE___PROGNAME
extern const char	*__progname;
#else
# define __progname "lldpctl"
#endif


static void
usage(void)
{
	fprintf(stderr, "Usage:   %s [OPTIONS ...] [INTERFACES ...]\n", __progname);
	fprintf(stderr, "Version: %s\n", PACKAGE_STRING);

	fprintf(stderr, "\n");

	fprintf(stderr, "-d          Enable more debugging information.\n");
	fprintf(stderr, "-a          Display all remote ports, including hidden ones.\n");
	fprintf(stderr, "-f format   Choose output format (plain, keyvalue or xml).\n");
	fprintf(stderr, "-L location Enable the transmission of LLDP-MED location TLV for the\n");
	fprintf(stderr, "            given interfaces. Can be repeated to enable the transmission\n");
	fprintf(stderr, "            of the location in several formats.\n");
	fprintf(stderr, "-P policy   Enable the transmission of LLDP-MED Network Policy TLVs\n");
	fprintf(stderr, "            for the given interfaces. Can be repeated to specify\n");
	fprintf(stderr, "            different policies.\n");
	fprintf(stderr, "-O poe      Enable the transmission of LLDP-MED POE-MDI TLV\n");
	fprintf(stderr, "            for the given interfaces.\n");
	fprintf(stderr, "-o poe      Enable the transmission of Dot3 POE-MDI TLV\n");
	fprintf(stderr, "            for the given interfaces.\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "see manual page lldpctl(8) for more information\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int ch, debug = 1;
	char * fmt = "plain";
	int action = 0, hidden = 0;
	lldpctl_conn_t *conn;

	/* Get and parse command line options */
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
		case 'o':
			action = 1;
			break;
		default:
			usage();
		}
	}

	log_init(debug, __progname);

	if ((action != 0) && (getuid() != 0)) {
		fatalx("mere mortals may not do that, 'root' privileges are required.");
	}

	conn = lldpctl_new(NULL, NULL, NULL);
	if (conn == NULL) exit(EXIT_FAILURE);

	if (!action) display_interfaces(conn, fmt, hidden, argc, argv);
	else modify_interfaces(conn, argc, argv, optind);

	lldpctl_release(conn);
	return EXIT_SUCCESS;
}
