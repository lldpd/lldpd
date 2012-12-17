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
	fprintf(stderr, "-w          Watch for changes.\n");
	fprintf(stderr, "-C          Display global configuration of lldpd.\n");
	fprintf(stderr, "-N          Make lldpd transmit LLDP PDU now.\n");
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

struct cbargs {
	int argc;
	char **argv;
	struct writer *w;
};

void
watchcb(lldpctl_conn_t *conn,
    lldpctl_change_t type,
    lldpctl_atom_t *interface,
    lldpctl_atom_t *neighbor,
    void *data)
{
	int ch, i;
	struct cbargs *args = data;
	optind = 0;
	while ((ch = getopt(args->argc, args->argv, LLDPCTL_ARGS)) != -1);
	if (optind < args->argc) {
		for (i = optind; i < args->argc; i++)
			if (strcmp(args->argv[i],
				lldpctl_atom_get_str(interface,
				    lldpctl_k_interface_name)) == 0)
				break;
		if (i == args->argc)
			return;
	}
	switch (type) {
	case lldpctl_c_deleted:
		tag_start(args->w, "lldp-deleted", "LLDP neighbor deleted");
		break;
	case lldpctl_c_updated:
		tag_start(args->w, "lldp-updated", "LLDP neighbor updated");
		break;
	case lldpctl_c_added:
		tag_start(args->w, "lldp-added", "LLDP neighbor added");
		break;
	default: return;
	}
	display_interface(conn, args->w, 1, interface, neighbor);
	tag_end(args->w);
}

int
main(int argc, char *argv[])
{
	int ch, debug = 1;
	char *fmt = "plain";
	int action = 0, hidden = 0, watch = 0, configuration = 0, now = 0;
	lldpctl_conn_t *conn;
	struct cbargs args;

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
		case 'w':
			watch = 1;
			break;
		case 'C':
			configuration = 1;
			break;
		case 'N':
			now = 1;
			break;
		default:
			usage();
		}
	}

	log_init(debug, __progname);

	if ((action != 0) &&
	    (getuid() != geteuid() || getgid() != getegid())) {
		fatalx("mere mortals may not do that, admin privileges are required.");
	}

	conn = lldpctl_new(NULL, NULL, NULL);
	if (conn == NULL) exit(EXIT_FAILURE);

	args.argc = argc;
	args.argv = argv;
	if (watch) {
		if (lldpctl_watch_callback(conn, watchcb, &args) < 0) {
			log_warnx(NULL, "unable to watch for neighbors. %s",
			    lldpctl_last_strerror(conn));
			exit(EXIT_FAILURE);
		}
	}

	do {
		if (strcmp(fmt, "plain") == 0) {
			args.w = txt_init(stdout);
		} else if (strcmp(fmt, "keyvalue") == 0) {
			args.w = kv_init(stdout);
		}
#ifdef USE_XML
		else if (strcmp(fmt,"xml") == 0 ) {
			args.w = xml_init(stdout);
		}
#endif
#ifdef USE_JSON
		else if (strcmp(fmt, "json") == 0) {
			args.w = json_init(stdout);
		}
#endif
		else {
			args.w = txt_init(stdout);
		}

		if (action) {
			modify_interfaces(conn, argc, argv, optind);
		} else if (watch) {
			if (lldpctl_watch(conn) < 0) {
				log_warnx(NULL, "unable to watch for neighbors. %s",
				    lldpctl_last_strerror(conn));
				watch = 0;
			}
		} else if (configuration) {
			display_configuration(conn, args.w);
		} else if (now) {
			lldpctl_atom_t *config = lldpctl_get_configuration(conn);
			if (config == NULL) {
				log_warnx(NULL, "unable to get configuration from lldpd. %s",
					lldpctl_last_strerror(conn));
			} else {
				if (lldpctl_atom_set_int(config,
					lldpctl_k_config_tx_interval, -1) == NULL) {
					log_warnx(NULL, "unable to ask lldpd for immediate retransmission. %s",
						lldpctl_last_strerror(conn));
				} else
					log_info(NULL, "immediate retransmission requested successfuly");
				lldpctl_atom_dec_ref(config);
			}
		} else {
			display_interfaces(conn, args.w,
			    hidden, argc, argv);
		}
		args.w->finish(args.w);
	} while (watch);

	lldpctl_release(conn);
	return EXIT_SUCCESS;
}
