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


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <libgen.h>

#include "client.h"

#ifdef HAVE___PROGNAME
extern const char	*__progname;
#else
# define __progname "lldpcli"
#endif

/* Global for completion */
static struct cmd_node *root = NULL;

static void
usage()
{
	fprintf(stderr, "Usage:   %s [OPTIONS ...] [COMMAND ...]\n", __progname);
	fprintf(stderr, "Version: %s\n", PACKAGE_STRING);

	fprintf(stderr, "\n");

	fprintf(stderr, "-d          Enable more debugging information.\n");
	fprintf(stderr, "-f format   Choose output format (plain, keyvalue or xml).\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "see manual page lldpcli(8) for more information\n");
	exit(1);
}

static int
is_privileged()
{
	return (!(getuid() != geteuid() || getgid() != getegid()));
}

static char*
prompt()
{
#define CESC "\033"
	int privileged = is_privileged();
	if (isatty(STDIN_FILENO)) {
		if (privileged)
			return "[lldpcli] # ";
		return "[lldpcli] $ ";
	}
	return "";
}

static int must_exit = 0;
/**
 * Exit the interpreter.
 */
static int
cmd_exit(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_info("lldpctl", "quit lldpcli");
	must_exit = 1;
	return 1;
}

/**
 * Send an "update" request.
 */
static int
cmd_update(struct lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, void *arg)
{
	log_info("lldpctl", "ask for global update");

	lldpctl_atom_t *config = lldpctl_get_configuration(conn);
	if (config == NULL) {
		log_warnx("lldpctl", "unable to get configuration from lldpd. %s",
		    lldpctl_last_strerror(conn));
		return 0;
	}
	if (lldpctl_atom_set_int(config,
		lldpctl_k_config_tx_interval, -1) == NULL) {
		log_warnx("lldpctl", "unable to ask lldpd for immediate retransmission. %s",
		    lldpctl_last_strerror(conn));
		lldpctl_atom_dec_ref(config);
		return 0;
	}
	log_info("lldpctl", "immediate retransmission requested successfuly");
	lldpctl_atom_dec_ref(config);
	return 1;
}

#ifdef HAVE_LIBREADLINE
static int
_cmd_complete(int all)
{
	char **argv = NULL;
	int argc = 0;
	int rc = 1;
	char *line = malloc(strlen(rl_line_buffer) + 2);
	if (!line) return -1;
	strcpy(line, rl_line_buffer);
	line[rl_point]   = 2;	/* empty character, will force a word */
	line[rl_point+1] = 0;

	if (tokenize_line(line, &argc, &argv) != 0)
		goto end;

	char *compl = commands_complete(root, argc, (const char **)argv, all);
	if (compl && strlen(argv[argc-1]) < strlen(compl)) {
		if (rl_insert_text(compl + strlen(argv[argc-1])) < 0) {
			free(compl);
			goto end;
		}
		free(compl);
		rc = 0;
		goto end;
	}
	/* No completion or several completion available. */
	fprintf(stderr, "\n");
	rl_forced_update_display();
	rc = 0;
end:
	free(line);
	tokenize_free(argc, argv);
	return rc;
}

static int
cmd_complete(int count, int ch)
{
	return _cmd_complete(0);
}

static int
cmd_help(int count, int ch)
{
	return _cmd_complete(1);
}
#else
static char*
readline()
{
	static char line[2048];
	fprintf(stderr, "%s", prompt());
	fflush(stderr);
	if (fgets(line, sizeof(line) - 2, stdin) == NULL)
		return NULL;
	return line;
}
#endif

static struct cmd_node*
register_commands()
{
	root = commands_root();
	register_commands_show(root);
	register_commands_watch(root);
	if (is_privileged()) {
		commands_new(
			commands_new(root, "update", "Update information and send LLDPU on all ports",
			    NULL, NULL, NULL),
			NEWLINE, "Update information and send LLDPU on all ports",
			NULL, cmd_update, NULL);
		register_commands_configure(root);
	}
	commands_new(root, "help", "Get help on a possible command",
	    NULL, cmd_store_env_and_pop, "help");
	commands_new(
		commands_new(root, "exit", "Exit interpreter", NULL, NULL, NULL),
		NEWLINE, "Exit interpreter", NULL, cmd_exit, NULL);
	return root;
}

static int
is_lldpctl(const char *name)
{
	static int last_result = -1;
	if (last_result == -1 && name) {
		char *basec = strdup(name);
		if (!basec) return 0;
		char *bname = basename(basec);
		last_result = (!strcmp(bname, "lldpctl"));
		free(basec);
	}
	return (last_result == -1)?0:last_result;
}

int
main(int argc, char *argv[])
{
	int ch, debug = 1, rc = EXIT_FAILURE;
	char *fmt = "plain";
	lldpctl_conn_t *conn = NULL;
	struct writer *w;

	char *interfaces = NULL;

	/* Get and parse command line options */
	while ((ch = getopt(argc, argv, "hdvf:")) != -1) {
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
		case 'f':
			fmt = optarg;
			break;
		default:
			usage();
		}
	}

	log_init(debug, __progname);

	/* Register commands */
	root = register_commands();

	if (is_lldpctl(argv[0])) {
		for (int i = optind; i < argc; i++) {
			char *prev = interfaces;
			if (asprintf(&interfaces, "%s%s%s",
				prev?prev:"", prev?",":"", argv[i]) == -1) {
				log_warnx("lldpctl", "not enough memory to build list of interfaces");
				goto end;
			}
			free(prev);
		}
		must_exit = 1;
	} else if (optind < argc) {
		/* More arguments! */
		must_exit = 1;
	} else {
#ifdef HAVE_LIBREADLINE
		/* Shell session */
		rl_bind_key('?',  cmd_help);
		rl_bind_key('\t', cmd_complete);
#endif
	}

	/* Make a connection */
	log_debug("lldpctl", "connect to lldpd");
	conn = lldpctl_new(NULL, NULL, NULL);
	if (conn == NULL)
		exit(EXIT_FAILURE);

	do {
		const char *line;
		char **cargv = NULL;
		int n, cargc = 0;
		if (!is_lldpctl(NULL) && (optind >= argc)) {
			line = readline(prompt());
			if (line == NULL) break; /* EOF */

			/* Tokenize it */
			log_debug("lldpctl", "tokenize command line");
			n = tokenize_line(line, &cargc, &cargv);
			switch (n) {
			case -1:
				log_warnx("lldpctl", "internal error while tokenizing");
				goto end;
			case 1:
				log_warnx("lldpctl", "unmatched quotes");
				continue;
			}
			if (cargc == 0) continue;
#ifdef HAVE_READLINE_HISTORY
			add_history(line);
#endif
		}

		/* Init output formatter */
		if      (strcmp(fmt, "plain")    == 0) w = txt_init(stdout);
		else if (strcmp(fmt, "keyvalue") == 0) w = kv_init(stdout);
#ifdef USE_XML
		else if (strcmp(fmt, "xml")      == 0) w = xml_init(stdout);
#endif
#ifdef USE_JSON
		else if (strcmp(fmt, "json")     == 0) w = json_init(stdout);
#endif
		else w = txt_init(stdout);

		if (is_lldpctl(NULL)) {
			if (!interfaces) {
				cargv = (char*[]){ "show", "neighbors", "details" };
				cargc = 3;
			} else {
				cargv = (char*[]){ "show", "neighbors", "ports", interfaces, "details" };
				cargc = 5;
			}
		} else if (optind < argc) {
			cargv = argv;
			cargv = &cargv[optind];
			cargc = argc - optind;
		}

		/* Execute command */
		if (commands_execute(conn, w,
			root, cargc, (const char **)cargv) != 0)
			log_info("lldpctl", "an error occurred while executing last command");
		w->finish(w);

		if (!is_lldpctl(NULL) && optind >= argc)
			tokenize_free(cargc, cargv);
	} while (!must_exit);

	rc = EXIT_SUCCESS;
end:
	if (conn) lldpctl_release(conn);
	if (root) commands_free(root);
	free(interfaces);
	return rc;
}
