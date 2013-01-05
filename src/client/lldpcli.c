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
#include <histedit.h>
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
prompt(EditLine *el)
{
	int privileged = is_privileged();
	if (privileged)
		return "[lldpcli] # ";
	return "[lldpcli] $ ";
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

static unsigned char
_cmd_complete(EditLine *el, int ch, int all)
{
	int rc = CC_ERROR;
	Tokenizer *eltok;
	if ((eltok = tok_init(NULL)) == NULL)
		goto end;

	const LineInfo *li = el_line(el);

	const char **argv;
	char *compl;
	int argc, cursorc, cursoro;
	if (tok_line(eltok, li, &argc, &argv, &cursorc, &cursoro) != 0)
		goto end;
	compl = commands_complete(root, argc, argv, cursorc, cursoro, all);
	if (compl) {
		el_deletestr(el, cursoro);
		if (el_insertstr(el, compl) == -1) {
			free(compl);
			goto end;
		}
		free(compl);
		rc = CC_REDISPLAY;
		goto end;
	}
	/* No completion or several completion available. We beep. */
	el_beep(el);
	rc = CC_REDISPLAY;
end:
	if (eltok) tok_end(eltok);
	return rc;
}

static unsigned char
cmd_complete(EditLine *el, int ch)
{
	return _cmd_complete(el, ch, 0);
}

static unsigned char
cmd_help(EditLine *el, int ch)
{
	return _cmd_complete(el, ch, 1);
}

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
	lldpctl_conn_t *conn;
	struct writer *w;

	EditLine  *el = NULL;
	History   *elhistory = NULL;
	HistEvent  elhistev;
	Tokenizer *eltok = NULL;

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
		goto skipeditline;
	} else {
		if (optind < argc) {
			/* More arguments! */
			must_exit = 1;
		}
	}

	/* Init editline */
	log_debug("lldpctl", "init editline");
	el = el_init("lldpctl", stdin, stdout, stderr);
	if (el == NULL) {
		log_warnx("lldpctl", "unable to setup editline");
		goto end;
	}
	el_set(el, EL_PROMPT, prompt);
	el_set(el, EL_SIGNAL, 1);
	el_set(el, EL_EDITOR, "emacs");
	/* If on a TTY, setup completion */
	if (isatty(STDERR_FILENO)) {
		el_set(el, EL_ADDFN, "command_complete",
		    "Execute completion", cmd_complete);
		el_set(el, EL_ADDFN, "command_help",
		    "Show completion", cmd_help);
		el_set(el, EL_BIND, "^I", "command_complete", NULL);
		el_set(el, EL_BIND, "?", "command_help", NULL);
	}

	/* Init history */
	elhistory = history_init();
	if (elhistory == NULL) {
		log_warnx("lldpctl", "unable to enable history");
	} else {
		history(elhistory, &elhistev, H_SETSIZE, 800);
		el_set(el, EL_HIST, history, elhistory);
	}

	/* Init tokenizer */
	eltok = tok_init(NULL);
	if (eltok == NULL) {
		log_warnx("lldpctl", "unable to initialize tokenizer");
		goto end;
	}

skipeditline:
	/* Make a connection */
	log_debug("lldpctl", "connect to lldpd");
	conn = lldpctl_new(NULL, NULL, NULL);
	if (conn == NULL)
		exit(EXIT_FAILURE);

	do {
		const char *line;
		const char **cargv;
		int count, n, cargc;

		if (!is_lldpctl(NULL) && (optind >= argc)) {
			/* Read a new line. */
			line = el_gets(el, &count);
			if (line == NULL) break;

			/* Tokenize it */
			log_debug("lldpctl", "tokenize command line");
			n = tok_str(eltok, line, &cargc, &cargv);
			switch (n) {
			case -1:
				log_warnx("lldpctl", "internal error while tokenizing");
				goto end;
			case 1:
			case 2:
			case 3:
				/* TODO: handle multiline statements */
				log_warnx("lldpctl", "unmatched quotes");
				tok_reset(eltok);
				continue;
			}
			if (cargc == 0) {
				tok_reset(eltok);
				continue;
			}
			if (elhistory) history(elhistory, &elhistev, H_ENTER, line);
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
				cargv = (const char*[]){ "show", "neighbors", "details" };
				cargc = 3;
			} else {
				cargv = (const char*[]){ "show", "neighbors", "ports", interfaces, "details" };
				cargc = 5;
			}
		} else if (optind < argc) {
			cargv = (const char **)argv;
			cargv = &cargv[optind];
			cargc = argc - optind;
		}

		/* Execute command */
		if (commands_execute(conn, w,
			root, cargc, cargv) != 0)
			log_info("lldpctl", "an error occurred while executing last command");
		w->finish(w);

		if (eltok) tok_reset(eltok);
	} while (!must_exit);

	rc = EXIT_SUCCESS;
end:
	if (conn) lldpctl_release(conn);
	if (eltok) tok_end(eltok);
	if (elhistory) history_end(elhistory);
	if (el) el_end(el);
	if (root) commands_free(root);
	free(interfaces);
	return rc;
}
