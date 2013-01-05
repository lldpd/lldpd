/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2012 Vincent Bernat <bernat@luffy.cx>
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

#ifndef _CLIENT_H
#define _CLIENT_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "../lib/lldpctl.h"
#include "../lldp-const.h"
#include "../log.h"
#include "../ctl.h"
#include "writer.h"

/* commands.c */
#define NEWLINE "<CR>"
struct cmd_node;
struct cmd_env;
struct cmd_node *commands_root(void);
struct cmd_node *commands_new(
	struct cmd_node *,
	const char *,
	const char *,
	int(*validate)(struct cmd_env*, void *),
	int(*execute)(struct lldpctl_conn_t*, struct writer*,
	    struct cmd_env*, void *),
	void *);
void commands_free(struct cmd_node *);
const char *cmdenv_arg(struct cmd_env*);
const char *cmdenv_get(struct cmd_env*, const char*);
int cmdenv_put(struct cmd_env*, const char*, const char*);
int cmdenv_pop(struct cmd_env*, int);
int commands_execute(struct lldpctl_conn_t *, struct writer *,
    struct cmd_node *, int argc, const char **argv);
char *commands_complete(struct cmd_node *, int argc, const char **argv,
    int cursorc, int cursoro, int all);
/* helpers */
int cmd_check_no_env(struct cmd_env *, void *);
int cmd_check_env(struct cmd_env *, void *);
int cmd_store_env(struct lldpctl_conn_t *, struct writer *,
    struct cmd_env *, void *);
int cmd_store_env_and_pop(struct lldpctl_conn_t *, struct writer *,
    struct cmd_env *, void *);
int cmd_store_env_value(struct lldpctl_conn_t *, struct writer *,
    struct cmd_env *, void *);
int cmd_store_env_value_and_pop(struct lldpctl_conn_t *, struct writer *,
    struct cmd_env *, void *);
int cmd_store_env_value_and_pop2(struct lldpctl_conn_t *, struct writer *,
    struct cmd_env *, void *);
int cmd_store_env_value_and_pop3(struct lldpctl_conn_t *, struct writer *,
    struct cmd_env *, void *);
lldpctl_atom_t* cmd_iterate_on_interfaces(struct lldpctl_conn_t *,
    struct cmd_env *);

/* misc.c */
int contains(const char *, const char *);
char*  totag(const char *);

/* display.c */
#define DISPLAY_BRIEF   1
#define DISPLAY_NORMAL  2
#define DISPLAY_DETAILS 3
void display_interfaces(lldpctl_conn_t *, struct writer *,
    struct cmd_env *, int, int);
void display_interface(lldpctl_conn_t *, struct writer *, int,
    lldpctl_atom_t *, lldpctl_atom_t *, int);
void display_configuration(lldpctl_conn_t *, struct writer *);

/* show.c */
void register_commands_show(struct cmd_node *);
void register_commands_watch(struct cmd_node *);

/* actions.c */
void register_commands_configure(struct cmd_node *);

#endif
