/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2014 Michel Stam <michel@reverze.net>,
 *  Vincent Bernat <bernat@luffy.cx>
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json.h>
#include <sys/queue.h>

#include "writer.h"
#include "../compat/compat.h"
#include "../log.h"

/* This list is used as a queue. The queue does not hold reference to the json_t
 * element except the first one. */
struct json_element {
	TAILQ_ENTRY(json_element) next;
	json_object *el;
};
TAILQ_HEAD(json_writer_private, json_element);

static void
jsonc_start(struct writer *w, const char *tag, const char *descr)
{
	struct json_writer_private *p = w->priv;
	struct json_element *current = TAILQ_LAST(p, json_writer_private);
	struct json_element *new;
	json_object *exist = NULL;

    if (!json_object_object_get_ex(current->el, tag, &exist)) {
		exist = json_object_new_array();
		json_object_object_add(current->el, tag, exist);
    }

	/* Queue the new element. */
	new = malloc(sizeof(*new));
	if (new == NULL) fatal(NULL, NULL);
	new->el = json_object_new_object();
	json_object_array_add(exist, new->el);
	TAILQ_INSERT_TAIL(p, new, next);
}

static void
jsonc_attr(struct writer *w, const char *tag,
    const char *descr, const char *value)
{
	struct json_writer_private *p = w->priv;
	struct json_element *current = TAILQ_LAST(p, json_writer_private);
	json_object *jvalue;
	if (value && (!strcmp(value, "yes") || !strcmp(value, "on")))
		jvalue = json_object_new_boolean(1);
	else if (value && (!strcmp(value, "no") || !strcmp(value, "off")))
		jvalue = json_object_new_boolean(0);
	else
		jvalue = json_object_new_string(value?value:"");
	json_object_object_add(current->el, tag, jvalue);
}

static void
jsonc_data(struct writer *w, const char *data)
{
	struct json_writer_private *p = w->priv;
	struct json_element *current = TAILQ_LAST(p, json_writer_private);
	json_object_object_add(current->el, "value",
	    json_object_new_string(data?data:""));
}

static void
jsonc_end(struct writer *w)
{
	struct json_writer_private *p = w->priv;
	struct json_element *current = TAILQ_LAST(p, json_writer_private);
	if (current == NULL) {
		log_warnx("lldpctl", "unbalanced tags");
		return;
	}
	TAILQ_REMOVE(p, current, next);
	free(current);
}

static void
jsonc_finish(struct writer *w)
{
	struct json_writer_private *p = w->priv;
	if (TAILQ_EMPTY(p)) {
		log_warnx("lldpctl", "nothing to output");
	} else if (TAILQ_NEXT(TAILQ_FIRST(p), next) != NULL) {
		log_warnx("lldpctl", "unbalanced tags");
		/* memory will leak... */
	} else {
		struct json_element *first = TAILQ_FIRST(p);
		int json_flags = (JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
		fprintf(stdout, "%s", json_object_to_json_string_ext(first->el, json_flags));
		json_object_put(first->el);
		TAILQ_REMOVE(p, first, next);
		free(first);
	}
	fprintf(stdout, "\n");
	free(p);
	free(w);
}

struct writer*
jsonc_init(FILE *fh)
{
	struct writer *result;
	struct json_writer_private *priv;
	struct json_element *root;

	priv = malloc(sizeof(*priv));
	root = malloc(sizeof(*root));
	if (priv == NULL || root == NULL) fatal(NULL, NULL);
	TAILQ_INIT(priv);
	TAILQ_INSERT_TAIL(priv, root, next);
	root->el = json_object_new_object();
	if (root->el == NULL)
		fatalx("lldpctl", "cannot create JSON root object");

	result = malloc(sizeof(*result));
	if (result == NULL) fatal(NULL, NULL);

	result->priv   = priv;
	result->start  = jsonc_start;
	result->attr   = jsonc_attr;
	result->data   = jsonc_data;
	result->end    = jsonc_end;
	result->finish = jsonc_finish;

	return result;
}
