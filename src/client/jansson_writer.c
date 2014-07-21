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

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <sys/queue.h>

#include "writer.h"
#include "../compat/compat.h"
#include "../log.h"

/*
 * { lldp:
 *    { interface: [

 * { chassis:
 *   { id: { type: "mac", value: "60:eb:69:ce:6e:a0" },
 *     name: "guybrush",
 *     descr: "Debian GNU/Linux 7.0 (wheezy)",
 *     capability: [{type: "bridge", enabled: true}, {type: "router", enabled: false}] },
*  <interface label="Interface" name="port2" via="LLDP" rid="1" age="0 day, 00:00:09">
*   <chassis label="Chassis">
*    <id label="ChassisID" type="mac">60:eb:69:ce:6e:a0</id>
*    <name label="SysName">guybrush.luffy.cx</name>
*    <descr label="SysDescr">Debian GNU/Linux 7.0 (wheezy) Linux 3.5-trunk-amd64 #1 SMP Debian 3.5.5-1~experimental.1 x86_64</descr>
*    <mgmt-ip label="MgmtIP">192.168.116.3</mgmt-ip>
*    <capability label="Capability" type="Bridge" enabled="off"/>
*    <capability label="Capability" type="Router" enabled="off"/>
*    <capability label="Capability" type="Wlan" enabled="on"/>
*   </chassis>
*   <port label="Port">
*    <id label="PortID" type="mac">fe:86:6f:b6:1e:db</id>
*    <descr label="PortDescr">port1</descr>
*    <auto-negotiation label="PMD autoneg" supported="no" enabled="no">
*     <current label="MAU oper type">10GigBaseR - R PCS/PMA, unknown PMD.</current>
*    </auto-negotiation>
*   </port>
*  </interface>
* </lldp>
*/

/* This list is used as a queue. The queue does not hold reference to the json_t
 * element except the first one. */
struct json_element {
	TAILQ_ENTRY(json_element) next;
	json_t *el;
};
TAILQ_HEAD(json_writer_private, json_element);

static void
jansson_start(struct writer *w, const char *tag, const char *descr)
{
	struct json_writer_private *p = w->priv;
	struct json_element *current = TAILQ_LAST(p, json_writer_private);
	struct json_element *new;
	json_t *exist;

	/* Try to find if a similar object exists. */
	exist = json_object_get(current->el, tag);
	if (!exist) {
		exist = json_array();
		json_object_set_new(current->el, tag, exist);
	}

	/* Queue the new element. */
	new = malloc(sizeof(*new));
	if (new == NULL) fatal(NULL, NULL);
	new->el = json_object();
	json_array_append_new(exist, new->el);
	TAILQ_INSERT_TAIL(p, new, next);
}

static void
jansson_attr(struct writer *w, const char *tag,
    const char *descr, const char *value)
{
	struct json_writer_private *p = w->priv;
	struct json_element *current = TAILQ_LAST(p, json_writer_private);
	json_t *jvalue;
	if (!strcmp(value, "yes") || !strcmp(value, "on"))
		jvalue = json_true();
	else if (!strcmp(value, "no") || !strcmp(value, "off"))
		jvalue = json_false();
	else
		jvalue = json_string(value);
	json_object_set_new(current->el, tag, jvalue);
}

static void
jansson_data(struct writer *w, const char *data)
{
	struct json_writer_private *p = w->priv;
	struct json_element *current = TAILQ_LAST(p, json_writer_private);
	json_object_set_new(current->el, "value", json_string(data));
}

static void
jansson_end(struct writer *w)
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

/* When an array has only one member, just remove the array. When an object has
 * `value` as the only key, remove the object. Moreover, for an object, move the
 * `name` key outside (inside a new object). This is a recursive function. We
 * think the depth will be limited. */
static json_t*
jansson_cleanup(json_t *el)
{
	json_t *new;
	if (el == NULL) return NULL;
	if (json_is_array(el) && json_array_size(el) == 1) {
		new = json_array_get(el, 0);
		return jansson_cleanup(new);
	}
	if (json_is_array(el)) {
		int i = json_array_size(el);
		new = json_array();
		while (i > 0) {
			json_array_insert_new(new, 0,
			    jansson_cleanup(json_array_get(el, --i)));
		}
		return new;
	}
	if (json_is_object(el) && json_object_size(el) == 1) {
		new = json_object_get(el, "value");
		if (new) {
			json_incref(new);
			return new; /* This is a string or a boolean, no need to
				     * cleanup */
		}
	}
	if (json_is_object(el)) {
		json_t *value;
		json_t *name = NULL;
		void *iter = json_object_iter(el);
		new = json_object();
		while (iter) {
			const char *key;
			key   = json_object_iter_key(iter);
			value = jansson_cleanup(json_object_iter_value(iter));
			if (strcmp(key, "name") || !json_is_string(value)) {
				json_object_set_new(new, key, value);
			} else {
				name = value;
			}
			iter  = json_object_iter_next(el, iter);
		}
		if (name) {
			/* Embed the current object into a new one with the name
			 * as key. */
			new = json_pack("{s: o}", /* o: stolen reference */
			    json_string_value(name), new);
			json_decref(name);
		}
		return new;
	}
	json_incref(el);
	return el;
}

static void
jansson_finish(struct writer *w)
{
	struct json_writer_private *p = w->priv;
	if (TAILQ_EMPTY(p)) {
		log_warnx("lldpctl", "nothing to output");
	} else if (TAILQ_NEXT(TAILQ_FIRST(p), next) != NULL) {
		log_warnx("lldpctl", "unbalanced tags");
		/* memory will leak... */
	} else {
		struct json_element *first = TAILQ_FIRST(p);
		json_t *export = jansson_cleanup(first->el);
		if (json_dumpf(export,
			stdout,
			JSON_INDENT(2) | JSON_PRESERVE_ORDER) == -1)
			log_warnx("lldpctl", "unable to output JSON");
		json_decref(first->el);
		json_decref(export);
		TAILQ_REMOVE(p, first, next);
		free(first);
	}
	free(p);
	free(w);
}

struct writer*
jansson_init(FILE *fh)
{
	struct writer *result;
	struct json_writer_private *priv;
	struct json_element *root;

	priv = malloc(sizeof(*priv));
	root = malloc(sizeof(*root));
	if (priv == NULL || root == NULL) fatal(NULL, NULL);
	TAILQ_INIT(priv);
	TAILQ_INSERT_TAIL(priv, root, next);
	root->el = json_object();
	if (root->el == NULL)
		fatalx("cannot create JSON root object");

	result = malloc(sizeof(*result));
	if (result == NULL) fatal(NULL, NULL);

	result->priv   = priv;
	result->start  = jansson_start;
	result->attr   = jansson_attr;
	result->data   = jansson_data;
	result->end    = jansson_end;
	result->finish = jansson_finish;

	return result;
}
