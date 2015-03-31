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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>

#include "lldpctl.h"
#include "../lldpd-structs.h"
#include "../log.h"
#include "private.h"
#include "fixedpoint.h"

static lldpctl_map_t empty_map[] = {{ 0, NULL }};

static struct atom_map atom_map_list = {
	.next = NULL
};

lldpctl_map_t*
lldpctl_key_get_map(lldpctl_key_t key)
{
	struct atom_map *map;
	for (map = atom_map_list.next; map ; map = map->next) {
		if (map->key == key)
			return map->map;
	}
	return empty_map;
}

void atom_map_register(struct atom_map *map)
{
	struct atom_map* iter = &atom_map_list;

	while (iter->next)
		iter = iter->next;

	iter->next = map;
}

static struct atom_builder atom_builder_list = {
	.nextb = NULL
};

void atom_builder_register(struct atom_builder *builder)
{
	struct atom_builder* iter = &atom_builder_list;

	while (iter->nextb)
		iter = iter->nextb;

	iter->nextb = builder;
}

lldpctl_atom_t*
_lldpctl_new_atom(lldpctl_conn_t *conn, atom_t type, ...)
{
	struct atom_builder *builder;
	struct lldpctl_atom_t *atom;
	va_list(ap);
	for (builder = atom_builder_list.nextb; builder ; builder = builder->nextb) {
		if (builder->type != type) continue;
		atom = calloc(1, builder->size);
		if (atom == NULL) {
			SET_ERROR(conn, LLDPCTL_ERR_NOMEM);
			return NULL;
		}
		atom->count = 1;
		atom->type  = type;
		atom->conn  = conn;
		TAILQ_INIT(&atom->buffers);
		atom->free  = builder->free;

		atom->iter  = builder->iter;
		atom->next  = builder->next;
		atom->value = builder->value;

		atom->get       = builder->get;
		atom->get_str   = builder->get_str;
		atom->get_buffer= builder->get_buffer;
		atom->get_int   = builder->get_int;

		atom->set       = builder->set;
		atom->set_str   = builder->set_str;
		atom->set_buffer= builder->set_buffer;
		atom->set_int   = builder->set_int;
		atom->create    = builder->create;

		va_start(ap, type);
		if (builder->init && builder->init(atom, ap) == 0) {
			free(atom);
			va_end(ap);
			/* Error to be set in init() */
			return NULL;
		}
		va_end(ap);
		return atom;
	}
	log_warnx("rpc", "unknown atom type: %d", type);
	SET_ERROR(conn, LLDPCTL_ERR_FATAL);
	return NULL;
}

/**
 * Allocate a buffer inside an atom.
 *
 * It will be freed automatically when the atom is released. This buffer cannot
 * be reallocated and should not be freed!
 *
 * @param atom Atom which will be used as a container.
 * @param size Size of the allocated area.
 * @return Pointer to the buffer or @c NULL if allocation fails.
 */
void*
_lldpctl_alloc_in_atom(lldpctl_atom_t *atom, size_t size)
{
	struct atom_buffer *buffer;

	if ((buffer = calloc(1, size + sizeof(struct atom_buffer))) == NULL) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOMEM);
		return NULL;
	}
	TAILQ_INSERT_TAIL(&atom->buffers, buffer, next);
	return &buffer->data[0];
}

/**
 * Allocate a buffer inside an atom and dump another buffer in it.
 *
 * The dump is done in hexadecimal with the provided separator.
 *
 * @param atom   Atom which will be used as a container.
 * @param input  Buffer we want to dump.
 * @param size   Size of the buffer
 * @param sep    Separator to use.
 * @param max    Maximum number of bytes to dump. Can be 0 if no maximum.
 * @return A string representing the dump of the buffer or @c NULL if error.
 */
const char*
_lldpctl_dump_in_atom(lldpctl_atom_t *atom,
    const uint8_t *input, size_t size,
    char sep, size_t max)
{
	static const char truncation[] = "[...]";
	size_t i, len;
	char *buffer = NULL;

	if (max > 0 && size > max)
		len = max * 3 + sizeof(truncation) + 1;
	else
		len = size * 3 + 1;

	if ((buffer = _lldpctl_alloc_in_atom(atom, len)) == NULL)
		return NULL;

	for (i = 0; (i < size) && (max == 0 || i < max); i++)
		snprintf(buffer + i * 3, 4, "%02x%c", *(u_int8_t*)(input + i), sep);
	if (max > 0 && size > max)
		snprintf(buffer + i * 3, sizeof(truncation) + 1, "%s", truncation);
	else
		*(buffer + i*3 - 1) = 0;
	return buffer;
}
