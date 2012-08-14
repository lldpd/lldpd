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

#define MARSHAL_EXPORT
#include "marshal.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <string.h>

#include "compat/compat.h"
#include "log.h"

#include "lldpd-structs.h"

/* A serialized object */
struct marshal_serialized {
	void         *orig;	/* Original reference. Also enforce alignment. */
	size_t        size;
	unsigned char object[0];
};

struct marshal_info marshal_info_string = {
	.name = "null string",
	.size = 0,
	.pointers = {MARSHAL_SUBINFO_NULL},
};
struct marshal_info marshal_info_fstring = {
	.name = "fixed string",
	.size = 0,
	.pointers = {MARSHAL_SUBINFO_NULL},
};
struct marshal_info marshal_info_ignore = {
	.name = "ignored",
	.size = 0,
	.pointers = {MARSHAL_SUBINFO_NULL},
};

/* List of already seen pointers */
struct ref {
	TAILQ_ENTRY(ref) next;
	void *pointer;
};
TAILQ_HEAD(ref_l, ref);

/* Serialize the given object. */
size_t
marshal_serialize_(struct marshal_info *mi, void *unserialized, void **input,
    int skip, void *_refs, int osize)
{
	struct ref_l *refs = _refs;
	struct ref *cref;
	int size;
	size_t len;
	struct marshal_subinfo *current;
	struct marshal_serialized *new = NULL, *serialized = NULL;

	/* Check if we have already serialized this one. */
	if (!refs) {
		refs = calloc(1, sizeof(struct ref_l));
		if (!refs) {
			LLOG_WARNX("unable to allocate memory for list of references");
			return -1;
		}
		TAILQ_INIT(refs);
	}
	TAILQ_FOREACH(cref, refs, next) {
		if (unserialized == cref->pointer)
			return 0;
	}

	/* Handle special cases. */
	size = mi->size;
	if (!strcmp(mi->name, "null string"))
		size = strlen((char *)unserialized) + 1;
	else if (!strcmp(mi->name, "fixed string"))
		size = osize;

	/* Allocate serialized structure */
	len = sizeof(struct marshal_serialized) + (skip?0:size);
	serialized = calloc(1, len);
	if (!serialized) {
		LLOG_WARNX("unable to allocate memory to serialize structure %s",
		    mi->name);
		len = -1;
		goto marshal_error;
	}
	serialized->orig = unserialized;

	/* Append the new reference */
	if (!(cref = calloc(1, sizeof(struct ref)))) {
		LLOG_WARNX("unable to allocate memory for list of references");
		free(serialized);
		len = -1;
		goto marshal_error;
	}
	cref->pointer = unserialized;
	TAILQ_INSERT_TAIL(refs, cref, next);

	/* First, serialize the main structure */
	if (!skip)
		memcpy(serialized->object, unserialized, size);

	/* Then, serialize inner structures */
	for (current = mi->pointers; current->mi; current++) {
		size_t sublen;
		void  *source;
		void  *target;
		if (current->kind == ignore) continue;
		if (current->kind == pointer) {
			memcpy(&source,
			    (unsigned char *)unserialized + current->offset,
			    sizeof(void *));
			if (source == NULL) continue;
		} else
			source = (void *)((unsigned char *)unserialized + current->offset);
		if (current->offset2)
			memcpy(&osize, (unsigned char*)unserialized + current->offset2, sizeof(int));
		sublen = marshal_serialize_(current->mi,
		    source, &target,
		    current->kind == substruct, refs, osize);
		if (sublen == -1) {
			LLOG_WARNX("unable to serialize substructure %s for %s",
			    current->mi->name, mi->name);
			free(serialized);
			return -1;
		}
		if (sublen == 0) continue; /* This was already serialized */
		/* Append the result */
		new = realloc(serialized, len + sublen);
		if (!new) {
			LLOG_WARNX("unable to allocate more memory to serialize structure %s",
			    mi->name);
			free(serialized);
			free(target);
			len = -1;
			goto marshal_error;
		}
		memcpy((unsigned char *)new + len, target, sublen);
		free(target);
		len += sublen;
		serialized = (struct marshal_serialized *)new;
	}

	serialized->size = len;
	*input = serialized;
marshal_error:
	if (refs && !_refs) {
		struct ref *cref, *cref_next;
		for (cref = TAILQ_FIRST(refs);
		     cref != NULL;
		     cref = cref_next) {
			cref_next = TAILQ_NEXT(cref, next);
			TAILQ_REMOVE(refs, cref, next);
			free(cref);
		}
		free(refs);
	}
	return len;
}

/* This structure is used to track memory allocation when serializing */
struct gc {
	TAILQ_ENTRY(gc) next;
	void *pointer;
	void *orig;		/* Original reference (not valid anymore !) */
};
TAILQ_HEAD(gc_l, gc);

static void*
marshal_alloc(struct gc_l *pointers, size_t len, void *orig)
{
	struct gc *gpointer = NULL;

	void *result = calloc(1, len);
	if (!result) return NULL;
	if ((gpointer = (struct gc *)calloc(1,
		    sizeof(struct gc))) == NULL) {
		free(result);
		return NULL;
	}
	gpointer->pointer = result;
	gpointer->orig = orig;
	TAILQ_INSERT_TAIL(pointers, gpointer, next);
	return result;
}
static void
marshal_free(struct gc_l *pointers, int gconly)
{
	struct gc *pointer, *pointer_next;
	for (pointer = TAILQ_FIRST(pointers);
	     pointer != NULL;
	     pointer = pointer_next) {
		pointer_next = TAILQ_NEXT(pointer, next);
		TAILQ_REMOVE(pointers, pointer, next);
		if (!gconly)
			free(pointer->pointer);
		free(pointer);
	}
}


/* Unserialize the given object. */
size_t
marshal_unserialize_(struct marshal_info *mi, void *buffer, size_t len, void **output,
    void *_pointers, int skip, int osize)
{
	int    total_len = sizeof(struct marshal_serialized) + (skip?0:mi->size);
	struct marshal_serialized *serialized = buffer;
	struct gc_l *pointers = _pointers;
	int size, already, extra = 0;
	void *new;
	struct marshal_subinfo *current;
	struct gc *apointer;

	if (len < sizeof(struct marshal_serialized) || len < total_len) {
		LLOG_WARNX("data to deserialize is too small (%zu) for structure %s",
		    len, mi->name);
		return 0;
	}

	/* Initialize garbage collection */
	if (!pointers) {
		pointers = calloc(1, sizeof(struct gc_l));
		if (!pointers) {
			LLOG_WARNX("unable to allocate memory for garbage collection");
			return 0;
		}
		TAILQ_INIT(pointers);
	}

	/* Special cases */
	size = mi->size;
	if (!strcmp(mi->name, "null string") || !strcmp(mi->name, "fixed string")) {
		switch (mi->name[0]) {
		case 'n': size = strnlen((char *)serialized->object,
		    len - sizeof(struct marshal_serialized)) + 1; break;
		case 'f': size = osize; extra=1; break; /* The extra byte is to ensure that
							   the string is null terminated. */
		}
		if (size > len - sizeof(struct marshal_serialized)) {
			LLOG_WARNX("data to deserialize contains a string too long");
			total_len = 0;
			goto unmarshal_error;
		}
		total_len += size;
	}

	/* First, the main structure */
	if (!skip) {
		if ((*output = marshal_alloc(pointers, size + extra, serialized->orig)) == NULL) {
			LLOG_WARNX("unable to allocate memory to unserialize structure %s",
			    mi->name);
			total_len = 0;
			goto unmarshal_error;
		}
		memcpy(*output, serialized->object, size);
	}

	/* Then, each substructure */
	for (current = mi->pointers; current->mi; current++) {
		size_t  sublen;
		new = (unsigned char *)*output + current->offset;
		if (current->kind == ignore) {
			memset((unsigned char *)*output + current->offset,
			       0, sizeof(void *));
			continue;
		}
		if (current->kind == pointer) {
			if (*(void **)new == NULL) continue;

			/* Did we already see this reference? */
			already = 0;
			TAILQ_FOREACH(apointer, pointers, next)
				if (apointer->orig == *(void **)new) {
					memcpy((unsigned char *)*output + current->offset,
					    &apointer->pointer, sizeof(void *));
					already = 1;
					break;
				}
			if (already) continue;
		}
		/* Deserialize */
		if (current->offset2)
			memcpy(&osize, (unsigned char *)*output + current->offset2, sizeof(int));
		sublen = marshal_unserialize_(current->mi,
		    (unsigned char *)buffer + total_len, len - total_len, &new, pointers,
		    current->kind == substruct, osize);
		if (sublen == 0) {
			LLOG_WARNX("unable to serialize substructure %s for %s",
			    current->mi->name, mi->name);
			total_len = 0;
			goto unmarshal_error;
		}
		/* Link the result */
		if (current->kind == pointer)
			memcpy((unsigned char *)*output + current->offset,
			    &new, sizeof(void *));
		total_len += sublen;
	}

unmarshal_error:
	if (pointers && !_pointers) {
		marshal_free(pointers, (total_len > 0));
		free(pointers);
	}
	return total_len;
}
