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

#ifndef _MARSHAL_H
#define _MARSHAL_H

#include <stddef.h>
#include <sys/types.h>

struct marshal_info;
enum marshal_subinfo_kind {
	pointer,
	substruct,
	ignore,
};
#define MARSHAL_INFO_POINTER 1
#define MARSHAL_INFO_SUB     2
struct marshal_subinfo {
	size_t offset;	     /* Offset compared to parent structure */
	size_t offset2;	     /* Ancillary offset (for related data) */
	enum marshal_subinfo_kind kind; /* Kind of substructure */
	struct  marshal_info *mi;
};
#define MARSHAL_SUBINFO_NULL { .offset = 0, .offset2 = 0, .kind = ignore, .mi = NULL }
struct marshal_info {
	char   *name;		/* Name of structure */
	size_t  size;		/* Size of the structure */
#if defined __GNUC__ && __GNUC__ < 3
	/* With gcc 2.96, flexible arrays are not supported, even with
	 * -std=gnu99. And with gcc 3.x, zero-sized arrays cannot be statically
	 * initialized (with more than one element). */
	struct marshal_subinfo pointers[0]; /* Pointer to other structures */
#else
	struct marshal_subinfo pointers[]; /* Pointer to other structures */
#endif
};
/* Special case for strings */
extern struct marshal_info marshal_info_string;
extern struct marshal_info marshal_info_fstring;
extern struct marshal_info marshal_info_ignore;

/* Declare a new marshal_info struct named after the type we want to
   marshal. The marshalled type has to be a structure. */
#define MARSHAL_INFO(type) marshal_info_##type
#ifdef MARSHAL_EXPORT
#define MARSHAL_BEGIN(type) struct marshal_info MARSHAL_INFO(type) =	\
	{								\
		.name = #type,						\
		.size = sizeof(struct type),				\
		.pointers = {
#define MARSHAL_ADD(_kind, type, subtype, member)		\
	{ .offset = offsetof(struct type, member),		\
	  .offset2 = 0,						\
	  .kind = _kind,					\
	  .mi = &MARSHAL_INFO(subtype) },
#define MARSHAL_FSTR(type, member, len)				\
	{ .offset = offsetof(struct type, member),		\
	  .offset2 = offsetof(struct type, len),		\
	  .kind = pointer,					\
	  .mi = &marshal_info_fstring },
#define MARSHAL_END MARSHAL_SUBINFO_NULL }}
#else
#define MARSHAL_BEGIN(type) extern struct marshal_info MARSHAL_INFO(type)
#define MARSHAL_ADD(...)
#define MARSHAL_FSTR(...)
#define MARSHAL_END
#endif
/* Shortcuts */
#define MARSHAL_POINTER(...) MARSHAL_ADD(pointer, ##__VA_ARGS__)
#define MARSHAL_SUBSTRUCT(...) MARSHAL_ADD(substruct, ##__VA_ARGS__)
#define MARSHAL_STR(type, member) MARSHAL_ADD(pointer, type, string, member)
#define MARSHAL_IGNORE(type, member) MARSHAL_ADD(ignore, type, ignore, member)
#define MARSHAL_TQE(type, field)			 \
	MARSHAL_POINTER(type, type, field.tqe_next)	 \
	MARSHAL_IGNORE(type, field.tqe_prev)
/* Support for TAILQ list is partial. Access to last and previous
   elements is not available. Some operations are therefore not
   possible. However, TAILQ_FOREACH is still
   available. */
#define MARSHAL_TQH(type, subtype)			 \
	MARSHAL_POINTER(type, subtype, tqh_first)	 \
	MARSHAL_IGNORE(type, tqh_last)
#define MARSHAL_SUBTQ(type, subtype, field)		 \
	MARSHAL_POINTER(type, subtype, field.tqh_first)	 \
	MARSHAL_IGNORE(type, field.tqh_last)
#define MARSHAL(type)			\
	MARSHAL_BEGIN(type)		\
	MARSHAL_END
#define MARSHAL_TQ(type, subtype)	\
	MARSHAL_BEGIN(type)		\
	MARSHAL_TQH(type, subtype)	\
	MARSHAL_END

/* Serialization */
ssize_t  marshal_serialize_(struct marshal_info *, void *, void **, int, void *, int)
	__attribute__((nonnull (1, 2, 3) ));
#define marshal_serialize(type, o, output) marshal_serialize_(&MARSHAL_INFO(type), o, output, 0, NULL, 0)

/* Unserialization */
size_t  marshal_unserialize_(struct marshal_info *, void *, size_t, void **, void*, int, int)
	__attribute__((nonnull (1, 2, 4) ));
#define marshal_unserialize(type, o, l, input) \
	marshal_unserialize_(&MARSHAL_INFO(type), o, l, input, NULL, 0, 0)

#endif
