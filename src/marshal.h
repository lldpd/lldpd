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
struct marshal_info {
	char   *name;		/* Name of structure */
	size_t  size;		/* Size of the structure */
	struct marshal_subinfo pointers[]; /* Pointer to other structures */
};
/* Special case for strings */
extern struct marshal_info marshal_info__string;
extern struct marshal_info marshal_info__fstring;
extern struct marshal_info marshal_info__ignore;

/* Declare a new marshal_info struct named after the type we want to
   marshal. The marshalled type has to be a structure. */
#define MARSHAL_BEGIN(type) struct marshal_info marshal_info_##type = \
	{								\
		.name = #type,						\
		.size = sizeof(struct type),				\
		.pointers = {
#define MARSHAL_ADD(_kind, type, subtype, member)		\
	{ .offset = offsetof(struct type, member),		\
	  .kind = _kind,					\
	  .mi = &marshal_info_##subtype },
#define MARSHAL_POINTER(...) MARSHAL_ADD(pointer, ##__VA_ARGS__)
#define MARSHAL_SUBSTRUCT(...) MARSHAL_ADD(substruct, ##__VA_ARGS__)
#define MARSHAL_STR(type, member) MARSHAL_ADD(pointer, type, _string, member)
#define MARSHAL_FSTR(type, member, len)				\
	{ .offset = offsetof(struct type, member),		\
	  .offset2 = offsetof(struct type, len),		\
	  .kind = pointer,					\
	  .mi = &marshal_info__fstring },
#define MARSHAL_IGNORE(type, member) MARSHAL_ADD(ignore, type, _ignore, member)
#define MARSHAL_TQE(type, field)			 \
	MARSHAL_POINTER(type, type, field.tqe_next)	 \
	MARSHAL_POINTER(type, type, field.tqe_prev)
#define MARSHAL_TQH(type, subtype)			 \
	MARSHAL_POINTER(type, subtype, tqh_first)	 \
	MARSHAL_POINTER(type, subtype, tqh_last)
#define MARSHAL_SUBTQ(type, subtype, field)		 \
	MARSHAL_POINTER(type, subtype, field.tqh_first)	 \
	MARSHAL_POINTER(type, subtype, field.tqh_last)
#define MARSHAL_END { .mi = NULL } } }
/* Shortcuts */
#define MARSHAL(type)			\
	MARSHAL_BEGIN(type)		\
	MARSHAL_END
#define MARSHAL_TQ(type, subtype)	\
	MARSHAL_BEGIN(type)		\
	MARSHAL_TQH(type, subtype)	\
	MARSHAL_END

/* Serialization */
size_t  _marshal_serialize(struct marshal_info *, void *, void **, int, void *, int);
#define marshal_serialize(type, o, output) _marshal_serialize(&marshal_info_##type, o, output, 0, NULL, 0)

/* Unserialization */
size_t  _marshal_unserialize(struct marshal_info *, void *, size_t, void **, void*, int, int);
#define marshal_unserialize(type, o, l, input) \
	_marshal_unserialize(&marshal_info_##type, o, l, (void **)input, NULL, 0, 0)

#endif
