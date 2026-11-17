/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2009 Vincent Bernat <bernat@luffy.cx>
 * Copyright (c) 2014 Michael Chapman
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

#ifndef _FRAME_H
#define _FRAME_H

static union {
	uint8_t f_uint8;
	uint16_t f_uint16;
	uint32_t f_uint32;
} types;

/* This set of macro are used to build packets. The current position in buffer
 * is `pos'. The length of the remaining space in buffer is `length'. `type'
 * should be a member of `types'.
 *
 * This was stolen from ladvd which was adapted from Net::CDP. The original
 * author of those macros, Michael Chapman, has relicensed those macros under
 * the ISC license. */

#define POKE(value, type, func)                                    \
	((length >= sizeof(type)) &&                               \
	    (type = func(value), memcpy(pos, &type, sizeof(type)), \
		length -= sizeof(type), pos += sizeof(type), 1))
#define POKE_UINT8(value) POKE(value, types.f_uint8, )
#define POKE_UINT16(value) POKE(value, types.f_uint16, htons)
#define POKE_UINT32(value) POKE(value, types.f_uint32, htonl)
#define POKE_BYTES(value, bytes) \
	((length >= (bytes)) &&  \
	    (memcpy(pos, value, bytes), length -= (bytes), pos += (bytes), 1))
#define POKE_SAVE(where) (where = pos, 1)
#define POKE_RESTORE(where)                        \
	do {                                       \
		if ((where) > pos)                 \
			length -= ((where) - pos); \
		else                               \
			length += (pos - (where)); \
		pos = (where);                     \
	} while (0)

/* This set of macro are used to parse packets. The same variable as for POKE_*
 * are used: `length' is the number of bytes that can still be read from `pos'
 * and should be a signed integer.
 *
 * The macros never read or skip past the end of the buffer. When fewer bytes
 * than requested remain (or when the requested size is negative), nothing is
 * read, `pos' is left untouched and `length' is set to -1. PEEK_UINT* then
 * return 0, PEEK_CMP() returns a non-zero value and PEEK_BYTES() leaves the
 * destination untouched. As `length' stays negative, any later PEEK_* fails
 * too: a decoder only needs to check `length' is not negative before using
 * what it has read. This is a safety net: decoders should still check the
 * size of each field before reading it. */

#define PEEK_CHECK(bytes) ((long)(bytes) >= 0 && (long)length >= (long)(bytes))
#define PEEK_FAIL (length = -1)
#define PEEK(type, func)                                                   \
	(PEEK_CHECK(sizeof(type)) ?                                        \
		(memcpy(&type, pos, sizeof(type)), length -= sizeof(type), \
		    pos += sizeof(type), func(type)) :                     \
		(PEEK_FAIL, 0))
#define PEEK_UINT8 PEEK(types.f_uint8, )
#define PEEK_UINT16 PEEK(types.f_uint16, ntohs)
#define PEEK_UINT32 PEEK(types.f_uint32, ntohl)
#define PEEK_BYTES(value, bytes)                      \
	do {                                          \
		long peek_len = (long)(bytes);        \
		if (PEEK_CHECK(peek_len)) {           \
			memcpy(value, pos, peek_len); \
			length -= peek_len;           \
			pos += peek_len;              \
		} else                                \
			PEEK_FAIL;                    \
	} while (0)
#define PEEK_DISCARD(bytes)                    \
	do {                                   \
		long peek_len = (long)(bytes); \
		if (PEEK_CHECK(peek_len)) {    \
			length -= peek_len;    \
			pos += peek_len;       \
		} else                         \
			PEEK_FAIL;             \
	} while (0)
#define PEEK_DISCARD_UINT8 PEEK_DISCARD(1)
#define PEEK_DISCARD_UINT16 PEEK_DISCARD(2)
#define PEEK_DISCARD_UINT32 PEEK_DISCARD(4)
#define PEEK_CMP(value, bytes)                                          \
	(PEEK_CHECK(bytes) ? (length -= (bytes), pos += (bytes),        \
				 memcmp(pos - (bytes), value, bytes)) : \
			     (PEEK_FAIL, -1))
#define PEEK_SAVE POKE_SAVE
#define PEEK_RESTORE(where)                           \
	do {                                          \
		if (length >= 0) POKE_RESTORE(where); \
	} while (0)

/* LLDP specific. We need a `tlv' pointer. */
#define POKE_START_LLDP_TLV(type) (tlv = pos, POKE_UINT16(type << 9))
#define POKE_END_LLDP_TLV                                        \
	(memcpy(&types.f_uint16, tlv, sizeof(uint16_t)),         \
	    types.f_uint16 |= htons((pos - (tlv + 2)) & 0x01ff), \
	    memcpy(tlv, &types.f_uint16, sizeof(uint16_t)), 1)

/* Same for CDP */
#define POKE_START_CDP_TLV(type) ((void)POKE_UINT16(type), tlv = pos, POKE_UINT16(0))
#define POKE_END_CDP_TLV                        \
	(types.f_uint16 = htons(pos - tlv + 2), \
	    memcpy(tlv, &types.f_uint16, sizeof(uint16_t)), 1)

/* Same for EDP */
#define POKE_START_EDP_TLV(type)                                              \
	((void)POKE_UINT8(EDP_TLV_MARKER), (void)POKE_UINT8(type), tlv = pos, \
	    POKE_UINT16(0))
#define POKE_END_EDP_TLV POKE_END_CDP_TLV

#endif /* _FRAME_H */
