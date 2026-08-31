/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2026 Ciro Iriarte <ciro.iriarte+software@gmail.com>
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

#ifndef _ORG_TLV_HANDLER_H
#define _ORG_TLV_HANDLER_H

#include <stdint.h>
#include "writer.h"

/* Handler callback: interpret raw TLV bytes and produce display output.
 * Return 1 if handled, 0 to fall through to config/hex. */
typedef int (*org_tlv_display_fn)(struct writer *w, uint8_t subtype,
    const uint8_t *data, int datalen);

/* One handler per OUI (handles all subtypes for that vendor) */
struct org_tlv_handler {
	uint8_t oui[3];
	const char *vendor_name;
	org_tlv_display_fn display;
	struct org_tlv_handler *next;
};

/* Registration and lookup */
void org_tlv_handler_register(struct org_tlv_handler *handler);
struct org_tlv_handler *org_tlv_handler_find(const uint8_t *oui);
void org_tlv_handler_init(void);

/* Registration macro — call from each handler file */
#define ORG_TLV_HANDLER_REGISTER(NAME)      \
  void org_tlv_handler_init_##NAME(void);   \
  void org_tlv_handler_init_##NAME(void)    \
  {                                         \
    org_tlv_handler_register(&NAME);        \
  }

#endif /* _ORG_TLV_HANDLER_H */
