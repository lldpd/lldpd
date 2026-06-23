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

#include <string.h>
#include "org_tlv_handler.h"

static struct org_tlv_handler *handler_list = NULL;

void
org_tlv_handler_register(struct org_tlv_handler *handler)
{
	handler->next = handler_list;
	handler_list = handler;
}

struct org_tlv_handler *
org_tlv_handler_find(const uint8_t *oui)
{
	struct org_tlv_handler *h;
	for (h = handler_list; h; h = h->next) {
		if (memcmp(h->oui, oui, 3) == 0)
			return h;
	}
	return NULL;
}

/* Initialize all registered handlers */
void org_tlv_handler_init_cisco_handler(void);

void
org_tlv_handler_init(void)
{
	org_tlv_handler_init_cisco_handler();
}
