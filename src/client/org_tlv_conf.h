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

#ifndef _ORG_TLV_CONF_H
#define _ORG_TLV_CONF_H

#include <stdint.h>
#include "writer.h"

/* Field type enum */
enum org_tlv_field_type {
	ORG_TLV_UINT8,
	ORG_TLV_UINT16,
	ORG_TLV_UINT32,
	ORG_TLV_STRING,
	ORG_TLV_IPV4,
	ORG_TLV_MAC,
	ORG_TLV_HEX,
};

/* Single field within a TLV definition */
struct org_tlv_field {
	char *name;
	enum org_tlv_field_type type;
	struct org_tlv_field *next;
};

/* Definition for one OUI+subtype */
struct org_tlv_def {
	uint8_t oui[3];
	uint8_t subtype;
	char *name;
	struct org_tlv_field *fields;
	struct org_tlv_def *next;
};

/* Vendor definition (one per OUI) */
struct org_tlv_vendor {
	uint8_t oui[3];
	char *vendor_name;
	struct org_tlv_vendor *next;
};

/* Load all .conf files from directory */
void org_tlv_conf_load(const char *dir);

/* Lookup a TLV definition by OUI + subtype */
struct org_tlv_def *org_tlv_conf_find(const uint8_t *oui, uint8_t subtype);

/* Lookup a vendor name by OUI */
struct org_tlv_vendor *org_tlv_vendor_find(const uint8_t *oui);

/* Display a TLV using a config definition */
void display_org_tlv_from_def(struct writer *w, struct org_tlv_def *def,
    const uint8_t *data, int datalen);

/* Free all loaded config data */
void org_tlv_conf_free(void);

#endif /* _ORG_TLV_CONF_H */
