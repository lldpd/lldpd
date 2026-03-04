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

static int
cisco_display(struct writer *w, uint8_t subtype, const uint8_t *data, int datalen)
{
	switch (subtype) {
	case 207: {
		/* ACI Policy Group UUIDs — list of 41-byte entries:
		 *   1 byte tier, 4 bytes reserved, 36 bytes UUID (ASCII) */
		const char *tier_names[] = {
			[0] = "Unknown",
			[1] = "Tenant",
			[2] = "App Profile",
			[3] = "EPG",
			[4] = "Bridge Domain",
			[5] = "VRF",
		};
		int ntiers = sizeof(tier_names) / sizeof(tier_names[0]);
		tag_start(w, "aci-policy-groups", "ACI Policy Groups");
		int pos = 0;
		while (pos + 41 <= datalen) {
			uint8_t tier = data[pos];
			const char *uuid_ascii = (const char *)&data[pos + 5];
			char uuid[37];
			memcpy(uuid, uuid_ascii, 36);
			uuid[36] = '\0';
			const char *name =
			    (tier < ntiers) ? tier_names[tier] : "Unknown";
			tag_start(w, "policy-group", name);
			tag_data(w, uuid);
			tag_end(w);
			pos += 41;
		}
		tag_end(w);
		return 1; /* handled */
	}
	default:
		return 0; /* not handled — fall through to config/hex */
	}
}

static struct org_tlv_handler cisco_handler = {
	.oui = { 0x00, 0x01, 0x42 },
	.vendor_name = "Cisco",
	.display = cisco_display,
};

ORG_TLV_HANDLER_REGISTER(cisco_handler);
