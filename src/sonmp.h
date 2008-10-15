/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#ifndef _SONMP_H
#define _SONMP_H

#define SONMP_MULTICAST_ADDR	{						\
	0x01, 0x00, 0x81, 0x00, 0x01, 0x00					\
}
#define LLC_ORG_NORTEL { 0x00, 0x00, 0x81 }
#define LLC_PID_SONMP_HELLO 0x01a2
#define LLC_PID_SONMP_FLATNET 0x01a1

#include "llc.h"

struct sonmp {
	struct ethllc llc;
	struct in_addr addr;
	u_int8_t seg[3];
	u_int8_t chassis;
	u_int8_t backplane;
	u_int8_t state;
	u_int8_t links;
} __attribute__ ((__packed__));

struct sonmp_chassis {
	int type;
	char *description;
};

#define SONMP_TOPOLOGY_CHANGED 1
#define SONMP_TOPOLOGY_UNCHANGED 2
#define SONMP_TOPOLOGY_NEW 3

#endif /* _SONMP_H */
