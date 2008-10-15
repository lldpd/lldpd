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

#ifndef _LLC_H
#define _LLC_H

struct ieee8023 {
	u_int8_t  dhost[ETH_ALEN];	/* destination eth addr	*/
	u_int8_t  shost[ETH_ALEN];	/* source ether addr	*/
	u_int16_t size;	        /* packet type ID field	*/
} __attribute__ ((__packed__));

struct ethllc {
	struct ieee8023 ether;
	u_int8_t  dsap;		/* destination SAP */
	u_int8_t  ssap;		/* source SAP */
	u_int8_t  control;		/* LLC control field */
	u_int8_t  org[3];
	u_int16_t protoid;
} __attribute__ ((__packed__));

#endif
