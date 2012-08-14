/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2009 Vincent Bernat <bernat@luffy.cx>
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

#include "lldpd.h"

u_int16_t
frame_checksum(const u_char *cp, int len, int cisco)
{
	unsigned int sum = 0, v = 0;
	int oddbyte = 0;

	/* We compute in network byte order */
	while ((len -= 2) >= 0) {
		sum += *cp++ << 8;
		sum += *cp++;
	}
	if ((oddbyte = len & 1) != 0)
		v = *cp;

	/* The remaining byte seems to be handled oddly by Cisco. Any hint about
	 * this is welcome. */
	if (oddbyte) {
		if (cisco)
			sum += v;
		else
			sum += v << 8;
	}
      	sum = (sum >> 16) + (sum & 0xffff);
      	sum += sum >> 16;
	sum = ntohs(sum);
      	return (0xffff & ~sum);
}
