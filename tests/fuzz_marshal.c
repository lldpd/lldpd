/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2026 Arthur SC Chan <arthur.chan@adalogics.com>
 *
 * Fuzz the marshalling layer used on the control socket between lldpd
 * and its clients: unmarshal the fuzzed bytes into a chassis/port, then
 * marshal the result back out (round-trip property), covering both the
 * decode and the encode direction of src/marshal.c.
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

#include "../src/daemon/lldpd.h"

#define kMinInputLength 4
#define kMaxInputLength 8192

/* Use this callback to avoid some logs */
void donothing(int pri, const char *msg) { };

extern int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	if (Size < kMinInputLength || Size > kMaxInputLength) {
		return 0;
	}

	struct lldpd_chassis *nchassis = NULL;
	struct lldpd_port *nport = NULL;
	void *out = NULL;
	size_t outlen;

	log_register(donothing);

	/* Chassis: unmarshal, then marshal back. */
	if (marshal_unserialize(lldpd_chassis, (void *)Data, Size,
		&nchassis) > 0 && nchassis != NULL) {
		outlen = marshal_serialize(lldpd_chassis, nchassis, &out);
		if (outlen > 0 && out != NULL) {
			free(out);
			out = NULL;
		}
		lldpd_chassis_cleanup(nchassis, 1);
	}

	/* Port (with its nested chassis/TLV sub-structs): same round-trip. */
	if (marshal_unserialize(lldpd_port, (void *)Data, Size,
		&nport) > 0 && nport != NULL) {
		outlen = marshal_serialize(lldpd_port, nport, &out);
		if (outlen > 0 && out != NULL) {
			free(out);
			out = NULL;
		}
		lldpd_port_cleanup(nport, 1);
		free(nport);
	}

	return 0;
}
