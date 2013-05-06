/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2013 Vincent Bernat <bernat@luffy.cx>
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
#include <unistd.h>
#include <stropts.h>
#include <inet/tunables.h>
#include <sys/sockio.h>

int
interfaces_routing_enabled(struct lldpd *cfg) {
	int rc;
	size_t iocsize = sizeof(mod_ioc_prop_t) + 1;
	mod_ioc_prop_t *mip = calloc(1, iocsize);
	if (mip == NULL) {
		log_warn("interfaces", "unable to allocate memory for ioctl");
		return -1;
	}
	mip->mpr_version = MOD_PROP_VERSION;
	mip->mpr_flags = MOD_PROP_ACTIVE;
	mip->mpr_proto = MOD_PROTO_IPV4;
	mip->mpr_valsize = iocsize + 1 - sizeof(mod_ioc_prop_t);
	strlcpy(mip->mpr_name, "forwarding", sizeof(mip->mpr_name));
	struct strioctl ioc = {
		.ic_cmd = SIOCGETPROP,
		.ic_timout = 0,
		.ic_len = iocsize,
		.ic_dp = (char*)mip
	};
	if (ioctl(cfg->g_sock, I_STR, &ioc) == -1) {
		free(mip);
		log_debug("interfaces", "unable to get value for IPv4 forwarding");
		return -1;
	}

	rc = (*mip->mpr_val == '1');
	free(mip);
	return rc;
}
