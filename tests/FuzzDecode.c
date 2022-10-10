//https://github.com/lldpd/lldpd/blob/9fd7b25f984569378f60ecfbe37372eb3417efd7/tests/decode.c

/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2015 Vincent Bernat <bernat@luffy.cx>
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

#include <stdlib.h>
#include <unistd.h>
#include "../src/daemon/lldpd.h"

#define kMinInputLength 30
#define kMaxInputLength 1500

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    int ret = 0;
    struct lldpd cfg;
	cfg.g_config.c_mgmt_pattern = NULL;

/* For decoding, we only need a very basic hardware */
    struct lldpd_hardware hardware;
    memset(&hardware, 0, sizeof(struct lldpd_hardware));
    hardware.h_mtu = 1500;
    strlcpy(hardware.h_ifname, "test", sizeof(hardware.h_ifname));

    struct lldpd_chassis *nchassis = NULL;
    struct lldpd_port *nport = NULL;

//Decoding
    ret += lldp_decode(&cfg, (char *)Data, Size, &hardware, &nchassis, &nport);
    ret += cdp_decode(&cfg, (char *)Data, Size, &hardware, &nchassis, &nport);
    ret += sonmp_decode(&cfg, (char *)Data, Size, &hardware, &nchassis, &nport);
    ret += edp_decode(&cfg, (char *)Data, Size, &hardware, &nchassis, &nport);

    return ret;
}