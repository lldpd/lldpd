/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
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
#include <net/bpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>

int
asroot_iface_init_os(int ifindex, char *name, int *fd)
{
	int enable, required, rc;
	struct bpf_insn filter[] = { LLDPD_FILTER_F };
	struct ifreq ifr = { .ifr_name = {} };
	struct bpf_program fprog = {
		.bf_insns = filter,
		.bf_len = sizeof(filter)/sizeof(struct bpf_insn)
	};

#ifndef HOST_OS_SOLARIS
	int n = 0;
	char dev[20];
	do {
		snprintf(dev, sizeof(dev), "/dev/bpf%d", n++);
		*fd = open(dev, O_RDWR);
	} while (*fd < 0 && errno == EBUSY);
#else
	*fd = open("/dev/bpf", O_RDWR);
#endif
	if (*fd < 0) {
		rc = errno;
		log_warn("privsep", "unable to find a free BPF");
		return rc;
	}

	/* Set buffer size */
	required = ETHER_MAX_LEN;
	if (ioctl(*fd, BIOCSBLEN, (caddr_t)&required) < 0) {
		rc = errno;
		log_warn("privsep",
		    "unable to set receive buffer size for BPF on %s",
		    name);
		return rc;
	}

	/* Bind the interface to BPF device */
	strlcpy(ifr.ifr_name, name, IFNAMSIZ);
	if (ioctl(*fd, BIOCSETIF, (caddr_t)&ifr) < 0) {
		rc = errno;
		log_warn("privsep", "failed to bind interface %s to BPF",
		    name);
		return rc;
	}

	/* Disable buffering */
	enable = 1;
	if (ioctl(*fd, BIOCIMMEDIATE, (caddr_t)&enable) < 0) {
		rc = errno;
		log_warn("privsep", "unable to disable buffering for %s",
		    name);
		return rc;
	}

	/* Let us write the MAC address (raw packet mode) */
	enable = 1;
	if (ioctl(*fd, BIOCSHDRCMPLT, (caddr_t)&enable) < 0) {
		rc = errno;
		log_warn("privsep",
		    "unable to set the `header complete` flag for %s",
		    name);
		return rc;
	}

	/* Don't see sent packets */
#ifdef HOST_OS_OPENBSD
	enable = BPF_DIRECTION_OUT;
	if (ioctl(*fd, BIOCSDIRFILT, (caddr_t)&enable) < 0)
#else
	enable = 0;
	if (ioctl(*fd, BIOCSSEESENT, (caddr_t)&enable) < 0)
#endif
	{
		rc = errno;
		log_warn("privsep",
		    "unable to set packet direction for BPF filter on %s",
		    name);
		return rc;
	}

	/* Install read filter */
	if (ioctl(*fd, BIOCSETF, (caddr_t)&fprog) < 0) {
		rc = errno;
		log_warn("privsep", "unable to setup BPF filter for %s",
		    name);
		return rc;
	}
#ifdef BIOCSETWF
	/* Install write filter (optional) */
	if (ioctl(*fd, BIOCSETWF, (caddr_t)&fprog) < 0) {
		rc = errno;
		log_info("privsep", "unable to setup write BPF filter for %s",
		    name);
		return rc;
	}
#endif

#ifdef BIOCLOCK
	/* Lock interface */
	if (ioctl(*fd, BIOCLOCK, (caddr_t)&enable) < 0) {
		rc = errno;
		log_info("privsep", "unable to lock BPF interface %s",
		    name);
		return rc;
	}
#endif
	return 0;
}
