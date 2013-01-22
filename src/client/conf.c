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

#include <unistd.h>
#include <string.h>

#include "client.h"
#include "../log.h"


/**
 * Register `configure` and `no configure` commands.
 */
void
register_commands_configure(struct cmd_node *root)
{
	int has_med  = (lldpctl_key_get_map(
		    lldpctl_k_med_policy_type)[0].string != NULL);
	int has_dot3 = (lldpctl_key_get_map(
		    lldpctl_k_dot3_power_class)[0].string != NULL);
	if (!has_med && !has_dot3) return;

	struct cmd_node *configure = commands_new(
		root,
		"configure",
		"Change system settings",
		NULL, NULL, NULL);
	cmd_restrict_ports(configure);

	if (has_med) register_commands_configure_med(configure);
	if (has_dot3) register_commands_configure_dot3(configure);
}
