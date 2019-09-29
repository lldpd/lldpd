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
	struct cmd_node *configure = commands_new(
		root,
		"configure",
		"Change system settings",
		NULL, NULL, NULL);
	struct cmd_node *unconfigure = commands_new(
		root,
		"unconfigure",
		"Unconfigure system settings",
		NULL, NULL, NULL);
	commands_privileged(commands_lock(configure));
	commands_privileged(commands_lock(unconfigure));
	cmd_restrict_ports(configure);
	cmd_restrict_ports(unconfigure);

	register_commands_configure_system(configure, unconfigure);
	register_commands_configure_lldp(configure, unconfigure);
	register_commands_configure_med(configure, unconfigure);
	register_commands_configure_dot3(configure);
}
