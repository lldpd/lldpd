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

/* Some of the code here (agent_priv_unix_*) has been adapted from code from
 * Net-SNMP project (snmplib/snmpUnixDomain.c). Net-SNMP project is licensed
 * using BSD and BSD-like licenses. I don't know the exact license of the file
 * snmplib/snmpUnixDomain.c. */

#include "lldpd.h"

#include <errno.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/agent/util_funcs.h>
#include <net-snmp/library/snmpUnixDomain.h>

oid netsnmp_UnixDomain[] = { TRANSPORT_DOMAIN_LOCAL };
static netsnmp_tdomain unixDomain;

static char *
agent_priv_unix_fmtaddr(netsnmp_transport *t, void *data, int len)
{
	/* We don't bother to implement the full function */
	return strdup("Local Unix socket with privilege separation: unknown");
}

static int
agent_priv_unix_recv(netsnmp_transport *t, void *buf, int size,
    void **opaque, int *olength)
{
	int rc = -1;
	socklen_t  tolen = sizeof(struct sockaddr_un);
	struct sockaddr *to = NULL;
	
	if (t == NULL || t->sock < 0)
		goto recv_error;
	to = (struct sockaddr *)malloc(sizeof(struct sockaddr_un));
	if (to == NULL)
		goto recv_error;
	memset(to, 0, tolen);
	if (getsockname(t->sock, to, &tolen) != 0)
		goto recv_error;
	while (rc < 0) {
		rc = recv(t->sock, buf, size, 0);
		if (rc < 0 && errno != EINTR) {
			LLOG_WARN("unable to receive from fd %d",
			    t->sock);
			goto recv_error;
		}
	}
	*opaque = (void*)to;
	*olength = sizeof(struct sockaddr_un);
	return rc;

recv_error:
	free(to);
	*opaque = NULL;
	*olength = 0;
	return -1;
}

static int
agent_priv_unix_send(netsnmp_transport *t, void *buf, int size,
    void **opaque, int *olength)
{
	int rc = -1;
	if (t != NULL && t->sock >= 0) {
		while (rc < 0) {
			rc = send(t->sock, buf, size, 0);
			if (rc < 0 && errno != EINTR) {
				break;
			}
		}
	}
	return rc;
}

static int
agent_priv_unix_close(netsnmp_transport *t)
{
	int rc = 0;

	if (t->sock >= 0) {
		rc = close(t->sock);
		t->sock = -1;
		return rc;
	}
	return -1;
}

static int
agent_priv_unix_accept(netsnmp_transport *t)
{
	LLOG_WARNX("should not have been called");
	return -1;
}

netsnmp_transport *
agent_priv_unix_transport(const char *string, int len, int local)
{
	struct sockaddr_un addr;
	netsnmp_transport *t = NULL;

	if (local) {
		LLOG_WARNX("should not have been called for local transport");
		return NULL;
	}
	
	if (len > 0 && len < (sizeof(addr.sun_path) - 1)) {
		addr.sun_family = AF_UNIX;
		memset(addr.sun_path, 0, sizeof(addr.sun_path));
		strncpy(addr.sun_path, string, len);
	} else {
		LLOG_WARNX("path too long for Unix domain transport");
		return NULL;
	}

	if ((t = (netsnmp_transport *)
		malloc(sizeof(netsnmp_transport))) == NULL)
		return NULL;

	memset(t, 0, sizeof(netsnmp_transport));

	t->domain = netsnmp_UnixDomain;
	t->domain_length =
	    sizeof(netsnmp_UnixDomain) / sizeof(netsnmp_UnixDomain[0]);

	if ((t->sock = priv_snmp_socket(&addr)) < 0) {
		netsnmp_transport_free(t);
		return NULL;
	}

	t->flags = NETSNMP_TRANSPORT_FLAG_STREAM;

	if ((t->remote = (u_char *)
		malloc(strlen(addr.sun_path))) == NULL) {
		agent_priv_unix_close(t);
		netsnmp_transport_free(t);
		return NULL;
        }
        memcpy(t->remote, addr.sun_path, strlen(addr.sun_path));
        t->remote_length = strlen(addr.sun_path);

	t->msgMaxSize = 0x7fffffff;
	t->f_recv     = agent_priv_unix_recv;
	t->f_send     = agent_priv_unix_send;
	t->f_close    = agent_priv_unix_close;
	t->f_accept   = agent_priv_unix_accept;
	t->f_fmtaddr  = agent_priv_unix_fmtaddr;

	return t;
}

netsnmp_transport *
agent_priv_unix_create_tstring(const char *string, int local,
    const char *default_target)
{
	if ((!string || *string == '\0') && default_target &&
	    *default_target != '\0') {
		string = default_target;
	}

	return agent_priv_unix_transport(string, strlen(string), local);
}

netsnmp_transport *
agent_priv_unix_create_ostring(const u_char * o, size_t o_len, int local)
{
	return agent_priv_unix_transport((char *)o, o_len, local);
}

void
agent_priv_register_domain()
{
	unixDomain.name = netsnmp_UnixDomain;
	unixDomain.name_length = sizeof(netsnmp_UnixDomain) / sizeof(oid);
	unixDomain.prefix = (const char**)calloc(2, sizeof(char *));
	unixDomain.prefix[0] = "unix";
	
	unixDomain.f_create_from_tstring_new = agent_priv_unix_create_tstring;
	unixDomain.f_create_from_ostring = agent_priv_unix_create_ostring;
	
	netsnmp_tdomain_register(&unixDomain);
}
