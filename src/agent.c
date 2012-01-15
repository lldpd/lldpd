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
#include "frame.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#if HAVE_NET_SNMP_AGENT_UTIL_FUNCS_H
#include <net-snmp/agent/util_funcs.h>
#else
/* The above header may be buggy. We just need this function. */
int header_generic(struct variable *, oid *, size_t *, int,
		   size_t *, WriteMethod **);
#endif

static oid lldp_oid[] = {1, 0, 8802, 1, 1, 2};

/* For net-snmp */
extern int register_sysORTable(oid *, size_t, const char *);
extern int unregister_sysORTable(oid *, size_t);

/* Global variable because no way to pass it as argument. Should not be used
 * elsewhere. */
static struct lldpd *scfg;

static inline uint8_t
swap_bits(uint8_t n)
{
  n = ((n&0xF0) >>4 ) | ( (n&0x0F) <<4);
  n = ((n&0xCC) >>2 ) | ( (n&0x33) <<2);
  n = ((n&0xAA) >>1 ) | ( (n&0x55) <<1);

  return  n;
};

extern struct timeval starttime;
static long int
lastchange(struct lldpd_port *port)
{
	if (port->p_lastchange > starttime.tv_sec)
		return (port->p_lastchange - starttime.tv_sec)*100;
	return 0;
}

/* -------------
  Helper functions to build header_*indexed_table() functions.
  Those functions keep an internal state. They are not reentrant!
*/
struct header_index {
	struct variable *vp;
	oid             *name;	 /* Requested/returned OID */
	size_t          *length; /* Length of above OID */
	int              exact;
	oid              best[MAX_OID_LEN]; /* Best OID */
	size_t           best_len;	    /* Best OID length */
	void            *entity;	    /* Best entity */
};
static struct header_index header_idx;

static void
header_index_init(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
        if ((snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
                memcpy(name, vp->name, sizeof(oid) * vp->namelen);
                *length = vp->namelen;
        }
	if(write_method != NULL) *write_method = 0;
	*var_len = sizeof(long);

	/* Initialize our header index structure */
	header_idx.vp = vp;
	header_idx.name = name;
	header_idx.length = length;
	header_idx.exact = exact;
	header_idx.best_len = 0;
	header_idx.entity = NULL;
}

static int
header_index_add(oid *index, size_t len, void *entity)
{
	int      result;
	oid     *target;
	size_t   target_len;

        target = header_idx.name + header_idx.vp->namelen;
        target_len = *header_idx.length - header_idx.vp->namelen;
	if ((result = snmp_oid_compare(index, len, target, target_len)) < 0)
		return 0;	/* Too small. */
	if (result == 0)
		return header_idx.exact;
	if (header_idx.best_len == 0 ||
	    (snmp_oid_compare(index, len,
			      header_idx.best,
			      header_idx.best_len) < 0)) {
		memcpy(header_idx.best, index, sizeof(oid) * len);
		header_idx.best_len = len;
		header_idx.entity = entity;
	}
	return 0;		/* No best match yet. */	
}

void*
header_index_best()
{
	if (header_idx.entity == NULL)
		return NULL;
	if (header_idx.exact)
		return NULL;
	memcpy(header_idx.name + header_idx.vp->namelen,
	       header_idx.best, sizeof(oid) * header_idx.best_len);
	*header_idx.length = header_idx.vp->namelen + header_idx.best_len;
	return header_idx.entity;
}
/* ----------------------------- */

static struct lldpd_hardware*
header_portindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		oid index[1] = { hardware->h_ifindex };
		if (header_index_add(index, 1,
				     hardware))
			return hardware;
	}
	return header_index_best();
}

#ifdef ENABLE_LLDPMED
static struct lldpd_med_policy*
header_pmedindexed_policy_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	int i;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		for (i = 0; i < LLDPMED_APPTYPE_LAST; i++) {
			if (hardware->h_lport.p_med_policy[i].type != i+1)
				continue;
			oid index[2] = { hardware->h_ifindex,
					 i + 1 };
			if (header_index_add(index, 2,
					     &hardware->h_lport.p_med_policy[i]))
				return &hardware->h_lport.p_med_policy[i];
		}
	}
	return header_index_best();
}

static struct lldpd_med_loc*
header_pmedindexed_location_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	int i;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		for (i = 0; i < LLDPMED_LOCFORMAT_LAST; i++) {
			if (hardware->h_lport.p_med_location[i].format != i+1)
				continue;
			oid index[2] = { hardware->h_ifindex,
					 i + 1 };
			if (header_index_add(index, 2,
					     &hardware->h_lport.p_med_location[i]))
				return &hardware->h_lport.p_med_location[i];
		}
	}
	return header_index_best();
}
#endif

static struct lldpd_port*
header_tprindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
			if (SMART_HIDDEN(scfg, port)) continue;
			oid index[3] = { lastchange(port),
					 hardware->h_ifindex,
					 port->p_chassis->c_index };
			if (header_index_add(index, 3,
					     port))
				return port;
		}
	}
	return header_index_best();
}

static struct lldpd_port*
header_tpripindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
			if (SMART_HIDDEN(scfg, port)) continue;
			if (port->p_chassis->c_mgmt.s_addr == INADDR_ANY)
				continue;
			oid index[9] = { lastchange(port),
					 hardware->h_ifindex,
					 port->p_chassis->c_index,
					 1, 4,
					 ((u_int8_t*)&port->p_chassis->c_mgmt.s_addr)[0],
					 ((u_int8_t*)&port->p_chassis->c_mgmt.s_addr)[1],
					 ((u_int8_t*)&port->p_chassis->c_mgmt.s_addr)[2],
					 ((u_int8_t*)&port->p_chassis->c_mgmt.s_addr)[3] };
			if (header_index_add(index, 9,
					     port))
				return port;
		}
	}
	return header_index_best();
}

#define TPR_VARIANT_MED_POLICY 2
#define TPR_VARIANT_MED_LOCATION 3
static struct lldpd_port*
header_tprmedindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method, int variant)
{
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
	int j;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
			if (SMART_HIDDEN(scfg, port)) continue;
			switch (variant) {
			case TPR_VARIANT_MED_POLICY:
				for (j = 0;
				     j < LLDPMED_APPTYPE_LAST;
				     j++) {
					if (port->p_med_policy[j].type != j+1)
						continue;
					oid index[4] = { lastchange(port),
							 hardware->h_ifindex,
							 port->p_chassis->c_index,
							 j+1 };
					if (header_index_add(index, 4,
							     port))
						return port;
				}
				break;
			case TPR_VARIANT_MED_LOCATION:
				for (j = 0;
				     j < LLDPMED_LOCFORMAT_LAST;
				     j++) {
					if (port->p_med_location[j].format != j+1)
						continue;
					oid index[4] = { lastchange(port),
							 hardware->h_ifindex,
							 port->p_chassis->c_index,
							 j+1 };
					if (header_index_add(index, 4,
							     port))
						return port;
				}
				break;
			}
		}
	}
	return header_index_best();
}

#ifdef ENABLE_DOT1
static struct lldpd_vlan*
header_pvindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
        struct lldpd_vlan *vlan;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(vlan, &hardware->h_lport.p_vlans, v_entries) {
			oid index[2] = { hardware->h_ifindex,
					 vlan->v_vid };
			if (header_index_add(index, 2, vlan))
				return vlan;
		}
	}
	return header_index_best();
}

static struct lldpd_vlan*
header_tprvindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
        struct lldpd_vlan *vlan;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
			if (SMART_HIDDEN(scfg, port)) continue;
                        TAILQ_FOREACH(vlan, &port->p_vlans, v_entries) {
				oid index[4] = { lastchange(port),
						 hardware->h_ifindex,
						 port->p_chassis->c_index,
						 vlan->v_vid };
				if (header_index_add(index, 4,
						     vlan))
					return vlan;
			}
		}
	}
	return header_index_best();
}

static struct lldpd_ppvid*
header_pppvidindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
        struct lldpd_ppvid *ppvid;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(ppvid, &hardware->h_lport.p_ppvids, p_entries) {
			oid index[2] = { hardware->h_ifindex,
					 ppvid->p_ppvid };
			if (header_index_add(index, 2,
					     ppvid))
				return ppvid;
		}
	}
	return header_index_best();
}

static struct lldpd_ppvid*
header_tprppvidindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
        struct lldpd_ppvid *ppvid;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
			if (SMART_HIDDEN(scfg, port)) continue;
                        TAILQ_FOREACH(ppvid, &port->p_ppvids, p_entries) {
				oid index[4] = { lastchange(port),
						 hardware->h_ifindex,
						 port->p_chassis->c_index,
						 ppvid->p_ppvid };
				if (header_index_add(index, 4,
						     ppvid))
					return ppvid;
                        }
		}
	}
	return header_index_best();
}

static struct lldpd_pi*
header_ppiindexed_table(struct variable *vp, oid *name, size_t *length,
			int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
        struct lldpd_pi *pi;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(pi, &hardware->h_lport.p_pids, p_entries) {
			oid index[2] = { hardware->h_ifindex,
					 frame_checksum((const u_char*)pi->p_pi,
							pi->p_pi_len, 0) };
			if (header_index_add(index, 2,
					     pi))
				return pi;
		}
	}
	return header_index_best();
}

static struct lldpd_pi*
header_tprpiindexed_table(struct variable *vp, oid *name, size_t *length,
			  int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;
        struct lldpd_pi *pi;

	header_index_init(vp, name, length, exact, var_len, write_method);
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
			if (SMART_HIDDEN(scfg, port)) continue;
                        TAILQ_FOREACH(pi, &port->p_pids, p_entries) {
				oid index[4] = { lastchange(port),
						 hardware->h_ifindex,
						 port->p_chassis->c_index,
						 frame_checksum((const u_char *)pi->p_pi,
								pi->p_pi_len, 0) };
				if (header_index_add(index, 4,
						     pi))
					return pi;
                        }
		}
	}
	return header_index_best();
}
#endif

/* Scalars */
#define LLDP_SNMP_TXINTERVAL 1
#define LLDP_SNMP_TXMULTIPLIER 2
#define LLDP_SNMP_REINITDELAY 3
#define LLDP_SNMP_TXDELAY 4
#define LLDP_SNMP_NOTIFICATION 5
#define LLDP_SNMP_LASTUPDATE 6
#define LLDP_SNMP_STATS_INSERTS 7
#define LLDP_SNMP_STATS_DELETES 8
#define LLDP_SNMP_STATS_DROPS 9
#define LLDP_SNMP_STATS_AGEOUTS 10
/* Local chassis */
#define LLDP_SNMP_LOCAL_CIDSUBTYPE 1
#define LLDP_SNMP_LOCAL_CID 2
#define LLDP_SNMP_LOCAL_SYSNAME 3
#define LLDP_SNMP_LOCAL_SYSDESCR 4
#define LLDP_SNMP_LOCAL_SYSCAP_SUP 5
#define LLDP_SNMP_LOCAL_SYSCAP_ENA 6
/* Stats */
#define LLDP_SNMP_STATS_TX_PORTNUM 1
#define LLDP_SNMP_STATS_TX 2
#define LLDP_SNMP_STATS_RX_PORTNUM 3
#define LLDP_SNMP_STATS_RX_DISCARDED 4
#define LLDP_SNMP_STATS_RX_ERRORS 5
#define LLDP_SNMP_STATS_RX 6
#define LLDP_SNMP_STATS_RX_TLVDISCARDED 7
#define LLDP_SNMP_STATS_RX_TLVUNRECOGNIZED 8
#define LLDP_SNMP_STATS_RX_AGEOUTS 9
/* Local ports */
#define LLDP_SNMP_LOCAL_PORTNUM 1
#define LLDP_SNMP_LOCAL_PIDSUBTYPE 2
#define LLDP_SNMP_LOCAL_PID 3
#define LLDP_SNMP_LOCAL_PORTDESC 4
#define LLDP_SNMP_LOCAL_DOT3_AUTONEG_SUPPORT 5
#define LLDP_SNMP_LOCAL_DOT3_AUTONEG_ENABLED 6
#define LLDP_SNMP_LOCAL_DOT3_AUTONEG_ADVERTISED 7
#define LLDP_SNMP_LOCAL_DOT3_AUTONEG_MAU 8
#define LLDP_SNMP_LOCAL_DOT3_AGG_STATUS 9
#define LLDP_SNMP_LOCAL_DOT3_AGG_ID 10
#define LLDP_SNMP_LOCAL_DOT3_MFS 11
#define LLDP_SNMP_LOCAL_DOT3_POWER_DEVICETYPE 12
#define LLDP_SNMP_LOCAL_DOT3_POWER_SUPPORT 13
#define LLDP_SNMP_LOCAL_DOT3_POWER_ENABLED 14
#define LLDP_SNMP_LOCAL_DOT3_POWER_PAIRCONTROL 15
#define LLDP_SNMP_LOCAL_DOT3_POWER_PAIRS 16
#define LLDP_SNMP_LOCAL_DOT3_POWER_CLASS 17
#define LLDP_SNMP_LOCAL_DOT3_POWER_TYPE 18
#define LLDP_SNMP_LOCAL_DOT3_POWER_SOURCE 19
#define LLDP_SNMP_LOCAL_DOT3_POWER_PRIORITY 20
#define LLDP_SNMP_LOCAL_DOT3_POWER_REQUESTED 21
#define LLDP_SNMP_LOCAL_DOT3_POWER_ALLOCATED 22
#define LLDP_SNMP_LOCAL_DOT1_PVID 23
/* Remote ports */
#define LLDP_SNMP_REMOTE_CIDSUBTYPE 1
#define LLDP_SNMP_REMOTE_CID 2
#define LLDP_SNMP_REMOTE_PIDSUBTYPE 3
#define LLDP_SNMP_REMOTE_PID 4
#define LLDP_SNMP_REMOTE_PORTDESC 5
#define LLDP_SNMP_REMOTE_SYSNAME 6
#define LLDP_SNMP_REMOTE_SYSDESC 7
#define LLDP_SNMP_REMOTE_SYSCAP_SUP 8
#define LLDP_SNMP_REMOTE_SYSCAP_ENA 9
#define LLDP_SNMP_REMOTE_DOT3_AUTONEG_SUPPORT 10
#define LLDP_SNMP_REMOTE_DOT3_AUTONEG_ENABLED 11
#define LLDP_SNMP_REMOTE_DOT3_AUTONEG_ADVERTISED 12
#define LLDP_SNMP_REMOTE_DOT3_AUTONEG_MAU 13
#define LLDP_SNMP_REMOTE_DOT3_AGG_STATUS 14
#define LLDP_SNMP_REMOTE_DOT3_AGG_ID 15
#define LLDP_SNMP_REMOTE_DOT3_MFS 16
#define LLDP_SNMP_REMOTE_DOT3_POWER_DEVICETYPE 17
#define LLDP_SNMP_REMOTE_DOT3_POWER_SUPPORT 18
#define LLDP_SNMP_REMOTE_DOT3_POWER_ENABLED 19
#define LLDP_SNMP_REMOTE_DOT3_POWER_PAIRCONTROL 20
#define LLDP_SNMP_REMOTE_DOT3_POWER_PAIRS 21
#define LLDP_SNMP_REMOTE_DOT3_POWER_CLASS 22
#define LLDP_SNMP_REMOTE_DOT3_POWER_TYPE 23
#define LLDP_SNMP_REMOTE_DOT3_POWER_SOURCE 24
#define LLDP_SNMP_REMOTE_DOT3_POWER_PRIORITY 25
#define LLDP_SNMP_REMOTE_DOT3_POWER_REQUESTED 26
#define LLDP_SNMP_REMOTE_DOT3_POWER_ALLOCATED 27
#define LLDP_SNMP_REMOTE_DOT1_PVID 28
/* Local vlans */
#define LLDP_SNMP_LOCAL_DOT1_VLANNAME 1
#define LLDP_SNMP_LOCAL_DOT1_VLANID 2
/* Remote vlans */
#define LLDP_SNMP_REMOTE_DOT1_VLANNAME 1
#define LLDP_SNMP_REMOTE_DOT1_VLANID 2
/* Local Port and Protocol VLAN IDs */
#define LLDP_SNMP_LOCAL_DOT1_PPVID		1
#define LLDP_SNMP_LOCAL_DOT1_PPVLAN_SUPPORTED	2
#define LLDP_SNMP_LOCAL_DOT1_PPVLAN_ENABLED	3
/* Remote Port and Protocol VLAN IDs */
#define LLDP_SNMP_REMOTE_DOT1_PPVID		1
#define LLDP_SNMP_REMOTE_DOT1_PPVLAN_SUPPORTED	2
#define LLDP_SNMP_REMOTE_DOT1_PPVLAN_ENABLED	3
/* Local Protocol Identity */
#define LLDP_SNMP_LOCAL_DOT1_PI			1
/* Remote Protocol Identity */
#define LLDP_SNMP_REMOTE_DOT1_PI		1
/* Management address */
#define LLDP_SNMP_LOCAL_ADDR_LEN 1
#define LLDP_SNMP_LOCAL_ADDR_IFSUBTYPE 2
#define LLDP_SNMP_LOCAL_ADDR_IFID 3
#define LLDP_SNMP_LOCAL_ADDR_OID 4
#define LLDP_SNMP_REMOTE_ADDR_IFSUBTYPE 5
#define LLDP_SNMP_REMOTE_ADDR_IFID 6
#define LLDP_SNMP_REMOTE_ADDR_OID 7
/* LLDP-MED local */
#define LLDP_SNMP_MED_LOCAL_CLASS 1
#define LLDP_SNMP_MED_LOCAL_HW 2
#define LLDP_SNMP_MED_LOCAL_FW 3
#define LLDP_SNMP_MED_LOCAL_SW 4
#define LLDP_SNMP_MED_LOCAL_SN 5
#define LLDP_SNMP_MED_LOCAL_MANUF 6
#define LLDP_SNMP_MED_LOCAL_MODEL 7
#define LLDP_SNMP_MED_LOCAL_ASSET 8
#define LLDP_SNMP_MED_LOCAL_POLICY_VID 9
#define LLDP_SNMP_MED_LOCAL_POLICY_PRIO 10
#define LLDP_SNMP_MED_LOCAL_POLICY_DSCP 11
#define LLDP_SNMP_MED_LOCAL_POLICY_UNKNOWN 12
#define LLDP_SNMP_MED_LOCAL_POLICY_TAGGED 13
#define LLDP_SNMP_MED_LOCAL_LOCATION 14
/* No more than 17 since we reuse LLDP_SNMP_MED_POE_DEVICETYPE and above */
/* LLDP-MED remote */
#define LLDP_SNMP_MED_REMOTE_CAP_AVAILABLE 1
#define LLDP_SNMP_MED_REMOTE_CAP_ENABLED 2
#define LLDP_SNMP_MED_REMOTE_CLASS 3
#define LLDP_SNMP_MED_REMOTE_HW 4
#define LLDP_SNMP_MED_REMOTE_FW 5
#define LLDP_SNMP_MED_REMOTE_SW 6
#define LLDP_SNMP_MED_REMOTE_SN 7
#define LLDP_SNMP_MED_REMOTE_MANUF 8
#define LLDP_SNMP_MED_REMOTE_MODEL 9
#define LLDP_SNMP_MED_REMOTE_ASSET 10
#define LLDP_SNMP_MED_REMOTE_POLICY_VID 11
#define LLDP_SNMP_MED_REMOTE_POLICY_PRIO 12
#define LLDP_SNMP_MED_REMOTE_POLICY_DSCP 13
#define LLDP_SNMP_MED_REMOTE_POLICY_UNKNOWN 14
#define LLDP_SNMP_MED_REMOTE_POLICY_TAGGED 15
#define LLDP_SNMP_MED_REMOTE_LOCATION 16
#define LLDP_SNMP_MED_POE_DEVICETYPE 17
#define LLDP_SNMP_MED_POE_PSE_POWERVAL 19
#define LLDP_SNMP_MED_POE_PSE_POWERSOURCE 20
#define LLDP_SNMP_MED_POE_PSE_POWERPRIORITY 21
#define LLDP_SNMP_MED_POE_PD_POWERVAL 22
#define LLDP_SNMP_MED_POE_PD_POWERSOURCE 23
#define LLDP_SNMP_MED_POE_PD_POWERPRIORITY 24

/* The following macro should be used anytime where the selected OID
   is finally not returned (for example, when the associated data is
   not available). In this case, we retry the function with the next
   OID. */
#define TRYNEXT(X)							\
	do {								\
		if (!exact && (name[*length-1] < MAX_SUBID))		\
			return X(vp, name, length,			\
				 exact, var_len, write_method);		\
		return NULL;						\
	} while (0)


static u_char*
agent_h_scalars(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	struct lldpd_hardware *hardware;
	struct lldpd_port *port;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_TXINTERVAL:
                long_ret = scfg->g_delay;
		return (u_char *)&long_ret;
	case LLDP_SNMP_TXMULTIPLIER:
		long_ret = LOCAL_CHASSIS(scfg)->c_ttl / scfg->g_delay;
		return (u_char *)&long_ret;
	case LLDP_SNMP_REINITDELAY:
		long_ret = 1;
		return (u_char *)&long_ret;
	case LLDP_SNMP_TXDELAY:
		long_ret = LLDPD_TX_MSGDELAY;
		return (u_char *)&long_ret;
	case LLDP_SNMP_NOTIFICATION:
		long_ret = 5;
		return (u_char *)&long_ret;
	case LLDP_SNMP_LASTUPDATE:
		long_ret = 0;
		TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries)
		    TAILQ_FOREACH(port, &hardware->h_rports, p_entries) {
			if (SMART_HIDDEN(scfg, port)) continue;
			if (port->p_lastchange > long_ret)
				long_ret = port->p_lastchange;
		}
		if (long_ret)
			long_ret = (long_ret - starttime.tv_sec) * 100;
		return (u_char *)&long_ret;
	case LLDP_SNMP_STATS_INSERTS:
		/* We assume this is equal to valid frames received on all ports */
		long_ret = 0;
		TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries)
			long_ret += hardware->h_rx_cnt;
		return (u_char *)&long_ret;
	case LLDP_SNMP_STATS_AGEOUTS:
		long_ret = 0;
		TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries)
			long_ret += hardware->h_rx_ageout_cnt;
		return (u_char *)&long_ret;
	case LLDP_SNMP_STATS_DELETES:
		long_ret = 0;
		TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries)
			long_ret += hardware->h_rx_ageout_cnt +
			    hardware->h_rx_cnt?(hardware->h_rx_cnt - 1):0;
		return (u_char *)&long_ret;
	case LLDP_SNMP_STATS_DROPS:
		/* We assume that we never have insufficient resources */
		long_ret = 0;
		return (u_char *)&long_ret;
	default:
		break;
	}
	return NULL;
}

#ifdef ENABLE_LLDPMED
/* This one is an helper function. */
static unsigned long
agent_h_med_power(struct variable *vp, struct lldpd_med_power *power)
{
	unsigned long long_ret;

	switch (vp->magic) {
	case LLDP_SNMP_MED_POE_DEVICETYPE:
		switch (power->devicetype) {
		case LLDPMED_POW_TYPE_PSE:
			long_ret = 2; break;
		case LLDPMED_POW_TYPE_PD:
			long_ret = 3; break;
		case 0:
			long_ret = 4; break;
		default:
			long_ret = 1;
		}
		return long_ret;
	case LLDP_SNMP_MED_POE_PSE_POWERVAL:
	case LLDP_SNMP_MED_POE_PD_POWERVAL:
		if (((vp->magic == LLDP_SNMP_MED_POE_PSE_POWERVAL) &&
			(power->devicetype ==
			LLDPMED_POW_TYPE_PSE)) ||
		    ((vp->magic == LLDP_SNMP_MED_POE_PD_POWERVAL) &&
			(power->devicetype ==
			    LLDPMED_POW_TYPE_PD))) {
			long_ret = power->val;
			return long_ret;
		}
		break;
	case LLDP_SNMP_MED_POE_PSE_POWERSOURCE:
		if (power->devicetype ==
		    LLDPMED_POW_TYPE_PSE) {
			switch (power->source) {
			case LLDPMED_POW_SOURCE_PRIMARY:
				long_ret = 2; break;
			case LLDPMED_POW_SOURCE_BACKUP:
				long_ret = 3; break;
			default:
				long_ret = 1;
			}
			return long_ret;
		}
		break;
	case LLDP_SNMP_MED_POE_PD_POWERSOURCE:
		if (power->devicetype ==
		    LLDPMED_POW_TYPE_PD) {
			switch (power->source) {
			case LLDPMED_POW_SOURCE_PSE:
				long_ret = 2; break;
			case LLDPMED_POW_SOURCE_LOCAL:
				long_ret = 3; break;
			case LLDPMED_POW_SOURCE_BOTH:
				long_ret = 4; break;
			default:
				long_ret = 1;
			}
			return long_ret;
		}
		break;
	case LLDP_SNMP_MED_POE_PSE_POWERPRIORITY:
	case LLDP_SNMP_MED_POE_PD_POWERPRIORITY:
		if (((vp->magic == LLDP_SNMP_MED_POE_PSE_POWERPRIORITY) &&
			(power->devicetype ==
			LLDPMED_POW_TYPE_PSE)) ||
		    ((vp->magic == LLDP_SNMP_MED_POE_PD_POWERPRIORITY) &&
			(power->devicetype ==
			    LLDPMED_POW_TYPE_PD))) {
			switch (power->priority) {
			case LLDPMED_POW_PRIO_CRITICAL:
				long_ret = 2; break;
			case LLDPMED_POW_PRIO_HIGH:
				long_ret = 3; break;
			case LLDPMED_POW_PRIO_LOW:
				long_ret = 4; break;
			default:
				long_ret = 1;
			}
			return long_ret;
		}
		break;
	}

	return (unsigned long)-1;
}

static u_char*
agent_h_local_med(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
        static unsigned long long_ret;
	struct lldpd_hardware *hardware;
	struct lldpd_med_power *power;
	int pse;

	if (!LOCAL_CHASSIS(scfg)->c_med_cap_available)
		return NULL;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_MED_LOCAL_CLASS:
		long_ret = LOCAL_CHASSIS(scfg)->c_med_type;
		return (u_char *)&long_ret;
	case LLDP_SNMP_MED_POE_DEVICETYPE:
	case LLDP_SNMP_MED_POE_PSE_POWERSOURCE:
	case LLDP_SNMP_MED_POE_PD_POWERVAL:
	case LLDP_SNMP_MED_POE_PD_POWERSOURCE:
	case LLDP_SNMP_MED_POE_PD_POWERPRIORITY:
		/* LLDP-MED requires only one device type for all
		   ports. Moreover, a PSE can only have one power source. At
		   least, all PD values are global and not per-port. We try to
		   do our best. For device type, we decide on the number of
		   PD/PSE ports. */
		pse = 0; power = NULL;
		TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
			if (hardware->h_lport.p_med_power.devicetype ==
			    LLDPMED_POW_TYPE_PSE) {
				pse++;
				if (pse == 1) /* Take this port as a reference */
					power = &hardware->h_lport.p_med_power;
			} else if (hardware->h_lport.p_med_power.devicetype ==
			    LLDPMED_POW_TYPE_PD) {
				pse--;
				if (pse == -1) /* Take this one instead */
					power = &hardware->h_lport.p_med_power;
			}
		}
		if (!power)
			break;	/* Neither PSE nor PD */
		long_ret = agent_h_med_power(vp, power);
		if (long_ret != (unsigned long)-1)
			return (u_char *)&long_ret;
		break;

#define LLDP_H_LOCAL_MED(magic, variable)				\
		case magic:						\
		    if (LOCAL_CHASSIS(scfg)->variable) {		\
			    *var_len = strlen(				\
				    LOCAL_CHASSIS(scfg)->variable);		\
			    return (u_char *)LOCAL_CHASSIS(scfg)->variable;	\
		    }							\
		break

	LLDP_H_LOCAL_MED(LLDP_SNMP_MED_LOCAL_HW,
	    c_med_hw);
	LLDP_H_LOCAL_MED(LLDP_SNMP_MED_LOCAL_SW,
	    c_med_sw);
	LLDP_H_LOCAL_MED(LLDP_SNMP_MED_LOCAL_FW,
	    c_med_fw);
	LLDP_H_LOCAL_MED(LLDP_SNMP_MED_LOCAL_SN,
	    c_med_sn);
	LLDP_H_LOCAL_MED(LLDP_SNMP_MED_LOCAL_MANUF,
	    c_med_manuf);
	LLDP_H_LOCAL_MED(LLDP_SNMP_MED_LOCAL_MODEL,
	    c_med_model);
	LLDP_H_LOCAL_MED(LLDP_SNMP_MED_LOCAL_ASSET,
	    c_med_asset);

	default:
		return NULL;
	}
	TRYNEXT(agent_h_local_med);
}

static u_char*
agent_h_local_med_policy(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_med_policy *policy;
        static unsigned long long_ret;

	if ((policy = (struct lldpd_med_policy *)header_pmedindexed_policy_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_MED_LOCAL_POLICY_VID:
		long_ret = policy->vid;
		break;
	case LLDP_SNMP_MED_LOCAL_POLICY_PRIO:
		long_ret = policy->priority;
		break;
	case LLDP_SNMP_MED_LOCAL_POLICY_DSCP:
		long_ret = policy->dscp;
		break;
	case LLDP_SNMP_MED_LOCAL_POLICY_UNKNOWN:
		long_ret = policy->unknown?1:2;
		break;
	case LLDP_SNMP_MED_LOCAL_POLICY_TAGGED:
		long_ret = policy->tagged?1:2;
		break;
	default:
		return NULL;
	}
	return (u_char *)&long_ret;
}

static u_char*
agent_h_local_med_location(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_med_loc *location;

	if ((location = (struct lldpd_med_loc *)header_pmedindexed_location_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_MED_LOCAL_LOCATION:
		*var_len = location->data_len;
		return (u_char *)location->data;
	}
	return NULL;
}

static u_char*
agent_h_local_med_power(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	struct lldpd_hardware *hardware;

	if ((hardware = header_portindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;
	if (!hardware->h_lport.p_med_power.devicetype)
		goto localpower_failed;

	long_ret = agent_h_med_power(vp, &hardware->h_lport.p_med_power);
	if (long_ret != (unsigned long)-1)
		return (u_char *)&long_ret;

localpower_failed:
	TRYNEXT(agent_h_local_med_power);
}

static u_char*
agent_h_remote_med(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_port *port;
	static uint8_t bit;
        static unsigned long long_ret;

	if ((port = header_tprindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	/* Optimization, we need to skip the whole chassis if no MED is available */
	if (!port->p_chassis->c_med_cap_available) {
		if (!exact && (name[*length-2] < MAX_SUBID))
			name[*length-2]++;
		goto remotemed_failed;
	}

	switch (vp->magic) {
        case LLDP_SNMP_MED_REMOTE_CLASS:
                long_ret = port->p_chassis->c_med_type;
		return (u_char *)&long_ret;
	case LLDP_SNMP_MED_REMOTE_CAP_AVAILABLE:
		*var_len = 1;
		bit = swap_bits(port->p_chassis->c_med_cap_available);
		return (u_char *)&bit;
	case LLDP_SNMP_MED_REMOTE_CAP_ENABLED:
		*var_len = 1;
		bit = swap_bits(port->p_med_cap_enabled);
		return (u_char *)&bit;

	case LLDP_SNMP_MED_POE_DEVICETYPE:
	case LLDP_SNMP_MED_POE_PSE_POWERVAL:
	case LLDP_SNMP_MED_POE_PD_POWERVAL:
	case LLDP_SNMP_MED_POE_PSE_POWERSOURCE:
	case LLDP_SNMP_MED_POE_PD_POWERSOURCE:
	case LLDP_SNMP_MED_POE_PSE_POWERPRIORITY:
	case LLDP_SNMP_MED_POE_PD_POWERPRIORITY:
		long_ret = agent_h_med_power(vp, &port->p_med_power);
		if (long_ret != (unsigned long)-1)
			return (u_char *)&long_ret;
		break;

#define LLDP_H_REMOTE_MED(magic, variable)				\
		case magic:						\
		    if (port->p_chassis->variable) {		\
			    *var_len = strlen(				\
				    port->p_chassis->variable);	\
			    return (u_char *)				\
				port->p_chassis->variable;		\
		    }							\
		break

	LLDP_H_REMOTE_MED(LLDP_SNMP_MED_REMOTE_HW,
	    c_med_hw);
	LLDP_H_REMOTE_MED(LLDP_SNMP_MED_REMOTE_SW,
	    c_med_sw);
	LLDP_H_REMOTE_MED(LLDP_SNMP_MED_REMOTE_FW,
	    c_med_fw);
	LLDP_H_REMOTE_MED(LLDP_SNMP_MED_REMOTE_SN,
	    c_med_sn);
	LLDP_H_REMOTE_MED(LLDP_SNMP_MED_REMOTE_MANUF,
	    c_med_manuf);
	LLDP_H_REMOTE_MED(LLDP_SNMP_MED_REMOTE_MODEL,
	    c_med_model);
	LLDP_H_REMOTE_MED(LLDP_SNMP_MED_REMOTE_ASSET,
	    c_med_asset);

	default:
		return NULL;
        }
remotemed_failed:
	TRYNEXT(agent_h_remote_med);
}

static u_char*
agent_h_remote_med_policy(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	int type;
	struct lldpd_port *port;
	struct lldpd_med_policy *policy;
        static unsigned long long_ret;

	if ((port = header_tprmedindexed_table(vp, name, length,
		    exact, var_len, write_method, TPR_VARIANT_MED_POLICY)) == NULL)
		return NULL;

	/* Optimization, we need to skip the whole chassis if no MED is available */
	if (!port->p_chassis->c_med_cap_available) {
		if (!exact && (name[*length-2] < MAX_SUBID))
			name[*length-2]++;
		goto remotemedpolicy_failed;
	}

	type = name[*length - 1];
	if ((type < 1) || (type > LLDPMED_APPTYPE_LAST))
		goto remotemedpolicy_failed;
	policy = &port->p_med_policy[type-1];
	if (policy->type != type)
		goto remotemedpolicy_failed;

	switch (vp->magic) {
        case LLDP_SNMP_MED_REMOTE_POLICY_VID:
                long_ret = policy->vid;
		return (u_char *)&long_ret;
	case LLDP_SNMP_MED_REMOTE_POLICY_PRIO:
		long_ret = policy->priority;
		return (u_char *)&long_ret;
	case LLDP_SNMP_MED_REMOTE_POLICY_DSCP:
		long_ret = policy->dscp;
		return (u_char *)&long_ret;
	case LLDP_SNMP_MED_REMOTE_POLICY_UNKNOWN:
		long_ret = policy->unknown?1:2;
		return (u_char *)&long_ret;
	case LLDP_SNMP_MED_REMOTE_POLICY_TAGGED:
		long_ret = policy->tagged?1:2;
		return (u_char *)&long_ret;
	default:
		return NULL;
        }
remotemedpolicy_failed:
	TRYNEXT(agent_h_remote_med_policy);
}

static u_char*
agent_h_remote_med_location(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	int type;
	struct lldpd_port *port;
	struct lldpd_med_loc *location;

	if ((port = header_tprmedindexed_table(vp, name, length,
		    exact, var_len, write_method, TPR_VARIANT_MED_LOCATION)) == NULL)
		return NULL;

	/* Optimization, we need to skip the whole chassis if no MED is available */
	if (!port->p_chassis->c_med_cap_available) {
		if (!exact && (name[*length-2] < MAX_SUBID))
			name[*length-2]++;
		goto remotemedlocation_failed;
	}

	type = name[*length - 1];
	if ((type < 1) || (type > LLDPMED_APPTYPE_LAST))
		goto remotemedlocation_failed;
	location = &port->p_med_location[type-1];
	if (location->format != type)
		goto remotemedlocation_failed;

	switch (vp->magic) {
        case LLDP_SNMP_MED_REMOTE_LOCATION:
		*var_len = location->data_len;
		return (u_char *)location->data;
	default:
		return NULL;
        }
remotemedlocation_failed:
	TRYNEXT(agent_h_remote_med_location);
}
#endif

static u_char*
agent_h_local_chassis(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	static uint8_t bit;
        static unsigned long long_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_LOCAL_CIDSUBTYPE:
                long_ret = LOCAL_CHASSIS(scfg)->c_id_subtype;
		return (u_char *)&long_ret;
	case LLDP_SNMP_LOCAL_CID:
		*var_len = LOCAL_CHASSIS(scfg)->c_id_len;
		return (u_char *)LOCAL_CHASSIS(scfg)->c_id;
	case LLDP_SNMP_LOCAL_SYSNAME:
		*var_len = strlen(LOCAL_CHASSIS(scfg)->c_name);
		return (u_char *)LOCAL_CHASSIS(scfg)->c_name;
	case LLDP_SNMP_LOCAL_SYSDESCR:
		*var_len = strlen(LOCAL_CHASSIS(scfg)->c_descr);
		return (u_char *)LOCAL_CHASSIS(scfg)->c_descr;
	case LLDP_SNMP_LOCAL_SYSCAP_SUP:
		*var_len = 1;
		bit = swap_bits(LOCAL_CHASSIS(scfg)->c_cap_available);
		return (u_char *)&bit;
	case LLDP_SNMP_LOCAL_SYSCAP_ENA:
		*var_len = 1;
		bit = swap_bits(LOCAL_CHASSIS(scfg)->c_cap_enabled);
		return (u_char *)&bit;
	default:
		break;
        }
	return NULL;
}

static u_char*
agent_h_stats(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	struct lldpd_hardware *hardware;

	if ((hardware = header_portindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_STATS_TX:
                long_ret = hardware->h_tx_cnt;
                return (u_char *)&long_ret;
	case LLDP_SNMP_STATS_RX:
                long_ret = hardware->h_rx_cnt;
		return (u_char *)&long_ret;
	case LLDP_SNMP_STATS_RX_DISCARDED:
	case LLDP_SNMP_STATS_RX_ERRORS:
		/* We discard only frame with errors. Therefore, the two values
		 * are equal */
                long_ret = hardware->h_rx_discarded_cnt;
		return (u_char *)&long_ret;
	case LLDP_SNMP_STATS_RX_TLVDISCARDED:
	case LLDP_SNMP_STATS_RX_TLVUNRECOGNIZED:
		/* We discard only unrecognized TLV. Malformed TLV
		   implies dropping the whole frame */
		long_ret = hardware->h_rx_unrecognized_cnt;
		return (u_char *)&long_ret;
	case LLDP_SNMP_STATS_RX_AGEOUTS:
                long_ret = hardware->h_rx_ageout_cnt;
		return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
}

static u_char*
agent_h_local_port(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
#ifdef ENABLE_DOT3
	static uint8_t bit;
#endif
	struct lldpd_hardware *hardware;
	static unsigned long long_ret;

	if ((hardware = header_portindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_LOCAL_PIDSUBTYPE:
                long_ret = hardware->h_lport.p_id_subtype;
		return (u_char *)&long_ret;
	case LLDP_SNMP_LOCAL_PID:
		*var_len = hardware->h_lport.p_id_len;
		return (u_char *)hardware->h_lport.p_id;
	case LLDP_SNMP_LOCAL_PORTDESC:
		*var_len = strlen(hardware->h_lport.p_descr);
		return (u_char *)hardware->h_lport.p_descr;
#ifdef ENABLE_DOT3
        case LLDP_SNMP_LOCAL_DOT3_AUTONEG_SUPPORT:
                long_ret = 2 - hardware->h_lport.p_macphy.autoneg_support;
                return (u_char *)&long_ret;
        case LLDP_SNMP_LOCAL_DOT3_AUTONEG_ENABLED:
                long_ret = 2 - hardware->h_lport.p_macphy.autoneg_enabled;
                return (u_char *)&long_ret;
        case LLDP_SNMP_LOCAL_DOT3_AUTONEG_ADVERTISED:
                *var_len = 2;
                return (u_char *)&hardware->h_lport.p_macphy.autoneg_advertised;
        case LLDP_SNMP_LOCAL_DOT3_AUTONEG_MAU:
                long_ret = hardware->h_lport.p_macphy.mau_type;
                return (u_char *)&long_ret;
        case LLDP_SNMP_LOCAL_DOT3_AGG_STATUS:
                bit = swap_bits((hardware->h_lport.p_aggregid > 0) ? 3 : 0);
                *var_len = 1;
                return (u_char *)&bit;
        case LLDP_SNMP_LOCAL_DOT3_AGG_ID:
                long_ret = hardware->h_lport.p_aggregid;
                return (u_char *)&long_ret;
	case LLDP_SNMP_LOCAL_DOT3_MFS:
		long_ret = hardware->h_lport.p_mfs;
		return (u_char *)&long_ret;
	case LLDP_SNMP_LOCAL_DOT3_POWER_DEVICETYPE:
		if (hardware->h_lport.p_power.devicetype) {
			long_ret = (hardware->h_lport.p_power.devicetype ==
			    LLDP_DOT3_POWER_PSE)?1:2;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_SUPPORT:
		if (hardware->h_lport.p_power.devicetype) {
			long_ret = (hardware->h_lport.p_power.supported)?1:2;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_ENABLED:
		if (hardware->h_lport.p_power.devicetype) {
			long_ret = (hardware->h_lport.p_power.enabled)?1:2;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_PAIRCONTROL:
		if (hardware->h_lport.p_power.devicetype) {
			long_ret = (hardware->h_lport.p_power.paircontrol)?1:2;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_PAIRS:
		if (hardware->h_lport.p_power.devicetype) {
			long_ret = hardware->h_lport.p_power.pairs;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_CLASS:
		if (hardware->h_lport.p_power.devicetype && hardware->h_lport.p_power.class) {
			long_ret = hardware->h_lport.p_power.class;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_TYPE:
		if (hardware->h_lport.p_power.devicetype &&
		    hardware->h_lport.p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			*var_len = 1;
			bit = (((hardware->h_lport.p_power.powertype ==
				    LLDP_DOT3_POWER_8023AT_TYPE1)?1:0) << 7) |
			    (((hardware->h_lport.p_power.devicetype ==
				    LLDP_DOT3_POWER_PSE)?0:1) << 6);
			return (u_char *)&bit;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_SOURCE:
		if (hardware->h_lport.p_power.devicetype &&
		    hardware->h_lport.p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			*var_len = 1;
			bit = swap_bits(hardware->h_lport.p_power.source%(1<<2));
			return (u_char *)&bit;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_PRIORITY:
		if (hardware->h_lport.p_power.devicetype &&
		    hardware->h_lport.p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			long_ret = hardware->h_lport.p_power.priority;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_REQUESTED:
		if (hardware->h_lport.p_power.devicetype &&
		    hardware->h_lport.p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			long_ret = hardware->h_lport.p_power.requested;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_LOCAL_DOT3_POWER_ALLOCATED:
		if (hardware->h_lport.p_power.devicetype &&
		    hardware->h_lport.p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			long_ret = hardware->h_lport.p_power.allocated;
			return (u_char *)&long_ret;
		}
		break;
#endif
#ifdef ENABLE_DOT1
	case LLDP_SNMP_LOCAL_DOT1_PVID:
		long_ret = hardware->h_lport.p_pvid; /* Should always be 0 */
		return (u_char *)&long_ret;
#endif
	default:
		break;
        }
	TRYNEXT(agent_h_local_port);
}

#ifdef ENABLE_DOT1
static u_char*
agent_h_local_vlan(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_vlan *vlan;
	static unsigned long long_ret;

	if ((vlan = header_pvindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_LOCAL_DOT1_VLANNAME:
		*var_len = strlen(vlan->v_name);
		return (u_char *)vlan->v_name;
	case LLDP_SNMP_LOCAL_DOT1_VLANID:
		long_ret = vlan->v_vid;
		return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
}

static u_char*
agent_h_remote_vlan(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_vlan *vlan;
	static unsigned long long_ret;

	if ((vlan = header_tprvindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_REMOTE_DOT1_VLANNAME:
		*var_len = strlen(vlan->v_name);
		return (u_char *)vlan->v_name;
	case LLDP_SNMP_REMOTE_DOT1_VLANID:
		long_ret = vlan->v_vid;
		return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
}
static u_char*
agent_h_local_ppvid(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_ppvid *ppvid;
	static unsigned long long_ret;

	if ((ppvid = header_pppvidindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_LOCAL_DOT1_PPVID:
		long_ret = ppvid->p_ppvid;
		return (u_char *)&long_ret;
	case LLDP_SNMP_LOCAL_DOT1_PPVLAN_SUPPORTED:
		long_ret = (ppvid->p_cap_status & LLDPD_PPVID_CAP_SUPPORTED)?1:2;
		return (u_char *)&long_ret;
	case LLDP_SNMP_LOCAL_DOT1_PPVLAN_ENABLED:
		long_ret = (ppvid->p_cap_status & LLDPD_PPVID_CAP_ENABLED)?1:2;
		return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
}

static u_char*
agent_h_remote_ppvid(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_ppvid *ppvid;
	static unsigned long long_ret;

	if ((ppvid = header_tprppvidindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_REMOTE_DOT1_PPVID:
		long_ret = ppvid->p_ppvid;
		return (u_char *)&long_ret;
	case LLDP_SNMP_REMOTE_DOT1_PPVLAN_SUPPORTED:
		long_ret = (ppvid->p_cap_status & LLDPD_PPVID_CAP_SUPPORTED)?1:2;
		return (u_char *)&long_ret;
	case LLDP_SNMP_REMOTE_DOT1_PPVLAN_ENABLED:
		long_ret = (ppvid->p_cap_status & LLDPD_PPVID_CAP_ENABLED)?1:2;
		return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
}
static u_char*
agent_h_local_pi(struct variable *vp, oid *name, size_t *length,
		 int exact, size_t *var_len, WriteMethod **write_method)
{	
	struct lldpd_pi *pi;

	if ((pi = header_ppiindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_LOCAL_DOT1_PI:
		*var_len = pi->p_pi_len;
		return (u_char *)pi->p_pi;
	default:
		break;
        }
        return NULL;
}
static u_char*
agent_h_remote_pi(struct variable *vp, oid *name, size_t *length,
		  int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_pi *pi;

	if ((pi = header_tprpiindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_REMOTE_DOT1_PI:
		*var_len = pi->p_pi_len;
		return (u_char *)pi->p_pi;
	default:
		break;
	}
	return NULL;
}
#endif

static u_char*
agent_h_remote_port(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_port *port;
	static uint8_t bit;
        static unsigned long long_ret;

	if ((port = header_tprindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
        case LLDP_SNMP_REMOTE_CIDSUBTYPE:
                long_ret = port->p_chassis->c_id_subtype;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_CID:
		*var_len = port->p_chassis->c_id_len;
		return (u_char *)port->p_chassis->c_id;
        case LLDP_SNMP_REMOTE_PIDSUBTYPE:
                long_ret = port->p_id_subtype;
		return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_PID:
		*var_len = port->p_id_len;
		return (u_char *)port->p_id;
        case LLDP_SNMP_REMOTE_PORTDESC:
		*var_len = strlen(port->p_descr);
		return (u_char *)port->p_descr;
        case LLDP_SNMP_REMOTE_SYSNAME:
		*var_len = strlen(port->p_chassis->c_name);
		return (u_char *)port->p_chassis->c_name;
        case LLDP_SNMP_REMOTE_SYSDESC:
		*var_len = strlen(port->p_chassis->c_descr);
		return (u_char *)port->p_chassis->c_descr;
        case LLDP_SNMP_REMOTE_SYSCAP_SUP:
		*var_len = 1;
		bit = swap_bits(port->p_chassis->c_cap_available);
		return (u_char *)&bit;
        case LLDP_SNMP_REMOTE_SYSCAP_ENA:
		*var_len = 1;
		bit = swap_bits(port->p_chassis->c_cap_enabled);
		return (u_char *)&bit;
#ifdef ENABLE_DOT3
        case LLDP_SNMP_REMOTE_DOT3_AUTONEG_SUPPORT:
                long_ret = 2 - port->p_macphy.autoneg_support;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_DOT3_AUTONEG_ENABLED:
                long_ret = 2 - port->p_macphy.autoneg_enabled;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_DOT3_AUTONEG_ADVERTISED:
                *var_len = 2;
                return (u_char *)&port->p_macphy.autoneg_advertised;
        case LLDP_SNMP_REMOTE_DOT3_AUTONEG_MAU:
                long_ret = port->p_macphy.mau_type;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_DOT3_AGG_STATUS:
                bit = swap_bits((port->p_aggregid > 0) ? 3 : 0);
                *var_len = 1;
                return (u_char *)&bit;
        case LLDP_SNMP_REMOTE_DOT3_AGG_ID:
                long_ret = port->p_aggregid;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_DOT3_MFS:
                long_ret = port->p_mfs;
                return (u_char *)&long_ret;
	case LLDP_SNMP_REMOTE_DOT3_POWER_DEVICETYPE:
		if (port->p_power.devicetype) {
			long_ret = (port->p_power.devicetype == LLDP_DOT3_POWER_PSE)?1:2;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_SUPPORT:
		if (port->p_power.devicetype) {
			long_ret = (port->p_power.supported)?1:2;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_ENABLED:
		if (port->p_power.devicetype) {
			long_ret = (port->p_power.enabled)?1:2;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_PAIRCONTROL:
		if (port->p_power.devicetype) {
			long_ret = (port->p_power.paircontrol)?1:2;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_PAIRS:
		if (port->p_power.devicetype) {
			long_ret = port->p_power.pairs;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_CLASS:
		if (port->p_power.devicetype && port->p_power.class) {
			long_ret = port->p_power.class;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_TYPE:
		if (port->p_power.devicetype &&
		    port->p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			*var_len = 1;
			bit = (((port->p_power.powertype ==
				    LLDP_DOT3_POWER_8023AT_TYPE1)?1:0) << 7) |
			    (((port->p_power.devicetype ==
				    LLDP_DOT3_POWER_PSE)?0:1) << 6);
			return (u_char *)&bit;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_SOURCE:
		if (port->p_power.devicetype &&
		    port->p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			*var_len = 1;
			bit = swap_bits(port->p_power.source%(1<<2));
			return (u_char *)&bit;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_PRIORITY:
		if (port->p_power.devicetype &&
		    port->p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			long_ret = port->p_power.priority;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_REQUESTED:
		if (port->p_power.devicetype &&
		    port->p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			long_ret = port->p_power.requested;
			return (u_char *)&long_ret;
		}
		break;
	case LLDP_SNMP_REMOTE_DOT3_POWER_ALLOCATED:
		if (port->p_power.devicetype &&
		    port->p_power.powertype != LLDP_DOT3_POWER_8023AT_OFF) {
			long_ret = port->p_power.allocated;
			return (u_char *)&long_ret;
		}
		break;
#endif
#ifdef ENABLE_DOT1
        case LLDP_SNMP_REMOTE_DOT1_PVID:
                long_ret = port->p_pvid;
                return (u_char *)&long_ret;
#endif
	default:
		break;
        }
	TRYNEXT(agent_h_remote_port);
}

static u_char*
agent_management(struct variable *vp, size_t *var_len, struct lldpd_chassis *chassis)
{
        static unsigned long int long_ret;
        static oid zeroDotZero[2] = {0, 0};

	switch (vp->magic) {
        case LLDP_SNMP_LOCAL_ADDR_LEN:
                long_ret = 5;
                return (u_char*)&long_ret;
        case LLDP_SNMP_LOCAL_ADDR_IFSUBTYPE:
        case LLDP_SNMP_REMOTE_ADDR_IFSUBTYPE:
                if (chassis->c_mgmt_if != 0)
                        long_ret = LLDP_MGMT_IFACE_IFINDEX;
                else
                        long_ret = 1;
                return (u_char*)&long_ret;
        case LLDP_SNMP_LOCAL_ADDR_IFID:
        case LLDP_SNMP_REMOTE_ADDR_IFID:
                long_ret = chassis->c_mgmt_if;
                return (u_char*)&long_ret;
        case LLDP_SNMP_LOCAL_ADDR_OID:
        case LLDP_SNMP_REMOTE_ADDR_OID:
                *var_len = sizeof(zeroDotZero);
                return (u_char*)zeroDotZero;
	default:
		break;
        }
        return NULL;
}

static u_char*
agent_h_local_management(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	int found = 1;

	header_index_init(vp, name, length, exact, var_len, write_method);
	oid index[6] = {
		1, 4,
		((u_int8_t*)&LOCAL_CHASSIS(scfg)->c_mgmt.s_addr)[0],
		((u_int8_t*)&LOCAL_CHASSIS(scfg)->c_mgmt.s_addr)[1],
		((u_int8_t*)&LOCAL_CHASSIS(scfg)->c_mgmt.s_addr)[2],
		((u_int8_t*)&LOCAL_CHASSIS(scfg)->c_mgmt.s_addr)[3] };
	if (header_index_add(index, 6,
			     &found) || header_index_best() != NULL)
		return agent_management(vp, var_len, LOCAL_CHASSIS(scfg));
	return NULL;
}

static u_char*
agent_h_remote_management(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_port *port;

	if ((port = header_tpripindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

        return agent_management(vp, var_len, port->p_chassis);
}

static struct variable8 lldp_vars[] = {
	/* Scalars */
	{LLDP_SNMP_TXINTERVAL, ASN_INTEGER, RONLY, agent_h_scalars, 3, {1, 1, 1}},
	{LLDP_SNMP_TXMULTIPLIER, ASN_INTEGER, RONLY, agent_h_scalars, 3, {1, 1, 2}},
	{LLDP_SNMP_REINITDELAY, ASN_INTEGER, RONLY, agent_h_scalars, 3, {1, 1, 3}},
	{LLDP_SNMP_TXDELAY, ASN_INTEGER, RONLY, agent_h_scalars, 3, {1, 1, 4}},
	{LLDP_SNMP_NOTIFICATION, ASN_INTEGER, RONLY, agent_h_scalars, 3, {1, 1, 5}},
	{LLDP_SNMP_LASTUPDATE, ASN_TIMETICKS, RONLY, agent_h_scalars, 3, {1, 2, 1}},
	{LLDP_SNMP_STATS_INSERTS, ASN_GAUGE, RONLY, agent_h_scalars, 3, {1, 2, 2}},
	{LLDP_SNMP_STATS_DELETES, ASN_GAUGE, RONLY, agent_h_scalars, 3, {1, 2, 3}},
	{LLDP_SNMP_STATS_DROPS, ASN_GAUGE, RONLY, agent_h_scalars, 3, {1, 2, 4}},
	{LLDP_SNMP_STATS_AGEOUTS, ASN_GAUGE, RONLY, agent_h_scalars, 3, {1, 2, 5}},
	/* Local chassis */
	{LLDP_SNMP_LOCAL_CIDSUBTYPE, ASN_INTEGER, RONLY, agent_h_local_chassis, 3, {1, 3, 1}},
	{LLDP_SNMP_LOCAL_CID, ASN_OCTET_STR, RONLY, agent_h_local_chassis, 3, {1, 3, 2}},
	{LLDP_SNMP_LOCAL_SYSNAME, ASN_OCTET_STR, RONLY, agent_h_local_chassis, 3, {1, 3, 3}},
	{LLDP_SNMP_LOCAL_SYSDESCR, ASN_OCTET_STR, RONLY, agent_h_local_chassis, 3, {1, 3, 4}},
	{LLDP_SNMP_LOCAL_SYSCAP_SUP, ASN_OCTET_STR, RONLY, agent_h_local_chassis, 3, {1, 3, 5}},
	{LLDP_SNMP_LOCAL_SYSCAP_ENA, ASN_OCTET_STR, RONLY, agent_h_local_chassis, 3, {1, 3, 6}},
	/* Stats */
	{LLDP_SNMP_STATS_TX, ASN_COUNTER, RONLY, agent_h_stats, 5, {1, 2, 6, 1, 2}},
	{LLDP_SNMP_STATS_RX_DISCARDED, ASN_COUNTER, RONLY, agent_h_stats, 5, {1, 2, 7, 1, 2}},
	{LLDP_SNMP_STATS_RX_ERRORS, ASN_COUNTER, RONLY, agent_h_stats, 5, {1, 2, 7, 1, 3}},
	{LLDP_SNMP_STATS_RX, ASN_COUNTER, RONLY, agent_h_stats, 5, {1, 2, 7, 1, 4}},
	{LLDP_SNMP_STATS_RX_TLVDISCARDED, ASN_COUNTER, RONLY, agent_h_stats, 5, {1, 2, 7, 1, 5}},
	{LLDP_SNMP_STATS_RX_TLVUNRECOGNIZED, ASN_COUNTER, RONLY, agent_h_stats, 5, {1, 2, 7, 1, 6}},
	{LLDP_SNMP_STATS_RX_AGEOUTS, ASN_GAUGE, RONLY, agent_h_stats, 5, {1, 2, 7, 1, 7}},
	/* Local ports */
	{LLDP_SNMP_LOCAL_PIDSUBTYPE, ASN_INTEGER, RONLY, agent_h_local_port, 5, {1, 3, 7, 1, 2}},
	{LLDP_SNMP_LOCAL_PID, ASN_OCTET_STR, RONLY, agent_h_local_port, 5, {1, 3, 7, 1, 3}},
	{LLDP_SNMP_LOCAL_PORTDESC, ASN_OCTET_STR, RONLY, agent_h_local_port, 5, {1, 3, 7, 1, 4}},
#ifdef ENABLE_DOT3
        {LLDP_SNMP_LOCAL_DOT3_AUTONEG_SUPPORT, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 1, 1, 1}},
        {LLDP_SNMP_LOCAL_DOT3_AUTONEG_ENABLED, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 1, 1, 2}},
        {LLDP_SNMP_LOCAL_DOT3_AUTONEG_ADVERTISED, ASN_OCTET_STR, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 1, 1, 3}},
        {LLDP_SNMP_LOCAL_DOT3_AUTONEG_MAU, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 1, 1, 4}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_DEVICETYPE, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 1}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_SUPPORT, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 2}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_ENABLED, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 3}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_PAIRCONTROL, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 4}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_PAIRS, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 5}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_CLASS, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 6}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_TYPE, ASN_OCTET_STR, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 7}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_SOURCE, ASN_OCTET_STR, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 8}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_PRIORITY, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 9}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_REQUESTED, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 10}},
	{LLDP_SNMP_LOCAL_DOT3_POWER_ALLOCATED, ASN_INTEGER, RONLY, agent_h_local_port, 8,
	 {1, 5, 4623, 1, 2, 2, 1, 11}},
        {LLDP_SNMP_LOCAL_DOT3_AGG_STATUS, ASN_OCTET_STR, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 3, 1, 1}},
        {LLDP_SNMP_LOCAL_DOT3_AGG_ID, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 3, 1, 2}},
        {LLDP_SNMP_LOCAL_DOT3_MFS, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 4, 1, 1}},
#endif
#ifdef ENABLE_DOT1
        {LLDP_SNMP_LOCAL_DOT1_PVID, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 32962, 1, 2, 1, 1, 1}},
        {LLDP_SNMP_LOCAL_DOT1_PPVID, ASN_INTEGER, RONLY, agent_h_local_ppvid, 8,
         {1, 5, 32962, 1, 2, 2, 1, 1}},
        {LLDP_SNMP_LOCAL_DOT1_PPVLAN_SUPPORTED, ASN_INTEGER, RONLY, agent_h_local_ppvid, 8,
         {1, 5, 32962, 1, 2, 2, 1, 2}},
        {LLDP_SNMP_LOCAL_DOT1_PPVLAN_ENABLED, ASN_INTEGER, RONLY, agent_h_local_ppvid, 8,
         {1, 5, 32962, 1, 2, 2, 1, 3}},
        {LLDP_SNMP_LOCAL_DOT1_VLANID, ASN_INTEGER, RONLY, agent_h_local_vlan, 8,
         {1, 5, 32962, 1, 2, 3, 1, 1}},
        {LLDP_SNMP_LOCAL_DOT1_VLANNAME, ASN_OCTET_STR, RONLY, agent_h_local_vlan, 8,
         {1, 5, 32962, 1, 2, 3, 1, 2}},
	{LLDP_SNMP_LOCAL_DOT1_PI, ASN_OCTET_STR, RONLY, agent_h_local_pi, 8,
	 {1, 5, 32962, 1, 2, 4, 1, 2}},
#endif
        /* Remote ports */
        {LLDP_SNMP_REMOTE_CIDSUBTYPE, ASN_INTEGER, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 4}},
        {LLDP_SNMP_REMOTE_CID, ASN_OCTET_STR, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 5}},
        {LLDP_SNMP_REMOTE_PIDSUBTYPE, ASN_INTEGER, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 6}},
        {LLDP_SNMP_REMOTE_PID, ASN_OCTET_STR, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 7}},
        {LLDP_SNMP_REMOTE_PORTDESC, ASN_OCTET_STR, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 8}},
        {LLDP_SNMP_REMOTE_SYSNAME, ASN_OCTET_STR, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 9}},
        {LLDP_SNMP_REMOTE_SYSDESC, ASN_OCTET_STR, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 10}},
        {LLDP_SNMP_REMOTE_SYSCAP_SUP, ASN_OCTET_STR, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 11}},
        {LLDP_SNMP_REMOTE_SYSCAP_ENA, ASN_OCTET_STR, RONLY, agent_h_remote_port, 5, {1, 4, 1, 1, 12}},
#ifdef ENABLE_DOT3
        {LLDP_SNMP_REMOTE_DOT3_AUTONEG_SUPPORT, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 1, 1, 1}},
        {LLDP_SNMP_REMOTE_DOT3_AUTONEG_ENABLED, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 1, 1, 2}},
        {LLDP_SNMP_REMOTE_DOT3_AUTONEG_ADVERTISED, ASN_OCTET_STR, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 1, 1, 3}},
        {LLDP_SNMP_REMOTE_DOT3_AUTONEG_MAU, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 1, 1, 4}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_DEVICETYPE, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 1}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_SUPPORT, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 2}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_ENABLED, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 3}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_PAIRCONTROL, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 4}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_PAIRS, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 5}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_CLASS, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 6}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_TYPE, ASN_OCTET_STR, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 7}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_SOURCE, ASN_OCTET_STR, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 8}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_PRIORITY, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 9}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_REQUESTED, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 10}},
	{LLDP_SNMP_REMOTE_DOT3_POWER_ALLOCATED, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
	 {1, 5, 4623, 1, 3, 2, 1, 11}},
        {LLDP_SNMP_REMOTE_DOT3_AGG_STATUS, ASN_OCTET_STR, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 3, 1, 1}},
        {LLDP_SNMP_REMOTE_DOT3_AGG_ID, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 3, 1, 2}},
        {LLDP_SNMP_REMOTE_DOT3_MFS, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 4, 1, 1}},
#endif
#ifdef ENABLE_DOT1
        {LLDP_SNMP_REMOTE_DOT1_PVID, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 32962, 1, 3, 1, 1, 1}},
        {LLDP_SNMP_REMOTE_DOT1_PPVID, ASN_INTEGER, RONLY, agent_h_remote_ppvid, 8,
         {1, 5, 32962, 1, 3, 2, 1, 1}},
        {LLDP_SNMP_REMOTE_DOT1_PPVLAN_SUPPORTED, ASN_INTEGER, RONLY, agent_h_remote_ppvid, 8,
         {1, 5, 32962, 1, 3, 2, 1, 2}},
        {LLDP_SNMP_REMOTE_DOT1_PPVLAN_ENABLED, ASN_INTEGER, RONLY, agent_h_remote_ppvid, 8,
         {1, 5, 32962, 1, 3, 2, 1, 3}},
        /* Remote vlans */
        {LLDP_SNMP_REMOTE_DOT1_VLANID, ASN_INTEGER, RONLY, agent_h_remote_vlan, 8,
         {1, 5, 32962, 1, 3, 3, 1, 1}},
        {LLDP_SNMP_REMOTE_DOT1_VLANNAME, ASN_OCTET_STR, RONLY, agent_h_remote_vlan, 8,
         {1, 5, 32962, 1, 3, 3, 1, 2}},
	/* Protocol identity */
	{LLDP_SNMP_REMOTE_DOT1_PI, ASN_OCTET_STR, RONLY, agent_h_remote_pi, 8,
	 {1, 5, 32962, 1, 3, 4, 1, 2}},
#endif
        /* Management address */
        {LLDP_SNMP_LOCAL_ADDR_LEN, ASN_INTEGER, RONLY, agent_h_local_management, 5,
         {1, 3, 8, 1, 3}},
        {LLDP_SNMP_LOCAL_ADDR_IFSUBTYPE, ASN_INTEGER, RONLY, agent_h_local_management, 5,
         {1, 3, 8, 1, 4}},
        {LLDP_SNMP_LOCAL_ADDR_IFID, ASN_INTEGER, RONLY, agent_h_local_management, 5,
         {1, 3, 8, 1, 5}},
        {LLDP_SNMP_LOCAL_ADDR_OID, ASN_OBJECT_ID, RONLY, agent_h_local_management, 5,
         {1, 3, 8, 1, 6}},
        {LLDP_SNMP_REMOTE_ADDR_IFSUBTYPE, ASN_INTEGER, RONLY, agent_h_remote_management, 5,
         {1, 4, 2, 1, 3}},
        {LLDP_SNMP_REMOTE_ADDR_IFID, ASN_INTEGER, RONLY, agent_h_remote_management, 5,
         {1, 4, 2, 1, 4}},
        {LLDP_SNMP_REMOTE_ADDR_OID, ASN_OBJECT_ID, RONLY, agent_h_remote_management, 5,
         {1, 4, 2, 1, 5}},
#ifdef ENABLE_LLDPMED
	/* LLDP-MED local */
	{LLDP_SNMP_MED_LOCAL_CLASS, ASN_INTEGER, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 1, 1}},
	{LLDP_SNMP_MED_LOCAL_POLICY_VID, ASN_INTEGER, RONLY, agent_h_local_med_policy, 8,
	 {1, 5, 4795, 1, 2, 1, 1, 2}},
	{LLDP_SNMP_MED_LOCAL_POLICY_PRIO, ASN_INTEGER, RONLY, agent_h_local_med_policy, 8,
	 {1, 5, 4795, 1, 2, 1, 1, 3}},
	{LLDP_SNMP_MED_LOCAL_POLICY_DSCP, ASN_INTEGER, RONLY, agent_h_local_med_policy, 8,
	 {1, 5, 4795, 1, 2, 1, 1, 4}},
	{LLDP_SNMP_MED_LOCAL_POLICY_UNKNOWN, ASN_INTEGER, RONLY, agent_h_local_med_policy, 8,
	 {1, 5, 4795, 1, 2, 1, 1, 5}},
	{LLDP_SNMP_MED_LOCAL_POLICY_TAGGED, ASN_INTEGER, RONLY, agent_h_local_med_policy, 8,
	 {1, 5, 4795, 1, 2, 1, 1, 6}},
	{LLDP_SNMP_MED_LOCAL_HW, ASN_OCTET_STR, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 2}},
	{LLDP_SNMP_MED_LOCAL_FW, ASN_OCTET_STR, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 3}},
	{LLDP_SNMP_MED_LOCAL_SW, ASN_OCTET_STR, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 4}},
	{LLDP_SNMP_MED_LOCAL_SN, ASN_OCTET_STR, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 5}},
	{LLDP_SNMP_MED_LOCAL_MANUF, ASN_OCTET_STR, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 6}},
	{LLDP_SNMP_MED_LOCAL_MODEL, ASN_OCTET_STR, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 7}},
	{LLDP_SNMP_MED_LOCAL_ASSET, ASN_OCTET_STR, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 8}},
	{LLDP_SNMP_MED_LOCAL_LOCATION, ASN_OCTET_STR, RONLY, agent_h_local_med_location, 8,
	 {1, 5, 4795, 1, 2, 9, 1, 2}},
	{LLDP_SNMP_MED_POE_DEVICETYPE, ASN_INTEGER, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 10}},
	{LLDP_SNMP_MED_POE_PSE_POWERVAL, ASN_GAUGE, RONLY, agent_h_local_med_power, 8,
	 {1, 5, 4795, 1, 2, 11, 1, 1}},
	{LLDP_SNMP_MED_POE_PSE_POWERPRIORITY, ASN_INTEGER, RONLY, agent_h_local_med_power, 8,
	 {1, 5, 4795, 1, 2, 11, 1, 2}},
	{LLDP_SNMP_MED_POE_PSE_POWERSOURCE, ASN_INTEGER, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 12}},
	{LLDP_SNMP_MED_POE_PD_POWERVAL, ASN_GAUGE, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 13}},
	{LLDP_SNMP_MED_POE_PD_POWERSOURCE, ASN_INTEGER, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 14}},
	{LLDP_SNMP_MED_POE_PD_POWERPRIORITY, ASN_INTEGER, RONLY, agent_h_local_med, 6,
	 {1, 5, 4795, 1, 2, 15}},
	/* LLDP-MED remote */
	{LLDP_SNMP_MED_REMOTE_CAP_AVAILABLE, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 1, 1, 1}},
	{LLDP_SNMP_MED_REMOTE_CAP_ENABLED, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 1, 1, 2}},
	{LLDP_SNMP_MED_REMOTE_CLASS, ASN_INTEGER, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 1, 1, 3}},
	{LLDP_SNMP_MED_REMOTE_HW, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 3, 1, 1}},
	{LLDP_SNMP_MED_REMOTE_FW, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 3, 1, 2}},
	{LLDP_SNMP_MED_REMOTE_SW, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 3, 1, 3}},
	{LLDP_SNMP_MED_REMOTE_SN, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 3, 1, 4}},
	{LLDP_SNMP_MED_REMOTE_MANUF, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 3, 1, 5}},
	{LLDP_SNMP_MED_REMOTE_MODEL, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 3, 1, 6}},
	{LLDP_SNMP_MED_REMOTE_ASSET, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 3, 1, 7}},
	{LLDP_SNMP_MED_REMOTE_POLICY_VID, ASN_INTEGER, RONLY, agent_h_remote_med_policy, 8,
	 {1, 5, 4795, 1, 3, 2, 1, 2}},
	{LLDP_SNMP_MED_REMOTE_POLICY_PRIO, ASN_INTEGER, RONLY, agent_h_remote_med_policy, 8,
	 {1, 5, 4795, 1, 3, 2, 1, 3}},
	{LLDP_SNMP_MED_REMOTE_POLICY_DSCP, ASN_INTEGER, RONLY, agent_h_remote_med_policy, 8,
	 {1, 5, 4795, 1, 3, 2, 1, 4}},
	{LLDP_SNMP_MED_REMOTE_POLICY_UNKNOWN, ASN_INTEGER, RONLY, agent_h_remote_med_policy, 8,
	 {1, 5, 4795, 1, 3, 2, 1, 5}},
	{LLDP_SNMP_MED_REMOTE_POLICY_TAGGED, ASN_INTEGER, RONLY, agent_h_remote_med_policy, 8,
	 {1, 5, 4795, 1, 3, 2, 1, 6}},
	{LLDP_SNMP_MED_REMOTE_LOCATION, ASN_OCTET_STR, RONLY, agent_h_remote_med_location, 8,
	 {1, 5, 4795, 1, 3, 4, 1, 2}},
	{LLDP_SNMP_MED_POE_DEVICETYPE, ASN_INTEGER, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 5, 1, 1}},
	{LLDP_SNMP_MED_POE_PSE_POWERVAL, ASN_GAUGE, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 6, 1, 1}},
	{LLDP_SNMP_MED_POE_PSE_POWERSOURCE, ASN_INTEGER, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 6, 1, 2}},
	{LLDP_SNMP_MED_POE_PSE_POWERPRIORITY, ASN_INTEGER, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 6, 1, 3}},
	{LLDP_SNMP_MED_POE_PD_POWERVAL, ASN_GAUGE, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 7, 1, 1}},
	{LLDP_SNMP_MED_POE_PD_POWERSOURCE, ASN_INTEGER, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 7, 1, 2}},
	{LLDP_SNMP_MED_POE_PD_POWERPRIORITY, ASN_INTEGER, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 7, 1, 3}},
#endif
};

void
agent_init(struct lldpd *cfg, char *agentx, int debug)
{
	int rc;
#ifdef HAVE___PROGNAME
	extern char *__progname;
#else
#  define __progname "lldpd"
#endif

	LLOG_INFO("Enable SNMP subagent");
	netsnmp_enable_subagent();
	snmp_disable_log();
	if (debug)
		snmp_enable_stderrlog();
	else
		snmp_enable_syslog_ident(__progname, LOG_DAEMON);

	scfg = cfg;

	/* We are chrooted, we don't want to handle persistent states */
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
	    NETSNMP_DS_LIB_DONT_PERSIST_STATE, TRUE);
	/* Do not load any MIB */
	setenv("MIBS", "", 1);

	/* We provide our UNIX domain transport */
	agent_priv_register_domain();

	if (agentx)
		netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
				      NETSNMP_DS_AGENT_X_SOCKET, agentx);
	init_agent("lldpAgent");
	REGISTER_MIB("lldp", lldp_vars, variable8, lldp_oid);
	init_snmp("lldpAgent");

	if ((rc = register_sysORTable(lldp_oid, OID_LENGTH(lldp_oid),
		    "lldpMIB implementation by lldpd")) != 0)
		LLOG_WARNX("Unable to register to sysORTable (%d)", rc);
}

void
agent_shutdown()
{
	unregister_sysORTable(lldp_oid, OID_LENGTH(lldp_oid));
	snmp_shutdown("lldpAgent");
}
