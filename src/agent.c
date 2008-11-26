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

#include "lldpd.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/agent/util_funcs.h>

static oid lldp_oid[] = {1, 0, 8802, 1, 1, 2};

/* For net-snmp */
extern int register_sysORTable(oid *, size_t, const char *);
extern int unregister_sysORTable(oid *, size_t);
extern struct timeval starttime;

/* Global variable because no way to pass it as argument. Should not be used
 * elsewhere. */
struct lldpd *scfg;

static inline uint8_t
swap_bits(uint8_t n)
{
  n = ((n&0xF0) >>4 ) | ( (n&0x0F) <<4);
  n = ((n&0xCC) >>2 ) | ( (n&0x33) <<2);
  n = ((n&0xAA) >>1 ) | ( (n&0x55) <<1);

  return  n;
};

struct lldpd_hardware*
header_portindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware, *phardware = NULL;
	unsigned int port, aport = 0, distance;

	if (header_simple_table(vp, name, length, exact, var_len, write_method, -1))
		return NULL;

	port = name[*length - 1];
	distance = -1;
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		if (INTERFACE_OPENED(hardware)) {
			aport = if_nametoindex(hardware->h_ifname);
			if (aport == port) {
                                /* Exact match */
                                return hardware;
			}
			if (aport < port)
				continue;
			if (aport - port < distance) {
				phardware = hardware;
				distance = aport - port;
			}
		}
	}
	if (phardware == NULL)
		return NULL;
	if (exact)
		return NULL;
        if (distance == -1)
                return NULL;
        aport = distance + port;
        name[*length - 1] = aport;
	return phardware;
}

struct lldpd_hardware*
header_tprindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method, int withip)
{
	struct lldpd_hardware *hardware, *phardware = NULL;
        oid *target, current[9], best[9];
        int result, target_len, oid_len;
        int i;

        if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
                memcpy(name, vp->name, sizeof(oid) * vp->namelen);
                *length = vp->namelen;
        }

	*write_method = 0;
	*var_len = sizeof(long);

        oid_len = (withip) ? 9:3;
        for (i = 0; i < oid_len; i++) best[i] = MAX_SUBID;
        target = &name[vp->namelen];
        target_len = *length - vp->namelen;
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		if ((INTERFACE_OPENED(hardware)) && (hardware->h_rchassis != NULL)) {
                        if (withip && (hardware->h_rchassis->c_mgmt.s_addr == INADDR_ANY))
                                continue;
                        current[0] = (hardware->h_rlastchange - starttime.tv_sec)*100;
                        current[1] = if_nametoindex(hardware->h_ifname);
                        current[2] = hardware->h_rid;
                        if (withip) {
                                current[3] = 1;
                                current[4] = 4;
                                current[8] = hardware->h_rchassis->c_mgmt.s_addr >> 24;
                                current[7] = (hardware->h_rchassis->c_mgmt.s_addr & 0xffffff) >> 16;
                                current[6] = (hardware->h_rchassis->c_mgmt.s_addr & 0xffff) >> 8;
                                current[5] = hardware->h_rchassis->c_mgmt.s_addr & 0xff;
                        }
                        if ((result = snmp_oid_compare(current, oid_len, target,
                                    target_len)) < 0)
                                continue;
                        if ((result == 0) && !exact)
                                continue;
                        if (result == 0)
                                return hardware;
                        if (snmp_oid_compare(current, oid_len, best, oid_len) < 0) {
                                memcpy(best, current, sizeof(oid) * oid_len);
                                phardware = hardware;
                        }
		}
	}
	if (phardware == NULL)
		return NULL;
	if (exact)
		return NULL;
        for (i = 0; i < oid_len; i++)
                if (best[i] != MAX_SUBID) break;
        if (i == oid_len)
                return NULL;
        memcpy(target, best, sizeof(oid) * oid_len);
        *length = vp->namelen + oid_len;

	return phardware;
}

struct lldpd_vlan*
header_pvindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
        struct lldpd_vlan *vlan, *pvlan = NULL;
        oid *target, current[2], best[2];
        int result, target_len;

        if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
                memcpy(name, vp->name, sizeof(oid) * vp->namelen);
                *length = vp->namelen;
        }

	*write_method = 0;
	*var_len = sizeof(long);

        best[0] = best[1] = MAX_SUBID;
        target = &name[vp->namelen];
        target_len = *length - vp->namelen;
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		if (INTERFACE_OPENED(hardware)) {
                        TAILQ_FOREACH(vlan, &hardware->h_lport.p_vlans, v_entries) {
                                current[0] = if_nametoindex(hardware->h_ifname);
                                current[1] = vlan->v_vid;
                                if ((result = snmp_oid_compare(current, 2, target,
                                            target_len)) < 0)
                                        continue;
                                if ((result == 0) && !exact)
                                        continue;
                                if (result == 0)
                                        return vlan;
                                if (snmp_oid_compare(current, 2, best, 2) < 0) {
                                        memcpy(best, current, sizeof(oid) * 2);
                                        pvlan = vlan;
                                }
                        }
		}
	}
	if (pvlan == NULL)
		return NULL;
	if (exact)
		return NULL;
        if ((best[0] == best[1]) &&
            (best[0] == MAX_SUBID))
                return NULL;
        memcpy(target, best, sizeof(oid) * 2);
        *length = vp->namelen + 2;

	return pvlan;
}

struct lldpd_vlan*
header_tprvindexed_table(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
        struct lldpd_vlan *vlan, *pvlan = NULL;
        oid *target, current[4], best[4];
        int result, target_len;

        if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
                memcpy(name, vp->name, sizeof(oid) * vp->namelen);
                *length = vp->namelen;
        }

	*write_method = 0;
	*var_len = sizeof(long);

        best[0] = best[1] = best[2] = best[3] = MAX_SUBID;
        target = &name[vp->namelen];
        target_len = *length - vp->namelen;
	TAILQ_FOREACH(hardware, &scfg->g_hardware, h_entries) {
		if ((INTERFACE_OPENED(hardware)) && (hardware->h_rport != NULL)) {
                        TAILQ_FOREACH(vlan, &hardware->h_rport->p_vlans, v_entries) {
                                current[0] = (hardware->h_rlastchange - starttime.tv_sec)*100;
                                current[1] = if_nametoindex(hardware->h_ifname);
                                current[2] = hardware->h_rid;
                                current[3] = vlan->v_vid;
                                if ((result = snmp_oid_compare(current, 4, target,
                                            target_len)) < 0)
                                        continue;
                                if ((result == 0) && !exact)
                                        continue;
                                if (result == 0)
                                        return vlan;
                                if (snmp_oid_compare(current, 4, best, 4) < 0) {
                                        memcpy(best, current, sizeof(oid) * 4);
                                        pvlan = vlan;
                                }
                        }
		}
	}
	if (pvlan == NULL)
		return NULL;
	if (exact)
		return NULL;
        if ((best[0] == best[1]) && (best[1] == best[2]) &&
            (best[2] == best[3]) && (best[0] == MAX_SUBID))
                return NULL;
        memcpy(target, best, sizeof(oid) * 4);
        *length = vp->namelen + 4;

	return pvlan;
}

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
/* Local vlans */
#define LLDP_SNMP_LOCAL_DOT1_VLANNAME 1
/* Remote vlans */
#define LLDP_SNMP_REMOTE_DOT1_VLANNAME 1
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
/* LLDP-MED remote */
#define LLDP_SNMP_MED_REMOTE_CAP 1
#define LLDP_SNMP_MED_REMOTE_CLASS 2
#define LLDP_SNMP_MED_REMOTE_HW 3
#define LLDP_SNMP_MED_REMOTE_FW 4
#define LLDP_SNMP_MED_REMOTE_SW 5
#define LLDP_SNMP_MED_REMOTE_SN 6
#define LLDP_SNMP_MED_REMOTE_MANUF 7
#define LLDP_SNMP_MED_REMOTE_MODEL 8
#define LLDP_SNMP_MED_REMOTE_ASSET 9

static u_char*
agent_h_scalars(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	static unsigned long long_ret;
	struct lldpd_hardware *hardware;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_TXINTERVAL:
                long_ret = scfg->g_delay;
		return (u_char *)&long_ret;
	case LLDP_SNMP_TXMULTIPLIER:
		long_ret = scfg->g_lchassis.c_ttl / scfg->g_delay;
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
			if (hardware->h_rlastchange > long_ret)
				long_ret = hardware->h_rlastchange;
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
static u_char*
agent_h_local_med(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
        static unsigned long long_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method))
		return NULL;

	if (!scfg->g_lchassis.c_med_cap)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_MED_LOCAL_CLASS:
		long_ret = scfg->g_lchassis.c_med_type;
		if (long_ret > 0)
			return (u_char *)&long_ret;
		break;

#define LLDP_H_LOCAL_MED(magic, variable)				\
		case magic:						\
		    if (scfg->g_lchassis.variable) {			\
			    *var_len = strlen(				\
				    scfg->g_lchassis.variable);		\
			    return (u_char *)scfg->g_lchassis.variable;	\
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
		break;
	}
	return NULL;
}

static u_char*
agent_h_remote_med(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	static uint8_t bit;
        static unsigned long long_ret;

	if (!scfg->g_lchassis.c_med_cap)
		return NULL;

	if ((hardware = header_tprindexed_table(vp, name, length,
		    exact, var_len, write_method, 0)) == NULL)
		return NULL;

	if (!hardware->h_rchassis->c_med_cap)
		return NULL;

	switch (vp->magic) {
        case LLDP_SNMP_MED_REMOTE_CLASS:
                long_ret = hardware->h_rchassis->c_med_type;
		if (long_ret > 0)
			return (u_char *)&long_ret;
		break;
	case LLDP_SNMP_MED_REMOTE_CAP:
		*var_len = 1;
		bit = swap_bits(hardware->h_rchassis->c_med_cap);
		return (u_char *)&bit;
#define LLDP_H_REMOTE_MED(magic, variable)				\
		case magic:						\
		    if (hardware->h_rchassis->variable) {		\
			    *var_len = strlen(				\
				    hardware->h_rchassis->variable);	\
			    return (u_char *)				\
				hardware->h_rchassis->variable;		\
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
		break;
        }
        return NULL;
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
                long_ret = scfg->g_lchassis.c_id_subtype;
		return (u_char *)&long_ret;
	case LLDP_SNMP_LOCAL_CID:
		*var_len = scfg->g_lchassis.c_id_len;
		return (u_char *)scfg->g_lchassis.c_id;
	case LLDP_SNMP_LOCAL_SYSNAME:
		*var_len = strlen(scfg->g_lchassis.c_name);
		return (u_char *)scfg->g_lchassis.c_name;
	case LLDP_SNMP_LOCAL_SYSDESCR:
		*var_len = strlen(scfg->g_lchassis.c_descr);
		return (u_char *)scfg->g_lchassis.c_descr;
	case LLDP_SNMP_LOCAL_SYSCAP_SUP:
		*var_len = 1;
		bit = swap_bits(scfg->g_lchassis.c_cap_available);
		return (u_char *)&bit;
	case LLDP_SNMP_LOCAL_SYSCAP_ENA:
		*var_len = 1;
		bit = swap_bits(scfg->g_lchassis.c_cap_enabled);
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
	static uint8_t bit;
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
        case LLDP_SNMP_LOCAL_DOT3_AUTONEG_SUPPORT:
                long_ret = 2 - hardware->h_lport.p_autoneg_support;
                return (u_char *)&long_ret;
        case LLDP_SNMP_LOCAL_DOT3_AUTONEG_ENABLED:
                long_ret = 2 - hardware->h_lport.p_autoneg_enabled;
                return (u_char *)&long_ret;
        case LLDP_SNMP_LOCAL_DOT3_AUTONEG_ADVERTISED:
                *var_len = 2;
                return (u_char *)&hardware->h_lport.p_autoneg_advertised;
        case LLDP_SNMP_LOCAL_DOT3_AUTONEG_MAU:
                long_ret = hardware->h_lport.p_mau_type;
                return (u_char *)&long_ret;
        case LLDP_SNMP_LOCAL_DOT3_AGG_STATUS:
                bit = swap_bits((hardware->h_lport.p_aggregid > 0) ? 3 : 0);
                *var_len = 1;
                return (u_char *)&bit;
        case LLDP_SNMP_LOCAL_DOT3_AGG_ID:
                long_ret = hardware->h_lport.p_aggregid;
                return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
}

static u_char*
agent_h_local_vlan(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_vlan *vlan;

	if ((vlan = header_pvindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_LOCAL_DOT1_VLANNAME:
		*var_len = strlen(vlan->v_name);
		return (u_char *)vlan->v_name;
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

	if ((vlan = header_tprvindexed_table(vp, name, length,
		    exact, var_len, write_method)) == NULL)
		return NULL;

	switch (vp->magic) {
	case LLDP_SNMP_REMOTE_DOT1_VLANNAME:
		*var_len = strlen(vlan->v_name);
		return (u_char *)vlan->v_name;
	default:
		break;
        }
        return NULL;
}

static u_char*
agent_h_remote_port(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;
	static uint8_t bit;
        static unsigned long long_ret;

	if ((hardware = header_tprindexed_table(vp, name, length,
		    exact, var_len, write_method, 0)) == NULL)
		return NULL;

	switch (vp->magic) {
        case LLDP_SNMP_REMOTE_CIDSUBTYPE:
                long_ret = hardware->h_rchassis->c_id_subtype;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_CID:
		*var_len = hardware->h_rchassis->c_id_len;
		return (u_char *)hardware->h_rchassis->c_id;
        case LLDP_SNMP_REMOTE_PIDSUBTYPE:
                long_ret = hardware->h_rport->p_id_subtype;
		return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_PID:
		*var_len = hardware->h_rport->p_id_len;
		return (u_char *)hardware->h_rport->p_id;
        case LLDP_SNMP_REMOTE_PORTDESC:
		*var_len = strlen(hardware->h_rport->p_descr);
		return (u_char *)hardware->h_rport->p_descr;
        case LLDP_SNMP_REMOTE_SYSNAME:
		*var_len = strlen(hardware->h_rchassis->c_name);
		return (u_char *)hardware->h_rchassis->c_name;
        case LLDP_SNMP_REMOTE_SYSDESC:
		*var_len = strlen(hardware->h_rchassis->c_descr);
		return (u_char *)hardware->h_rchassis->c_descr;
        case LLDP_SNMP_REMOTE_SYSCAP_SUP:
		*var_len = 1;
		bit = swap_bits(hardware->h_rchassis->c_cap_available);
		return (u_char *)&bit;
        case LLDP_SNMP_REMOTE_SYSCAP_ENA:
		*var_len = 1;
		bit = swap_bits(hardware->h_rchassis->c_cap_enabled);
		return (u_char *)&bit;
        case LLDP_SNMP_REMOTE_DOT3_AUTONEG_SUPPORT:
                long_ret = 2 - hardware->h_rport->p_autoneg_support;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_DOT3_AUTONEG_ENABLED:
                long_ret = 2 - hardware->h_rport->p_autoneg_enabled;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_DOT3_AUTONEG_ADVERTISED:
                *var_len = 2;
                return (u_char *)&hardware->h_rport->p_autoneg_advertised;
        case LLDP_SNMP_REMOTE_DOT3_AUTONEG_MAU:
                long_ret = hardware->h_rport->p_mau_type;
                return (u_char *)&long_ret;
        case LLDP_SNMP_REMOTE_DOT3_AGG_STATUS:
                bit = swap_bits((hardware->h_rport->p_aggregid > 0) ? 3 : 0);
                *var_len = 1;
                return (u_char *)&bit;
        case LLDP_SNMP_REMOTE_DOT3_AGG_ID:
                long_ret = hardware->h_rport->p_aggregid;
                return (u_char *)&long_ret;
	default:
		break;
        }
        return NULL;
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
        oid *target, best[6];
        int result, target_len;

        if (scfg->g_lchassis.c_mgmt.s_addr == INADDR_ANY)
                return NULL;

        if ((result = snmp_oid_compare(name, *length, vp->name, vp->namelen)) < 0) {
                memcpy(name, vp->name, sizeof(oid) * vp->namelen);
                *length = vp->namelen;
        }

	*write_method = 0;
	*var_len = sizeof(long);

        target = &name[vp->namelen];
        target_len = *length - vp->namelen;

        best[0] = 1;
        best[1] = 4;
        best[5] = scfg->g_lchassis.c_mgmt.s_addr >> 24;
        best[4] = (scfg->g_lchassis.c_mgmt.s_addr & 0xffffff) >> 16;
        best[3] = (scfg->g_lchassis.c_mgmt.s_addr & 0xffff) >> 8;
        best[2] = scfg->g_lchassis.c_mgmt.s_addr & 0xff;

        if ((result = snmp_oid_compare(target, target_len, best, 6)) < 0) {
                if (exact)
                        return NULL;
                memcpy(target, best, sizeof(oid) * 6);
                *length = vp->namelen + 6;
        } else if (exact && (result != 0))
                return NULL;
        else if (!exact && result == 0)
                return NULL;

        return agent_management(vp, var_len, &scfg->g_lchassis);
}

static u_char*
agent_h_remote_management(struct variable *vp, oid *name, size_t *length,
    int exact, size_t *var_len, WriteMethod **write_method)
{
	struct lldpd_hardware *hardware;

	if ((hardware = header_tprindexed_table(vp, name, length,
		    exact, var_len, write_method, 1)) == NULL)
		return NULL;

        return agent_management(vp, var_len, hardware->h_rchassis);
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
        {LLDP_SNMP_LOCAL_DOT3_AUTONEG_SUPPORT, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 1, 1, 1}},
        {LLDP_SNMP_LOCAL_DOT3_AUTONEG_ENABLED, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 1, 1, 2}},
        {LLDP_SNMP_LOCAL_DOT3_AUTONEG_ADVERTISED, ASN_OCTET_STR, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 1, 1, 3}},
        {LLDP_SNMP_LOCAL_DOT3_AUTONEG_MAU, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 1, 1, 4}},
        {LLDP_SNMP_LOCAL_DOT3_AGG_STATUS, ASN_OCTET_STR, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 3, 1, 1}},
        {LLDP_SNMP_LOCAL_DOT3_AGG_ID, ASN_INTEGER, RONLY, agent_h_local_port, 8,
         {1, 5, 4623, 1, 2, 3, 1, 2}},
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
        {LLDP_SNMP_REMOTE_DOT3_AUTONEG_SUPPORT, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 1, 1, 1}},
        {LLDP_SNMP_REMOTE_DOT3_AUTONEG_ENABLED, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 1, 1, 2}},
        {LLDP_SNMP_REMOTE_DOT3_AUTONEG_ADVERTISED, ASN_OCTET_STR, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 1, 1, 3}},
        {LLDP_SNMP_REMOTE_DOT3_AUTONEG_MAU, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 1, 1, 4}},
        {LLDP_SNMP_REMOTE_DOT3_AGG_STATUS, ASN_OCTET_STR, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 3, 1, 1}},
        {LLDP_SNMP_REMOTE_DOT3_AGG_ID, ASN_INTEGER, RONLY, agent_h_remote_port, 8,
         {1, 5, 4623, 1, 3, 3, 1, 2}},
        /* Local vlans */
        {LLDP_SNMP_LOCAL_DOT1_VLANNAME, ASN_OCTET_STR, RONLY, agent_h_local_vlan, 8,
         {1, 5, 32962, 1, 2, 3, 1, 2}},
        /* Remote vlans */
        {LLDP_SNMP_REMOTE_DOT1_VLANNAME, ASN_OCTET_STR, RONLY, agent_h_remote_vlan, 8,
         {1, 5, 32962, 1, 3, 3, 1, 2}},
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
	/* LLDP-MED remote */
	{LLDP_SNMP_MED_REMOTE_CAP, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
	 {1, 5, 4795, 1, 3, 1, 1, 1}},
	{LLDP_SNMP_MED_REMOTE_CAP, ASN_OCTET_STR, RONLY, agent_h_remote_med, 8,
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
#endif
};

void
agent_init(struct lldpd *cfg, int debug)
{
	int rc;
	extern char *__progname;

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
