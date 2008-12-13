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

#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <linux/sockios.h>

int
lldp_send(struct lldpd *global, struct lldpd_chassis *chassis,
		struct lldpd_hardware *hardware)
{
	struct ether_header eh;
	const u_int8_t mcastaddr[] = LLDP_MULTICAST_ADDR;
	struct iovec *iov = NULL;
	struct lldp_id chid, pid;
	struct lldp_ttl ttl;
	struct lldp_end end;
	struct lldp_string name;
	struct lldp_string descr;
	struct lldp_string str;
	struct lldp_cap cap;
	struct lldp_mgmt mgmt;
#ifdef ENABLE_DOT1
	const u_int8_t dot1[] = LLDP_TLV_ORG_DOT1;
	struct lldp_vlan *ovlan = NULL;
	int v;
	struct lldpd_vlan *vlan;
#endif
#ifdef ENABLE_DOT3
	const u_int8_t dot3[] = LLDP_TLV_ORG_DOT3;
	struct lldp_aggreg aggreg;
	struct lldp_macphy macphy;
#endif
#ifdef ENABLE_LLDPMED
	int i;
	const u_int8_t med[] = LLDP_TLV_ORG_MED;
	struct lldpmed_cap medcap;
	struct lldp_org medhw, medfw, medsw, medsn,
	    medmodel, medasset, medmanuf, medloc[3];
#endif
	struct lldpd_port *port = &hardware->h_lport;
	u_int c = -1, len = 0;
	struct lldpd_frame *buffer;

#define IOV_NEW							\
	if ((iov = (struct iovec*)realloc(iov, (++c + 1) *	\
		    sizeof(struct iovec))) == NULL)		\
		fatal(NULL);

	/* Ethernet header */
	memset(&eh, 0, sizeof(eh));
	memcpy(&eh.ether_shost, &hardware->h_lladdr,
	    sizeof(eh.ether_shost));
	memcpy(&eh.ether_dhost, &mcastaddr,
	    sizeof(eh.ether_dhost));
	eh.ether_type = htons(ETHERTYPE_LLDP);
	IOV_NEW;
	iov[c].iov_base = &eh;
	iov[c].iov_len = sizeof(struct ether_header);

	/* Chassis ID */
	memset(&chid, 0, sizeof(chid));
	len = chassis->c_id_len + sizeof(chid);
	chid.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_CHASSIS_ID,
	    len - sizeof(struct lldp_tlv_head));
	chid.tlv_id_subtype = chassis->c_id_subtype;
	IOV_NEW;
	iov[c].iov_base = &chid;
	iov[c].iov_len = sizeof(chid);
	IOV_NEW;
	iov[c].iov_base = chassis->c_id;
	iov[c].iov_len = chassis->c_id_len;

	/* Port ID */
	memset(&pid, 0, sizeof(pid));
	len = port->p_id_len + sizeof(pid);
	pid.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_PORT_ID,
	    len - sizeof(struct lldp_tlv_head));
	pid.tlv_id_subtype = port->p_id_subtype;
	IOV_NEW;
	iov[c].iov_base = &pid;
	iov[c].iov_len = sizeof(pid);
	IOV_NEW;
	iov[c].iov_base = port->p_id;
	iov[c].iov_len = port->p_id_len;

	/* Time to live */
	memset(&ttl, 0, sizeof(ttl));
	len = sizeof(ttl);
	ttl.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_TTL,
	    len - sizeof(struct lldp_tlv_head));
	ttl.tlv_ttl = htons(chassis->c_ttl);
	IOV_NEW;
	iov[c].iov_base = &ttl;
	iov[c].iov_len = sizeof(ttl);

	/* System name */
	memset(&name, 0, sizeof(name));
	len = sizeof(name) + strlen(chassis->c_name);
	name.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_SYSTEM_NAME,
	    len - sizeof(struct lldp_tlv_head));
	IOV_NEW;
	iov[c].iov_base = &name;
	iov[c].iov_len = sizeof(name);
	IOV_NEW;
	iov[c].iov_base = chassis->c_name;
	iov[c].iov_len = strlen(chassis->c_name);

	/* System description */
	memset(&descr, 0, sizeof(descr));
	len = sizeof(descr) + strlen(chassis->c_descr);
	descr.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_SYSTEM_DESCR,
	    len - sizeof(struct lldp_tlv_head));
	IOV_NEW;
	iov[c].iov_base = &descr;
	iov[c].iov_len = sizeof(descr);
	IOV_NEW;
	iov[c].iov_base = chassis->c_descr;
	iov[c].iov_len = strlen(chassis->c_descr);

	/* System capabilities */
	memset(&cap, 0, sizeof(cap));
	len = sizeof(cap);
	cap.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_SYSTEM_CAP,
	    len - sizeof(struct lldp_tlv_head));
	cap.tlv_cap_available = htons(chassis->c_cap_available);
	cap.tlv_cap_enabled = htons(chassis->c_cap_enabled);
	IOV_NEW;
	iov[c].iov_base = &cap;
	iov[c].iov_len = len;

	if (chassis->c_mgmt.s_addr != INADDR_ANY) {
		/* Management address */
		memset(&mgmt, 0, sizeof(mgmt));
		len = sizeof(mgmt);
		mgmt.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_MGMT_ADDR,
		    len - sizeof(struct lldp_tlv_head));
		mgmt.mgmt_len = sizeof(struct in_addr) + sizeof(u_int8_t);
		mgmt.mgmt_subtype = LLDP_MGMT_ADDR_IP4;
		memcpy(&mgmt.mgmt_addr, &chassis->c_mgmt,
		    sizeof(struct in_addr));

		/* Interface port type, OID */
		if (chassis->c_mgmt_if == 0)
			mgmt.mgmt_iface_subtype =
			    LLDP_MGMT_IFACE_UNKNOWN;
		else {
			mgmt.mgmt_iface_subtype =
			    LLDP_MGMT_IFACE_IFINDEX;
			mgmt.mgmt_iface_id =
			    htonl(chassis->c_mgmt_if);
		}
		IOV_NEW;
		iov[c].iov_base = &mgmt;
		iov[c].iov_len = len;
	}

	/* Port description */
	memset(&str, 0, sizeof(str));
	len = sizeof(str) + strlen(port->p_descr);
	str.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_PORT_DESCR,
	    len - sizeof(struct lldp_tlv_head));
	IOV_NEW;
	iov[c].iov_base = &str;
	iov[c].iov_len = sizeof(str);
	IOV_NEW;
	iov[c].iov_base = port->p_descr;
	iov[c].iov_len = strlen(port->p_descr);

#ifdef ENABLE_DOT1
	/* VLANs */
	v = 0;
	TAILQ_FOREACH(vlan, &port->p_vlans, v_entries)
	    v++;
	if ((v > 0) &&
	    ((ovlan = (struct lldp_vlan*)malloc(v*sizeof(struct lldp_vlan))) == NULL))
		LLOG_WARN("no room for vlans");
	else {
		TAILQ_FOREACH(vlan, &port->p_vlans, v_entries) {
			v--;
			memset(&ovlan[v], 0, sizeof(ovlan[v]));
			ovlan[v].tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_ORG,
			    sizeof(ovlan[v].tlv_org_id) +
			    sizeof(ovlan[v].tlv_org_subtype) + sizeof(ovlan[v].vid) +
			    sizeof(ovlan[v].len) + strlen(vlan->v_name));
			memcpy(ovlan[v].tlv_org_id, dot1, sizeof(ovlan[v].tlv_org_id));
			ovlan[v].tlv_org_subtype = LLDP_TLV_DOT1_VLANNAME;
			ovlan[v].vid = htons(vlan->v_vid);
			ovlan[v].len = strlen(vlan->v_name);
			IOV_NEW;
			iov[c].iov_base = &ovlan[v];
			iov[c].iov_len = sizeof(ovlan[v]);
			IOV_NEW;
			iov[c].iov_base = vlan->v_name;
			iov[c].iov_len = strlen(vlan->v_name);
		}
	}
#endif

#ifdef ENABLE_DOT3
	/* Aggregation status */
	memset(&aggreg, 0, sizeof(aggreg));
	aggreg.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_ORG,
	    sizeof(aggreg.tlv_org_id) +
	    sizeof(aggreg.tlv_org_subtype) +
	    sizeof(aggreg.status) + sizeof(aggreg.id));
	memcpy(aggreg.tlv_org_id, dot3, sizeof(aggreg.tlv_org_id));
	aggreg.tlv_org_subtype = LLDP_TLV_DOT3_LA;
	aggreg.status = (port->p_aggregid) ? 3:1; /* Bit 0 = capability ; Bit 1 = status */
	aggreg.id = htonl(port->p_aggregid);
	IOV_NEW;
	iov[c].iov_base = &aggreg;
	iov[c].iov_len = sizeof(aggreg);

	/* MAC/PHY */
	memset(&macphy, 0, sizeof(macphy));
	macphy.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_ORG,
	    sizeof(macphy.tlv_org_id) +
	    sizeof(macphy.tlv_org_subtype) +
	    sizeof(macphy.autoneg) + sizeof(macphy.advertised) +
	    sizeof(macphy.mau));
	memcpy(macphy.tlv_org_id, dot3, sizeof(macphy.tlv_org_id));
	macphy.tlv_org_subtype = LLDP_TLV_DOT3_MAC;
	macphy.autoneg = port->p_autoneg_support |
	    (port->p_autoneg_enabled << 1);
	macphy.advertised = htons(port->p_autoneg_advertised);
	macphy.mau = htons(port->p_mau_type);
	IOV_NEW;
	iov[c].iov_base = &macphy;
	iov[c].iov_len = sizeof(macphy);
#endif

#ifdef ENABLE_LLDPMED
	if (global->g_lchassis.c_med_cap_enabled) {
		/* LLDP-MED cap */
		memset(&medcap, 0, sizeof(medcap));
		medcap.tlv_head.type_len = LLDP_TLV_HEAD(LLDP_TLV_ORG,
		    sizeof(medcap.tlv_org_id) +
		    sizeof(medcap.tlv_org_subtype) + 
		    sizeof(medcap.tlv_cap) + sizeof(medcap.tlv_type));
		memcpy(medcap.tlv_org_id, med, sizeof(medcap.tlv_org_id));
		medcap.tlv_org_subtype = LLDP_TLV_MED_CAP;
		medcap.tlv_cap = htons(global->g_lchassis.c_med_cap_available);
		medcap.tlv_type = global->g_lchassis.c_med_type;
		IOV_NEW;
		iov[c].iov_base = &medcap;
		iov[c].iov_len = sizeof(medcap);

		/* LLDP-MED inventory */
#define LLDP_INVENTORY(value, target, subtype)				\
		if (value) {						\
		    memset(&target, 0, sizeof(target));			\
		    len = (strlen(value)>32)?32:strlen(value);		\
		    target.tlv_head.type_len =				\
			LLDP_TLV_HEAD(LLDP_TLV_ORG,			\
			    sizeof(target.tlv_org_id) +			\
			    sizeof(target.tlv_org_subtype) +		\
			    len);					\
		    memcpy(target.tlv_org_id, med,			\
			sizeof(target.tlv_org_id));			\
		    target.tlv_org_subtype = subtype;			\
		    IOV_NEW;						\
		    iov[c].iov_base = &target;				\
		    iov[c].iov_len = sizeof(target);			\
		    IOV_NEW;						\
		    iov[c].iov_base = value;				\
		    iov[c].iov_len = len;				\
		}

		if (global->g_lchassis.c_med_cap_enabled & LLDPMED_CAP_IV) {
			LLDP_INVENTORY(global->g_lchassis.c_med_hw,
			    medhw, LLDP_TLV_MED_IV_HW);
			LLDP_INVENTORY(global->g_lchassis.c_med_fw,
			    medfw, LLDP_TLV_MED_IV_FW);
			LLDP_INVENTORY(global->g_lchassis.c_med_sw,
			    medsw, LLDP_TLV_MED_IV_SW);
			LLDP_INVENTORY(global->g_lchassis.c_med_sn,
			    medsn, LLDP_TLV_MED_IV_SN);
			LLDP_INVENTORY(global->g_lchassis.c_med_manuf,
			    medmanuf, LLDP_TLV_MED_IV_MANUF);
			LLDP_INVENTORY(global->g_lchassis.c_med_model,
			    medmodel, LLDP_TLV_MED_IV_MODEL);
			LLDP_INVENTORY(global->g_lchassis.c_med_asset,
			    medasset, LLDP_TLV_MED_IV_ASSET);
		}

		/* LLDP-MED location */
		for (i = 0; i < LLDPMED_LOCFORMAT_LAST; i++) {
			if (global->g_lchassis.c_med_location[i].format == i + 1) {
				memset(&medloc[i], 0, sizeof(struct lldp_org));
				medloc[i].tlv_head.type_len =
				    LLDP_TLV_HEAD(LLDP_TLV_ORG,
					sizeof(medloc[i].tlv_org_id) +
					sizeof(medloc[i].tlv_org_subtype) + 1 +
					global->g_lchassis.c_med_location[i].data_len);
				memcpy(medloc[i].tlv_org_id, med,
				    sizeof(medloc[i].tlv_org_id));
				medloc[i].tlv_org_subtype = LLDP_TLV_MED_LOCATION;
				IOV_NEW;
				iov[c].iov_base = &medloc[i];
				iov[c].iov_len = sizeof(medloc[i]);
				IOV_NEW;
				iov[c].iov_base =
				    &global->g_lchassis.c_med_location[i].format;
				iov[c].iov_len = 1;
				IOV_NEW;
				iov[c].iov_base =
				    global->g_lchassis.c_med_location[i].data;
				iov[c].iov_len =
				    global->g_lchassis.c_med_location[i].data_len;
			}
		}
	}
#endif

	/* END */
	memset(&end, 0, sizeof(end));
	IOV_NEW;
	iov[c].iov_base = &end;
	iov[c].iov_len = sizeof(end);

	c++;
	if (!global->g_multi ||
	    (hardware->h_mode == LLDPD_MODE_ANY) ||
	    (hardware->h_mode == LLDPD_MODE_LLDP)) {
		
		if (writev((hardware->h_raw_real > 0) ? hardware->h_raw_real :
			hardware->h_raw, iov, c) == -1) {
			LLOG_WARN("unable to send packet on real device for %s",
			    hardware->h_ifname);
			free(iov);
#ifdef ENABLE_DOT1
			free(ovlan);
#endif
			return ENETDOWN;
		}

		hardware->h_tx_cnt++;
	}

	iov_dump(&buffer, iov, c);
	free(iov);
#ifdef ENABLE_DOT1
	free(ovlan);
#endif
	if (buffer != NULL) {

		/* We assume that LLDP frame is the reference */
		if ((hardware->h_llastframe == NULL) ||
		    (hardware->h_llastframe->size != buffer->size) ||
		    (memcmp(hardware->h_llastframe->frame, buffer->frame,
			buffer->size) != 0)) {
			free(hardware->h_llastframe);
			hardware->h_llastframe = buffer;
			hardware->h_llastchange = time(NULL);
		} else
			free(buffer);
	}

	return 0;
}

int
lldp_decode(struct lldpd *cfg, char *frame, int s,
    struct lldpd_hardware *hardware,
    struct lldpd_chassis **newchassis, struct lldpd_port **newport)
{
	struct lldpd_chassis *chassis;
	struct lldpd_port *port;
	struct ether_header *ether;
	const char lldpaddr[] = LLDP_MULTICAST_ADDR;
	const char dot1[] = LLDP_TLV_ORG_DOT1;
	const char dot3[] = LLDP_TLV_ORG_DOT3;
	const char med[] = LLDP_TLV_ORG_MED;
	int f;			 /* Current position in frame */
	int size, type, subtype; /* TLV header */
	char *b;
	int gotend = 0;

	if ((chassis = calloc(1, sizeof(struct lldpd_chassis))) == NULL) {
		LLOG_WARN("failed to allocate remote chassis");
		return -1;
	}
	if ((port = calloc(1, sizeof(struct lldpd_port))) == NULL) {
		LLOG_WARN("failed to allocate remote port");
		free(chassis);
		return -1;
	}
#ifdef ENABLE_DOT1
	TAILQ_INIT(&port->p_vlans);
#endif

	if (s < sizeof(struct ether_header)) {
		LLOG_WARNX("too short frame received on %s", hardware->h_ifname);
		goto malformed;
	}
	ether = (struct ether_header *)frame;
	if (memcmp(ether->ether_dhost, lldpaddr, sizeof(lldpaddr)) != 0) {
		LLOG_INFO("frame not targeted at LLDP multicast address received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	if (ETHERTYPE_LLDP != ntohs(ether->ether_type)) {
		LLOG_INFO("non LLDP frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}

	f = sizeof(struct ether_header);
	while ((f < s) && (!gotend)) {
		if (f + 2 > s) {
			LLOG_WARNX("tlv header too short received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		size = ntohs(*(u_int16_t*)(frame + f)) & 0x1ff;
		type = ntohs(*(u_int16_t*)(frame + f)) >> 9;
		f += 2;
		if (f + size > s) {
			LLOG_WARNX("tlv header too short received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		switch (type) {
		case LLDP_TLV_END:
			if (size != 0) {
				LLOG_WARNX("lldp end received with size not null on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if (f != s)
				LLOG_DEBUG("extra data after lldp end on %s",
				    hardware->h_ifname);
			gotend = 1;
			break;
		case LLDP_TLV_CHASSIS_ID:
		case LLDP_TLV_PORT_ID:
			if (size < 2) {
				LLOG_WARNX("tlv id too small received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			subtype = *(u_int8_t*)(frame + f);
			f++;
			if ((subtype == 0) || (subtype > 7)) {
				LLOG_WARNX("unknown subtype for tlv id received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if ((b = (char *)calloc(1, size - 1)) == NULL) {
				LLOG_WARN("unable to allocate memory for id tlv "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			memcpy(b, frame + f, size - 1);
			if (type == LLDP_TLV_PORT_ID) {
				port->p_id_subtype = subtype;
				port->p_id = b;
				port->p_id_len = size - 1;
			} else {
				chassis->c_id_subtype = subtype;
				chassis->c_id = b;
				chassis->c_id_len = size - 1;
			}
			f += size - 1;
			break;
		case LLDP_TLV_TTL:
			if (size < 2) {
				LLOG_WARNX("too short frame for ttl tlv received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			chassis->c_ttl = ntohs(*(u_int16_t*)(frame + f));
			f += size;
			break;
		case LLDP_TLV_PORT_DESCR:
		case LLDP_TLV_SYSTEM_NAME:
		case LLDP_TLV_SYSTEM_DESCR:
			if (size < 1) {
				LLOG_DEBUG("empty tlv received on %s",
				    hardware->h_ifname);
				break;
			}
			if ((b = (char *)calloc(1, size + 1)) == NULL) {
				LLOG_WARN("unable to allocate memory for string tlv "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			memcpy(b, frame + f, size);
			f += size;
			if (type == LLDP_TLV_PORT_DESCR)
				port->p_descr = b;
			else if (type == LLDP_TLV_SYSTEM_NAME)
				chassis->c_name = b;
			else chassis->c_descr = b;
			break;
		case LLDP_TLV_SYSTEM_CAP:
			if (size < 4) {
				LLOG_WARNX("too short system cap tlv "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			chassis->c_cap_available = ntohs(*(u_int16_t*)(frame + f));
			f += 2;
			chassis->c_cap_enabled = ntohs(*(u_int16_t*)(frame + f));
			f += size - 2;
			break;
		case LLDP_TLV_MGMT_ADDR:
			if (size < 11) {
				LLOG_WARNX("too short management tlv received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if ((chassis->c_mgmt.s_addr == INADDR_ANY) &&
			    (*(u_int8_t*)(frame + f) == 5) &&
			    (*(u_int8_t*)(frame + f + 1) == 1)) {
				/* We have an IPv4 address, we ignore anything else */
				memcpy(&chassis->c_mgmt, frame + f + 2, sizeof(struct in_addr));
				chassis->c_mgmt_if = 0;
				/* We only handle ifIndex subtype */
				if (*(u_int8_t*)(frame + f + 6) == LLDP_MGMT_IFACE_IFINDEX)
					chassis->c_mgmt_if = ntohl(*(u_int32_t*)(frame + f + 7));
			}
			f += size;
			break;
		case LLDP_TLV_ORG:
			if (size < 4) {
				LLOG_WARNX("too short org tlv received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if (memcmp(dot1, frame + f, 3) == 0) {
#ifndef ENABLE_DOT1
				f += size;
				hardware->h_rx_unrecognized_cnt++;
#else
				/* Dot1 */
				if ((*(u_int8_t*)(frame + f + 3)) ==
				    LLDP_TLV_DOT1_VLANNAME) {
					struct lldpd_vlan *vlan;
					int vlan_len;

					if ((size < 7) ||
					    (size < 7 + *(u_int8_t*)(frame + f + 6))) {
						LLOG_WARNX("too short vlan tlv "
						    "received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					f += 4;
					if ((vlan = (struct lldpd_vlan *)calloc(1,
						    sizeof(struct lldpd_vlan))) == NULL) {
						LLOG_WARN("unable to alloc vlan "
						    "structure for "
						    "tlv received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					vlan->v_vid = ntohs(*(u_int16_t*)(frame + f));
					f += 2;
					vlan_len = *(u_int8_t*)(frame + f);
					f += 1;
					if ((vlan->v_name =
						(char *)calloc(1, vlan_len + 1)) == NULL) {
						LLOG_WARN("unable to alloc vlan name for "
						    "tlv received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					memcpy(vlan->v_name, frame + f,
					    vlan_len);
					TAILQ_INSERT_TAIL(&port->p_vlans,
					    vlan, v_entries);
					f += size - 7;
				} else {
					/* Unknown Dot1 TLV, ignore it */
					f += size;
					hardware->h_rx_unrecognized_cnt++;
				}
#endif
			} else if (memcmp(dot3, frame + f, 3) == 0) {
#ifndef ENABLE_DOT3
				f += size;
				hardware->h_rx_unrecognized_cnt++;
#else
				/* Dot3 */
				subtype = *(u_int8_t*)(frame + f + 3);
				switch (subtype) {
				case LLDP_TLV_DOT3_MAC:
					f += 4;
					if (size < 9) {
						LLOG_WARNX("too short mac/phy tlv "
						    "received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					port->p_autoneg_support =
					    *(u_int8_t*)(frame + f) && 0x1;
					port->p_autoneg_enabled =
					    *(u_int8_t*)(frame + f) && 0x2;
					f += 1;
					port->p_autoneg_advertised =
					    ntohs(*(u_int16_t*)(frame + f));
					f += 2;
					port->p_mau_type =
					    ntohs(*(u_int16_t*)(frame + f));
					f += size - 7;
					break;
				case LLDP_TLV_DOT3_LA:
					if (size < 9) {
						LLOG_WARNX("too short aggreg tlv "
						    "received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					port->p_aggregid =
					    ntohl(*(u_int32_t*)(frame + f + 5));
					f += size;
					break;
				default:
					/* Unknown Dot3 TLV, ignore it */
					f += size;
					hardware->h_rx_unrecognized_cnt++;
				}
#endif
			} else if (memcmp(med, frame + f, 3) == 0) {
				/* LLDP-MED */
#ifndef ENABLE_LLDPMED
				f += size;
				hardware->h_rx_unrecognized_cnt++;
#else
				u_int32_t policy;
				int loctype;

				subtype = *(u_int8_t*)(frame + f + 3);
				switch (subtype) {
				case LLDP_TLV_MED_CAP:
					f += 4;
					if (size < 7) {
						LLOG_WARNX("too short LLDP-MED cap "
						    "tlv received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					chassis->c_med_cap_available =
					    ntohs(*(u_int16_t*)(frame + f));
					f += 2;
					chassis->c_med_type =
					    *(u_int8_t*)(frame + f);
					f += size - 6;
					chassis->c_med_cap_enabled |=
					    LLDPMED_CAP_CAP;
					break;
				case LLDP_TLV_MED_POLICY:
					f += 4;
					if (size < 8) {
						LLOG_WARNX("too short LLDP-MED policy "
						    "tlv received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					policy = ntohl(*((u_int32_t *)(frame + f)));
					if (((policy >> 24) < 1) ||
					    ((policy >> 24) > LLDPMED_APPTYPE_LAST)) {
						LLOG_INFO("unknown policy field %d "
						    "received on %s",
						    hardware->h_ifname);
						f += 4;
						break;
					}
					chassis->c_med_policy[(policy >> 24) - 1].type =
					    (policy >> 24);
					chassis->c_med_policy[(policy >> 24) - 1].unknown =
					    ((policy & 0x800000) != 0);
					chassis->c_med_policy[(policy >> 24) - 1].tagged =
					    ((policy & 0x400000) != 0);
					chassis->c_med_policy[(policy >> 24) - 1].vid =
					    (policy & 0x001FFE00) >> 9;
					chassis->c_med_policy[(policy >> 24) - 1].priority =
					    (policy & 0x1C0) >> 6;
					chassis->c_med_policy[(policy >> 24) - 1].dscp =
					    policy & 0x3F;
					f += size - 4;
					chassis->c_med_cap_enabled |=
					    LLDPMED_CAP_POLICY;
					break;
				case LLDP_TLV_MED_LOCATION:
					f += 4;
					if (size <= 5) {
						LLOG_WARNX("too short LLDP-MED location "
						    "tlv received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					loctype = *(u_int8_t*)(frame + f);
					f += 1;
					if ((loctype < 1) || (loctype > LLDPMED_LOCFORMAT_LAST)) {
						LLOG_INFO("unknown location type "
						    "received on %s",
						    hardware->h_ifname);
						f += size - 5;
						break;
					}
					if ((chassis->c_med_location[loctype - 1].data =
						(char*)malloc(size - 5)) == NULL) {
						LLOG_WARN("unable to allocate memory "
						    "for LLDP-MED location for "
						    "frame received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					memcpy(chassis->c_med_location[loctype - 1].data,
					    (char*)(frame + f),
					    size - 5);
					chassis->c_med_location[loctype - 1].data_len =
					    size - 5;
					chassis->c_med_location[loctype - 1].format = loctype;
					f += size - 5;
					chassis->c_med_cap_enabled |=
					    LLDPMED_CAP_LOCATION;
					break;
				case LLDP_TLV_MED_MDI:
					f += 4;
					if (size < 7) {
						LLOG_WARNX("too short LLDP-MED PoE-MDI "
						    "tlv received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					switch (*(u_int8_t*)(frame + f) & 0xC0) {
					case 0x0:
						chassis->c_med_pow_devicetype = LLDPMED_POW_TYPE_PSE;
						chassis->c_med_cap_enabled |=
						    LLDPMED_CAP_MDI_PSE;
						switch (*(u_int8_t*)(frame + f) & 0x30) {
						case 0x0:
							chassis->c_med_pow_source =
							    LLDPMED_POW_SOURCE_UNKNOWN;
							break;
						case 0x10:
							chassis->c_med_pow_source =
							    LLDPMED_POW_SOURCE_PRIMARY;
							break;
						case 0x20:
							chassis->c_med_pow_source =
							    LLDPMED_POW_SOURCE_BACKUP;
							break;
						default:
							chassis->c_med_pow_source =
							    LLDPMED_POW_SOURCE_RESERVED;
						}
						break;
					case 0x40:
						chassis->c_med_pow_devicetype = LLDPMED_POW_TYPE_PD;
						chassis->c_med_cap_enabled |=
						    LLDPMED_CAP_MDI_PD;
						switch (*(u_int8_t*)(frame + f) & 0x30) {
						case 0x0:
							chassis->c_med_pow_source =
							    LLDPMED_POW_SOURCE_UNKNOWN;
							break;
						case 0x10:
							chassis->c_med_pow_source =
							    LLDPMED_POW_SOURCE_PSE;
							break;
						case 0x20:
							chassis->c_med_pow_source =
							    LLDPMED_POW_SOURCE_LOCAL;
							break;
						default:
							chassis->c_med_pow_source =
							    LLDPMED_POW_SOURCE_BOTH;
						}
						break;
					default:
						chassis->c_med_pow_devicetype =
						    LLDPMED_POW_TYPE_RESERVED;
					}
					switch (*(u_int8_t*)(frame + f) & 0x0F) {
					case 0x0:
						chassis->c_med_pow_priority =
						    LLDPMED_POW_PRIO_UNKNOWN;
						break;
					case 0x1:
						chassis->c_med_pow_priority =
						    LLDPMED_POW_PRIO_CRITICAL;
						break;
					case 0x2:
						chassis->c_med_pow_priority =
						    LLDPMED_POW_PRIO_HIGH;
						break;
					case 0x3:
						chassis->c_med_pow_priority =
						    LLDPMED_POW_PRIO_LOW;
						break;
					default:
						chassis->c_med_pow_priority =
						    LLDPMED_POW_PRIO_UNKNOWN;
					}
					f += 1;
					chassis->c_med_pow_val =
					    ntohs(*(u_int16_t*)(frame + f));
					f += size - 5;
					break;
				case LLDP_TLV_MED_IV_HW:
				case LLDP_TLV_MED_IV_SW:
				case LLDP_TLV_MED_IV_FW:
				case LLDP_TLV_MED_IV_SN:
				case LLDP_TLV_MED_IV_MANUF:
				case LLDP_TLV_MED_IV_MODEL:
				case LLDP_TLV_MED_IV_ASSET:
					f += 4;
					if (size <= 4)
						b = NULL;
					else {
						if ((b = (char*)malloc(size - 3)) ==
						    NULL) {
							LLOG_WARN("unable to allocate "
							    "memory for LLDP-MED "
							    "inventory for frame "
							    "received on %s",
							    hardware->h_ifname);
							goto malformed;
						}
						strlcpy(b,
						    (char*)(frame + f),
						    size - 3);
					}
					switch (subtype) {
					case LLDP_TLV_MED_IV_HW:
						chassis->c_med_hw = b;
						break;
					case LLDP_TLV_MED_IV_FW:
						chassis->c_med_fw = b;
						break;
					case LLDP_TLV_MED_IV_SW:
						chassis->c_med_sw = b;
						break;
					case LLDP_TLV_MED_IV_SN:
						chassis->c_med_sn = b;
						break;
					case LLDP_TLV_MED_IV_MANUF:
						chassis->c_med_manuf = b;
						break;
					case LLDP_TLV_MED_IV_MODEL:
						chassis->c_med_fw = b;
						break;
					case LLDP_TLV_MED_IV_ASSET:
						chassis->c_med_asset = b;
						break;
					default:
						LLOG_WARNX("should not be there!");
						free(b);
						break;
					}
					f += size - 4;
					chassis->c_med_cap_enabled |=
					    LLDPMED_CAP_IV;
					break;
				default:
					/* Unknown LLDP MED, ignore it */
					f += size;
					hardware->h_rx_unrecognized_cnt++;
				}
#endif /* ENABLE_LLDPMED */
			} else {
				LLOG_INFO("unknown org tlv received on %s",
				    hardware->h_ifname);
				hardware->h_rx_unrecognized_cnt++;
				f += size;
			}
			break;
		default:
			LLOG_WARNX("unknown tlv (%d) received on %s",
			    type, hardware->h_ifname);
			goto malformed;
		}
	}

	/* Some random check */
	if ((chassis->c_id == NULL) ||
	    (port->p_id == NULL) ||
	    (chassis->c_ttl == 0) ||
	    (gotend == 0)) {
		LLOG_WARNX("some mandatory tlv are missing for frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
#define NOTRECEIVED "Not received"
	if (chassis->c_name == NULL) {
		if ((chassis->c_name = (char *)calloc(1, strlen(NOTRECEIVED) + 1)) == NULL) {
			LLOG_WARNX("unable to allocate null chassis name");
			goto malformed;
		}
		memcpy(chassis->c_name, NOTRECEIVED, strlen(NOTRECEIVED));
	}
	if (chassis->c_descr == NULL) {
		if ((chassis->c_descr = (char *)calloc(1, strlen(NOTRECEIVED) + 1)) == NULL) {
			LLOG_WARNX("unable to allocate null chassis description");
			goto malformed;
		}
		memcpy(chassis->c_descr, NOTRECEIVED, strlen(NOTRECEIVED));
	}
	if (port->p_descr == NULL) {
		if ((port->p_descr = (char *)calloc(1, strlen(NOTRECEIVED) + 1)) == NULL) {
			LLOG_WARNX("unable to allocate null port description");
			goto malformed;
		}
		memcpy(port->p_descr, NOTRECEIVED, strlen(NOTRECEIVED));
	}
	*newchassis = chassis;
	*newport = port;
	return 1;
malformed:
	lldpd_chassis_cleanup(chassis);
	lldpd_port_cleanup(port);
	return -1;
}
