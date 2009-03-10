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
#include "frame.h"

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
	struct lldpd_port *port;
	struct lldpd_frame *frame;
	int length;
	u_int8_t *packet, *pos, *tlv;

	u_int8_t mcastaddr[] = LLDP_MULTICAST_ADDR;
#ifdef ENABLE_DOT1
	const u_int8_t dot1[] = LLDP_TLV_ORG_DOT1;
	struct lldpd_vlan *vlan;
#endif
#ifdef ENABLE_DOT3
	const u_int8_t dot3[] = LLDP_TLV_ORG_DOT3;
#endif
#ifdef ENABLE_LLDPMED
	int i;
	const u_int8_t med[] = LLDP_TLV_ORG_MED;
#endif

	port = &hardware->h_lport;
	length = hardware->h_mtu;
	if ((packet = (u_int8_t*)malloc(length)) == NULL)
		return ENOMEM;
	memset(packet, 0, length);
	pos = packet;

	/* Ethernet header */
	if (!(
	      /* LLDP multicast address */
	      POKE_BYTES(mcastaddr, sizeof(mcastaddr)) &&
	      /* Source MAC address */
	      POKE_BYTES(&hardware->h_lladdr, sizeof(hardware->h_lladdr)) &&
	      /* LLDP frame */
	      POKE_UINT16(ETHERTYPE_LLDP)))
		goto toobig;

	/* Chassis ID */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_CHASSIS_ID) &&
	      POKE_UINT8(chassis->c_id_subtype) &&
	      POKE_BYTES(chassis->c_id, chassis->c_id_len) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* Port ID */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_PORT_ID) &&
	      POKE_UINT8(port->p_id_subtype) &&
	      POKE_BYTES(port->p_id, port->p_id_len) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* Time to live */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_TTL) &&
	      POKE_UINT16(chassis->c_ttl) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* System name */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_NAME) &&
	      POKE_BYTES(chassis->c_name, strlen(chassis->c_name)) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* System description */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_DESCR) &&
	      POKE_BYTES(chassis->c_descr, strlen(chassis->c_descr)) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* System capabilities */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_CAP) &&
	      POKE_UINT16(chassis->c_cap_available) &&
	      POKE_UINT16(chassis->c_cap_enabled) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	if (chassis->c_mgmt.s_addr != INADDR_ANY) {
		/* Management address */
		if (!(
		      POKE_START_LLDP_TLV(LLDP_TLV_MGMT_ADDR) &&
		      /* Size of the address, including its type */
		      POKE_UINT8(sizeof(struct in_addr) + 1) &&
		      /* Address is IPv4 */
		      POKE_UINT8(LLDP_MGMT_ADDR_IP4) &&
		      POKE_BYTES(&chassis->c_mgmt, sizeof(struct in_addr))))
			goto toobig;

		/* Interface port type, OID */
		if (chassis->c_mgmt_if == 0) {
			if (!(
			      /* We don't know the management interface */
			      POKE_UINT8(LLDP_MGMT_IFACE_UNKNOWN) &&
			      POKE_UINT32(0)))
				goto toobig;
		} else {
			if (!(
			      /* We have the index of the management interface */
			      POKE_UINT8(LLDP_MGMT_IFACE_IFINDEX) &&
			      POKE_UINT32(chassis->c_mgmt_if)))
				goto toobig;
		}
		if (!(
		      /* We don't provide an OID for management */
		      POKE_UINT8(0) &&
		      POKE_END_LLDP_TLV))
			goto toobig;
	}

	/* Port description */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_PORT_DESCR) &&
	      POKE_BYTES(port->p_descr, strlen(port->p_descr)) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

#ifdef ENABLE_DOT1
	/* VLANs */
	TAILQ_FOREACH(vlan, &port->p_vlans, v_entries) {
		if (!(
		      POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&
		      POKE_BYTES(dot1, sizeof(dot1)) &&
		      POKE_UINT8(LLDP_TLV_DOT1_VLANNAME) &&
		      POKE_UINT16(vlan->v_vid) &&
		      POKE_UINT8(strlen(vlan->v_name)) &&
		      POKE_BYTES(vlan->v_name, strlen(vlan->v_name)) &&
		      POKE_END_LLDP_TLV))
			goto toobig;
	}
#endif

#ifdef ENABLE_DOT3
	/* Aggregation status */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&
	      POKE_BYTES(dot3, sizeof(dot3)) &&
	      POKE_UINT8(LLDP_TLV_DOT3_LA) &&
	      /* Bit 0 = capability ; Bit 1 = status */
	      POKE_UINT8((port->p_aggregid) ? 3:1) &&
	      POKE_UINT32(port->p_aggregid) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* MAC/PHY */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&
	      POKE_BYTES(dot3, sizeof(dot3)) &&
	      POKE_UINT8(LLDP_TLV_DOT3_MAC) &&
	      POKE_UINT8(port->p_autoneg_support |
			 (port->p_autoneg_enabled << 1)) &&
	      POKE_UINT16(port->p_autoneg_advertised) &&
	      POKE_UINT16(port->p_mau_type) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* MFS */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&
	      POKE_BYTES(dot3, sizeof(dot3)) &&
	      POKE_UINT8(LLDP_TLV_DOT3_MFS) &&
	      POKE_UINT16(port->p_mfs) &&
	      POKE_END_LLDP_TLV))
		goto toobig;
#endif

#ifdef ENABLE_LLDPMED
	if (port->p_med_cap_enabled) {
		/* LLDP-MED cap */
		if (!(
		      POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&
		      POKE_BYTES(med, sizeof(med)) &&
		      POKE_UINT8(LLDP_TLV_MED_CAP) &&
		      POKE_UINT16(chassis->c_med_cap_available) &&
		      POKE_UINT8(chassis->c_med_type) &&
		      POKE_END_LLDP_TLV))
			goto toobig;

		/* LLDP-MED inventory */
#define LLDP_INVENTORY(value, subtype)					\
		if (value) {						\
		    if (!(						\
			  POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&		\
			  POKE_BYTES(med, sizeof(med)) &&		\
			  POKE_UINT8(subtype) &&			\
			  POKE_BYTES(value,				\
				(strlen(value)>32)?32:strlen(value)) &&	\
			  POKE_END_LLDP_TLV))				\
			    goto toobig;				\
		}

		if (port->p_med_cap_enabled & LLDPMED_CAP_IV) {
			LLDP_INVENTORY(chassis->c_med_hw,
			    LLDP_TLV_MED_IV_HW);
			LLDP_INVENTORY(chassis->c_med_fw,
			    LLDP_TLV_MED_IV_FW);
			LLDP_INVENTORY(chassis->c_med_sw,
			    LLDP_TLV_MED_IV_SW);
			LLDP_INVENTORY(chassis->c_med_sn,
			    LLDP_TLV_MED_IV_SN);
			LLDP_INVENTORY(chassis->c_med_manuf,
			    LLDP_TLV_MED_IV_MANUF);
			LLDP_INVENTORY(chassis->c_med_model,
			    LLDP_TLV_MED_IV_MODEL);
			LLDP_INVENTORY(chassis->c_med_asset,
			    LLDP_TLV_MED_IV_ASSET);
		}

		/* LLDP-MED location */
		for (i = 0; i < LLDPMED_LOCFORMAT_LAST; i++) {
			if (port->p_med_location[i].format == i + 1) {
				if (!(
				      POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&
				      POKE_BYTES(med, sizeof(med)) &&
				      POKE_UINT8(LLDP_TLV_MED_LOCATION) &&
				      POKE_UINT8(port->p_med_location[i].format) &&
				      POKE_BYTES(port->p_med_location[i].data,
					  port->p_med_location[i].data_len) &&
				      POKE_END_LLDP_TLV))
					goto toobig;
			}
		}
	}
#endif

	/* END */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_END) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	if (!global->g_multi ||
	    (hardware->h_mode == LLDPD_MODE_ANY) ||
	    (hardware->h_mode == LLDPD_MODE_LLDP)) {
		
		if (write((hardware->h_raw_real > 0) ? hardware->h_raw_real :
			hardware->h_raw, packet, 
			pos - packet) == -1) {
			LLOG_WARN("unable to send packet on real device for %s",
			    hardware->h_ifname);
			free(packet);
			return ENETDOWN;
		}

		hardware->h_tx_cnt++;
	}

	/* We assume that LLDP frame is the reference */
	if ((frame = (struct lldpd_frame*)malloc(
			sizeof(int) + pos - packet)) != NULL) {
		frame->size = pos - packet;
		memcpy(&frame->frame, packet, frame->size);
		if ((hardware->h_llastframe == NULL) ||
		    (hardware->h_llastframe->size != frame->size) ||
		    (memcmp(hardware->h_llastframe->frame, frame->frame,
			frame->size) != 0)) {
			free(hardware->h_llastframe);
		hardware->h_llastframe = frame;
		hardware->h_llastchange = time(NULL);
		} else
			free(frame);
	}

	free(packet);
	return 0;

toobig:
	free(packet);
	return E2BIG;
}

#define CHECK_TLV_SIZE(x, name)				   \
	do { if (tlv_size < (x)) {			   \
	   LLOG_WARNX(name " TLV too short received on %s",\
	       hardware->h_ifname);			   \
	   goto malformed;				   \
	} } while (0)

int
lldp_decode(struct lldpd *cfg, char *frame, int s,
    struct lldpd_hardware *hardware,
    struct lldpd_chassis **newchassis, struct lldpd_port **newport)
{
	struct lldpd_chassis *chassis;
	struct lldpd_port *port;
	const char lldpaddr[] = LLDP_MULTICAST_ADDR;
	const char dot1[] = LLDP_TLV_ORG_DOT1;
	const char dot3[] = LLDP_TLV_ORG_DOT3;
	const char med[] = LLDP_TLV_ORG_MED;
	char orgid[3];
	int length, gotend = 0;
	int tlv_size, tlv_type, tlv_subtype;
	u_int8_t *pos, *tlv;
	char *b;
#ifdef ENABLE_DOT1
	struct lldpd_vlan *vlan;
	int vlan_len;
#endif

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

	length = s;
	pos = (u_int8_t*)frame;

	if (length < 2*ETH_ALEN + sizeof(u_int16_t)) {
		LLOG_WARNX("too short frame received on %s", hardware->h_ifname);
		goto malformed;
	}
	if (PEEK_CMP(lldpaddr, ETH_ALEN) != 0) {
		LLOG_INFO("frame not targeted at LLDP multicast address received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	PEEK_DISCARD(ETH_ALEN);	/* Skip source address */
	if (PEEK_UINT16 != ETHERTYPE_LLDP) {
		LLOG_INFO("non LLDP frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}

	while (length && (!gotend)) {
		if (length < 2) {
			LLOG_WARNX("tlv header too short received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		tlv_size = PEEK_UINT16;
		tlv_type = tlv_size >> 9;
		tlv_size = tlv_size & 0x1ff;
		PEEK_SAVE(tlv);
		if (length < tlv_size) {
			LLOG_WARNX("frame too short for tlv received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		switch (tlv_type) {
		case LLDP_TLV_END:
			if (tlv_size != 0) {
				LLOG_WARNX("lldp end received with size not null on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if (length)
				LLOG_DEBUG("extra data after lldp end on %s",
				    hardware->h_ifname);
			gotend = 1;
			break;
		case LLDP_TLV_CHASSIS_ID:
		case LLDP_TLV_PORT_ID:
			CHECK_TLV_SIZE(2, "Port Id");
			tlv_subtype = PEEK_UINT8;
			if ((tlv_subtype == 0) || (tlv_subtype > 7)) {
				LLOG_WARNX("unknown subtype for tlv id received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if ((b = (char *)calloc(1, tlv_size - 1)) == NULL) {
				LLOG_WARN("unable to allocate memory for id tlv "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			PEEK_BYTES(b, tlv_size - 1);
			if (tlv_type == LLDP_TLV_PORT_ID) {
				port->p_id_subtype = tlv_subtype;
				port->p_id = b;
				port->p_id_len = tlv_size - 1;
			} else {
				chassis->c_id_subtype = tlv_subtype;
				chassis->c_id = b;
				chassis->c_id_len = tlv_size - 1;
			}
			break;
		case LLDP_TLV_TTL:
			CHECK_TLV_SIZE(2, "TTL");
			chassis->c_ttl = PEEK_UINT16;
			break;
		case LLDP_TLV_PORT_DESCR:
		case LLDP_TLV_SYSTEM_NAME:
		case LLDP_TLV_SYSTEM_DESCR:
			if (tlv_size < 1) {
				LLOG_DEBUG("empty tlv received on %s",
				    hardware->h_ifname);
				break;
			}
			if ((b = (char *)calloc(1, tlv_size + 1)) == NULL) {
				LLOG_WARN("unable to allocate memory for string tlv "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			PEEK_BYTES(b, tlv_size);
			if (tlv_type == LLDP_TLV_PORT_DESCR)
				port->p_descr = b;
			else if (tlv_type == LLDP_TLV_SYSTEM_NAME)
				chassis->c_name = b;
			else chassis->c_descr = b;
			break;
		case LLDP_TLV_SYSTEM_CAP:
			CHECK_TLV_SIZE(4, "System capabilities");
			chassis->c_cap_available = PEEK_UINT16;
			chassis->c_cap_enabled = PEEK_UINT16;
			break;
		case LLDP_TLV_MGMT_ADDR:
			CHECK_TLV_SIZE(11, "Management address");
			if ((chassis->c_mgmt.s_addr == INADDR_ANY) &&
			    (PEEK_UINT8 == 1+sizeof(struct in_addr)) &&
			    (PEEK_UINT8 == LLDP_MGMT_ADDR_IP4)) {
				/* We have an IPv4 address, we ignore anything else */
				PEEK_BYTES(&chassis->c_mgmt, sizeof(struct in_addr));
				chassis->c_mgmt_if = 0;
				/* We only handle ifIndex subtype */
				if (PEEK_UINT8 == LLDP_MGMT_IFACE_IFINDEX)
					chassis->c_mgmt_if = PEEK_UINT32;
			}
			break;
		case LLDP_TLV_ORG:
			CHECK_TLV_SIZE(4, "Organisational");
			PEEK_BYTES(orgid, sizeof(orgid));
			tlv_subtype = PEEK_UINT8;
			if (memcmp(dot1, orgid, sizeof(orgid)) == 0) {
#ifndef ENABLE_DOT1
				hardware->h_rx_unrecognized_cnt++;
#else
				/* Dot1 */
				switch (tlv_subtype) {
				case LLDP_TLV_DOT1_VLANNAME:
					CHECK_TLV_SIZE(7, "VLAN");
					if ((vlan = (struct lldpd_vlan *)calloc(1,
						    sizeof(struct lldpd_vlan))) == NULL) {
						LLOG_WARN("unable to alloc vlan "
						    "structure for "
						    "tlv received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					vlan->v_vid = PEEK_UINT16;
					vlan_len = PEEK_UINT8;
					CHECK_TLV_SIZE(7 + vlan_len, "VLAN");
					if ((vlan->v_name =
						(char *)calloc(1, vlan_len + 1)) == NULL) {
						LLOG_WARN("unable to alloc vlan name for "
						    "tlv received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					PEEK_BYTES(vlan->v_name, vlan_len);
					TAILQ_INSERT_TAIL(&port->p_vlans,
					    vlan, v_entries);
					break;
				case LLDP_TLV_DOT1_PVID:
					CHECK_TLV_SIZE(6, "PVID");
					port->p_pvid = PEEK_UINT16;
					break;
				default:
					/* Unknown Dot1 TLV, ignore it */
					hardware->h_rx_unrecognized_cnt++;
				}
#endif
			} else if (memcmp(dot3, orgid, sizeof(orgid)) == 0) {
#ifndef ENABLE_DOT3
				hardware->h_rx_unrecognized_cnt++;
#else
				/* Dot3 */
				switch (tlv_subtype) {
				case LLDP_TLV_DOT3_MAC:
					CHECK_TLV_SIZE(9, "MAC/PHY");
					port->p_autoneg_support = PEEK_UINT8;
					port->p_autoneg_enabled =
					    port->p_autoneg_support && 0x2;
					port->p_autoneg_support =
					    port->p_autoneg_support && 0x1;
					port->p_autoneg_advertised =
					    PEEK_UINT16;
					port->p_mau_type = PEEK_UINT16;
					break;
				case LLDP_TLV_DOT3_LA:
					CHECK_TLV_SIZE(9, "Link aggregation");
					PEEK_DISCARD_UINT8;
					port->p_aggregid = PEEK_UINT32;
					break;
				case LLDP_TLV_DOT3_MFS:
					CHECK_TLV_SIZE(6, "MFS");
					port->p_mfs = PEEK_UINT16;
					break;
				default:
					/* Unknown Dot3 TLV, ignore it */
					hardware->h_rx_unrecognized_cnt++;
				}
#endif
			} else if (memcmp(med, orgid, sizeof(orgid)) == 0) {
				/* LLDP-MED */
#ifndef ENABLE_LLDPMED
				hardware->h_rx_unrecognized_cnt++;
#else
				u_int32_t policy;
				int loctype;
				int power;

				switch (tlv_subtype) {
				case LLDP_TLV_MED_CAP:
					CHECK_TLV_SIZE(7, "LLDP-MED capabilities");
					chassis->c_med_cap_available = PEEK_UINT16;
					chassis->c_med_type = PEEK_UINT8;
					port->p_med_cap_enabled |=
					    LLDPMED_CAP_CAP;
					break;
				case LLDP_TLV_MED_POLICY:
					CHECK_TLV_SIZE(8, "LLDP-MED policy");
					policy = PEEK_UINT32;
					if (((policy >> 24) < 1) ||
					    ((policy >> 24) > LLDPMED_APPTYPE_LAST)) {
						LLOG_INFO("unknown policy field %d "
						    "received on %s",
						    hardware->h_ifname);
						break;
					}
					port->p_med_policy[(policy >> 24) - 1].type =
					    (policy >> 24);
					port->p_med_policy[(policy >> 24) - 1].unknown =
					    ((policy & 0x800000) != 0);
					port->p_med_policy[(policy >> 24) - 1].tagged =
					    ((policy & 0x400000) != 0);
					port->p_med_policy[(policy >> 24) - 1].vid =
					    (policy & 0x001FFE00) >> 9;
					port->p_med_policy[(policy >> 24) - 1].priority =
					    (policy & 0x1C0) >> 6;
					port->p_med_policy[(policy >> 24) - 1].dscp =
					    policy & 0x3F;
					port->p_med_cap_enabled |=
					    LLDPMED_CAP_POLICY;
					break;
				case LLDP_TLV_MED_LOCATION:
					CHECK_TLV_SIZE(5, "LLDP-MED Location");
					loctype = PEEK_UINT8;
					if ((loctype < 1) ||
					    (loctype > LLDPMED_LOCFORMAT_LAST)) {
						LLOG_INFO("unknown location type "
						    "received on %s",
						    hardware->h_ifname);
						break;
					}
					if ((port->p_med_location[loctype - 1].data =
						(char*)malloc(tlv_size - 5)) == NULL) {
						LLOG_WARN("unable to allocate memory "
						    "for LLDP-MED location for "
						    "frame received on %s",
						    hardware->h_ifname);
						goto malformed;
					}
					PEEK_BYTES(port->p_med_location[loctype - 1].data,
					    tlv_size - 5);
					port->p_med_location[loctype - 1].data_len =
					    tlv_size - 5;
					port->p_med_location[loctype - 1].format = loctype;
					port->p_med_cap_enabled |=
					    LLDPMED_CAP_LOCATION;
					break;
				case LLDP_TLV_MED_MDI:
					CHECK_TLV_SIZE(7, "LLDP-MED PoE-MDI");
					power = PEEK_UINT8;
					switch (power & 0xC0) {
					case 0x0:
						port->p_med_pow_devicetype = LLDPMED_POW_TYPE_PSE;
						port->p_med_cap_enabled |=
						    LLDPMED_CAP_MDI_PSE;
						switch (power & 0x30) {
						case 0x0:
							port->p_med_pow_source =
							    LLDPMED_POW_SOURCE_UNKNOWN;
							break;
						case 0x10:
							port->p_med_pow_source =
							    LLDPMED_POW_SOURCE_PRIMARY;
							break;
						case 0x20:
							port->p_med_pow_source =
							    LLDPMED_POW_SOURCE_BACKUP;
							break;
						default:
							port->p_med_pow_source =
							    LLDPMED_POW_SOURCE_RESERVED;
						}
						break;
					case 0x40:
						port->p_med_pow_devicetype = LLDPMED_POW_TYPE_PD;
						port->p_med_cap_enabled |=
						    LLDPMED_CAP_MDI_PD;
						switch (power & 0x30) {
						case 0x0:
							port->p_med_pow_source =
							    LLDPMED_POW_SOURCE_UNKNOWN;
							break;
						case 0x10:
							port->p_med_pow_source =
							    LLDPMED_POW_SOURCE_PSE;
							break;
						case 0x20:
							port->p_med_pow_source =
							    LLDPMED_POW_SOURCE_LOCAL;
							break;
						default:
							port->p_med_pow_source =
							    LLDPMED_POW_SOURCE_BOTH;
						}
						break;
					default:
						port->p_med_pow_devicetype =
						    LLDPMED_POW_TYPE_RESERVED;
					}
					switch (power & 0x0F) {
					case 0x0:
						port->p_med_pow_priority =
						    LLDPMED_POW_PRIO_UNKNOWN;
						break;
					case 0x1:
						port->p_med_pow_priority =
						    LLDPMED_POW_PRIO_CRITICAL;
						break;
					case 0x2:
						port->p_med_pow_priority =
						    LLDPMED_POW_PRIO_HIGH;
						break;
					case 0x3:
						port->p_med_pow_priority =
						    LLDPMED_POW_PRIO_LOW;
						break;
					default:
						port->p_med_pow_priority =
						    LLDPMED_POW_PRIO_UNKNOWN;
					}
					port->p_med_pow_val = PEEK_UINT16;
					break;
				case LLDP_TLV_MED_IV_HW:
				case LLDP_TLV_MED_IV_SW:
				case LLDP_TLV_MED_IV_FW:
				case LLDP_TLV_MED_IV_SN:
				case LLDP_TLV_MED_IV_MANUF:
				case LLDP_TLV_MED_IV_MODEL:
				case LLDP_TLV_MED_IV_ASSET:
					if (tlv_size <= 4)
						b = NULL;
					else {
						if ((b = (char*)malloc(tlv_size - 3)) ==
						    NULL) {
							LLOG_WARN("unable to allocate "
							    "memory for LLDP-MED "
							    "inventory for frame "
							    "received on %s",
							    hardware->h_ifname);
							goto malformed;
						}
						PEEK_BYTES(b, tlv_size - 4);
						b[tlv_size - 4] = '\0';
					}
					switch (tlv_subtype) {
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
						chassis->c_med_model = b;
						break;
					case LLDP_TLV_MED_IV_ASSET:
						chassis->c_med_asset = b;
						break;
					default:
						LLOG_WARNX("should not be there!");
						free(b);
						break;
					}
					port->p_med_cap_enabled |=
					    LLDPMED_CAP_IV;
					break;
				default:
					/* Unknown LLDP MED, ignore it */
					hardware->h_rx_unrecognized_cnt++;
				}
#endif /* ENABLE_LLDPMED */
			} else {
				LLOG_INFO("unknown org tlv received on %s",
				    hardware->h_ifname);
				hardware->h_rx_unrecognized_cnt++;
			}
			break;
		default:
			LLOG_WARNX("unknown tlv (%d) received on %s",
			    tlv_type, hardware->h_ifname);
			goto malformed;
		}
		if (pos > tlv + tlv_size) {
			LLOG_WARNX("BUG: already past TLV!");
			goto malformed;
		}
		PEEK_DISCARD(tlv + tlv_size - pos);
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
	lldpd_port_cleanup(port, 1);
	return -1;
}
