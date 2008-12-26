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

#ifdef ENABLE_EDP

#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fnmatch.h>

static int seq = 0;

int
edp_send(struct lldpd *global, struct lldpd_chassis *chassis,
    struct lldpd_hardware *hardware)
{
	struct edp_header eh;
	struct ethllc llc;
	const u_int8_t mcastaddr[] = EDP_MULTICAST_ADDR;
	const u_int8_t llcorg[] = LLC_ORG_EXTREME;
	struct iovec *iov = NULL;
#ifdef ENABLE_DOT1
	struct edp_tlv_vlan *ovlan = NULL;
	struct lldpd_vlan *vlan;
	unsigned int state = 0;
#endif
	struct edp_tlv_head device;
	struct edp_tlv_head null;
	struct edp_tlv_info info;
	u_int8_t edp_fakeversion[] = {7, 6, 4, 99};
	unsigned int i, c, v, len;
	/* Subsequent XXX can be replaced by other values. We place
	   them here to ensure the position of "" to be a bit
	   invariant with version changes. */
	char *deviceslot[] = { "eth", "veth", "XXX", "XXX", "XXX", "XXX", "XXX", "XXX", "", NULL };

#define IOV_NEW							\
	if ((iov = (struct iovec*)realloc(iov, (++c + 1) *	\
		    sizeof(struct iovec))) == NULL)		\
		fatal(NULL);

#ifdef ENABLE_DOT1
	while (state != 2) {
		free(iov); iov = NULL;
		free(ovlan); ovlan = NULL;
#endif
		c = v = -1;

		/* Ether + LLC */
		memset(&llc, 0, sizeof(llc));
		memcpy(&llc.ether.shost, &hardware->h_lladdr,
		    sizeof(llc.ether.shost));
		memcpy(&llc.ether.dhost, &mcastaddr,
		    sizeof(llc.ether.dhost));
		llc.dsap = llc.ssap = 0xaa;
		llc.control = 0x03;
		memcpy(llc.org, llcorg, sizeof(llc.org));
		llc.protoid = htons(LLC_PID_EDP);
		IOV_NEW;
		iov[c].iov_base = &llc;
		iov[c].iov_len = sizeof(llc);

		/* EDP header */
		memset(&eh, 0, sizeof(eh));
		eh.version = 1;
		eh.sequence = htons(seq++);
		if ((chassis->c_id_len != ETH_ALEN) ||
		    (chassis->c_id_subtype != LLDP_CHASSISID_SUBTYPE_LLADDR)) {
			LLOG_WARNX("local chassis does not use MAC address as chassis ID!?");
			return EINVAL;
		}
		memcpy(&eh.mac, chassis->c_id, ETH_ALEN);
		IOV_NEW;
		iov[c].iov_base = &eh;
		iov[c].iov_len = sizeof(eh);

#ifdef ENABLE_DOT1
		switch (state) {
		case 0:
#endif
			/* Display TLV */
			memset(&device, 0, sizeof(device));
			device.tlv_marker = EDP_TLV_MARKER;
			device.tlv_type = EDP_TLV_DISPLAY;
			device.tlv_len = htons(sizeof(device) + strlen(chassis->c_name) + 1);
			IOV_NEW;
			iov[c].iov_base = &device;
			iov[c].iov_len = sizeof(device);
			IOV_NEW;
			iov[c].iov_base = chassis->c_name;
			iov[c].iov_len = strlen(chassis->c_name) + 1;

			/* Info TLV */
			memset(&info, 0, sizeof(info));
			info.head.tlv_marker = EDP_TLV_MARKER;
			info.head.tlv_type = EDP_TLV_INFO;
			info.head.tlv_len = htons(sizeof(info));
			for (i=0; deviceslot[i] != NULL; i++) {
				if (strncmp(hardware->h_ifname, deviceslot[i],
					strlen(deviceslot[i])) == 0) {
					info.slot = htons(i);
					info.port = htons(atoi(hardware->h_ifname +
						strlen(deviceslot[i])));
					break;
				}
			}
			if (deviceslot[i] == NULL) {
				info.slot = htons(8);
				info.port = htons(if_nametoindex(hardware->h_ifname));
			}
			memcpy(info.version, edp_fakeversion, sizeof(info.version));
			info.connections[0] = info.connections[1] = 0xff;
			IOV_NEW;
			iov[c].iov_base = &info;
			iov[c].iov_len = sizeof(info);
#ifdef ENABLE_DOT1
			break;
		case 1:
			v = 0;
			TAILQ_FOREACH(vlan, &hardware->h_lport.p_vlans,
			    v_entries)
			    v++;
			if (v == 0) {
				v = -1;
				break;
			}
			if ((ovlan = (struct edp_tlv_vlan*)malloc(
					v*sizeof(struct edp_tlv_vlan))) == NULL) {
				LLOG_WARN("no room for vlans");
				v = -1;
			}
			TAILQ_FOREACH(vlan, &hardware->h_lport.p_vlans,
			    v_entries) {
				v--;
				memset(&ovlan[v], 0, sizeof(ovlan[v]));
				ovlan[v].head.tlv_marker = EDP_TLV_MARKER;
				ovlan[v].head.tlv_type = EDP_TLV_VLAN;
				ovlan[v].head.tlv_len = htons(sizeof(ovlan[v]) +
				    strlen(vlan->v_name) + 1);
				ovlan[v].vid = htons(vlan->v_vid);
				IOV_NEW;
				iov[c].iov_base = &ovlan[v];
				iov[c].iov_len = sizeof(ovlan[v]);
				IOV_NEW;
				iov[c].iov_base = vlan->v_name;
				iov[c].iov_len = strlen(vlan->v_name) + 1;
			}
			break;
		}

		if ((state == 1) && (v == -1))	/* No VLAN, no need to send another TLV */
			break;
#endif
			
		/* Null TLV */
		memset(&null, 0, sizeof(null));
		null.tlv_marker = EDP_TLV_MARKER;
		null.tlv_type = EDP_TLV_NULL;
		null.tlv_len = htons(sizeof(null));
		IOV_NEW;
		iov[c].iov_base = &null;
		iov[c].iov_len = sizeof(null);

		c++;

		/* Compute len and checksum */
		len = 0;
		for (i = 0; i < c; i++) {
			len += iov[i].iov_len;
		}
		len -= sizeof(struct ieee8023);
		llc.ether.size = htons(len);
		len = len + sizeof(struct ieee8023) - sizeof(struct ethllc);
		eh.len = htons(len);
		eh.checksum = iov_checksum(&iov[1], c - 1, 0);

		if (writev((hardware->h_raw_real > 0) ? hardware->h_raw_real :
			hardware->h_raw, iov, c) == -1) {
			LLOG_WARN("unable to send packet on real device for %s",
			    hardware->h_ifname);
#ifdef ENABLE_DOT1
			free(ovlan);
#endif
			free(iov);
			return ENETDOWN;
		}

#ifdef ENABLE_DOT1		
		state++;
	}
#endif

	hardware->h_tx_cnt++;
#ifdef ENABLE_DOT1
	free(ovlan);
#endif
	free(iov);

	return 0;
}

int
edp_decode(struct lldpd *cfg, char *frame, int s,
    struct lldpd_hardware *hardware,
    struct lldpd_chassis **newchassis, struct lldpd_port **newport)
{
	struct lldpd_chassis *chassis;
	struct lldpd_port *port;
	struct ethllc *llc;
	struct edp_header *eh;
	struct edp_tlv_head *tlv;
	struct edp_tlv_info *info;
#ifdef ENABLE_DOT1
	struct edp_tlv_vlan *vlan;
	struct lldpd_vlan *lvlan, *lvlan_next;
#endif
	const unsigned char edpaddr[] = EDP_MULTICAST_ADDR;
	struct iovec iov;
	int f, len, gotend = 0, gotvlans = 0;

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

	if (s < sizeof(struct ethllc) + sizeof(struct edp_header)) {
		LLOG_WARNX("too short frame received on %s", hardware->h_ifname);
		goto malformed;
	}

	llc = (struct ethllc *)frame;
	if (memcmp(&llc->ether.dhost, edpaddr, sizeof(edpaddr)) != 0) {
		LLOG_INFO("frame not targeted at EDP multicast address received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	if (ntohs(llc->ether.size) > s - sizeof(struct ieee8023)) {
		LLOG_WARNX("incorrect 802.3 frame size reported on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	if (llc->protoid != htons(LLC_PID_EDP)) {
		LLOG_DEBUG("incorrect LLC protocol ID received on %s",
		    hardware->h_ifname);
		goto malformed;
	}

	f = sizeof(struct ethllc);
	eh = (struct edp_header *)(frame + f);
	if (eh->version != 1) {
		LLOG_WARNX("incorrect EDP version (%d) for frame received on %s",
		    eh->version, hardware->h_ifname);
		goto malformed;
	}
	if (eh->idtype != htons(0)) {
		LLOG_WARNX("incorrect device id type for frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	if (ntohs(eh->len) > s - f) {
		LLOG_WARNX("incorrect size for EDP frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	chassis->c_ttl = LLDPD_TTL;
	chassis->c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
	chassis->c_id_len = ETH_ALEN;
	if ((chassis->c_id = (char *)malloc(ETH_ALEN)) == NULL) {
		LLOG_WARN("unable to allocate memory for chassis ID");
		goto malformed;
	}
	memcpy(chassis->c_id, eh->mac, ETH_ALEN);
	/* We ignore reserved bytes and sequence number */
	iov.iov_len = ntohs(eh->len);
	iov.iov_base = frame + f;
	if (iov_checksum(&iov, 1, 0) != 0) {
		LLOG_WARNX("incorrect EDP checksum for frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}

	f += sizeof(struct edp_header);
	while ((f < s) && !gotend) {
		if (f + sizeof(struct edp_tlv_head) > s) {
			LLOG_WARNX("EDP TLV header is too large for "
			    "frame received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		tlv = (struct edp_tlv_head *)(frame + f);
		len = ntohs(tlv->tlv_len) - sizeof(struct edp_tlv_head);
		if ((len < 0) || (f + sizeof(struct edp_tlv_head) + len > s)) {
			LLOG_DEBUG("incorrect size in EDP TLV header for frame "
			    "received on %s",
			    hardware->h_ifname);
			/* Some poor old Extreme Summit are quite bogus */
			gotend = 1;
			break;
		}
		f += sizeof(struct edp_tlv_head);
		if (tlv->tlv_marker != EDP_TLV_MARKER) {
			LLOG_WARNX("incorrect marker starting EDP TLV header for frame "
			    "received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		switch (tlv->tlv_type) {
		case EDP_TLV_INFO:
			if (len != sizeof(struct edp_tlv_info) -
			    sizeof(struct edp_tlv_head)) {
				LLOG_WARNX("wrong size for EDP TLV info for frame "
				    "received on %s (%d vs %d)",
				    hardware->h_ifname);
				goto malformed;
			}
			info = (struct edp_tlv_info *)(frame + f -
			    sizeof(struct edp_tlv_head));
			port->p_id_subtype = LLDP_PORTID_SUBTYPE_IFNAME;
			if (asprintf(&port->p_id, "%d/%d",
				ntohs(info->slot) + 1, ntohs(info->port) + 1) == -1) {
				LLOG_WARN("unable to allocate memory for "
				    "port ID");
				goto malformed;
			}
			port->p_id_len = strlen(port->p_id);
			if (asprintf(&port->p_descr, "Slot %d / Port %d",
				ntohs(info->slot) + 1, ntohs(info->port) + 1) == -1) {
				LLOG_WARN("unable to allocate memory for "
				    "port description");
				goto malformed;
			}
			if (asprintf(&chassis->c_descr,
				"EDP enabled device, version %d.%d.%d.%d",
				info->version[0], info->version[1],
				info->version[2], info->version[3]) == -1) {
				LLOG_WARN("unable to allocate memory for "
				    "chassis description");
				goto malformed;
			}
			break;
		case EDP_TLV_DISPLAY:
			if ((chassis->c_name = (char *)calloc(1, len + 1)) == NULL) {
				LLOG_WARN("unable to allocate memory for chassis "
				    "name");
				goto malformed;
			}
			/* TLV display contains a lot of garbage */
			strlcpy(chassis->c_name, frame + f, len);
			break;
		case EDP_TLV_NULL:
			if (len != 0) {
				LLOG_WARNX("null tlv with incorrect size in frame "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if (f != s)
				LLOG_DEBUG("extra data after edp frame on %s",
				    hardware->h_ifname);
			gotend = 1;
			break;
		case EDP_TLV_VLAN:
#ifdef ENABLE_DOT1
			if (len < sizeof(struct edp_tlv_vlan) -
			    sizeof(struct edp_tlv_head)) {
				LLOG_WARNX("wrong size for EDP TLV vlan for frame "
				    "received on %s (%d vs %d)",
				    hardware->h_ifname);
				goto malformed;
			}
			vlan = (struct edp_tlv_vlan *)(frame + f -
			    sizeof(struct edp_tlv_head));
			if ((lvlan = (struct lldpd_vlan *)calloc(1,
				    sizeof(struct lldpd_vlan))) == NULL) {
				LLOG_WARN("unable to allocate vlan");
				goto malformed;
			}
			lvlan->v_vid = ntohs(vlan->vid);
			if ((lvlan->v_name = (char *)calloc(1, len + 1 -
				    sizeof(struct edp_tlv_vlan) +
				    sizeof(struct edp_tlv_head))) == NULL) {
				LLOG_WARN("unable to allocate vlan name");
				goto malformed;
			}
			strlcpy(lvlan->v_name, frame + f + sizeof(struct edp_tlv_vlan) -
			    sizeof(struct edp_tlv_head), len -
			    sizeof(struct edp_tlv_vlan) +
			    sizeof(struct edp_tlv_head));
			if (vlan->ip.s_addr != INADDR_ANY) {
				if (chassis->c_mgmt.s_addr == INADDR_ANY)
					chassis->c_mgmt.s_addr = vlan->ip.s_addr;
				else
					/* We need to guess the good one */
					if (cfg->g_mgmt_pattern != NULL) {
						/* We can try to use this to prefer an address */
						char *ip;
						ip = inet_ntoa(vlan->ip);
						if (fnmatch(cfg->g_mgmt_pattern,
							ip, 0) == 0)
							chassis->c_mgmt.s_addr = vlan->ip.s_addr;
					}
			}
			TAILQ_INSERT_TAIL(&port->p_vlans,
			    lvlan, v_entries);
#endif
			gotvlans = 1;
			break;
		default:
			LLOG_DEBUG("unknown EDP TLV type (%d) received on %s",
			    tlv->tlv_type, hardware->h_ifname);
			hardware->h_rx_unrecognized_cnt++;
		}
		f += len;
	}
	if ((chassis->c_id == NULL) ||
	    (port->p_id == NULL) ||
	    (chassis->c_name == NULL) ||
	    (chassis->c_descr == NULL) ||
	    (port->p_descr == NULL) ||
	    (gotend == 0)) {
#ifdef ENABLE_DOT1
		if (gotvlans && gotend) {
			/* VLAN can be sent in a separate frames. We need to add
			 * those vlans to an existing chassis */
			if (hardware->h_rchassis &&
			    (hardware->h_rchassis->c_id_subtype == chassis->c_id_subtype) &&
			    (hardware->h_rchassis->c_id_len == chassis->c_id_len) &&
			    (memcmp(hardware->h_rchassis->c_id, chassis->c_id,
				chassis->c_id_len) == 0)) {
				/* We attach the VLANs to current hardware */
				lldpd_vlan_cleanup(hardware->h_rport);
				for (lvlan = TAILQ_FIRST(&port->p_vlans);
				     lvlan != NULL;
				     lvlan = lvlan_next) {
					lvlan_next = TAILQ_NEXT(lvlan, v_entries);
					TAILQ_REMOVE(&port->p_vlans, lvlan, v_entries);
					TAILQ_INSERT_TAIL(&hardware->h_rport->p_vlans,
					    lvlan, v_entries);
				}
				/* And the IP address */
				hardware->h_rchassis->c_mgmt.s_addr =
				    chassis->c_mgmt.s_addr;
			}
			/* We discard the remaining frame */
			goto malformed;
		}
#else
		if (gotvlans)
			goto malformed;
#endif
		LLOG_WARNX("some mandatory tlv are missing for frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	*newchassis = chassis;
	*newport = port;
	return 1;

malformed:
	lldpd_chassis_cleanup(chassis);
	lldpd_port_cleanup(port);
	return -1;
}

#endif /* ENABLE_EDP */
