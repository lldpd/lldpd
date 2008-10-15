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

#include <errno.h>
#include <arpa/inet.h>

int
cdp_send(struct lldpd *global, struct lldpd_chassis *chassis,
	 struct lldpd_hardware *hardware, int version)
{
	struct cdp_header ch;
	struct ethllc llc;
	const u_int8_t mcastaddr[] = CDP_MULTICAST_ADDR;
	const u_int8_t llcorg[] = LLC_ORG_CISCO;
	struct iovec *iov = NULL;
	struct cdp_tlv_head device;
	struct cdp_tlv_head port;
	struct cdp_tlv_head soft;
	struct cdp_tlv_head platform;
	struct cdp_tlv_address_head ah;
	struct cdp_tlv_address_one ao;
	struct cdp_tlv_capabilities cap;
	unsigned int c = -1, i, len;

#define IOV_NEW							\
	if ((iov = (struct iovec*)realloc(iov, (++c + 1) *	\
		    sizeof(struct iovec))) == NULL)		\
		fatal(NULL);

	/* Ether + LLC */
	memset(&llc, 0, sizeof(llc));
	memcpy(&llc.ether.shost, &hardware->h_lladdr,
	    sizeof(llc.ether.shost));
	memcpy(&llc.ether.dhost, &mcastaddr,
	    sizeof(llc.ether.dhost));
	llc.dsap = llc.ssap = 0xaa;
	llc.control = 0x03;
	memcpy(llc.org, llcorg, sizeof(llc.org));
	llc.protoid = htons(LLC_PID_CDP);
	IOV_NEW;
	iov[c].iov_base = &llc;
	iov[c].iov_len = sizeof(llc);

	/* CDP header */
	memset(&ch, 0, sizeof(ch));
	ch.version = version;
	ch.ttl = chassis->c_ttl;
	IOV_NEW;
	iov[c].iov_base = &ch;
	iov[c].iov_len = sizeof(struct cdp_header);

	/* Chassis ID */
	memset(&device, 0, sizeof(device));
	device.tlv_type = htons(CDP_TLV_CHASSIS);
	device.tlv_len = htons(sizeof(device) + strlen(chassis->c_name));
	IOV_NEW;
	iov[c].iov_base = &device;
	iov[c].iov_len = sizeof(device);
	IOV_NEW;
	iov[c].iov_base = chassis->c_name;
	iov[c].iov_len = strlen(chassis->c_name);

	/* Adresses */
	memset(&ah, 0, sizeof(ah));
	ah.head.tlv_type = htons(CDP_TLV_ADDRESSES);
	ah.head.tlv_len = htons(sizeof(ah) + sizeof(ao));
	ah.nb = htonl(1);
	IOV_NEW;
	iov[c].iov_base = &ah;
	iov[c].iov_len = sizeof(ah);
	memset(&ao, 0, sizeof(ao));
	ao.ptype = 1;
	ao.plen = 1;
	ao.proto = CDP_ADDRESS_PROTO_IP;
	ao.alen = htons(sizeof(struct in_addr));
	memcpy(&ao.addr, &chassis->c_mgmt, sizeof(struct in_addr));
	IOV_NEW;
	iov[c].iov_base = &ao;
	iov[c].iov_len = sizeof(ao);

	/* Port ID */
	memset(&port, 0, sizeof(port));
	port.tlv_type = htons(CDP_TLV_PORT);
	port.tlv_len = htons(sizeof(port) + strlen(hardware->h_lport.p_descr));
	IOV_NEW;
	iov[c].iov_base = &port;
	iov[c].iov_len = sizeof(port);
	IOV_NEW;
	iov[c].iov_base = hardware->h_lport.p_descr;
	iov[c].iov_len = strlen(hardware->h_lport.p_descr);

	/* Capaibilities */
	memset(&cap, 0, sizeof(cap));
	cap.head.tlv_type = htons(CDP_TLV_CAPABILITIES);
	cap.head.tlv_len = htons(sizeof(cap));
	cap.cap = 0;
	if (chassis->c_cap_enabled & LLDP_CAP_ROUTER)
		cap.cap |= CDP_CAP_ROUTER;
	if (chassis->c_cap_enabled & LLDP_CAP_BRIDGE)
		cap.cap |= CDP_CAP_BRIDGE;
	cap.cap = htonl(cap.cap);
	IOV_NEW;
	iov[c].iov_base = &cap;
	iov[c].iov_len = sizeof(cap);

	/* Software version */
	memset(&soft, 0, sizeof(soft));
	soft.tlv_type = htons(CDP_TLV_SOFTWARE);
	soft.tlv_len = htons(sizeof(soft) + strlen(chassis->c_descr));
	IOV_NEW;
	iov[c].iov_base = &soft;
	iov[c].iov_len = sizeof(soft);
	IOV_NEW;
	iov[c].iov_base = chassis->c_descr;
	iov[c].iov_len = strlen(chassis->c_descr);

	/* Platform */
	memset(&platform, 0, sizeof(platform));
	platform.tlv_type = htons(CDP_TLV_PLATFORM);
	platform.tlv_len = htons(sizeof(platform) + strlen("Linux"));
	IOV_NEW;
	iov[c].iov_base = &platform;
	iov[c].iov_len = sizeof(platform);
	IOV_NEW;
	iov[c].iov_base = "Linux";
	iov[c].iov_len = strlen("Linux");

	c++;

	/* Compute len and checksum */
	len = 0;
	for (i = 0; i < c; i++) {
		len += iov[i].iov_len;
	}
	len -= sizeof(struct ieee8023);
	llc.ether.size = htons(len);
	ch.checksum = iov_checksum(&iov[1], c - 1, 1);

	if (writev((hardware->h_raw_real > 0) ? hardware->h_raw_real :
		   hardware->h_raw, iov, c) == -1) {
		LLOG_WARN("unable to send packet on real device for %s",
			   hardware->h_ifname);
		free(iov);
		return ENETDOWN;
	}

	hardware->h_tx_cnt++;

	free(iov);
	return 0;
}

int
cdp_decode(struct lldpd *cfg, char *frame, int s,
    struct lldpd_hardware *hardware,
    struct lldpd_chassis **newchassis, struct lldpd_port **newport)
{
	struct lldpd_chassis *chassis;
	struct lldpd_port *port;
	struct ethllc *llc;
	struct cdp_header *ch;
	struct cdp_tlv_head *tlv;
	struct cdp_tlv_address_head *ah;
	struct cdp_tlv_address_one *ao;
	struct iovec iov;
	u_int16_t cksum;
	char *software = NULL, *platform = NULL;
	int software_len = 0, platform_len = 0;
	const unsigned char cdpaddr[] = CDP_MULTICAST_ADDR;
	int i, f, len, rlen;

	if ((chassis = calloc(1, sizeof(struct lldpd_chassis))) == NULL) {
		LLOG_WARN("failed to allocate remote chassis");
		return -1;
	}
	if ((port = calloc(1, sizeof(struct lldpd_port))) == NULL) {
		LLOG_WARN("failed to allocate remote port");
		free(chassis);
		return -1;
	}
	TAILQ_INIT(&port->p_vlans);

	if (s < sizeof(struct ethllc) + sizeof(struct cdp_header)) {
		LLOG_WARNX("too short frame received on %s", hardware->h_ifname);
		goto malformed;
	}

	llc = (struct ethllc *)frame;
	if (memcmp(&llc->ether.dhost, cdpaddr, sizeof(cdpaddr)) != 0) {
		LLOG_INFO("frame not targeted at CDP multicast address received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	if (ntohs(llc->ether.size) > s - sizeof(struct ieee8023)) {
		LLOG_WARNX("incorrect 802.3 frame size reported on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	if (llc->protoid != htons(LLC_PID_CDP)) {
		LLOG_DEBUG("incorrect LLC protocol ID received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	f = sizeof(struct ethllc);
	ch = (struct cdp_header *)(frame + f);
	if ((ch->version != 1) && (ch->version != 2)) {
		LLOG_WARNX("incorrect CDP version (%d) for frame received on %s",
		    ch->version, hardware->h_ifname);
		goto malformed;
	}
	chassis->c_ttl = ntohs(ch->ttl);
	iov.iov_len = s - f;
	iov.iov_base = frame + f;
	cksum = iov_checksum(&iov, 1, 1);
	/* An off-by-one error may happen. Just ignore it */
	if ((cksum != 0) && (cksum != 0xfffe)) {
		LLOG_INFO("incorrect CDP checksum for frame received on %s (%d)",
			  hardware->h_ifname, cksum);
		goto malformed;
	}

	f += sizeof(struct cdp_header);
	while (f < s) {
		if (f + sizeof(struct cdp_tlv_head) > s) {
			LLOG_WARNX("CDP TLV header is too large for "
			    "frame received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		tlv = (struct cdp_tlv_head *)(frame + f);
		len = ntohs(tlv->tlv_len) - sizeof(struct cdp_tlv_head);
		if ((len < 0) || (f + sizeof(struct cdp_tlv_head) + len > s)) {
			LLOG_WARNX("incorrect size in CDP TLV header for frame "
			    "received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		switch (ntohs(tlv->tlv_type)) {
		case CDP_TLV_CHASSIS:
			f += sizeof(struct cdp_tlv_head);
			if ((chassis->c_name = (char *)calloc(1, len + 1)) == NULL) {
				LLOG_WARN("unable to allocate memory for chassis name");
				goto malformed;
			}
			memcpy(chassis->c_name, frame + f, len);
			chassis->c_id_subtype = LLDP_CHASSISID_SUBTYPE_LOCAL;
			if ((chassis->c_id =  (char *)malloc(len)) == NULL) {
				LLOG_WARN("unable to allocate memory for chassis ID");
				goto malformed;
			}
			memcpy(chassis->c_id, frame + f, len);
			chassis->c_id_len = len;
			f += len;
			break;
		case CDP_TLV_ADDRESSES:
			if (len < 4) {
				LLOG_WARNX("incorrect size in CDP TLV header for frame "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			ah = (struct cdp_tlv_address_head *)(frame + f);
			f += sizeof(struct cdp_tlv_address_head);
			len -= 4;
			for (i = 0; i < ntohl(ah->nb); i++) {
				if (len < sizeof(struct cdp_tlv_address_one) -
				    sizeof(struct in_addr)) {
					LLOG_WARNX("incorrect size for address TLV in "
					    "frame received from %s",
					    hardware->h_ifname);
					goto malformed;
				}
				ao = (struct cdp_tlv_address_one *)(frame + f);
				rlen = 2 + ao->plen + 2 + ntohs(ao->alen);
				if (len < rlen) {
					LLOG_WARNX("incorrect address size in TLV "
					    "received from %s",
					    hardware->h_ifname);
					goto malformed;
				}
				if ((ao->ptype == 1) && (ao->plen == 1) &&
				    (ao->proto == CDP_ADDRESS_PROTO_IP) &&
				    (ntohs(ao->alen) == sizeof(struct in_addr)) &&
				    (chassis->c_mgmt.s_addr == INADDR_ANY))
					chassis->c_mgmt.s_addr = ao->addr.s_addr;
				f += rlen;
				len -= rlen;
			}
			if (len != 0) {
				LLOG_WARNX("not enough addresses found in TLV "
				    "received from %s",
				    hardware->h_ifname);
				goto malformed;
			}
			break;
		case CDP_TLV_PORT:
			f += sizeof(struct cdp_tlv_head);
			if ((port->p_descr = (char *)calloc(1, len + 1)) == NULL) {
				LLOG_WARN("unable to allocate memory for port description");
				goto malformed;
			}
			memcpy(port->p_descr, frame + f, len);
			port->p_id_subtype = LLDP_PORTID_SUBTYPE_LLADDR;
			if ((port->p_id =  (char *)malloc(ETH_ALEN)) == NULL) {
				LLOG_WARN("unable to allocate memory for port ID");
				goto malformed;
			}
			memcpy(port->p_id, llc->ether.shost, ETH_ALEN);
			port->p_id_len = ETH_ALEN;
			f += len;
			break;
		case CDP_TLV_CAPABILITIES:
			f += sizeof(struct cdp_tlv_head);
			if (len != 4) {
				LLOG_WARNX("incorrect size for capabilities TLV "
				    "on frame received from %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if (ntohl(*(u_int32_t*)(frame + f)) & CDP_CAP_ROUTER)
				chassis->c_cap_enabled |= LLDP_CAP_ROUTER;
			if (ntohl(*(u_int32_t*)(frame + f)) & 0x0e)
				chassis->c_cap_enabled |= LLDP_CAP_BRIDGE;
			if (chassis->c_cap_enabled == 0)
				chassis->c_cap_enabled = LLDP_CAP_STATION;
			chassis->c_cap_available = chassis->c_cap_enabled;
			f += 4;
			break;
		case CDP_TLV_SOFTWARE:
			f += sizeof(struct cdp_tlv_head);
			software_len = len;
			software = (char *)(frame + f);
			f += len;
			break;
		case CDP_TLV_PLATFORM:
			f += sizeof(struct cdp_tlv_head);
			platform_len = len;
			platform = (char *)(frame + f);
			f += len;
			break;
		default:
			LLOG_DEBUG("unknown CDP TLV type (%d) received on %s",
			    ntohs(tlv->tlv_type), hardware->h_ifname);
			f += sizeof(struct cdp_tlv_head) + len;
		}
	}
	if (!software && platform) {
		if ((chassis->c_descr = (char *)calloc(1,
			    platform_len + 1)) == NULL) {
			LLOG_WARN("unable to allocate memory for chassis description");
			goto malformed;
		}
		memcpy(chassis->c_descr, platform, platform_len);
	} else if (software && !platform) {
		if ((chassis->c_descr = (char *)calloc(1,
			    software_len + 1)) == NULL) {
			LLOG_WARN("unable to allocate memory for chassis description");
			goto malformed;
		}
		memcpy(chassis->c_descr, software, software_len);
	} else if (software && platform) {
#define CONCAT_PLATFORM " running on\n"
		if ((chassis->c_descr = (char *)calloc(1,
			    software_len + platform_len +
			    strlen(CONCAT_PLATFORM) + 1)) == NULL) {
			LLOG_WARN("unable to allocate memory for chassis description");
			goto malformed;
		}
		memcpy(chassis->c_descr, platform, platform_len);
		memcpy(chassis->c_descr + platform_len,
		    CONCAT_PLATFORM, strlen(CONCAT_PLATFORM));
		memcpy(chassis->c_descr + platform_len + strlen(CONCAT_PLATFORM),
		    software, software_len);
	}
	if ((chassis->c_id == NULL) ||
	    (port->p_id == NULL) ||
	    (chassis->c_name == NULL) ||
	    (chassis->c_descr == NULL) ||
	    (port->p_descr == NULL) ||
	    (chassis->c_ttl == 0) ||
	    (chassis->c_cap_enabled == 0)) {
		LLOG_WARNX("some mandatory tlv are missing for frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	*newchassis = chassis;
	*newport = port;
	return 1;

malformed:
	free(chassis->c_name);
	free(chassis->c_id);
	free(chassis->c_descr);
	free(chassis);
	free(port->p_id);
	free(port->p_descr);
	lldpd_vlan_cleanup(port);
	free(port);
	return -1;
}

int
cdpv1_send(struct lldpd *global, struct lldpd_chassis *chassis,
    struct lldpd_hardware *hardware)
{
	return cdp_send(global, chassis, hardware, 1);
}

int
cdpv2_send(struct lldpd *global, struct lldpd_chassis *chassis,
    struct lldpd_hardware *hardware)
{
	return cdp_send(global, chassis, hardware, 2);
}

int
cdp_guess(char *frame, int len, int version)
{
	const u_int8_t mcastaddr[] = CDP_MULTICAST_ADDR;
	struct cdp_header *ch;
	if (len < sizeof(struct ethllc) + sizeof(struct cdp_header))
		return 0;
	if (memcmp(frame, mcastaddr, ETH_ALEN) != 0)
		return 0;
	ch = (struct cdp_header *)(frame + sizeof(struct ethllc));
	return (ch->version == version);
}

int
cdpv1_guess(char *frame, int len)
{
	return cdp_guess(frame, len, 1);
}

int
cdpv2_guess(char *frame, int len)
{
	return cdp_guess(frame, len, 2);
}
