#define _GNU_SOURCE 1
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <check.h>
#include "../src/lldpd.h"

int dump = -1;
char *filename = NULL;
struct packet {
	TAILQ_ENTRY(packet) next;
	int size;
	char data[];
};
TAILQ_HEAD(, packet) pkts;
char *buffer[] = { NULL };
char macaddress[ETH_ALEN] = { 0x5e, 0x10, 0x8e, 0xe7, 0x84, 0xad };
struct lldpd_hardware hardware;
struct lldpd_chassis chassis;

/* See:
 * http://wiki.wireshark.org/Development/LibpcapFileFormat
 */
struct pcap_hdr {
        u_int32_t magic_number;   /* magic number */
        u_int16_t version_major;  /* major version number */
        u_int16_t version_minor;  /* minor version number */
        u_int32_t thiszone;       /* GMT to local correction */
        u_int32_t sigfigs;        /* accuracy of timestamps */
        u_int32_t snaplen;        /* max length of captured packets, in octets */
        u_int32_t network;        /* data link type */
};
struct pcaprec_hdr {
	u_int32_t ts_sec;         /* timestamp seconds */
        u_int32_t ts_usec;        /* timestamp microseconds */
        u_int32_t incl_len;       /* number of octets of packet saved in file */
        u_int32_t orig_len;       /* actual length of packet */
};

int
pcap_send(struct lldpd *cfg, struct lldpd_hardware *hardware,
    char *buffer, size_t size)
{
	struct pcaprec_hdr hdr;
	struct packet *pkt;
	int n;

	/* Write pcap record header */
	hdr.ts_sec = time(NULL);
	hdr.ts_usec = 0;
	hdr.incl_len = hdr.orig_len = size;
	n = write(dump, &hdr, sizeof(hdr));
	fail_unless(n != -1, "unable to write pcap record header to %s", filename);

	/* Write data */
	n = write(dump, buffer, size);
	fail_unless(n != -1, "unable to write pcap data to %s", filename);

	/* Append to list of packets */
	pkt = (struct packet *)malloc(size + sizeof(TAILQ_HEAD(,packet)) + sizeof(int));
	fail_unless(pkt != NULL);
	memcpy(pkt->data, buffer, size);
	pkt->size = size;
	TAILQ_INSERT_TAIL(&pkts, pkt, next);
	return 0;
}

struct lldpd_ops fake_ops = {
	.send = pcap_send,
	.recv = NULL,		/* Won't be used */
	.cleanup = NULL,	/* Won't be used */
};


void
setup()
{
	static int serial = 0;
	struct pcap_hdr hdr;
	int n;
	/* Prepare packet buffer */
	TAILQ_INIT(&pkts);
	/* Open a new dump file */
	n = asprintf(&filename, "lldp_send_%04d.pcap", serial++);
	fail_unless(n != -1, "unable to compute filename");
	dump = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	fail_unless(dump != -1);
	/* Write a PCAP header */
	hdr.magic_number = 0xa1b2c3d4;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.thiszone = 0;
	hdr.sigfigs = 0;
	hdr.snaplen = 65535;
	hdr.network = 1;
	n = write(dump, &hdr, sizeof(hdr));
	fail_unless(n != -1, "unable to write pcap header to %s", filename);
	/* Prepare hardware */
	memset(&hardware, 0, sizeof(struct lldpd_hardware));
	TAILQ_INIT(&hardware.h_rports);
	TAILQ_INIT(&hardware.h_lport.p_vlans);
	hardware.h_mtu = 1500;
	hardware.h_ifindex = 1;
	strcpy(hardware.h_ifname, "test");
	memcpy(hardware.h_lladdr, macaddress, ETH_ALEN);
	hardware.h_ops = &fake_ops;
	/* Prepare chassis */
	memset(&chassis, 0, sizeof(struct lldpd_chassis));
	hardware.h_lport.p_chassis = &chassis;
	chassis.c_ttl = 180;
}

void
teardown()
{
	struct packet *npkt, *pkt;
	for (pkt = TAILQ_FIRST(&pkts);
	    pkt != NULL;
	    pkt = npkt) {
		npkt = TAILQ_NEXT(pkt, next);
		TAILQ_REMOVE(&pkts, pkt, next);
		free(pkt);
	}
	if (dump != -1) {
		close(dump);
		dump = -1;
	}
	if (filename) {
		free(filename);
		filename = NULL;
	}
}

START_TEST (test_send_basic)
{
	int n;
	/* Packet we should build:
Ethernet II, Src: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad), Dst: LLDP_Multicast (01:80:c2:00:00:0e)
    Destination: LLDP_Multicast (01:80:c2:00:00:0e)
    Source: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = MAC address
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 0111 = TLV Length: 7
        Chassis Id Subtype: MAC address (4)
        Chassis Id: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
    Port Subtype = Interface name
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0001 0001 = TLV Length: 17
        Port Id Subtype: Interface name (5)
        Port Id: FastEthernet 1/5
    Time To Live = 180 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 180
    System Name = First chassis
        0000 101. .... .... = TLV Type: System Name (5)
        .... ...0 0000 1101 = TLV Length: 13
        System Name = First chassis
    System Description = Chassis description
        0000 110. .... .... = TLV Type: System Description (6)
        .... ...0 0001 0011 = TLV Length: 19
        System Description = Chassis description
    Capabilities
        0000 111. .... .... = TLV Type: System Capabilities (7)
        .... ...0 0000 0100 = TLV Length: 4
        Capabilities: 0x0010
            .... .... ...1 .... = Router
        Enabled Capabilities: 0x0010
            .... .... ...1 .... = Router
    Port Description = Fake port description
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0001 0101 = TLV Length: 21
        Port Description: Fake port description
    IEEE 802.3 - Link Aggregation
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Link Aggregation (0x03)
        Aggregation Status: 0x01
            .... ...1 = Aggregation Capability: Yes
            .... ..0. = Aggregation Status: Not Enabled
        Aggregated Port Id: 0
    IEEE 802.3 - MAC/PHY Configuration/Status
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: MAC/PHY Configuration/Status (0x01)
        Auto-Negotiation Support/Status: 0x00
            .... ...0 = Auto-Negotiation: Not Supported
            .... ..0. = Auto-Negotiation: Not Enabled
        PMD Auto-Negotiation Advertised Capability: 0x0000
        Operational MAU Type: Unknown (0x0000)
    IEEE 802.3 - Maximum Frame Size
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0110 = TLV Length: 6
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Maximum Frame Size (0x04)
        Maximum Frame Size: 1516
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
	*/
	char pkt1[] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x5e, 0x10,
		0x8e, 0xe7, 0x84, 0xad, 0x88, 0xcc, 0x02, 0x07,
		0x04, 0x5e, 0x10, 0x8e, 0xe7, 0x84, 0xad, 0x04,
		0x11, 0x05, 0x46, 0x61, 0x73, 0x74, 0x45, 0x74,
		0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x31,
		0x2f, 0x35, 0x06, 0x02, 0x00, 0xb4, 0x0a, 0x0d,
		0x46, 0x69, 0x72, 0x73, 0x74, 0x20, 0x63, 0x68,
		0x61, 0x73, 0x73, 0x69, 0x73, 0x0c, 0x13, 0x43,
		0x68, 0x61, 0x73, 0x73, 0x69, 0x73, 0x20, 0x64,
		0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69,
		0x6f, 0x6e, 0x0e, 0x04, 0x00, 0x10, 0x00, 0x10,
		0x08, 0x15, 0x46, 0x61, 0x6b, 0x65, 0x20, 0x70,
		0x6f, 0x72, 0x74, 0x20, 0x64, 0x65, 0x73, 0x63,
		0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0xfe,
		0x09, 0x00, 0x12, 0x0f, 0x03, 0x01, 0x00, 0x00,
		0x00, 0x00, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0x00,
		0x12, 0x0f, 0x04, 0x05, 0xec, 0x00, 0x00 };
	struct packet *pkt;

	/* Populate port and chassis */
	hardware.h_lport.p_id_subtype = LLDP_PORTID_SUBTYPE_IFNAME;
	hardware.h_lport.p_id = "FastEthernet 1/5";
	hardware.h_lport.p_id_len = strlen(hardware.h_lport.p_id);
	hardware.h_lport.p_descr = "Fake port description";
	hardware.h_lport.p_mfs = 1516;
	chassis.c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
	chassis.c_id = macaddress;
	chassis.c_id_len = ETH_ALEN;
	chassis.c_name = "First chassis";
	chassis.c_descr = "Chassis description";
	chassis.c_cap_available = chassis.c_cap_enabled = LLDP_CAP_ROUTER;

	/* Build packet */
	n = lldp_send(NULL, &hardware);
	fail_unless(n == 0, "unable to build packet");
	fail_unless(!TAILQ_EMPTY(&pkts));
	pkt = TAILQ_FIRST(&pkts);
	ck_assert_int_eq(pkt->size, sizeof(pkt1));
	fail_unless(memcmp(pkt->data, pkt1, sizeof(pkt1)) == 0);
	fail_unless(TAILQ_NEXT(pkt, next) == NULL, "more than one packet sent");
}
END_TEST

START_TEST (test_send_vlan)
{
	int n;
	struct lldpd_vlan vlan1, vlan2, vlan3;
	/* Packet we should build:
Ethernet II, Src: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad), Dst: LLDP_Multicast (01:80:c2:00:00:0e)
    Destination: LLDP_Multicast (01:80:c2:00:00:0e)
        Address: LLDP_Multicast (01:80:c2:00:00:0e)
    Source: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
        Address: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
he factory default)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = Locally assigned
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 1101 = TLV Length: 13
        Chassis Id Subtype: Locally assigned (7)
        Chassis Id: Chassis name
    Port Subtype = MAC address
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0000 0111 = TLV Length: 7
        Port Id Subtype: MAC address (3)
        Port Id: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
    Time To Live = 180 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 180
    System Name = Second chassis
        0000 101. .... .... = TLV Type: System Name (5)
        .... ...0 0000 1110 = TLV Length: 14
        System Name = Second chassis
    System Description = Chassis description
        0000 110. .... .... = TLV Type: System Description (6)
        .... ...0 0001 0011 = TLV Length: 19
        System Description = Chassis description
    Capabilities
        0000 111. .... .... = TLV Type: System Capabilities (7)
        .... ...0 0000 0100 = TLV Length: 4
        Capabilities: 0x0014
            .... .... .... .1.. = Bridge
            .... .... ...1 .... = Router
        Enabled Capabilities: 0x0010
            .... .... ...1 .... = Router
    Port Description = Fake port description
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0001 0101 = TLV Length: 21
        Port Description: Fake port description
    IEEE 802.1 - VLAN Name
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0001 = TLV Length: 17
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: VLAN Name (0x03)
        VLAN Identifier: 157 (0x009D)
        VLAN Name Length: 10
        VLAN Name: First VLAN
    IEEE 802.1 - VLAN Name
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0010 = TLV Length: 18
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: VLAN Name (0x03)
        VLAN Identifier: 1247 (0x04DF)
        VLAN Name Length: 11
        VLAN Name: Second VLAN
    IEEE 802.1 - VLAN Name
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0001 = TLV Length: 17
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: VLAN Name (0x03)
        VLAN Identifier: 741 (0x02E5)
        VLAN Name Length: 10
        VLAN Name: Third VLAN
    IEEE 802.3 - Link Aggregation
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Link Aggregation (0x03)
        Aggregation Status: 0x01
            .... ...1 = Aggregation Capability: Yes
            .... ..0. = Aggregation Status: Not Enabled
        Aggregated Port Id: 0
    IEEE 802.3 - MAC/PHY Configuration/Status
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: MAC/PHY Configuration/Status (0x01)
        Auto-Negotiation Support/Status: 0x00
            .... ...0 = Auto-Negotiation: Not Supported
            .... ..0. = Auto-Negotiation: Not Enabled
        PMD Auto-Negotiation Advertised Capability: 0x0000
        Operational MAU Type: Unknown (0x0000)
    IEEE 802.3 - Maximum Frame Size
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0110 = TLV Length: 6
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Maximum Frame Size (0x04)
        Maximum Frame Size: 1516
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
	*/
	char pkt1[] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x5e, 0x10,
		0x8e, 0xe7, 0x84, 0xad, 0x88, 0xcc, 0x02, 0x0d,
		0x07, 0x43, 0x68, 0x61, 0x73, 0x73, 0x69, 0x73,
		0x20, 0x6e, 0x61, 0x6d, 0x65, 0x04, 0x07, 0x03,
		0x5e, 0x10, 0x8e, 0xe7, 0x84, 0xad, 0x06, 0x02,
		0x00, 0xb4, 0x0a, 0x0e, 0x53, 0x65, 0x63, 0x6f,
		0x6e, 0x64, 0x20, 0x63, 0x68, 0x61, 0x73, 0x73,
		0x69, 0x73, 0x0c, 0x13, 0x43, 0x68, 0x61, 0x73,
		0x73, 0x69, 0x73, 0x20, 0x64, 0x65, 0x73, 0x63,
		0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x0e,
		0x04, 0x00, 0x14, 0x00, 0x10, 0x08, 0x15, 0x46,
		0x61, 0x6b, 0x65, 0x20, 0x70, 0x6f, 0x72, 0x74,
		0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
		0x74, 0x69, 0x6f, 0x6e, 0xfe, 0x11, 0x00, 0x80,
		0xc2, 0x03, 0x00, 0x9d, 0x0a, 0x46, 0x69, 0x72,
		0x73, 0x74, 0x20, 0x56, 0x4c, 0x41, 0x4e, 0xfe,
		0x12, 0x00, 0x80, 0xc2, 0x03, 0x04, 0xdf, 0x0b,
		0x53, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x56,
		0x4c, 0x41, 0x4e, 0xfe, 0x11, 0x00, 0x80, 0xc2,
		0x03, 0x02, 0xe5, 0x0a, 0x54, 0x68, 0x69, 0x72,
		0x64, 0x20, 0x56, 0x4c, 0x41, 0x4e, 0xfe, 0x09,
		0x00, 0x12, 0x0f, 0x03, 0x01, 0x00, 0x00, 0x00,
		0x00, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0x00, 0x12,
		0x0f, 0x04, 0x05, 0xec, 0x00, 0x00 };
	struct packet *pkt;

	/* Populate port and chassis */
	hardware.h_lport.p_id_subtype = LLDP_PORTID_SUBTYPE_LLADDR;
	hardware.h_lport.p_id = macaddress;
	hardware.h_lport.p_id_len = ETH_ALEN;
	hardware.h_lport.p_descr = "Fake port description";
	hardware.h_lport.p_mfs = 1516;
	chassis.c_id_subtype = LLDP_CHASSISID_SUBTYPE_LOCAL;
	chassis.c_id = "Chassis name";
	chassis.c_id_len = strlen(chassis.c_id);
	chassis.c_name = "Second chassis";
	chassis.c_descr = "Chassis description";
	chassis.c_cap_available = LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE;
	chassis.c_cap_enabled = LLDP_CAP_ROUTER;
	vlan1.v_name = "First VLAN"; vlan1.v_vid = 157;
	vlan2.v_name = "Second VLAN"; vlan2.v_vid = 1247;
	vlan3.v_name = "Third VLAN"; vlan3.v_vid = 741;
	TAILQ_INSERT_TAIL(&hardware.h_lport.p_vlans, &vlan1, v_entries);
	TAILQ_INSERT_TAIL(&hardware.h_lport.p_vlans, &vlan2, v_entries);
	TAILQ_INSERT_TAIL(&hardware.h_lport.p_vlans, &vlan3, v_entries);

	/* Build packet */
	n = lldp_send(NULL, &hardware);
	fail_unless(n == 0, "unable to build packet");
	fail_unless(!TAILQ_EMPTY(&pkts));
	pkt = TAILQ_FIRST(&pkts);
	ck_assert_int_eq(pkt->size, sizeof(pkt1));
	fail_unless(memcmp(pkt->data, pkt1, sizeof(pkt1)) == 0);
	fail_unless(TAILQ_NEXT(pkt, next) == NULL, "more than one packet sent");
}
END_TEST

START_TEST (test_send_med)
{
	int n;
	char loc[] = {0x28, 0x02, 0x55, 0x53, 0x01, 0x02, 0x43, 0x41, 0x03,
		      0x09, 0x52, 0x6f, 0x73, 0x65, 0x76, 0x69, 0x6c,
		      0x6c, 0x65, 0x06, 0x09, 0x46, 0x6f, 0x6f, 0x74,
		      0x68, 0x69, 0x6c, 0x6c, 0x73, 0x13, 0x04, 0x38,
		      0x30, 0x30, 0x30, 0x1a, 0x03, 0x52, 0x33, 0x4c};

	/* Packet we should build:
Ethernet II, Src: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad), Dst: LLDP_Multicast (01:80:c2:00:00:0e)
    Destination: LLDP_Multicast (01:80:c2:00:00:0e)
        Address: LLDP_Multicast (01:80:c2:00:00:0e)
    Source: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
        Address: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
he factory default)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = Locally assigned
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 1101 = TLV Length: 13
        Chassis Id Subtype: Locally assigned (7)
        Chassis Id: Chassis name
    Port Subtype = MAC address
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0000 0111 = TLV Length: 7
        Port Id Subtype: MAC address (3)
        Port Id: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
    Time To Live = 180 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 180
    System Name = Third chassis
        0000 101. .... .... = TLV Type: System Name (5)
        .... ...0 0000 1101 = TLV Length: 13
        System Name = Third chassis
    System Description = Chassis description
        0000 110. .... .... = TLV Type: System Description (6)
        .... ...0 0001 0011 = TLV Length: 19
        System Description = Chassis description
    Capabilities
        0000 111. .... .... = TLV Type: System Capabilities (7)
        .... ...0 0000 0100 = TLV Length: 4
        Capabilities: 0x0014
            .... .... .... .1.. = Bridge
            .... .... ...1 .... = Router
        Enabled Capabilities: 0x0010
            .... .... ...1 .... = Router
    Port Description = Fake port description
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0001 0101 = TLV Length: 21
        Port Description: Fake port description
    IEEE 802.3 - Link Aggregation
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Link Aggregation (0x03)
        Aggregation Status: 0x01
            .... ...1 = Aggregation Capability: Yes
            .... ..0. = Aggregation Status: Not Enabled
        Aggregated Port Id: 0
    IEEE 802.3 - MAC/PHY Configuration/Status
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: MAC/PHY Configuration/Status (0x01)
        Auto-Negotiation Support/Status: 0x00
            .... ...0 = Auto-Negotiation: Not Supported
            .... ..0. = Auto-Negotiation: Not Enabled
        PMD Auto-Negotiation Advertised Capability: 0x0000
        Operational MAU Type: Unknown (0x0000)
    IEEE 802.3 - Maximum Frame Size
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0110 = TLV Length: 6
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Maximum Frame Size (0x04)
        Maximum Frame Size: 1516
    TIA - Media Capabilities
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0111 = TLV Length: 7
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Media Capabilities (0x01)
        Capabilities: 0x002f
            .... .... .... ...1 = LLDP-MED Capabilities
            .... .... .... ..1. = Network Policy
            .... .... .... .1.. = Location Identification
            .... .... .... 1... = Extended Power via MDI-PSE
            .... .... ..1. .... = Inventory
        Class Type: Endpoint Class III
    TIA - Inventory - Hardware Revision
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0010 = TLV Length: 18
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Hardware Revision (0x05)
        Hardware Revision: hardware rev 5
    TIA - Inventory - Firmware Revision
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1000 = TLV Length: 8
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Firmware Revision (0x06)
        Firmware Revision: 47b5
    TIA - Inventory - Software Revision
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1100 = TLV Length: 12
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Software Revision (0x07)
        Software Revision: 2.6.22b5
    TIA - Inventory - Serial Number
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1100 = TLV Length: 12
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Serial Number (0x08)
        Serial Number: SN 47842
    TIA - Location Identification
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0010 1110 = TLV Length: 46
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Location Identification (0x03)
        Location Data Format: Civic Address LCI (2)
        LCI Length: 40
        What: Location of the client (2)
        Country: US
        CA Type: National subdivisions (province, state, etc) (1)
        CA Length: 2
        CA Value: CA
        CA Type: City, township (3)
        CA Length: 9
        CA Value: Roseville
        CA Type: Street (6)
        CA Length: 9
        CA Value: Foothills
        CA Type: House number (19)
        CA Length: 4
        CA Value: 8000
        CA Type: Unit (26)
        CA Length: 3
        CA Value: R3L
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
	*/
	char pkt1[] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x5e, 0x10,
		0x8e, 0xe7, 0x84, 0xad, 0x88, 0xcc, 0x02, 0x0d,
		0x07, 0x43, 0x68, 0x61, 0x73, 0x73, 0x69, 0x73,
		0x20, 0x6e, 0x61, 0x6d, 0x65, 0x04, 0x07, 0x03,
		0x5e, 0x10, 0x8e, 0xe7, 0x84, 0xad, 0x06, 0x02,
		0x00, 0xb4, 0x0a, 0x0d, 0x54, 0x68, 0x69, 0x72,
		0x64, 0x20, 0x63, 0x68, 0x61, 0x73, 0x73, 0x69,
		0x73, 0x0c, 0x13, 0x43, 0x68, 0x61, 0x73, 0x73,
		0x69, 0x73, 0x20, 0x64, 0x65, 0x73, 0x63, 0x72,
		0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x0e, 0x04,
		0x00, 0x14, 0x00, 0x10, 0x08, 0x15, 0x46, 0x61,
		0x6b, 0x65, 0x20, 0x70, 0x6f, 0x72, 0x74, 0x20,
		0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
		0x69, 0x6f, 0x6e, 0xfe, 0x09, 0x00, 0x12, 0x0f,
		0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x09,
		0x00, 0x12, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xfe, 0x06, 0x00, 0x12, 0x0f, 0x04, 0x05,
		0xec, 0xfe, 0x07, 0x00, 0x12, 0xbb, 0x01, 0x00,
		0x2f, 0x03, 0xfe, 0x12, 0x00, 0x12, 0xbb, 0x05,
		0x68, 0x61, 0x72, 0x64, 0x77, 0x61, 0x72, 0x65,
		0x20, 0x72, 0x65, 0x76, 0x20, 0x35, 0xfe, 0x08,
		0x00, 0x12, 0xbb, 0x06, 0x34, 0x37, 0x62, 0x35,
		0xfe, 0x0c, 0x00, 0x12, 0xbb, 0x07, 0x32, 0x2e,
		0x36, 0x2e, 0x32, 0x32, 0x62, 0x35, 0xfe, 0x0c,
		0x00, 0x12, 0xbb, 0x08, 0x53, 0x4e, 0x20, 0x34,
		0x37, 0x38, 0x34, 0x32, 0xfe, 0x2e, 0x00, 0x12,
		0xbb, 0x03, 0x02, 0x28, 0x02, 0x55, 0x53, 0x01,
		0x02, 0x43, 0x41, 0x03, 0x09, 0x52, 0x6f, 0x73,
		0x65, 0x76, 0x69, 0x6c, 0x6c, 0x65, 0x06, 0x09,
		0x46, 0x6f, 0x6f, 0x74, 0x68, 0x69, 0x6c, 0x6c,
		0x73, 0x13, 0x04, 0x38, 0x30, 0x30, 0x30, 0x1a,
		0x03, 0x52, 0x33, 0x4c, 0x00, 0x00 };
	struct packet *pkt;

	/* Populate port and chassis */
	hardware.h_lport.p_id_subtype = LLDP_PORTID_SUBTYPE_LLADDR;
	hardware.h_lport.p_id = macaddress;
	hardware.h_lport.p_id_len = ETH_ALEN;
	hardware.h_lport.p_descr = "Fake port description";
	hardware.h_lport.p_mfs = 1516;
	chassis.c_id_subtype = LLDP_CHASSISID_SUBTYPE_LOCAL;
	chassis.c_id = "Chassis name";
	chassis.c_id_len = strlen(chassis.c_id);
	chassis.c_name = "Third chassis";
	chassis.c_descr = "Chassis description";
	chassis.c_cap_available = LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE;
	chassis.c_cap_enabled = LLDP_CAP_ROUTER;
	chassis.c_med_cap_available = LLDPMED_CAP_CAP | LLDPMED_CAP_POLICY |
		LLDPMED_CAP_LOCATION | LLDPMED_CAP_MDI_PSE |
		LLDPMED_CAP_IV;
	chassis.c_med_type = LLDPMED_CLASS_III;
	chassis.c_med_hw = "hardware rev 5";
	chassis.c_med_fw = "47b5";
	chassis.c_med_sw = "2.6.22b5";
	chassis.c_med_sn = "SN 47842";
	hardware.h_lport.p_med_cap_enabled = chassis.c_med_cap_available;
	hardware.h_lport.p_med_location[LLDPMED_LOCFORMAT_CIVIC-1].format =
		LLDPMED_LOCFORMAT_CIVIC;
	hardware.h_lport.p_med_location[LLDPMED_LOCFORMAT_CIVIC-1].data_len =
		loc[0] + 1; /* +1 is because of the size */
	hardware.h_lport.p_med_location[LLDPMED_LOCFORMAT_CIVIC-1].data = loc;
	/* The following is ignored */
	hardware.h_lport.p_med_policy[LLDPMED_APPTYPE_SOFTPHONEVOICE-1].type =
		LLDPMED_APPTYPE_SOFTPHONEVOICE;
	hardware.h_lport.p_med_policy[LLDPMED_APPTYPE_SOFTPHONEVOICE-1].tagged =
		1;
	hardware.h_lport.p_med_policy[LLDPMED_APPTYPE_SOFTPHONEVOICE-1].vid =
		51;
	hardware.h_lport.p_med_policy[LLDPMED_APPTYPE_SOFTPHONEVOICE-1].priority =
		6;
	hardware.h_lport.p_med_policy[LLDPMED_APPTYPE_SOFTPHONEVOICE-1].dscp =
		46;
	hardware.h_lport.p_med_pow_devicetype = LLDPMED_POW_TYPE_PSE;
	hardware.h_lport.p_med_pow_source = LLDPMED_POW_SOURCE_PRIMARY;
	hardware.h_lport.p_med_pow_priority = LLDPMED_POW_PRIO_HIGH;
	hardware.h_lport.p_med_pow_val = 65;

	/* Build packet */
	n = lldp_send(NULL, &hardware);
	fail_unless(n == 0, "unable to build packet");
	fail_unless(!TAILQ_EMPTY(&pkts));
	pkt = TAILQ_FIRST(&pkts);
	ck_assert_int_eq(pkt->size, sizeof(pkt1));
	fail_unless(memcmp(pkt->data, pkt1, sizeof(pkt1)) == 0);
	fail_unless(TAILQ_NEXT(pkt, next) == NULL, "more than one packet sent");
}
END_TEST

START_TEST (test_send_dot3)
{
	int n;
	/* Packet we should build:
Ethernet II, Src: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad), Dst: LLDP_Multicast (01:80:c2:00:00:0e)
    Destination: LLDP_Multicast (01:80:c2:00:00:0e)
        Address: LLDP_Multicast (01:80:c2:00:00:0e)
    Source: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
        Address: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
he factory default)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = MAC address
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 0111 = TLV Length: 7
        Chassis Id Subtype: MAC address (4)
        Chassis Id: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
    Port Subtype = Interface name
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0001 0001 = TLV Length: 17
        Port Id Subtype: Interface name (5)
        Port Id: FastEthernet 1/5
    Time To Live = 180 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 180
    System Name = Fourth chassis
        0000 101. .... .... = TLV Type: System Name (5)
        .... ...0 0000 1110 = TLV Length: 14
        System Name = Fourth chassis
    System Description = Long chassis description
        0000 110. .... .... = TLV Type: System Description (6)
        .... ...0 0001 1000 = TLV Length: 24
        System Description = Long chassis description
    Capabilities
        0000 111. .... .... = TLV Type: System Capabilities (7)
        .... ...0 0000 0100 = TLV Length: 4
        Capabilities: 0x0018
            .... .... .... 1... = WLAN access point
            .... .... ...1 .... = Router
        Enabled Capabilities: 0x0018
            .... .... .... 1... = WLAN access point
            .... .... ...1 .... = Router
    Port Description = Fake port description
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0001 0101 = TLV Length: 21
        Port Description: Fake port description
    IEEE 802.3 - Link Aggregation
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Link Aggregation (0x03)
        Aggregation Status: 0x03
            .... ...1 = Aggregation Capability: Yes
            .... ..1. = Aggregation Status: Enabled
        Aggregated Port Id: 5
    IEEE 802.3 - MAC/PHY Configuration/Status
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1001 = TLV Length: 9
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: MAC/PHY Configuration/Status (0x01)
        Auto-Negotiation Support/Status: 0x03
            .... ...1 = Auto-Negotiation: Supported
            .... ..1. = Auto-Negotiation: Enabled
        PMD Auto-Negotiation Advertised Capability: 0x6C00
            .... .1.. .... .... = 100BASE-TX (full duplex mode)
            .... 1... .... .... = 100BASE-TX (half duplex mode)
            ..1. .... .... .... = 10BASE-T (full duplex mode)
            .1.. .... .... .... = 10BASE-T (half duplex mode)
        Operational MAU Type: 100BaseTXFD - 2 pair category 5 UTP, full duplex mode (0x0010)
    IEEE 802.3 - Maximum Frame Size
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0110 = TLV Length: 6
        Organization Unique Code: IEEE 802.3 (0x00120f)
        IEEE 802.3 Subtype: Maximum Frame Size (0x04)
        Maximum Frame Size: 1516
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
	*/
	char pkt1[] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x5e, 0x10,
		0x8e, 0xe7, 0x84, 0xad, 0x88, 0xcc, 0x02, 0x07,
		0x04, 0x5e, 0x10, 0x8e, 0xe7, 0x84, 0xad, 0x04,
		0x11, 0x05, 0x46, 0x61, 0x73, 0x74, 0x45, 0x74,
		0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x31,
		0x2f, 0x35, 0x06, 0x02, 0x00, 0xb4, 0x0a, 0x0e,
		0x46, 0x6f, 0x75, 0x72, 0x74, 0x68, 0x20, 0x63,
		0x68, 0x61, 0x73, 0x73, 0x69, 0x73, 0x0c, 0x18,
		0x4c, 0x6f, 0x6e, 0x67, 0x20, 0x63, 0x68, 0x61,
		0x73, 0x73, 0x69, 0x73, 0x20, 0x64, 0x65, 0x73,
		0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
		0x0e, 0x04, 0x00, 0x18, 0x00, 0x18, 0x08, 0x15,
		0x46, 0x61, 0x6b, 0x65, 0x20, 0x70, 0x6f, 0x72,
		0x74, 0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69,
		0x70, 0x74, 0x69, 0x6f, 0x6e, 0xfe, 0x09, 0x00,
		0x12, 0x0f, 0x03, 0x03, 0x00, 0x00, 0x00, 0x05,
		0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0x6c,
		0x00, 0x00, 0x10, 0xfe, 0x06, 0x00, 0x12, 0x0f,
		0x04, 0x05, 0xec, 0x00, 0x00 };
	struct packet *pkt;

	/* Populate port and chassis */
	hardware.h_lport.p_id_subtype = LLDP_PORTID_SUBTYPE_IFNAME;
	hardware.h_lport.p_id = "FastEthernet 1/5";
	hardware.h_lport.p_id_len = strlen(hardware.h_lport.p_id);
	hardware.h_lport.p_descr = "Fake port description";
	hardware.h_lport.p_mfs = 1516;
	hardware.h_lport.p_aggregid = 5;
	hardware.h_lport.p_autoneg_support = 1;
	hardware.h_lport.p_autoneg_enabled = 1;
	hardware.h_lport.p_autoneg_advertised = LLDP_DOT3_LINK_AUTONEG_10BASE_T |
		LLDP_DOT3_LINK_AUTONEG_10BASET_FD | LLDP_DOT3_LINK_AUTONEG_100BASE_TX |
		LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD;
	hardware.h_lport.p_mau_type = LLDP_DOT3_MAU_100BASETXFD;
	chassis.c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
	chassis.c_id = macaddress;
	chassis.c_id_len = ETH_ALEN;
	chassis.c_name = "Fourth chassis";
	chassis.c_descr = "Long chassis description";
	chassis.c_cap_available = chassis.c_cap_enabled = LLDP_CAP_ROUTER | LLDP_CAP_WLAN;

	/* Build packet */
	n = lldp_send(NULL, &hardware);
	fail_unless(n == 0, "unable to build packet");
	fail_unless(!TAILQ_EMPTY(&pkts));
	pkt = TAILQ_FIRST(&pkts);
	ck_assert_int_eq(pkt->size, sizeof(pkt1));
	fail_unless(memcmp(pkt->data, pkt1, sizeof(pkt1)) == 0);
	fail_unless(TAILQ_NEXT(pkt, next) == NULL, "more than one packet sent");
}
END_TEST

Suite *
lldp_suite(void)
{
	Suite *s = suite_create("LLDP");

	/* Send tests are first run without knowing the result. The
	   result is then checked with:
	     tshark -V -T text -r tests/lldp_send_0000.pcap

	   If the result is correct, then, we get the packet as C
	   bytes using wireshark export to C arrays (tshark seems not
	   be able to do this).
	*/

	TCase *tc_send = tcase_create("Send LLDP packets");
	tcase_add_checked_fixture(tc_send, setup, teardown);
	tcase_add_test(tc_send, test_send_basic);
	tcase_add_test(tc_send, test_send_vlan);
	tcase_add_test(tc_send, test_send_med);
	tcase_add_test(tc_send, test_send_dot3);
	suite_add_tcase(s, tc_send);

	TCase *tc_receive = tcase_create("Receive LLDP packets");
	suite_add_tcase(s, tc_receive);

	return s;
}

int
main()
{
	int number_failed;
	Suite *s = lldp_suite ();
	SRunner *sr = srunner_create (s);
	srunner_set_fork_status (sr, CK_NOFORK); /* Can't fork because
						    we need to write
						    files */
	srunner_run_all (sr, CK_ENV);
	number_failed = srunner_ntests_failed (sr);
	srunner_free (sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
