#define _GNU_SOURCE 1
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <check.h>
#include "../src/lldpd.h"
#include "common.h"

char filenameprefix[] = "lldp_send";

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
		0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
#ifdef ENABLE_DOT3
		0xfe, 0x09,
		0x00, 0x12, 0x0f, 0x03, 0x01, 0x00, 0x00,
		0x00, 0x00, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0x00,
		0x12, 0x0f, 0x04, 0x05, 0xec,
#endif
		0x00, 0x00 };
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
	if (n != 0) {
		fail("unable to build packet");
		return;
	}
	if (TAILQ_EMPTY(&pkts)) {
		fail("no packets sent");
		return;
	}
	pkt = TAILQ_FIRST(&pkts);
	ck_assert_int_eq(pkt->size, sizeof(pkt1));
	fail_unless(memcmp(pkt->data, pkt1, sizeof(pkt1)) == 0);
	fail_unless(TAILQ_NEXT(pkt, next) == NULL, "more than one packet sent");
}
END_TEST

#ifdef ENABLE_DOT1
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
		0x64, 0x20, 0x56, 0x4c, 0x41, 0x4e,
#ifdef ENABLE_DOT3
		0xfe, 0x09,
		0x00, 0x12, 0x0f, 0x03, 0x01, 0x00, 0x00, 0x00,
		0x00, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0x00, 0x12,
		0x0f, 0x04, 0x05, 0xec,
#endif
		0x00, 0x00 };
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
	if (n != 0) {
		fail("unable to build packet");
		return;
	}
	if (TAILQ_EMPTY(&pkts)) {
		fail("no packets sent");
		return;
	}
	pkt = TAILQ_FIRST(&pkts);
	ck_assert_int_eq(pkt->size, sizeof(pkt1));
	fail_unless(memcmp(pkt->data, pkt1, sizeof(pkt1)) == 0);
	fail_unless(TAILQ_NEXT(pkt, next) == NULL, "more than one packet sent");
}
END_TEST
#endif

#ifdef ENABLE_LLDPMED
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
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
    Source: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
        Address: 5e:10:8e:e7:84:ad (5e:10:8e:e7:84:ad)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = Locally assigned, Id: Chassis name
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
    TIA - Network Policy
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1000 = TLV Length: 8
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Network Policy (0x02)
        Application Type: Softphone Voice (5)
        0... .... .... .... = Policy: Defined
        .1.. .... .... .... = Tagged: Yes
        ...0 0000 0110 011. = VLAN Id: 51
        .... ...1 10.. .... = L2 Priority: 6
        ..10 1110 = DSCP Value: 46
    TIA - Extended Power-via-MDI
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0111 = TLV Length: 7
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Extended Power-via-MDI (0x04)
        00.. .... = Power Type: PSE Device
        ..01 .... = Power Source: Primary Power Source
        .... 0010 = Power Priority: High
        Power Value: 65
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
		0x69, 0x6f, 0x6e,
#ifdef ENABLE_DOT3
		0xfe, 0x09, 0x00, 0x12, 0x0f,
		0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x09,
		0x00, 0x12, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xfe, 0x06, 0x00, 0x12, 0x0f, 0x04, 0x05,
		0xec,
#endif
		0xfe, 0x07, 0x00, 0x12, 0xbb, 0x01, 0x00,
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
		0x03, 0x52, 0x33, 0x4c, 0xfe, 0x08, 0x00, 0x12,
		0xbb, 0x02, 0x05, 0x40, 0x67, 0xae, 0xfe, 0x07,
		0x00, 0x12, 0xbb, 0x04, 0x12, 0x00, 0x41,
		0x00, 0x00 };

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
	hardware.h_lport.p_med_power.devicetype = LLDPMED_POW_TYPE_PSE;
	hardware.h_lport.p_med_power.source = LLDPMED_POW_SOURCE_PRIMARY;
	hardware.h_lport.p_med_power.priority = LLDPMED_POW_PRIO_HIGH;
	hardware.h_lport.p_med_power.val = 65;

	/* Build packet */
	n = lldp_send(NULL, &hardware);
	if (n != 0) {
		fail("unable to build packet");
		return;
	}
	if (TAILQ_EMPTY(&pkts)) {
		fail("no packets sent");
		return;
	}
	pkt = TAILQ_FIRST(&pkts);
	ck_assert_int_eq(pkt->size, sizeof(pkt1));
	fail_unless(memcmp(pkt->data, pkt1, sizeof(pkt1)) == 0);
	fail_unless(TAILQ_NEXT(pkt, next) == NULL, "more than one packet sent");
}
END_TEST
#endif

#ifdef ENABLE_DOT3
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
	hardware.h_lport.p_macphy.autoneg_support = 1;
	hardware.h_lport.p_macphy.autoneg_enabled = 1;
	hardware.h_lport.p_macphy.autoneg_advertised = LLDP_DOT3_LINK_AUTONEG_10BASE_T |
		LLDP_DOT3_LINK_AUTONEG_10BASET_FD | LLDP_DOT3_LINK_AUTONEG_100BASE_TX |
		LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD;
	hardware.h_lport.p_macphy.mau_type = LLDP_DOT3_MAU_100BASETXFD;
	chassis.c_id_subtype = LLDP_CHASSISID_SUBTYPE_LLADDR;
	chassis.c_id = macaddress;
	chassis.c_id_len = ETH_ALEN;
	chassis.c_name = "Fourth chassis";
	chassis.c_descr = "Long chassis description";
	chassis.c_cap_available = chassis.c_cap_enabled = LLDP_CAP_ROUTER | LLDP_CAP_WLAN;

	/* Build packet */
	n = lldp_send(NULL, &hardware);
	if (n != 0) {
		fail("unable to build packet");
		return;
	}
	if (TAILQ_EMPTY(&pkts)) {
		fail("no packets sent");
		return;
	}
	pkt = TAILQ_FIRST(&pkts);
	ck_assert_int_eq(pkt->size, sizeof(pkt1));
	fail_unless(memcmp(pkt->data, pkt1, sizeof(pkt1)) == 0);
	fail_unless(TAILQ_NEXT(pkt, next) == NULL, "more than one packet sent");
}
END_TEST
#endif

START_TEST (test_recv_min)
{
	char pkt1[] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x17,
		0xd1, 0xa8, 0x35, 0xbe, 0x88, 0xcc, 0x02, 0x07,
		0x04, 0x00, 0x17, 0xd1, 0xa8, 0x35, 0xbf, 0x04,
		0x07, 0x03, 0x00, 0x17, 0xd1, 0xa8, 0x36, 0x02,
		0x06, 0x02, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00 };
	/* This is:
Ethernet II, Src: Nortel_a8:35:be (00:17:d1:a8:35:be), Dst: LLDP_Multicast (01:80:c2:00:00:0e)
    Destination: LLDP_Multicast (01:80:c2:00:00:0e)
    Source: Nortel_a8:35:be (00:17:d1:a8:35:be)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = MAC address
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 0111 = TLV Length: 7
        Chassis Id Subtype: MAC address (4)
        Chassis Id: Nortel_a8:35:bf (00:17:d1:a8:35:bf)
    Port Subtype = MAC address
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0000 0111 = TLV Length: 7
        Port Id Subtype: MAC address (3)
        Port Id: Nortel_a8:36:02 (00:17:d1:a8:36:02)
    Time To Live = 120 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 120
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
	*/
	struct lldpd_chassis *nchassis = NULL;
	struct lldpd_port *nport = NULL;
	char mac1[] = { 0x0, 0x17, 0xd1, 0xa8, 0x35, 0xbf };
	char mac2[] = { 0x0, 0x17, 0xd1, 0xa8, 0x36, 0x02 };

	fail_unless(lldp_decode(NULL, pkt1, sizeof(pkt1), &hardware,
		&nchassis, &nport) != -1);
	if (!nchassis || !nport) {
		fail("unable to decode packet");
		return;
	}
	ck_assert_int_eq(nchassis->c_id_subtype,
	    LLDP_CHASSISID_SUBTYPE_LLADDR);
	ck_assert_int_eq(nchassis->c_id_len, ETH_ALEN);
	fail_unless(memcmp(mac1, nchassis->c_id, ETH_ALEN) == 0);
	ck_assert_int_eq(nport->p_id_subtype,
	    LLDP_PORTID_SUBTYPE_LLADDR);
	ck_assert_int_eq(nport->p_id_len, ETH_ALEN);
	fail_unless(memcmp(mac2, nport->p_id, ETH_ALEN) == 0);
	ck_assert_int_eq(nchassis->c_ttl, 120);
	ck_assert_str_eq(nchassis->c_name, "Not received");
	ck_assert_str_eq(nchassis->c_descr, "Not received");
	ck_assert_str_eq(nport->p_descr, "Not received");
}
END_TEST

START_TEST (test_recv_lldpd)
{
	/* This is a frame generated by lldpd */
	char pkt1[] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x16,
		0x17, 0x2f, 0xa1, 0xb6, 0x88, 0xcc, 0x02, 0x07,
		0x04, 0x00, 0x16, 0x17, 0x2f, 0xa1, 0xb6, 0x04,
		0x07, 0x03, 0x00, 0x16, 0x17, 0x2f, 0xa1, 0xb6,
		0x06, 0x02, 0x00, 0x78, 0x0a, 0x1a, 0x6e, 0x61,
		0x72, 0x75, 0x74, 0x6f, 0x2e, 0x58, 0x58, 0x58,
		0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
		0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
		0x0c, 0x3f, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20,
		0x32, 0x2e, 0x36, 0x2e, 0x32, 0x39, 0x2d, 0x32,
		0x2d, 0x61, 0x6d, 0x64, 0x36, 0x34, 0x20, 0x23,
		0x31, 0x20, 0x53, 0x4d, 0x50, 0x20, 0x53, 0x75,
		0x6e, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x31, 0x37,
		0x20, 0x31, 0x37, 0x3a, 0x31, 0x35, 0x3a, 0x34,
		0x37, 0x20, 0x55, 0x54, 0x43, 0x20, 0x32, 0x30,
		0x30, 0x39, 0x20, 0x78, 0x38, 0x36, 0x5f, 0x36,
		0x34, 0x0e, 0x04, 0x00, 0x1c, 0x00, 0x14, 0x10,
		0x0c, 0x05, 0x01, 0x0a, 0xee, 0x50, 0x4b, 0x02,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x08, 0x04, 0x65,
		0x74, 0x68, 0x30, 0xfe, 0x09, 0x00, 0x12, 0x0f,
		0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x09,
		0x00, 0x12, 0x0f, 0x01, 0x03, 0x6c, 0x03, 0x00,
		0x10, 0xfe, 0x06, 0x00, 0x12, 0x0f, 0x04, 0x05,
		0xdc, 0xfe, 0x07, 0x00, 0x12, 0xbb, 0x01, 0x00,
		0x00, 0x00, 0xfe, 0x0f, 0x00, 0x12, 0xbb, 0x05,
		0x4e, 0x44, 0x39, 0x39, 0x31, 0x37, 0x38, 0x39,
		0x37, 0x30, 0x32, 0xfe, 0x0b, 0x00, 0x12, 0xbb,
		0x06, 0x30, 0x38, 0x30, 0x30, 0x31, 0x32, 0x20,
		0xfe, 0x12, 0x00, 0x12, 0xbb, 0x07, 0x32, 0x2e,
		0x36, 0x2e, 0x32, 0x39, 0x2d, 0x32, 0x2d, 0x61,
		0x6d, 0x64, 0x36, 0x34, 0xfe, 0x10, 0x00, 0x12,
		0xbb, 0x08, 0x31, 0x30, 0x35, 0x38, 0x32, 0x30,
		0x38, 0x35, 0x30, 0x30, 0x30, 0x39, 0xfe, 0x15,
		0x00, 0x12, 0xbb, 0x09, 0x4e, 0x45, 0x43, 0x20,
		0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72,
		0x73, 0x20, 0x53, 0x41, 0x53, 0xfe, 0x13, 0x00,
		0x12, 0xbb, 0x0a, 0x50, 0x4f, 0x57, 0x45, 0x52,
		0x4d, 0x41, 0x54, 0x45, 0x20, 0x56, 0x4c, 0x33,
		0x35, 0x30, 0xfe, 0x0d, 0x00, 0x12, 0xbb, 0x0b,
		0x31, 0x30, 0x30, 0x32, 0x30, 0x37, 0x31, 0x32,
		0x30, 0x00, 0x00 };
	/* This is:
Ethernet II, Src: Msi_2f:a1:b6 (00:16:17:2f:a1:b6), Dst: LLDP_Multicast (01:80:c2:00:00:0e)
    Destination: LLDP_Multicast (01:80:c2:00:00:0e)
    Source: Msi_2f:a1:b6 (00:16:17:2f:a1:b6)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = MAC address
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 0111 = TLV Length: 7
        Chassis Id Subtype: MAC address (4)
        Chassis Id: Msi_2f:a1:b6 (00:16:17:2f:a1:b6)
    Port Subtype = MAC address
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0000 0111 = TLV Length: 7
        Port Id Subtype: MAC address (3)
        Port Id: Msi_2f:a1:b6 (00:16:17:2f:a1:b6)
    Time To Live = 120 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 120
    System Name = naruto.XXXXXXXXXXXXXXXXXXX
        0000 101. .... .... = TLV Type: System Name (5)
        .... ...0 0001 1010 = TLV Length: 26
        System Name = naruto.bureau.b1.p.fti.net
    System Description = Linux 2.6.29-2-amd64 #1 SMP Sun May 17 17:15:47 UTC 2009 x86_64
        0000 110. .... .... = TLV Type: System Description (6)
        .... ...0 0011 1111 = TLV Length: 63
        System Description = Linux 2.6.29-2-amd64 #1 SMP Sun May 17 17:15:47 UTC 2009 x86_64
    Capabilities
        0000 111. .... .... = TLV Type: System Capabilities (7)
        .... ...0 0000 0100 = TLV Length: 4
        Capabilities: 0x001c
            .... .... .... .1.. = Bridge
            .... .... .... 1... = WLAN access point
            .... .... ...1 .... = Router
        Enabled Capabilities: 0x0014
            .... .... .... .1.. = Bridge
            .... .... ...1 .... = Router
    Management Address
        0001 000. .... .... = TLV Type: Management Address (8)
        .... ...0 0000 1100 = TLV Length: 12
        Address String Length: 5
        Address Subtype: IPv4 (1)
        Management Address: 10.238.80.75
        Interface Subtype: ifIndex (2)
        Interface Number: 3
        OID String Length: 0
    Port Description = eth0
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0000 0100 = TLV Length: 4
        Port Description: eth0
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
        Auto-Negotiation Support/Status: 0x03
            .... ...1 = Auto-Negotiation: Supported
            .... ..1. = Auto-Negotiation: Enabled
        PMD Auto-Negotiation Advertised Capability: 0x6C03
            .... .... .... ...1 = 1000BASE-T (full duplex mode)
            .... .... .... ..1. = 1000BASE-T (half duplex mode)
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
        Maximum Frame Size: 1500
    TIA - Media Capabilities
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0111 = TLV Length: 7
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Media Capabilities (0x01)
        Capabilities: 0x0000
        Class Type: Type Not Defined
    TIA - Inventory - Hardware Revision
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1111 = TLV Length: 15
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Hardware Revision (0x05)
        Hardware Revision: ND991789702
    TIA - Inventory - Firmware Revision
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1011 = TLV Length: 10
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Firmware Revision (0x06)
        Firmware Revision: 080012
    TIA - Inventory - Software Revision
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0010 = TLV Length: 18
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Software Revision (0x07)
        Software Revision: 2.6.29-2-amd64
    TIA - Inventory - Serial Number
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0000 = TLV Length: 16
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Serial Number (0x08)
        Serial Number: 105820850009
    TIA - Inventory - Manufacturer Name
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0101 = TLV Length: 21
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Manufacturer Name (0x09)
        Manufacturer Name: NEC Computers SAS
    TIA - Inventory - Model Name
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0011 = TLV Length: 19
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Model Name (0x0a)
        Model Name: POWERMATE VL350
    TIA - Inventory - Asset ID
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1101 = TLV Length: 13
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Inventory - Asset ID (0x0b)
        Asset ID: 100207120
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
	*/
	struct lldpd_chassis *nchassis = NULL;
	struct lldpd_port *nport = NULL;
	char mac1[] = { 0x00, 0x16, 0x17, 0x2f, 0xa1, 0xb6 };

	fail_unless(lldp_decode(NULL, pkt1, sizeof(pkt1), &hardware,
		&nchassis, &nport) != -1);
	if (!nchassis || !nport) {
		fail("unable to decode packet");
		return;
	}
	ck_assert_int_eq(nchassis->c_id_subtype,
	    LLDP_CHASSISID_SUBTYPE_LLADDR);
	ck_assert_int_eq(nchassis->c_id_len, ETH_ALEN);
	fail_unless(memcmp(mac1, nchassis->c_id, ETH_ALEN) == 0);
	ck_assert_int_eq(nport->p_id_subtype,
	    LLDP_PORTID_SUBTYPE_LLADDR);
	ck_assert_int_eq(nport->p_id_len, ETH_ALEN);
	fail_unless(memcmp(mac1, nport->p_id, ETH_ALEN) == 0);
	ck_assert_int_eq(nchassis->c_ttl, 120);
	ck_assert_str_eq(nchassis->c_name, "naruto.XXXXXXXXXXXXXXXXXXX");
	ck_assert_str_eq(nchassis->c_descr,
	    "Linux 2.6.29-2-amd64 #1 SMP Sun May 17 17:15:47 UTC 2009 x86_64");
	ck_assert_str_eq(nport->p_descr, "eth0");
	ck_assert_int_eq(nchassis->c_cap_available,
	    LLDP_CAP_WLAN | LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE);
	ck_assert_int_eq(nchassis->c_cap_enabled,
	    LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE);
	ck_assert_int_eq(nchassis->c_mgmt.s_addr,
	    (u_int32_t)inet_addr("10.238.80.75"));
	ck_assert_int_eq(nchassis->c_mgmt_if, 3);
#ifdef ENABLE_DOT3
	ck_assert_int_eq(nport->p_aggregid, 0);
	ck_assert_int_eq(nport->p_macphy.autoneg_enabled, 1);
	ck_assert_int_eq(nport->p_macphy.autoneg_support, 1);
	ck_assert_int_eq(nport->p_macphy.autoneg_advertised,
	    LLDP_DOT3_LINK_AUTONEG_1000BASE_TFD |
	    LLDP_DOT3_LINK_AUTONEG_1000BASE_T |
	    LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD |
	    LLDP_DOT3_LINK_AUTONEG_100BASE_TX |
	    LLDP_DOT3_LINK_AUTONEG_10BASET_FD |
	    LLDP_DOT3_LINK_AUTONEG_10BASE_T);
	ck_assert_int_eq(nport->p_macphy.mau_type,
	    LLDP_DOT3_MAU_100BASETXFD);
	ck_assert_int_eq(nport->p_mfs, 1500);
#endif
#ifdef ENABLE_LLDPMED
	ck_assert_int_eq(nchassis->c_med_type, 0);
	ck_assert_str_eq(nchassis->c_med_hw, "ND991789702");
	ck_assert_str_eq(nchassis->c_med_fw, "080012 "); /* Extra space */
	ck_assert_str_eq(nchassis->c_med_sw, "2.6.29-2-amd64");
	ck_assert_str_eq(nchassis->c_med_sn, "105820850009");
	ck_assert_str_eq(nchassis->c_med_manuf, "NEC Computers SAS");
	ck_assert_str_eq(nchassis->c_med_model, "POWERMATE VL350");
	ck_assert_str_eq(nchassis->c_med_asset, "100207120");
#endif
}
END_TEST

#ifdef ENABLE_DOT1
START_TEST (test_recv_vlans)
{
	char pkt1[] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x1f,
		0x46, 0xd2, 0xfc, 0x01, 0x88, 0xcc, 0x02, 0x07,
		0x04, 0x00, 0x1f, 0x46, 0xd2, 0xfc, 0x00, 0x04,
		0x07, 0x03, 0x00, 0x1f, 0x46, 0xd2, 0xfc, 0x15,
		0x06, 0x02, 0x00, 0x78, 0x08, 0x07, 0x50, 0x6f,
		0x72, 0x74, 0x20, 0x32, 0x31, 0x0a, 0x07, 0x73,
		0x77, 0x69, 0x74, 0x63, 0x68, 0x31, 0x0c, 0x4c,
		0x45, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74,
		0x20, 0x52, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67,
		0x20, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x20,
		0x35, 0x35, 0x31, 0x30, 0x2d, 0x32, 0x34, 0x54,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x48, 0x57,
		0x3a, 0x33, 0x33, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x46, 0x57, 0x3a, 0x35, 0x2e, 0x30,
		0x2e, 0x30, 0x2e, 0x34, 0x20, 0x20, 0x20, 0x53,
		0x57, 0x3a, 0x76, 0x35, 0x2e, 0x31, 0x2e, 0x30,
		0x2e, 0x30, 0x31, 0x34, 0x0e, 0x04, 0x00, 0x14,
		0x00, 0x04, 0x10, 0x15, 0x05, 0x01, 0xac, 0x14,
		0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09,
		0x2b, 0x06, 0x01, 0x04, 0x01, 0x2d, 0x03, 0x34,
		0x01, 0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, 0x01,
		0xf4, 0xfe, 0x0f, 0x00, 0x80, 0xc2, 0x03, 0x01,
		0xf4, 0x08, 0x54, 0x65, 0x73, 0x74, 0x56, 0x6c,
		0x61, 0x6e, 0xfe, 0x10, 0x00, 0x80, 0xc2, 0x03,
		0x01, 0xf5, 0x09, 0x54, 0x65, 0x73, 0x74, 0x56,
		0x6c, 0x61, 0x6e, 0x32, 0xfe, 0x10, 0x00, 0x80,
		0xc2, 0x03, 0x01, 0xf6, 0x09, 0x54, 0x65, 0x73,
		0x74, 0x56, 0x6c, 0x61, 0x6e, 0x33, 0xfe, 0x0d,
		0x00, 0x80, 0xc2, 0x04, 0x08, 0x00, 0x26, 0x42,
		0x42, 0x03, 0x00, 0x00, 0x00, 0xfe, 0x08, 0x00,
		0x80, 0xc2, 0x04, 0x03, 0x88, 0x8e, 0x01, 0xfe,
		0x07, 0x00, 0x80, 0xc2, 0x04, 0x02, 0x88, 0xcc,
		0x00, 0x00 };
	/* This is:
Ethernet II, Src: Nortel_d2:fc:01 (00:1f:46:d2:fc:01), Dst: LLDP_Multicast (01:80:c2:00:00:0e)
    Destination: LLDP_Multicast (01:80:c2:00:00:0e)
    Source: Nortel_d2:fc:01 (00:1f:46:d2:fc:01)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = MAC address
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 0111 = TLV Length: 7
        Chassis Id Subtype: MAC address (4)
        Chassis Id: Nortel_d2:fc:00 (00:1f:46:d2:fc:00)
    Port Subtype = MAC address
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0000 0111 = TLV Length: 7
        Port Id Subtype: MAC address (3)
        Port Id: Nortel_d2:fc:15 (00:1f:46:d2:fc:15)
    Time To Live = 120 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 120
    Port Description = Port 21
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0000 0111 = TLV Length: 7
        Port Description: Port 21
    System Name = switch1
        0000 101. .... .... = TLV Type: System Name (5)
        .... ...0 0000 0111 = TLV Length: 7
        System Name = switch1
    System Description = Ethernet Routing Switch 5510-24T      HW:33       FW:5.0.0.4   SW:v5.1.0.014
        0000 110. .... .... = TLV Type: System Description (6)
        .... ...0 0100 1100 = TLV Length: 76
        System Description = Ethernet Routing Switch 5510-24T      HW:33       FW:5.0.0.4   SW:v5.1.0.014
    Capabilities
        0000 111. .... .... = TLV Type: System Capabilities (7)
        .... ...0 0000 0100 = TLV Length: 4
        Capabilities: 0x0014
            .... .... .... .1.. = Bridge
            .... .... ...1 .... = Router
        Enabled Capabilities: 0x0004
            .... .... .... .1.. = Bridge
    Management Address
        0001 000. .... .... = TLV Type: Management Address (8)
        .... ...0 0001 0101 = TLV Length: 21
        Address String Length: 5
        Address Subtype: IPv4 (1)
        Management Address: 172.20.3.2 (172.20.3.2)
        Interface Subtype: Unknown (1)
        Interface Number: 0
        OID String Length: 9
        Object Identifier: 2B060104012D033401
    IEEE 802.1 - Port VLAN ID
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0110 = TLV Length: 6
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: Port VLAN ID (0x01)
        Port VLAN Identifier: 500 (0x01F4)
    IEEE 802.1 - VLAN Name
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1111 = TLV Length: 15
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: VLAN Name (0x03)
        VLAN Identifier: 500 (0x01F4)
        VLAN Name Length: 8
        VLAN Name: TestVlan
    IEEE 802.1 - VLAN Name
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0000 = TLV Length: 16
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: VLAN Name (0x03)
        VLAN Identifier: 501 (0x01F5)
        VLAN Name Length: 9
        VLAN Name: TestVlan2
    IEEE 802.1 - VLAN Name
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0001 0000 = TLV Length: 16
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: VLAN Name (0x03)
        VLAN Identifier: 502 (0x01F6)
        VLAN Name Length: 9
        VLAN Name: TestVlan3
    IEEE 802.1 - Protocol Identity
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1101 = TLV Length: 13
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: Protocol Identity (0x04)
        Protocol Identity Length: 8
        Protocol Identity: 0026424203000000
    IEEE 802.1 - Protocol Identity
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1000 = TLV Length: 8
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: Protocol Identity (0x04)
        Protocol Identity Length: 3
        Protocol Identity: 888E01
    IEEE 802.1 - Protocol Identity
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0111 = TLV Length: 7
        Organization Unique Code: IEEE 802.1 (0x0080c2)
        IEEE 802.1 Subtype: Protocol Identity (0x04)
        Protocol Identity Length: 2
        Protocol Identity: 88CC
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
	*/
	struct lldpd_chassis *nchassis = NULL;
	struct lldpd_port *nport = NULL;
	char mac1[] = { 0x00, 0x1f, 0x46, 0xd2, 0xfc, 0x00 };
	char mac2[] = { 0x00, 0x1f, 0x46, 0xd2, 0xfc, 0x15 };
	struct lldpd_vlan *vlan;

	fail_unless(lldp_decode(NULL, pkt1, sizeof(pkt1), &hardware,
		&nchassis, &nport) != -1);
	if (!nchassis || !nport) {
		fail("unable to decode packet");
		return;
	}
	ck_assert_int_eq(nchassis->c_id_subtype,
	    LLDP_CHASSISID_SUBTYPE_LLADDR);
	ck_assert_int_eq(nchassis->c_id_len, ETH_ALEN);
	fail_unless(memcmp(mac1, nchassis->c_id, ETH_ALEN) == 0);
	ck_assert_int_eq(nport->p_id_subtype,
	    LLDP_PORTID_SUBTYPE_LLADDR);
	ck_assert_int_eq(nport->p_id_len, ETH_ALEN);
	fail_unless(memcmp(mac2, nport->p_id, ETH_ALEN) == 0);
	ck_assert_int_eq(nchassis->c_ttl, 120);
	ck_assert_str_eq(nchassis->c_name, "switch1");
	ck_assert_str_eq(nchassis->c_descr,
	    "Ethernet Routing Switch 5510-24T      HW:33       FW:5.0.0.4   SW:v5.1.0.014");
	ck_assert_str_eq(nport->p_descr, "Port 21");
	ck_assert_int_eq(nchassis->c_cap_available,
	    LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE);
	ck_assert_int_eq(nchassis->c_cap_enabled,
	    LLDP_CAP_BRIDGE);
	ck_assert_int_eq(nchassis->c_mgmt.s_addr,
	    (u_int32_t)inet_addr("172.20.3.2"));
	ck_assert_int_eq(nchassis->c_mgmt_if, 0);
	if (TAILQ_EMPTY(&nport->p_vlans)) {
		fail("no VLAN");
		return;
	}
	vlan = TAILQ_FIRST(&nport->p_vlans);
	ck_assert_int_eq(vlan->v_vid, 500);
	ck_assert_str_eq(vlan->v_name, "TestVlan");
	vlan = TAILQ_NEXT(vlan, v_entries);
	if (!vlan) {
		fail("no more VLAN");
		return;
	}
	ck_assert_int_eq(vlan->v_vid, 501);
	ck_assert_str_eq(vlan->v_name, "TestVlan2");
	vlan = TAILQ_NEXT(vlan, v_entries);
	if (!vlan) {
		fail("no more VLAN");
		return;
	}
	ck_assert_int_eq(vlan->v_vid, 502);
	ck_assert_str_eq(vlan->v_name, "TestVlan3");
	vlan = TAILQ_NEXT(vlan, v_entries);
	fail_unless(vlan == NULL);
}
END_TEST
#endif

#ifdef ENABLE_LLDPMED
START_TEST (test_recv_med)
{
	char pkt1[] = {
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x13,
		0x21, 0x57, 0xca, 0x7f, 0x88, 0xcc, 0x02, 0x07,
		0x04, 0x00, 0x13, 0x21, 0x57, 0xca, 0x40, 0x04,
		0x02, 0x07, 0x31, 0x06, 0x02, 0x00, 0x78, 0x08,
		0x01, 0x31, 0x0a, 0x1a, 0x50, 0x72, 0x6f, 0x43,
		0x75, 0x72, 0x76, 0x65, 0x20, 0x53, 0x77, 0x69,
		0x74, 0x63, 0x68, 0x20, 0x32, 0x36, 0x30, 0x30,
		0x2d, 0x38, 0x2d, 0x50, 0x57, 0x52, 0x0c, 0x5f,
		0x50, 0x72, 0x6f, 0x43, 0x75, 0x72, 0x76, 0x65,
		0x20, 0x4a, 0x38, 0x37, 0x36, 0x32, 0x41, 0x20,
		0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x20, 0x32,
		0x36, 0x30, 0x30, 0x2d, 0x38, 0x2d, 0x50, 0x57,
		0x52, 0x2c, 0x20, 0x72, 0x65, 0x76, 0x69, 0x73,
		0x69, 0x6f, 0x6e, 0x20, 0x48, 0x2e, 0x30, 0x38,
		0x2e, 0x38, 0x39, 0x2c, 0x20, 0x52, 0x4f, 0x4d,
		0x20, 0x48, 0x2e, 0x30, 0x38, 0x2e, 0x35, 0x58,
		0x20, 0x28, 0x2f, 0x73, 0x77, 0x2f, 0x63, 0x6f,
		0x64, 0x65, 0x2f, 0x62, 0x75, 0x69, 0x6c, 0x64,
		0x2f, 0x66, 0x69, 0x73, 0x68, 0x28, 0x74, 0x73,
		0x5f, 0x30, 0x38, 0x5f, 0x35, 0x29, 0x29, 0x0e,
		0x04, 0x00, 0x14, 0x00, 0x04, 0x10, 0x0c, 0x05,
		0x01, 0x0f, 0xff, 0x7a, 0x94, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00,
#ifdef ENABLE_DOT3
		0xfe, 0x09, 0x00, 0x12, 0x0f,
		0x01, 0x03, 0x6c, 0x00, 0x00, 0x10,
#endif
		0xfe, 0x07,
		0x00, 0x12, 0xbb, 0x01, 0x00, 0x0f, 0x04, 0xfe,
		0x08, 0x00, 0x12, 0xbb, 0x02, 0x01, 0x40, 0x65,
		0xae, 0xfe, 0x2e, 0x00, 0x12, 0xbb, 0x03, 0x02,
		0x28, 0x02, 0x55, 0x53, 0x01, 0x02, 0x43, 0x41,
		0x03, 0x09, 0x52, 0x6f, 0x73, 0x65, 0x76, 0x69,
		0x6c, 0x6c, 0x65, 0x06, 0x09, 0x46, 0x6f, 0x6f,
		0x74, 0x68, 0x69, 0x6c, 0x6c, 0x73, 0x13, 0x04,
		0x38, 0x30, 0x30, 0x30, 0x1a, 0x03, 0x52, 0x33,
		0x4c, 0xfe, 0x07, 0x00, 0x12, 0xbb, 0x04, 0x03,
		0x00, 0x41, 0x00, 0x00 };
	/* This is:
Ethernet II, Src: HewlettP_57:ca:7f (00:13:21:57:ca:7f), Dst: LLDP_Multicast (01:80:c2:00:00:0e)
    Destination: LLDP_Multicast (01:80:c2:00:00:0e)
    Source: HewlettP_57:ca:7f (00:13:21:57:ca:7f)
    Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Link Layer Discovery Protocol
    Chassis Subtype = MAC address
        0000 001. .... .... = TLV Type: Chassis Id (1)
        .... ...0 0000 0111 = TLV Length: 7
        Chassis Id Subtype: MAC address (4)
        Chassis Id: HewlettP_57:ca:40 (00:13:21:57:ca:40)
    Port Subtype = Locally assigned
        0000 010. .... .... = TLV Type: Port Id (2)
        .... ...0 0000 0010 = TLV Length: 2
        Port Id Subtype: Locally assigned (7)
        Port Id: 1
    Time To Live = 120 sec
        0000 011. .... .... = TLV Type: Time to Live (3)
        .... ...0 0000 0010 = TLV Length: 2
        Seconds: 120
    Port Description = 1
        0000 100. .... .... = TLV Type: Port Description (4)
        .... ...0 0000 0001 = TLV Length: 1
        Port Description: 1
    System Name = ProCurve Switch 2600-8-PWR
        0000 101. .... .... = TLV Type: System Name (5)
        .... ...0 0001 1010 = TLV Length: 26
        System Name = ProCurve Switch 2600-8-PWR
    System Description = ProCurve J8762A Switch 2600-8-PWR, revision H.08.89, ROM H.08.5X (/sw/code/build/fish(ts_08_5))
        0000 110. .... .... = TLV Type: System Description (6)
        .... ...0 0101 1111 = TLV Length: 95
        System Description = ProCurve J8762A Switch 2600-8-PWR, revision H.08.89, ROM H.08.5X (/sw/code/build/fish(ts_08_5))
    Capabilities
        0000 111. .... .... = TLV Type: System Capabilities (7)
        .... ...0 0000 0100 = TLV Length: 4
        Capabilities: 0x0014
            .... .... .... .1.. = Bridge
            .... .... ...1 .... = Router
        Enabled Capabilities: 0x0004
            .... .... .... .1.. = Bridge
    Management Address
        0001 000. .... .... = TLV Type: Management Address (8)
        .... ...0 0000 1100 = TLV Length: 12
        Address String Length: 5
        Address Subtype: IPv4 (1)
        Management Address: 15.255.122.148 (15.255.122.148)
        Interface Subtype: ifIndex (2)
        Interface Number: 0
        OID String Length: 0
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
    TIA - Media Capabilities
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0111 = TLV Length: 7
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Media Capabilities (0x01)
        Capabilities: 0x000f
            .... .... .... ...1 = LLDP-MED Capabilities
            .... .... .... ..1. = Network Policy
            .... .... .... .1.. = Location Identification
            .... .... .... 1... = Extended Power via MDI-PSE
        Class Type: Network Connectivity
    TIA - Network Policy
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 1000 = TLV Length: 8
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Network Policy (0x02)
        Applicaton Type: Voice (1)
        0... .... .... .... = Policy: Defined
        .1.. .... .... .... = Tagged: Yes
        ...0 0000 0110 010. = VLAN Id: 50
        .... ...1 10.. .... = L2 Priority: 6
        ..10 1110 = DSCP Value: 46
    TIA - Location Identification
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0010 1110 = TLV Length: 46
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Location Identification (0x03)
        Location Data Format: Civic Address LCI (2)
        LCI Length: 40
[...]
    TIA - Extended Power-via-MDI
        1111 111. .... .... = TLV Type: Organization Specific (127)
        .... ...0 0000 0111 = TLV Length: 7
        Organization Unique Code: TIA (0x0012bb)
        Media Subtype: Extended Power-via-MDI (0x04)
        00.. .... = Power Type: PSE Device
        ..00 .... = Power Source: Unknown
        .... 0011 = Power Priority: Low
        Power Value: 65
    End of LLDPDU
        0000 000. .... .... = TLV Type: End of LLDPDU (0)
        .... ...0 0000 0000 = TLV Length: 0
	*/
	struct lldpd_chassis *nchassis = NULL;
	struct lldpd_port *nport = NULL;
	char mac1[] = { 0x00, 0x13, 0x21, 0x57, 0xca, 0x40 };

	fail_unless(lldp_decode(NULL, pkt1, sizeof(pkt1), &hardware,
		&nchassis, &nport) != -1);
	if (!nchassis || !nport) {
		fail("unable to decode packet");
		return;
	}
	ck_assert_int_eq(nchassis->c_id_subtype,
	    LLDP_CHASSISID_SUBTYPE_LLADDR);
	ck_assert_int_eq(nchassis->c_id_len, ETH_ALEN);
	fail_unless(memcmp(mac1, nchassis->c_id, ETH_ALEN) == 0);
	ck_assert_int_eq(nport->p_id_subtype,
	    LLDP_PORTID_SUBTYPE_LOCAL);
	ck_assert_int_eq(nport->p_id_len, 1);
	ck_assert_int_eq(nport->p_id[0], '1');
	ck_assert_int_eq(nchassis->c_ttl, 120);
	ck_assert_str_eq(nchassis->c_name, "ProCurve Switch 2600-8-PWR");
	ck_assert_str_eq(nchassis->c_descr,
	    "ProCurve J8762A Switch 2600-8-PWR, revision H.08.89, ROM H.08.5X (/sw/code/build/fish(ts_08_5))");
	ck_assert_str_eq(nport->p_descr, "1");
	ck_assert_int_eq(nchassis->c_cap_available,
	    LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE);
	ck_assert_int_eq(nchassis->c_cap_enabled,
	    LLDP_CAP_BRIDGE);
	ck_assert_int_eq(nchassis->c_mgmt.s_addr,
	    (u_int32_t)inet_addr("15.255.122.148"));
	ck_assert_int_eq(nchassis->c_mgmt_if, 0);
#ifdef ENABLE_DOT3
	ck_assert_int_eq(nport->p_macphy.autoneg_enabled, 1);
	ck_assert_int_eq(nport->p_macphy.autoneg_support, 1);
	ck_assert_int_eq(nport->p_macphy.autoneg_advertised,
	    LLDP_DOT3_LINK_AUTONEG_100BASE_TXFD |
	    LLDP_DOT3_LINK_AUTONEG_100BASE_TX |
	    LLDP_DOT3_LINK_AUTONEG_10BASET_FD |
	    LLDP_DOT3_LINK_AUTONEG_10BASE_T);
	ck_assert_int_eq(nport->p_macphy.mau_type,
	    LLDP_DOT3_MAU_100BASETXFD);
#endif
	ck_assert_int_eq(nchassis->c_med_cap_available,
	    LLDPMED_CAP_CAP | LLDPMED_CAP_POLICY |
	    LLDPMED_CAP_LOCATION | LLDPMED_CAP_MDI_PSE);
	ck_assert_int_eq(nchassis->c_med_type, LLDPMED_NETWORK_DEVICE);
	ck_assert_int_eq(nport->p_med_policy[LLDPMED_APPTYPE_VOICE-1].type,
	    LLDPMED_APPTYPE_VOICE);
	ck_assert_int_eq(nport->p_med_policy[LLDPMED_APPTYPE_VOICE-1].unknown,
	    0);
	ck_assert_int_eq(nport->p_med_policy[LLDPMED_APPTYPE_VOICE-1].tagged,
	    1);
	ck_assert_int_eq(nport->p_med_policy[LLDPMED_APPTYPE_VOICE-1].vid,
	    50);
	ck_assert_int_eq(nport->p_med_policy[LLDPMED_APPTYPE_VOICE-1].priority,
	    6);
	ck_assert_int_eq(nport->p_med_policy[LLDPMED_APPTYPE_VOICE-1].dscp,
	    46);
	ck_assert_int_eq(nport->p_med_policy[LLDPMED_APPTYPE_SOFTPHONEVOICE-1].type,
	    0);
	ck_assert_int_eq(nport->p_med_location[LLDPMED_LOCFORMAT_CIVIC-1].format,
	    LLDPMED_LOCFORMAT_CIVIC);
	ck_assert_int_eq(nport->p_med_location[LLDPMED_LOCFORMAT_COORD-1].format,
	    0);
	ck_assert_int_eq(nport->p_med_power.val, 65);
	ck_assert_int_eq(nport->p_med_power.source, LLDPMED_POW_SOURCE_UNKNOWN);
	ck_assert_int_eq(nport->p_med_power.priority, LLDPMED_POW_PRIO_LOW);
	ck_assert_int_eq(nport->p_med_power.devicetype, LLDPMED_POW_TYPE_PSE);
}
END_TEST
#endif

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
	tcase_add_checked_fixture(tc_send, pcap_setup, pcap_teardown);
	tcase_add_test(tc_send, test_send_basic);
#ifdef ENABLE_DOT1
	tcase_add_test(tc_send, test_send_vlan);
#endif
#ifdef ENABLE_LLDPMED
	tcase_add_test(tc_send, test_send_med);
#endif
#ifdef ENABLE_DOT3
	tcase_add_test(tc_send, test_send_dot3);
#endif
	suite_add_tcase(s, tc_send);

	TCase *tc_receive = tcase_create("Receive LLDP packets");
	tcase_add_test(tc_receive, test_recv_min);
	tcase_add_test(tc_receive, test_recv_lldpd);
#ifdef ENABLE_DOT1
	tcase_add_test(tc_receive, test_recv_vlans);
#endif
#ifdef ENABLE_LLDPMED
	tcase_add_test(tc_receive, test_recv_med);
#endif
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
