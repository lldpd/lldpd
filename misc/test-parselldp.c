#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "../lldp.h"

#define IF "lan"
#define LLDPMAC {0x01,0x80,0xC2,0x00,0x00,0x0E}
#define MTU 1500

int set_multi(int add) {
  int s;
  struct ifreq ifr;
  const char lldpaddr[] = LLDPMAC;

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    return -1;
  bzero(&ifr, sizeof(ifr));
  strncpy(ifr.ifr_name, IF, IFNAMSIZ);
  bcopy(lldpaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  if (ioctl(s, add ? SIOCADDMULTI : SIOCDELMULTI, &ifr) < 0)
    return -1;
  return 0;
}

void dump(const char *frame, int s) {
  int i = 0;
  while (s != i) {
    printf("%02hhx ", frame[i++]);
    if (i % 20 == 0)
      printf("\n");
  }
  printf("\n");
}

int check_mac(const char *frame, int s) {
  const char lldpaddr[] = LLDPMAC;
  if (s < sizeof(lldpaddr)) 
    return -1;
  if (memcmp(frame, lldpaddr, sizeof(lldpaddr)) == 0) {
    return 1;
  }
  return -1;
}

int check_protocol(const char *frame, int s) {
  const char proto[] = { 0x88, 0xcc };
  if (s < 2 * ETH_ALEN + 2)
    return -1;
  if (memcmp(frame + 2 * ETH_ALEN, proto, sizeof(proto)) == 0) {
    return 1;
  }
  return -1;
}

int check_tlv_end(const char *frame, int s) {
  if (s != 0) {
    warnx("End of LLDPDU is too large (%d > 0)", s);
    return -1;
  }
  return 0;
}

int check_tlv_chassisid(const char *frame, int s) {
  u_int8_t subtype;
  if (s < 2) {
    warnx("Chassis ID TLV too small (%d < 2)", s);
    return -1;
  }
  subtype = *(u_int8_t*)frame;
  switch (subtype) {
  case LLDP_CHASSISID_SUBTYPE_CHASSIS:
  case LLDP_CHASSISID_SUBTYPE_IFALIAS:
  case LLDP_CHASSISID_SUBTYPE_PORT:
  case LLDP_CHASSISID_SUBTYPE_ADDR:
  case LLDP_CHASSISID_SUBTYPE_IFNAME:
  case LLDP_CHASSISID_SUBTYPE_LOCAL:
    printf("Unhandled chassis ID type (%x)\n", subtype);
    break;
  case LLDP_CHASSISID_SUBTYPE_LLADDR:
    if (s != 7) {
      warnx("Incorrect MAC address size (%d != 6)", s-1);
      return -1;
    }
    printf("Chassis mac address:\n %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
	   *(char *)(frame + 1),
	   *(char *)(frame + 2),
	   *(char *)(frame + 3),
	   *(char *)(frame + 4),
	   *(char *)(frame + 5),
	   *(char *)(frame + 6));
    break;
  default:
    warnx("Unknown Chassis ID subtype (%x)", subtype);
  }
  return 0;
}

int check_tlv_portid(const char *frame, int s) {
  u_int8_t subtype;
  if (s < 2) {
    warnx("Port ID TLV too small (%d < 2)", s);
    return -1;
  }
  subtype = *(u_int8_t*)frame;
  switch (subtype) {
  case LLDP_PORTID_SUBTYPE_IFALIAS:
  case LLDP_PORTID_SUBTYPE_PORT:
  case LLDP_PORTID_SUBTYPE_ADDR:
  case LLDP_PORTID_SUBTYPE_IFNAME:
  case LLDP_PORTID_SUBTYPE_LOCAL:
    printf("Unhandled Port ID type (%x)\n", subtype);
    break;
  case LLDP_PORTID_SUBTYPE_LLADDR:
    if (s != 7) {
      warnx("Incorrect MAC address size (%d != 6)", s-1);
      return -1;
    }
    printf("Port mac address:\n %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
	   *(char *)(frame + 1),
	   *(char *)(frame + 2),
	   *(char *)(frame + 3),
	   *(char *)(frame + 4),
	   *(char *)(frame + 5),
	   *(char *)(frame + 6));
    break;
  default:
    warnx("Unknown Port ID subtype (%x)", subtype);
  }
  return 0;
}

int check_tlv_ttl(const char *frame, int s) {
  if (s != 2) {
    warnx("Incorrect TTL length (%d != 2)", s);
    return -1;
  }
  printf("TTL:\n %d\n", ntohs(*(u_int16_t*)frame));
  return 0;
}

int check_tlv_simplestring(const char *frame, int s, char *what) {
  char *desc;
  if (s < 1) {
    warnx("Incorrect %s length (%d < 1)", what, s);
    return -1;
  }
  if (!(desc = (char *)malloc(s+1))) {
    warnx("Not able to allocate memory");
    return -1;
  }
  strncpy(desc, frame, s);
  desc[s] = 0;
  printf("%s:\n %s\n", what, desc);
  free(desc);
  return 0;
}

int check_tlv_portdescr(const char *frame, int s) {
  return check_tlv_simplestring(frame, s, "Port description");
}

int check_tlv_systemname(const char *frame, int s) {
  return check_tlv_simplestring(frame, s, "System name");
}

int check_tlv_systemdescr(const char *frame, int s) {
  return check_tlv_simplestring(frame, s, "System description");
}

int check_tlv_systemcap(const char *frame, int s) {
  if (s != 4) {
    warnx("Incorrect system capabilities length (%d != 4)", s);
    return -1;
  }
  printf("System capabilities (available/enabled):\n %x %x\n",
	 ntohs(*(u_int16_t*)frame),
	 ntohs(*(u_int16_t*)(frame+2)));
  return 0;
}

int check_tlv_manaddr(const char *frame, int s) {
  return 0;
}

int check_tlv_dot1(const char *frame, int s) {
  int subtype;
  int l;
  char *vlanname;
  if (s < 1) {
    warnx("DOT1 frame too short (%d < 1)", s);
    return -1;
  }
  subtype = *(u_int8_t*)frame;
  switch (subtype) {
  case LLDP_TLV_DOT1_PPVID:
  case LLDP_TLV_DOT1_PI:
    warnx("Unhandled dot1 subtype");
    break;
  case LLDP_TLV_DOT1_PVID:
    if (s < 3) {
      warnx("DOT1 PVID frame too short (%d < 3)", s);
      return -1;
    }
    printf("PVID:\n %d\n", ntohs(*(u_int16_t*)(frame + 1)));
    break;
  case LLDP_TLV_DOT1_VLANNAME:
    if (s < 4) {
      warnx("DOT1 VLAN name frame too short (%d < 4)", s);
      return -1;
    }
    l = *(u_int8_t*)(frame + 3);
    if (s < 4 + l) {
      warnx("DOT1 VLAN name frame too short (%d < 4 + %d)", s, l);
      return -1;
    }
    vlanname = (char *)malloc(l + 1);
    strncpy(vlanname, frame+4, l);
    vlanname[l] = 0;
    printf("VLAN name/id:\n %s/%d\n", vlanname, ntohs(*(u_int16_t*)(frame + 1)));
    break;
  default:
    warnx("Unknown dot1 subtype (%d)", subtype);
    return -1;
  }
  return 0;
}

int check_tlv_dot3(const char *frame, int s) {
  warnx("Do nothing for dot3");
  return 0;
}

int check_tlv_org(const char *frame, int s) {
  char dot1[] = LLDP_TLV_ORG_DOT1; 
  char dot3[] = LLDP_TLV_ORG_DOT3;
  if (s < 3) {
    warnx("Frame too short (3)");
    return -1;
  }
  if (memcmp(dot1, frame, 3) == 0)
    return check_tlv_dot1(frame + 3, s - 3);
  if (memcmp(dot3, frame, 3) == 0)
    return check_tlv_dot3(frame + 3, s - 3);

  warnx("Unknown org code");
  return -1;
}

int check_tlv(const char *frame, int offset, int s) {
  int (*sub_tlv[])(const char *frame, int s) = {
    check_tlv_end,
    check_tlv_chassisid,
    check_tlv_portid,
    check_tlv_ttl,
    check_tlv_portdescr,
    check_tlv_systemname,
    check_tlv_systemdescr,
    check_tlv_systemcap,
    check_tlv_manaddr,
    NULL };
  int size;
  int type;
  int i = 0;
  int rc = 0;

  if (offset + 2 > s) {
    warnx("Frame too short (1)");
    return -1;
  }
  size = ntohs(*(u_int16_t*)(frame + offset)) & 0x1ff;
  type = ntohs(*(u_int16_t*)(frame + offset)) >> 9;
  if (offset + size > s) {
    warnx("Frame too short (2)");
    return -1;
  }

  switch (type) {
  case LLDP_TLV_ORG:
    rc = check_tlv_org(frame + offset + 2, size);
    break;
  default:
    while (sub_tlv[i] != NULL) {
      if (type == i) {
	rc = (*sub_tlv[i])(frame + offset + 2, size);
	break;
      } else i++;
    }
    if (sub_tlv[i] == NULL) {
      warnx("Unknown TLV type (%x)", type);
      return -1;
    }
  }

  if (rc < 0)
    return rc;
  return offset + size + 2;
}

int main() {
  int s, l, i;
  struct sockaddr_ll sa;
  char frame[MTU];

  if (set_multi(1) < 0)
    err(1, "Unable to set multicast address");
  
  if ((s = socket(PF_PACKET, SOCK_RAW, htons(0x88cc))) < 0) {
    warn("Unable to create socket");
    goto end;
  }

  bzero(&sa, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = 0;
  sa.sll_ifindex = if_nametoindex(IF);
  if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
    warn("Unable to bind");
    goto end;
  }

  while (1) {
    l = recv(s, frame, MTU, 0);
    dump(frame, l);
    if (check_mac(frame, l) < 0) {
      warnx("Not LLDP MAC address");
      continue;
    }
    if (check_protocol(frame, l) < 0) {
      warnx("Not LLDP protocol");
      continue;
    }
    i = 2 * ETH_ALEN + 2;
    while (i < l) {
      i = check_tlv(frame, i, l);
      if (i < 0)
	break;
    }
  }
  

 end:
  if (set_multi(0) < 0)
    err(1, "Unable to unset multicast address");
  
  return 0;
}
