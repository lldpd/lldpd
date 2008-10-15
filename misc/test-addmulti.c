#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

int main() {
  int s;
  struct ifreq ifr;
  const unsigned char lldpaddr[] = {0x01,0x80,0xC2,0x00,0x00,0x0E};

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    err(1, "Unable to open socket");
  bzero(&ifr, sizeof(ifr));
  strncpy(ifr.ifr_name, "lan", IFNAMSIZ);
  bcopy(lldpaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  if (ioctl(s, SIOCADDMULTI, &ifr) < 0)
    err(1, "Unable to ioctl");
  return 0;
}
