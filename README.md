lldpd: implementation of IEEE 802.1ab (LLDP)
============================================

[![Build Status](https://secure.travis-ci.org/vincentbernat/lldpd.png?branch=master)](http://travis-ci.org/vincentbernat/lldpd)

  https://github.com/vincentbernat/lldpd/wiki

LLDP (Link Layer Discovery Protocol) is an industry standard protocol
designed to supplant proprietary Link-Layer protocols such as
Extreme's EDP (Extreme Discovery Protocol) and CDP (Cisco Discovery
Protocol). The goal of LLDP is to provide an inter-vendor compatible
mechanism to deliver Link-Layer notifications to adjacent network
devices.

lldpd implements both reception and sending. It also implements an
SNMP subagent for net-snmp to get local and remote LLDP
information. The LLDP MIB is partially implemented but the most useful
tables are here. lldpd also partially implements LLDP-MED.

lldpd supports bridge, vlan and bonding. bonding need to be done on
real physical devices, not on bridges, vlans, etc. However, vlans can
be mapped on the bonding device. You can bridge vlan but not add vlans
on bridges. More complex setups may give false results.

To compile lldpd, use the following:

    ./configure
    make
    sudo make install

You need libevent that you can grab from http://libevent.org or
install from your package system (libevent-dev for Debian/Ubuntu and
libevent-devel for Redhat/Fedora/CentOS/SuSE).

If your system does not have libevent, here is a quick howto to
download it and compile it statically into lldpd:

    # Grab and compile libevent
    wget https://github.com/downloads/libevent/libevent/libevent-2.0.16-stable.tar.gz
    tar zxvf libevent-2.0.16-stable.tar.gz
    cd libevent-2.0.16-stable
    ./configure --prefix=$PWD/usr/local --enable-static --disable-shared
    make
    make install
    
    # Compile lldpd with static linking
    cd ..
    ./configure --with-libevent=libevent-2.0.16-stable/usr/local/lib/libevent.la
    make
    sudo make install

If it complains about a missing agent/struct.h, your installation of
Net-SNMP is incomplete. The easiest way to fix this is to provide an
empty struct.h:

    touch src/struct.h

If you are missing some headers or if some headers are incorrect
(if_vlan.h and if_bonding.h on RHEL 2.1 for example), you can copy
some more current version (for example from Debian Lenny or from
Fedora) in some directory like "extra-headers/":

 - `./extra-headers/linux/if_vlan.h`
 - `./extra-headers/linux/if_bonding.h`

Then, configure like this:

    ./configure CFLAGS="-Wall -I${PWD}/extra-headers"

This has been tested with RHEL 2.1.

lldpd uses privilege separation to increase its security. Two
processes, one running as root and doing minimal stuff and the other
running as an unprivileged user into a chroot doing most of the stuff,
are cooperating. You need to create a user called `_lldpd` in a group
`_lldpd` (this can be change with `./configure`). You also need to
create an empty directory `/var/run/lldpd` (it needs to be owned by
root, not `_lldpd`!). If you get fuzzy timestamps from syslog, copy
`/etc/locatime` into the chroot.

`lldpctl` lets one query information collected through the command
line. If you don't want to run it as root, just install it setuid or
setgid `_lldpd`.

lldpd also implements CDP (Cisco Discovery Protocol), FDP (Foundry
Discovery Protocol), SONMP (Nortel Discovery Protocol) and EDP
(Extreme Discovery Protocol). However, recent versions of IOS should
support LLDP and most Extreme stuff support LLDP. When a EDP, CDP or
SONMP frame is received on a given interface, lldpd starts sending
EDP, CDP, FDP or SONMP frame on this interface. Informations collected
through EDP/CDP/FDP/SONMP are integrated with other informations and
can be queried with `lldpctl` or through SNMP.

For bonding, you need 2.6.24 (in previous version, PACKET_ORIGDEV
affected only non multicast packets). See:

 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commitdiff;h=80feaacb8a6400a9540a961b6743c69a5896b937
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commitdiff;h=8032b46489e50ef8f3992159abd0349b5b8e476c

Otherwise, a packet received on a bond will be affected to all
interfaces of the bond.

On 2.6.27, we are able to receive packets on real interface for bonded
devices. This allows one to get neighbor information on active/backup
bonds. Without the 2.6.27, lldpd won't receive any information on
inactive slaves. Here are the patchs (thanks to Joe Eykholt):

 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=0d7a3681232f545c6a59f77e60f7667673ef0e93
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=cc9bd5cebc0825e0fabc0186ab85806a0891104f
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=f982307f22db96201e41540295f24e8dcc10c78f

Some devices (notably Cisco IOS) send frames on the native VLAN while
they should send them untagged. If your network card does not support
accelerated VLAN, you will receive those frames as well. However, if
your network card handles VLAN encapsulation/decapsulation, you need a
recent kernel to be able to receive those frames without listening on
all available VLAN. Starting from Linux 2.6.27, lldpd is able to
capture VLAN frames when VLAN acceleration is supported by the network
card. Here is the patch:
 http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=bc1d0411b804ad190cdadabac48a10067f17b9e6

More information:
 * http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol
 * http://standards.ieee.org/getieee802/download/802.1AB-2005.pdf
 * http://wiki.wireshark.org/LinkLayerDiscoveryProtocol

lldpd is distributed under the following license:

 > Permission to use, copy, modify, and/or distribute this software for any
 > purpose with or without fee is hereby granted, provided that the above
 > copyright notice and this permission notice appear in all copies.
 >
 > THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 > WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 > MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 > ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 > WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 > ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 > OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
