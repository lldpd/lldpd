import pytest
import pyroute2
import struct
import socket
import fcntl
import time
from .namespaces import Namespace


def int_to_mac(c):
    """Turn an int into a MAC address."""
    return ":".join(('{:02x}',)*6).format(
        *struct.unpack('BBBBBB', c.to_bytes(6, byteorder='big')))


class LinksFactory(object):
    """A factory for veth pair of interfaces and other L2 stuff.

    Each veth interfaces will get named ethX with X strictly
    increasing at each call.

    """

    def __init__(self):
        # We create all those links in a dedicated namespace to avoid
        # conflict with other namespaces.
        self.ns = Namespace('net')
        self.count = 0

    def __call__(self, *args, **kwargs):
        return self.veth(*args, **kwargs)

    def veth(self, ns1, ns2, sleep=0, mtu=1500):
        """Create a veth pair between two namespaces."""
        with self.ns:
            # First, create a link
            first = 'eth{}'.format(self.count)
            second = 'eth{}'.format(self.count + 1)
            with pyroute2.IPRoute() as ipr:
                ipr.link('add',
                         ifname=first,
                         peer=second,
                         kind='veth')
                idx = [ipr.link_lookup(ifname=x)[0]
                       for x in (first, second)]

                # Set an easy to remember MAC address
                ipr.link('set', index=idx[0],
                         address=int_to_mac(self.count + 1))
                ipr.link('set', index=idx[1],
                         address=int_to_mac(self.count + 2))

                # Set MTU
                ipr.link('set', index=idx[0], mtu=mtu)
                ipr.link('set', index=idx[1], mtu=mtu)

                # Then, move each to the target namespace
                ipr.link('set', index=idx[0], net_ns_fd=ns1.fd('net'))
                ipr.link('set', index=idx[1], net_ns_fd=ns2.fd('net'))

            # And put them up
            with ns1:
                with pyroute2.IPRoute() as ipr:
                    ipr.link('set', index=idx[0], state='up')
            time.sleep(sleep)
            with ns2:
                with pyroute2.IPRoute() as ipr:
                    ipr.link('set', index=idx[1], state='up')

            self.count += 2

    def bridge(self, name, *ifaces, filtering=False):
        """Create a bridge."""
        with pyroute2.IPRoute() as ipr:
            # Create the bridge
            ipr.link('add',
                     ifname=name,
                     kind='bridge',
                     br_vlan_filtering=filtering)
            idx = ipr.link_lookup(ifname=name)[0]
            # Attach interfaces
            for iface in ifaces:
                port = ipr.link_lookup(ifname=iface)[0]
                ipr.link('set', index=port, master=idx)
            # Put the bridge up
            ipr.link('set', index=idx, state='up')
            return idx

    def _bond_or_team(self, kind, name, *ifaces):
        """Create a bond or a team."""
        with pyroute2.RawIPRoute() as ipr:
            # Create the bond
            ipr.link('add',
                     ifname=name,
                     kind=kind)
            idx = ipr.link_lookup(ifname=name)[0]
            # Attach interfaces
            for iface in ifaces:
                slave = ipr.link_lookup(ifname=iface)[0]
                ipr.link('set', index=slave, state='down')
                ipr.link('set', index=slave, master=idx)
            # Put the bond up
            ipr.link('set', index=idx, state='up')
            return idx

    def team(self, name, *ifaces):
        """Create a team."""
        # Unfortunately, pyroute2 will try to run teamd too. This
        # doesn't work.
        return self._bond_or_team("team", name, *ifaces)

    def bond(self, name, *ifaces):
        """Create a bond."""
        return self._bond_or_team("bond", name, *ifaces)

    def dummy(self, name):
        """Create a dummy interface."""
        with pyroute2.IPRoute() as ipr:
            ipr.link('add', ifname=name, kind='dummy')
            idx = ipr.link_lookup(ifname=name)[0]
            ipr.link('set', index=idx, state='up')
            return idx

    def vlan(self, name, id, iface):
        """Create a VLAN."""
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=iface)[0]
            ipr.link('add',
                     ifname=name,
                     kind='vlan',
                     vlan_id=id,
                     link=idx)
            idx = ipr.link_lookup(ifname=name)[0]
            ipr.link('set', index=idx, state='up')
            return idx

    def bridge_vlan(self, iface, vid, tagged=True, pvid=False, remove=False):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=iface)[0]
            flags = []
            if not tagged:
                flags.append('untagged')
            if pvid:
                flags.append('pvid')
            if not remove:
                ipr.vlan_filter('del', index=idx, vlan_info={"vid": 1})
            ipr.vlan_filter('add' if not remove else 'del', index=idx,
                            vlan_info={'vid': vid,
                                       'flags': flags})

    def up(self, name):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=name)[0]
            ipr.link('set', index=idx, state='up')

    def down(self, name):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=name)[0]
            ipr.link('set', index=idx, state='down')

    def remove(self, name):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=name)[0]
            ipr.link('del', index=idx)

    def unbridge(self, bridgename, name):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=name)[0]
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            ifr = struct.pack("16si", b"br42", idx)
            fcntl.ioctl(s,
                        0x89a3,     # SIOCBRDELIF
                        ifr)
            s.close()


@pytest.fixture
def links():
    return LinksFactory()
