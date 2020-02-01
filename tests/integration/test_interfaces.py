import pytest
import pyroute2
import time


def test_simple_bridge(lldpd1, lldpd, lldpcli, namespaces, links):
    links(namespaces(3), namespaces(2))  # Another link to setup a bridge
    with namespaces(2):
        links.bridge('br42', 'eth1', 'eth3')
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.chassis.Bridge.enabled'] == 'on'


def test_remove_bridge(lldpd, lldpcli, namespaces, links):
    links(namespaces(1), namespaces(2))
    links(namespaces(3), namespaces(1))  # Another link to setup a bridge
    with namespaces(1):
        links.bridge('br42', 'eth0', 'eth3')
        lldpd("-r")
    with namespaces(2):
        lldpd()
        time.sleep(2)
        lldpcli("pause")        # Prevent any updates
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        # Remove from bridge. We don't use netlink because we wouldn't
        # get the wanted effect: we also get a RTM_NEWLINK by doing
        # that. Only the bridge ioctl() would prevent that.
        links.unbridge('br42', 'eth0')
        time.sleep(1)
        # Check if we still have eth0
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'


@pytest.mark.skipif("'Dot1' not in config.lldpd.features",
                    reason="Dot1 not supported")
@pytest.mark.parametrize('when', ['before', 'after'])
def test_bridge_with_vlan(lldpd1, lldpd, lldpcli, namespaces, links, when):
    links(namespaces(3), namespaces(2))  # Another link to setup a bridge
    with namespaces(2):
        if when == 'after':
            lldpd()
        links.bridge('br42', 'eth1', 'eth3')
        links.vlan('vlan100', 100, 'br42')
        links.vlan('vlan200', 200, 'br42')
        links.vlan('vlan300', 300, 'br42')
        if when == 'before':
            lldpd()
        else:
            time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.vlan'] == \
            ['vlan100', 'vlan200', 'vlan300']
        assert out['lldp.eth0.vlan.vlan-id'] == \
            ['100', '200', '300']


@pytest.mark.skipif("'Dot1' not in config.lldpd.features",
                    reason="Dot1 not supported")
@pytest.mark.parametrize('when', ['before', 'after'])
def test_vlan_aware_bridge_with_vlan(lldpd1, lldpd, lldpcli, namespaces, links,
                                     when):
    links(namespaces(3), namespaces(2))  # Another link to setup a bridge
    with namespaces(2):
        if when == 'after':
            lldpd()
        links.bridge('br42', 'eth1', 'eth3')
        links.bridge_vlan('eth1', 100, pvid=True)
        links.bridge_vlan('eth1', 200)
        links.bridge_vlan('eth1', 300)
        if when == 'before':
            lldpd()
        else:
            time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.vlan'] == \
            ['vlan100', 'vlan200', 'vlan300']
        assert out['lldp.eth0.vlan.vlan-id'] == \
            ['100', '200', '300']
        assert out['lldp.eth0.vlan.pvid'] == \
            ['yes', 'no', 'no']


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
@pytest.mark.parametrize('when', ['before', 'after'])
def test_bond(lldpd1, lldpd, lldpcli, namespaces, links, when):
    links(namespaces(3), namespaces(2))  # Another link to setup a bond
    with namespaces(2):
        if when == 'after':
            lldpd()
        idx = links.bond('bond42', 'eth3', 'eth1')
        ipr = pyroute2.IPRoute()
        # The bond has the MAC of eth3
        assert ipr.get_links(idx)[0].get_attr('IFLA_ADDRESS') == \
            "00:00:00:00:00:04"
        if when == 'before':
            lldpd()
        else:
            time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.port.aggregation'] == str(idx)
        # lldpd should be able to retrieve the right MAC
        assert out['lldp.eth0.port.mac'] == '00:00:00:00:00:02'


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
@pytest.mark.skipif("'rtnl-link-team' not in config.kernel.features",
                    reason="No team support in kernel")
@pytest.mark.parametrize('when', ['before', 'after'])
def test_team(lldpd1, lldpd, lldpcli, namespaces, links, when):
    links(namespaces(3), namespaces(2))  # Another link to setup a bond
    with namespaces(2):
        if when == 'after':
            lldpd()
        idx = links.team('team42', 'eth3', 'eth1')
        if when == 'before':
            lldpd()
        else:
            time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.port.aggregation'] == str(idx)
        # Unfortunately, we cannot get the right MAC currently... So,
        # this bit will succeed by chance.
        assert out['lldp.eth0.port.mac'] == '00:00:00:00:00:02'


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
@pytest.mark.skipif("'Dot1' not in config.lldpd.features",
                    reason="Dot1 not supported")
@pytest.mark.parametrize('when', ['before', 'after'])
def test_bond_with_vlan(lldpd1, lldpd, lldpcli, namespaces, links, when):
    links(namespaces(3), namespaces(2))  # Another link to setup a bond
    with namespaces(2):
        if when == 'after':
            lldpd()
        links.bond('bond42', 'eth3', 'eth1')
        links.vlan('vlan300', 300, 'bond42')
        links.vlan('vlan301', 301, 'bond42')
        links.vlan('vlan302', 302, 'bond42')
        links.vlan('vlan303', 303, 'bond42')
        if when == 'before':
            lldpd()
        else:
            time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.vlan'] == \
            ['vlan300', 'vlan301', 'vlan302', 'vlan303']
        assert out['lldp.eth0.vlan.vlan-id'] == \
            ['300', '301', '302', '303']


@pytest.mark.skipif("'Dot1' not in config.lldpd.features",
                    reason="Dot1 not supported")
@pytest.mark.parametrize('when', ['before', 'after'])
def test_just_vlan(lldpd1, lldpd, lldpcli, namespaces, links, when):
    with namespaces(2):
        if when == 'after':
            lldpd()
        links.vlan('vlan300', 300, 'eth1')
        links.vlan('vlan400', 400, 'eth1')
        if when == 'before':
            lldpd()
        else:
            time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.vlan'] == ['vlan300', 'vlan400']
        assert out['lldp.eth0.vlan.vlan-id'] == ['300', '400']


@pytest.mark.skipif("'Dot1' not in config.lldpd.features",
                    reason="Dot1 not supported")
@pytest.mark.parametrize('kind', ['plain', 'bridge', 'vlan-aware-bridge', 'bond'])
def test_remove_vlan(lldpd1, lldpd, lldpcli, namespaces, links, kind):
    with namespaces(2):
        if kind == 'bond':
            iface = 'bond42'
            links.bond(iface, 'eth1')
        elif kind in ('bridge', 'vlan-aware-bridge'):
            iface = 'bridge42'
            links.bridge(iface, 'eth1')
        else:
            assert kind == 'plain'
            iface = 'eth1'
        if kind != 'vlan-aware-bridge':
            links.vlan('vlan300', 300, iface)
            links.vlan('vlan400', 400, iface)
            links.vlan('vlan500', 500, iface)
            lldpd()
            links.remove('vlan300')
        else:
            links.bridge_vlan('eth1', 300, pvid=True)
            links.bridge_vlan('eth1', 400)
            links.bridge_vlan('eth1', 500)
            lldpd()
            links.bridge_vlan('eth1', 300, remove=True)
        time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.vlan'] == ['vlan400', 'vlan500']
        assert out['lldp.eth0.vlan.vlan-id'] == ['400', '500']
        assert out['lldp.eth0.vlan.pvid'] == ['no', 'no']


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
def test_unenslave_bond(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        links.bond('bond42', 'eth1')
        lldpd()
        links.remove('bond42')
        links.up('eth1')
        time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert 'lldp.eth0.port.aggregation' not in out


@pytest.mark.skipif("'Dot1' not in config.lldpd.features",
                    reason="Dot1 not supported")
def test_unenslave_bond_with_vlan(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        links.bond('bond42', 'eth1')
        links.vlan('vlan300', 300, 'bond42')
        links.vlan('vlan400', 400, 'eth1')
        lldpd()
        links.remove('bond42')
        links.up('eth1')
        time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.vlan'] == 'vlan400'
        assert out['lldp.eth0.vlan.vlan-id'] == '400'


def test_down_then_up(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        links.down('eth1')
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out == {}
    with namespaces(2):
        links.up('eth1')
        time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'


@pytest.mark.skipif("'Dot1' not in config.lldpd.features",
                    reason="Dot1 not supported")
def test_down_then_up_with_vlan(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        links.vlan('vlan300', 300, 'eth1')
        links.vlan('vlan400', 400, 'eth1')
        links.down('eth1')
        lldpd()
        links.up('eth1')
        time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.vlan'] == ['vlan300', 'vlan400']
        assert out['lldp.eth0.vlan.vlan-id'] == ['300', '400']


def test_new_interface(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        lldpd()
    links(namespaces(1), namespaces(2), 4)
    time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth2.port.descr'] == 'eth3'
        assert out['lldp.eth0.rid'] == out['lldp.eth2.rid']  # Same chassis
