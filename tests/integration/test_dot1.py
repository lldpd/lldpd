import pytest


@pytest.mark.skipif("'Dot1' not in config.lldpd.features", reason="Dot1 not supported")
class TestLldpDot1(object):
    def test_one_vlan(self, lldpd1, lldpd, lldpcli, namespaces, links):
        with namespaces(2):
            links.vlan("vlan100", 100, "eth1")
            lldpd()
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out["lldp.eth0.vlan"] == "vlan100"
            assert out["lldp.eth0.vlan.vlan-id"] == "100"

    def test_several_vlans(self, lldpd1, lldpd, lldpcli, namespaces, links):
        with namespaces(2):
            for v in [100, 200, 300, 4000]:
                links.vlan("vlan{}".format(v), v, "eth1")
            lldpd()
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            # We know that lldpd is walking interfaces in index order
            assert out["lldp.eth0.vlan"] == [
                "vlan100",
                "vlan200",
                "vlan300",
                "vlan4000",
            ]
            assert out["lldp.eth0.vlan.vlan-id"] == ["100", "200", "300", "4000"]

    @pytest.mark.skip(reason="unreliable test")
    def test_too_many_vlans(self, lldpd1, lldpd, lldpcli, namespaces, links):
        with namespaces(2):
            for v in range(100, 1000):
                links.vlan("vlan{}".format(v), v, "eth1")
            lldpd()
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert "lldp.eth0.vlan" not in out
            assert "lldp.eth0.age" in out

    def test_vlan_advertisement_inclusive(self, lldpd1, lldpd, lldpcli, namespaces, links):
        vlan = [100, 200, 300, 4000]
        with namespaces(1):
            lldpd()
            for v in vlan:
                links.vlan("vlan{}".format(v), v, "eth0")
            result = lldpcli("configure", "ports", "eth0", "lldp", "vlan-advertisements", "pattern","300,4000")
            assert result.returncode == 0 == 0
            out = lldpcli("-f", "keyvalue", "show", "interface", "details")
            # We know that lldpd is walking interfaces in index order
            assert out["lldp.eth0.vlan"] == [
                "vlan300",
                "vlan4000",
            ]
            assert out["lldp.eth0.vlan.vlan-id"] == ["300", "4000"]

    def test_vlan_advertisement_exclusive(self, lldpd1, lldpd, lldpcli, namespaces, links):
        vlan = [100, 200, 300, 4000]
        with namespaces(1):
            lldpd()
            for v in vlan:
                links.vlan("vlan{}".format(v), v, "eth0")
            result = lldpcli("configure", "ports", "eth0", "lldp", "vlan-advertisements", "pattern","*,!300,!4000")
            assert result.returncode == 0 == 0
            out = lldpcli("-f", "keyvalue", "show", "interface", "details")
            # We know that lldpd is walking interfaces in index order
            assert out["lldp.eth0.vlan"] == [
                "vlan100",
                "vlan200",
            ]
            assert out["lldp.eth0.vlan.vlan-id"] == ["100", "200"]

    def test_vlan_advertisement_unconfigure(self, lldpd1, lldpd, lldpcli, namespaces, links):
        vlan = [100, 200, 300, 4000]
        with namespaces(1):
            lldpd()
            for v in vlan:
                links.vlan("vlan{}".format(v), v, "eth0")
            result = lldpcli("configure", "ports", "eth0", "lldp", "vlan-advertisements", "pattern","*,!300,!4000")
            assert result.returncode == 0 == 0
            result = lldpcli("unconfigure", "ports", "eth0", "lldp", "vlan-advertisements", "pattern")
            assert result.returncode == 0 == 0
            out = lldpcli("-f", "keyvalue", "show", "interface", "details")
            # We know that lldpd is walking interfaces in index order
            assert out["lldp.eth0.vlan"] == [
                "vlan100",
                "vlan200",
                "vlan300",
                "vlan4000",
            ]
            assert out["lldp.eth0.vlan.vlan-id"] == ["100", "200", "300", "4000"]
    # TODO: PI and PPVID (but lldpd doesn't know how to generate them)
