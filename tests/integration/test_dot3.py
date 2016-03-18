import pytest
import pyroute2
import shlex
import time


@pytest.mark.skipif('Dot3' not in pytest.config.lldpd.features,
                    reason="Dot3 not supported")
class TestLldpDot3(object):

    def test_aggregate(self, lldpd1, lldpd, lldpcli, namespaces, links):
        links(namespaces(3), namespaces(2))  # Another link to setup a bond
        with namespaces(2):
            idx = links.bond('bond42', 'eth1', 'eth3')
            lldpd()
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out['lldp.eth0.port.descr'] == 'eth1'
            assert out['lldp.eth0.port.aggregation'] == str(idx)

    # TODO: unfortunately, with veth, it's not possible to get an
    # interface with autoneg.

    @pytest.mark.parametrize("command, expected", [
        ("pse supported enabled paircontrol powerpairs spare class class-3",
         {'supported': 'yes',
          'enabled': 'yes',
          'paircontrol': 'yes',
          'device-type': 'PSE',
          'pairs': 'spare',
          'class': 'class 3'}),
        ("pd supported enabled powerpairs spare class class-3 type 1 source "
         "pse priority low requested 10000 allocated 15000",
         {'supported': 'yes',
          'enabled': 'yes',
          'paircontrol': 'no',
          'device-type': 'PD',
          'pairs': 'spare',
          'class': 'class 3',
          'power-type': '1',
          'source': 'Primary power source',
          'priority': 'low',
          'requested': '10000',
          'allocated': '15000'})])
    def test_power(self, lldpd1, lldpd, lldpcli, namespaces,
                   command, expected):
        with namespaces(2):
            lldpd()
            result = lldpcli(
                *shlex.split("configure dot3 power {}".format(command)))
            assert result.returncode == 0
            time.sleep(3)
        with namespaces(1):
            pfx = "lldp.eth0.port.power."
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            out = {k[len(pfx):]: v
                   for k, v in out.items()
                   if k.startswith(pfx)}
            assert out == expected
