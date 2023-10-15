import pytest
import shlex
import time


@pytest.mark.skipif("'Dot3' not in config.lldpd.features", reason="Dot3 not supported")
class TestLldpDot3(object):
    def test_aggregate(self, lldpd1, lldpd, lldpcli, namespaces, links):
        links(namespaces(3), namespaces(2))  # Another link to setup a bond
        with namespaces(2):
            idx = links.bond("bond42", "eth1", "eth3")
            lldpd()
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out["lldp.eth0.port.descr"] == "eth1"
            assert out["lldp.eth0.port.aggregation"] == str(idx)

    # TODO: unfortunately, with veth, it's not possible to get an
    # interface with autoneg.

    @pytest.mark.parametrize(
        "command, expected",
        [
            (
                "pse supported enabled paircontrol powerpairs spare class class-3",
                {
                    "supported": "yes",
                    "enabled": "yes",
                    "paircontrol": "yes",
                    "device-type": "PSE",
                    "pairs": "spare",
                    "class": "class 3",
                },
            ),
            (
                "pd supported enabled powerpairs spare class class-3 type 1 source "
                "pse priority low requested 10000 allocated 15000",
                {
                    "supported": "yes",
                    "enabled": "yes",
                    "paircontrol": "no",
                    "device-type": "PD",
                    "pairs": "spare",
                    "class": "class 3",
                    "power-type": "1",
                    "source": "Primary power source",
                    "priority": "low",
                    "requested": "10000",
                    "allocated": "15000",
                },
            ),
            (
                "pd type-ext 4 powerpairs signal class-a 4 class-b 3 class-ext 5 "
                "pd-status 2 pd-4pid 0 "
                "requested-a 1000 allocated-a 900 "
                "requested-b 2000 allocated-b 500 "
                "pd-load 400",
                {
                    "supported": "no",
                    "enabled": "no",
                    "paircontrol": "no",
                    "device-type": "PD",
                    "pairs": "signal",
                    "power-type": "2",
                    # 802.3at is not configured
                    "class": "unknown",
                    "source": "unknown",
                    "priority": "unknown",
                    "requested": "0",
                    "allocated": "0",
                    # 802.3bt is configured
                    "requested-a": "1000",
                    "allocated-a": "900",
                    "requested-b": "2000",
                    "allocated-b": "500",
                    "power-pairs-ext": "unknown",
                    "pse-power-status": "unknown",
                    "pd-power-status": "4-pair powered dual-signature PD",
                    "power-class-ext-a": "class 4",
                    "power-class-ext-b": "class 3",
                    "power-class-ext": "class 5",
                    "power-type-ext": "unknown",
                    "pd-load": "???",
                    "max-power": "0",
                },
            ),
        ],
    )
    def test_power(self, lldpd1, lldpd, lldpcli, namespaces, command, expected):
        with namespaces(2):
            lldpd()
            result = lldpcli(*shlex.split("configure dot3 power {}".format(command)))
            assert result.returncode == 0
            time.sleep(3)
        with namespaces(1):
            pfx = "lldp.eth0.port.power."
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            out = {k[len(pfx) :]: v for k, v in out.items() if k.startswith(pfx)}
            assert out == expected

    def test_autoneg_power(self, links, lldpd, lldpcli, namespaces):
        links(namespaces(1), namespaces(2))
        with namespaces(1):
            lldpd()
        with namespaces(2):
            lldpd()
            result = lldpcli(
                *shlex.split(
                    "configure dot3 power pd "
                    "supported enabled paircontrol "
                    "powerpairs spare "
                    "class class-3 "
                    "type 1 source both priority low "
                    "requested 20000 allocated 5000"
                )
            )
            assert result.returncode == 0
            time.sleep(2)
        with namespaces(1):
            # Did we receive the request?
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out["lldp.eth0.port.power.requested"] == "20000"
            assert out["lldp.eth0.port.power.allocated"] == "5000"
            # Send an answer we agree to give almost that (this part
            # cannot be automated, lldpd cannot take this decision).
            result = lldpcli(
                *shlex.split(
                    "configure dot3 power pse "
                    "supported enabled paircontrol powerpairs "
                    "spare class class-3 "
                    "type 1 source primary priority high "
                    "requested 20000 allocated 19000"
                )
            )
            assert result.returncode == 0
            time.sleep(2)
        with namespaces(2):
            # Did we receive that?
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out["lldp.eth1.port.power.requested"] == "20000"
            assert out["lldp.eth1.port.power.allocated"] == "19000"
        with namespaces(1):
            # Did we get an echo back? This part is handled
            # automatically by lldpd: we confirm we received the
            # answer "immediately".
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out["lldp.eth0.port.power.requested"] == "20000"
            assert out["lldp.eth0.port.power.allocated"] == "19000"
