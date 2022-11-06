import os
import pytest
import platform
import time
import shlex


@pytest.mark.skipif(
    "'LLDP-MED' not in config.lldpd.features", reason="LLDP-MED not supported"
)
class TestLldpMed(object):
    @pytest.mark.parametrize(
        "classe, expected",
        [
            (1, "Generic Endpoint (Class I)"),
            (2, "Media Endpoint (Class II)"),
            (3, "Communication Device Endpoint (Class III)"),
            (4, "Network Connectivity Device"),
        ],
    )
    def test_med_devicetype(self, lldpd1, lldpd, lldpcli, namespaces, classe, expected):
        with namespaces(2):
            lldpd("-M", str(classe))
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out["lldp.eth0.lldp-med.device-type"] == expected

    def test_med_capabilities(self, lldpd1, lldpd, lldpcli, namespaces):
        with namespaces(2):
            lldpd("-M", "2")
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            out = {
                k.split(".")[3]: v for k, v in out.items() if k.endswith(".available")
            }
            assert out == {
                "Capabilities": "yes",
                "Policy": "yes",
                "Location": "yes",
                "MDI/PSE": "yes",
                "MDI/PD": "yes",
                "Inventory": "yes",
            }

    @pytest.mark.skipif(
        not os.path.isdir("/sys/class/dmi/id"), reason="/sys/class/dmi not available"
    )
    def test_med_inventory(self, lldpd1, lldpd, lldpcli, namespaces, replace_file):
        with namespaces(2):
            # /sys/class/dmi/id/*
            for what, value in dict(
                product_version="1.14",
                bios_version="1.10",
                product_serial="45872512",
                sys_vendor="Spectacular",
                product_name="Workstation",
                chassis_asset_tag="487122",
            ).items():
                replace_file("/sys/class/dmi/id/{}".format(what), value)
            lldpd("-M", "1")
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out["lldp.eth0.chassis.name"] == "ns-2.example.com"
            assert out["lldp.eth0.lldp-med.inventory.hardware"] == "1.14"
            assert out["lldp.eth0.lldp-med.inventory.firmware"] == "1.10"
            assert out["lldp.eth0.lldp-med.inventory.serial"] == "45872512"
            assert out["lldp.eth0.lldp-med.inventory.manufacturer"] == "Spectacular"
            assert out["lldp.eth0.lldp-med.inventory.model"] == "Workstation"
            assert out["lldp.eth0.lldp-med.inventory.asset"] == "487122"
            assert out["lldp.eth0.lldp-med.inventory.software"] == platform.release()

    @pytest.mark.parametrize(
        "command, pfx, expected",
        [
            # Policies
            (
                "policy application voice tagged vlan 500 priority voice dscp 46",
                "policy",
                {
                    "apptype": "Voice",
                    "defined": "yes",
                    "priority": "Voice",
                    "pcp": "5",
                    "dscp": "46",
                    "vlan.vid": "500",
                },
            ),
            (
                "policy application video-conferencing unknown dscp 3 priority video",
                "policy",
                {
                    "apptype": "Video Conferencing",
                    "defined": "no",
                    "priority": "Video",
                    "pcp": "4",
                    "dscp": "3",
                },
            ),
            # Locations
            (
                "location coordinate latitude 48.58667N longitude 2.2014E "
                "altitude 117.47 m datum WGS84",
                "Coordinates",
                {
                    "geoid": "WGS84",
                    "lat": "48.58666N",
                    "lon": "2.2013E",
                    "altitude.unit": "m",
                    "altitude": "117.46",
                },
            ),
            (
                "location address country US language en_US street "
                '"Commercial Road" city "Roseville"',
                "Civic address",
                {
                    "country": "US",
                    "language": "en_US",
                    "city": "Roseville",
                    "street": "Commercial Road",
                },
            ),
            ("location elin 911", "ELIN", {"ecs": "911"}),
            # Power
            (
                "power pd source pse priority high value 5000",
                "poe",
                {
                    "device-type": "PD",
                    "source": "PSE",
                    "priority": "high",
                    "power": "5000",
                },
            ),
            (
                "power pse source backup priority critical value 300",
                "poe",
                {
                    "device-type": "PSE",
                    "source": "Backup Power Source / Power Conservation Mode",
                    "priority": "critical",
                    "power": "300",
                },
            ),
        ],
    )
    def test_med_configuration(
        self, lldpd1, lldpd, lldpcli, namespaces, command, pfx, expected
    ):
        with namespaces(2):
            lldpd("-M", "1")
            result = lldpcli(*shlex.split("configure med {}".format(command)))
            assert result.returncode == 0
            time.sleep(3)
        with namespaces(1):
            pfx = "lldp.eth0.lldp-med.{}.".format(pfx)
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            out = {k[len(pfx) :]: v for k, v in out.items() if k.startswith(pfx)}
            assert out == expected
