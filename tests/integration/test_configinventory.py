import os
import pytest
import platform
import time
import shlex

@pytest.mark.skipif("'LLDP-MED' not in config.lldpd.features",
                    reason="LLDP-MED not supported")
class TestConfigInventory(object):

    def test_configinventory(self, lldpd1, lldpd, lldpcli, namespaces,
                           replace_file):
        with namespaces(2):
            if os.path.isdir("/sys/class/dmi/id"):
                # /sys/class/dmi/id/*
                for what, value in dict(product_version="1.14",
                                        bios_version="1.10",
                                        product_serial="45872512",
                                        sys_vendor="Spectacular",
                                        product_name="Workstation",
                                        chassis_asset_tag="487122").items():
                    replace_file("/sys/class/dmi/id/{}".format(what),
                                value)
            lldpd("-M", "1")

        def test_default_inventory(namespaces, lldpcli):
            with namespaces(1):
                if os.path.isdir("/sys/class/dmi/id"):
                    out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
                    assert out['lldp.eth0.chassis.name'] == 'ns-2.example.com'
                    assert out['lldp.eth0.lldp-med.inventory.hardware'] == '1.14'
                    assert out['lldp.eth0.lldp-med.inventory.firmware'] == '1.10'
                    assert out['lldp.eth0.lldp-med.inventory.serial'] == '45872512'
                    assert out['lldp.eth0.lldp-med.inventory.manufacturer'] == \
                        'Spectacular'
                    assert out['lldp.eth0.lldp-med.inventory.model'] == 'Workstation'
                    assert out['lldp.eth0.lldp-med.inventory.asset'] == '487122'
                    assert out['lldp.eth0.lldp-med.inventory.software'] == \
                        platform.release()
                else:
                    assert 'lldp.eth0.lldp-med.inventory.hardware' not in out.items()
                    assert 'lldp.eth0.lldp-med.inventory.firmware' not in out.items()
                    assert 'lldp.eth0.lldp-med.inventory.serial' not in out.items()
                    assert 'lldp.eth0.lldp-med.inventory.manufacturer' not in out.items()
                    assert 'lldp.eth0.lldp-med.inventory.model' not in out.items()
                    assert 'lldp.eth0.lldp-med.inventory.asset' not in out.items()
                    assert 'lldp.eth0.lldp-med.inventory.software' not in out.items()

        test_default_inventory(namespaces, lldpcli)

        custom_values = [
                ('hardware-revision', 'hardware', 'SQRT2_1.41421356237309504880'),
                ('software-revision', 'software', 'E_2.7182818284590452354'),
                ('firmware-revision', 'firmware', 'PI_3.14159265358979323846'),
                ('serial', 'serial', 'FIBO_112358'),
                ('manufacturer', 'manufacturer', 'Cybertron'),
                ('model', 'model', 'OptimusPrime'),
                ('asset', 'asset', 'SQRT3_1.732050807568877')
            ]
        with namespaces(2):
            for what, pfx, value in custom_values:
                result = lldpcli(
                    *shlex.split("configure inventory {} {}".format(what, value)))
                assert result.returncode == 0
                result = lldpcli("resume")
                assert result.returncode == 0
                result = lldpcli("update")
                assert result.returncode == 0
            time.sleep(3)

        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            for what, pfx, value in custom_values:
                key_to_find = "lldp.eth0.lldp-med.inventory.{}".format(pfx)
                assert out[key_to_find] == value

        with namespaces(2):
            for what, pfx, value in custom_values:
                result = lldpcli(
                    *shlex.split("unconfigure inventory {}".format(what)))
                assert result.returncode == 0
                result = lldpcli("resume")
                assert result.returncode == 0
                result = lldpcli("update")
                assert result.returncode == 0

        test_default_inventory(namespaces, lldpcli)

