import pytest
import time

pytestmark = pytest.mark.skipif(not pytest.config.lldpd.snmp,
                                reason="no SNMP support")


def test_snmp_register(snmpd, snmpwalk, lldpd, namespaces):
    with namespaces(1):
        snmpd()
        lldpd("-x")
        out = snmpwalk(".1.3.6.1.2.1.1.9.1.3")
        assert 'STRING: "lldpMIB implementation by lldpd"' in out.values()


def test_snmp_one_neighbor(snmpd, snmpwalk, lldpd, namespaces):
    with namespaces(1):
        snmpd()
        lldpd("-x")
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = snmpwalk(".1.0.8802.1.1.2.1")
        assert out['.1.0.8802.1.1.2.1.2.1.0'].startswith(
            "Timeticks: ")
        assert out['.1.0.8802.1.1.2.1.3.2.0'] == 'STRING: "ns-1.example.com"'
        assert out['.1.0.8802.1.1.2.1.3.3.0'] == 'STRING: "ns-1.example.com"'
        assert out['.1.0.8802.1.1.2.1.3.4.0'].startswith(
            'STRING: "Spectacular GNU/Linux 2016 Linux')
