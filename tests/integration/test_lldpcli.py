import pytest
import shlex
import time
import re
import platform
import json
import xml.etree.ElementTree as ET

if hasattr(ET, "canonicalize"):
    canonicalize = ET.canonicalize
else:
    def canonicalize(x):
        x


@pytest.fixture(scope='session')
def uname():
    return "{} {} {} {}".format(
        platform.system(),
        platform.release(),
        platform.version(),
        platform.machine())

@pytest.mark.parametrize("command, expected", [
    ("neighbors",
     """-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface:    eth0, via: LLDP, RID: 1, Time: 0 day, 00:00:{seconds}
  Chassis:
    ChassisID:    mac 00:00:00:00:00:02
    SysName:      ns-2.example.com
    SysDescr:     Spectacular GNU/Linux 2016 {uname}
    MgmtIP:       fe80::200:ff:fe00:2
    MgmtIface:    2
    Capability:   Bridge, off
    Capability:   Router, {router}
    Capability:   Wlan, off
    Capability:   Station, {station}
  Port:
    PortID:       mac 00:00:00:00:00:02
    PortDescr:    eth1
    TTL:          120{dot3}
-------------------------------------------------------------------------------
"""),
    ("interfaces",
     """-------------------------------------------------------------------------------
LLDP interfaces:
-------------------------------------------------------------------------------
Interface:    eth0
  Administrative status: RX and TX
  Chassis:
    ChassisID:    mac 00:00:00:00:00:01
    SysName:      ns-1.example.com
    SysDescr:     Spectacular GNU/Linux 2016 {uname}
    MgmtIP:       fe80::200:ff:fe00:1
    MgmtIface:    3
    Capability:   Bridge, off
    Capability:   Router, {router}
    Capability:   Wlan, off
    Capability:   Station, {station}
  Port:
    PortID:       mac 00:00:00:00:00:01
    PortDescr:    eth0{dot3}
  TTL:          120
-------------------------------------------------------------------------------
""")], ids=["neighbors", "interfaces"])
def test_text_output(request, lldpd1, lldpd, lldpcli, namespaces, uname,
                     command, expected):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        result = lldpcli(
            *shlex.split("show {} details".format(command)))
        assert result.returncode == 0
        out = result.stdout.decode('ascii')

        if 'Dot3' in request.config.lldpd.features:
            dot3 = """
    PMD autoneg:  supported: no, enabled: no
      MAU oper type: 10GbaseT - Four-pair Category 6A or better, full duplex mode only"""
        else:
            dot3 = ""

        out = result.stdout.decode('ascii')
        if command == "neighbors":
            time = re.search(r'^Interface: .*Time: (.*)$',
                             out,
                             re.MULTILINE).group(1)
            seconds = re.search(r'^Interface: .*(\d\d)$',
                                out,
                                re.MULTILINE).group(1)
        else:
            time = None
            seconds = None
        router = re.search(r'^    Capability:   Router, (.*)$',
                           out,
                           re.MULTILINE).group(1)
        station = re.search(r'^    Capability:   Station, (.*)$',
                            out,
                            re.MULTILINE).group(1)
        out = re.sub(r' *$', '', out, flags=re.MULTILINE)
        assert out == expected.format(seconds=seconds,
                                      time=time,
                                      router=router,
                                      station=station,
                                      uname=uname,
                                      dot3=dot3)

@pytest.mark.skipif("'JSON' not in config.lldpcli.outputs",
                    reason="JSON not supported")
@pytest.mark.parametrize("command, expected", [
    ("neighbors",
     {"lldp": {
        "interface": {
          "eth0": {
            "via": "LLDP",
            "rid": "1",
            "chassis": {
              "ns-2.example.com": {
                "id": {
                  "type": "mac",
                  "value": "00:00:00:00:00:02"},
                "descr": "Spectacular GNU/Linux 2016 {}".format(uname),
                "mgmt-ip": "fe80::200:ff:fe00:2",
                "mgmt-iface": "2",
                "capability": [
                  {"type": "Bridge", "enabled": False},
                  {"type": "Wlan", "enabled": False},]}},
            "port": {
              "id": {
                "type": "mac",
                "value": "00:00:00:00:00:02"},
              "descr": "eth1",
              "ttl": "120"}}}}}),
    ("interfaces",
     {"lldp": {
        "interface": {
          "eth0": {
            "status": "RX and TX",
            "chassis": {
              "ns-1.example.com": {
                "id": {
                  "type": "mac",
                  "value": "00:00:00:00:00:01"},
                "descr": "Spectacular GNU/Linux 2016 {}".format(uname),
                "mgmt-ip": "fe80::200:ff:fe00:1",
                "mgmt-iface": "3",
                "capability": [
                  {"type": "Bridge", "enabled": False},
                  {"type": "Wlan", "enabled": False},]}},
            "port": {
              "id": {
                "type": "mac",
                "value": "00:00:00:00:00:01"},
              "descr": "eth0"},
            "ttl": {
              "ttl": "120"}}}}})], ids=["neighbors", "interfaces"])
def test_json_output(request, lldpd1, lldpd, lldpcli, namespaces, uname,
                     command, expected):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        result = lldpcli(
            *shlex.split("-f json show {} details".format(command)))
        assert result.returncode == 0
        out = result.stdout.decode('ascii')
        j = json.loads(out)

        eth0 = j['lldp']['interface']['eth0']
        name = next(k for k,v in eth0['chassis'].items() if k.startswith('ns'))
        if command == "neighbors":
            del eth0['age']
        del eth0['chassis'][name]['capability'][3]
        del eth0['chassis'][name]['capability'][1]

        descr = "Spectacular GNU/Linux 2016 {}".format(uname)
        expected['lldp']['interface']['eth0']['chassis'][name]["descr"] = descr

        if 'Dot3' in request.config.lldpd.features:
            expected['lldp']['interface']['eth0']['port']['auto-negotiation'] = {
                "enabled": False,
                "supported": False,
                "current": "10GbaseT - Four-pair Category 6A or better, full duplex mode only"
            }

        assert j == expected

@pytest.mark.skipif("'JSON' not in config.lldpcli.outputs",
                    reason="JSON not supported")
@pytest.mark.parametrize("command, expected", [
    ("neighbors",
     {"lldp": [{
            "interface": [{
                "name": "eth0",
                "via": "LLDP",
                "rid": "1",
                "chassis": [{
                    "id": [{
                        "type": "mac",
                        "value": "00:00:00:00:00:02"
                    }],
                    "name": [{"value": "ns-2.example.com"}],
                    "descr": [{"value": "Spectacular GNU/Linux 2016 {}".format(uname)}],
                    "mgmt-ip": [{"value": "fe80::200:ff:fe00:2"}],
                    "mgmt-iface": [{"value": "2"}],
                    "capability": [
                        {"type": "Bridge", "enabled": False},
                        {"type": "Wlan", "enabled": False},
                    ]}
                ],
                "port": [{
                    "id": [{
                        "type": "mac",
                        "value": "00:00:00:00:00:02"
                    }],
                    "descr": [{"value": "eth1"}],
                    "ttl": [{"value": "120"}]
                }]
            }]}
        ]}),
    ("interfaces",
     {"lldp": [{
            "interface": [{
                "name": "eth0",
                "status": [{
                    "value": "RX and TX",
                }],
                "chassis": [{
                    "id": [{
                        "type": "mac",
                        "value": "00:00:00:00:00:01"
                    }],
                    "name": [{"value": "ns-1.example.com"}],
                    "descr": [{"value": "Spectacular GNU/Linux 2016 {}".format(uname)}],
                    "mgmt-ip": [{"value": "fe80::200:ff:fe00:1"}],
                    "mgmt-iface": [{"value": "3"}],
                    "capability": [
                        {"type": "Bridge", "enabled": False},
                        {"type": "Wlan", "enabled": False},
                    ]}
                ],
                "port": [{
                    "id": [{
                        "type": "mac",
                        "value": "00:00:00:00:00:01"
                    }],
                    "descr": [{"value": "eth0"}]
                }],
                "ttl": [{"ttl": "120"}]
            }]}
        ]})], ids=["neighbors", "interfaces"])
def test_json0_output(request, lldpd1, lldpd, lldpcli, namespaces, uname,
                      command, expected):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        result = lldpcli(
            *shlex.split("-f json0 show {} details".format(command)))
        assert result.returncode == 0
        out = result.stdout.decode('ascii')
        j = json.loads(out)

        eth0 = j['lldp'][0]['interface'][0]
        if command == "neighbors":
            del eth0['age']
        del eth0['chassis'][0]['capability'][3]
        del eth0['chassis'][0]['capability'][1]

        descr = "Spectacular GNU/Linux 2016 {}".format(uname)
        expected['lldp'][0]['interface'][0]['chassis'][0]["descr"][0]['value'] = descr

        if 'Dot3' in request.config.lldpd.features:
            expected['lldp'][0]['interface'][0]['port'][0]['auto-negotiation'] = [{
                "enabled": False,
                "supported": False,
                "current": [{"value":
                             "10GbaseT - Four-pair Category 6A or better, full duplex mode only"}]
            }]
        assert j == expected


@pytest.mark.skipif("'XML' not in config.lldpcli.outputs",
                    reason="XML not supported")
@pytest.mark.parametrize("command, expected", [
    ("neighbors",
"""<?xml version="1.0" encoding="UTF-8"?>
<lldp label="LLDP neighbors">
 <interface label="Interface" name="eth0" via="LLDP" rid="1" age="{age}">
  <chassis label="Chassis">
   <id label="ChassisID" type="mac">00:00:00:00:00:02</id>
   <name label="SysName">ns-2.example.com</name>
   <descr label="SysDescr">Spectacular GNU/Linux 2016 {uname}</descr>
   <mgmt-ip label="MgmtIP">fe80::200:ff:fe00:2</mgmt-ip>
   <mgmt-iface label="MgmtIface">2</mgmt-iface>
   <capability label="Capability" type="Bridge" enabled="off"/>
   <capability label="Capability" type="Router" enabled="{router}"/>
   <capability label="Capability" type="Wlan" enabled="off"/>
   <capability label="Capability" type="Station" enabled="{station}"/>
  </chassis>
  <port label="Port">
   <id label="PortID" type="mac">00:00:00:00:00:02</id>
   <descr label="PortDescr">eth1</descr>
   <ttl label="TTL">120</ttl>{dot3}
  </port>
 </interface>
</lldp>
"""),
("interfaces",
"""<?xml version="1.0" encoding="UTF-8"?>
<lldp label="LLDP interfaces">
 <interface label="Interface" name="eth0">
  <status label="Administrative status">RX and TX</status>
  <chassis label="Chassis">
   <id label="ChassisID" type="mac">00:00:00:00:00:01</id>
   <name label="SysName">ns-1.example.com</name>
   <descr label="SysDescr">Spectacular GNU/Linux 2016 {uname}</descr>
   <mgmt-ip label="MgmtIP">fe80::200:ff:fe00:1</mgmt-ip>
   <mgmt-iface label="MgmtIface">3</mgmt-iface>
   <capability label="Capability" type="Bridge" enabled="off"/>
   <capability label="Capability" type="Router" enabled="{router}"/>
   <capability label="Capability" type="Wlan" enabled="off"/>
   <capability label="Capability" type="Station" enabled="{station}"/>
  </chassis>
  <port label="Port">
   <id label="PortID" type="mac">00:00:00:00:00:01</id>
   <descr label="PortDescr">eth0</descr>{dot3}
  </port>
  <ttl label="TTL" ttl="120"/>
 </interface>
</lldp>
""")], ids=["neighbors", "interfaces"])
def test_xml_output(request, lldpd1, lldpd, lldpcli, namespaces, uname,
                    command, expected):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        result = lldpcli(
            *shlex.split("-f xml show {} details".format(command)))
        assert result.returncode == 0
        out = result.stdout.decode('ascii')
        xml = ET.fromstring(out)

        if command == "neighbors":
            age = xml.findall('./interface[1]')[0].attrib['age']
        else:
            age = None
        router = xml.findall("./interface[1]/chassis/"
                           "capability[@type='Router']")[0].attrib['enabled']
        station = xml.findall("./interface[1]/chassis/"
                            "capability[@type='Station']")[0].attrib['enabled']
        if 'Dot3' in request.config.lldpd.features:
            dot3 = """
   <auto-negotiation enabled="no" label="PMD autoneg" supported="no">
    <current label="MAU oper type">10GbaseT - Four-pair Category 6A or better, full duplex mode only</current>
   </auto-negotiation>"""
        else:
            dot3 = ""
        expected = ET.fromstring(expected.format(age=age,
                                                 router=router,
                                                 station=station,
                                                 uname=uname,
                                                 dot3=dot3))
        assert canonicalize(ET.tostring(xml)) == canonicalize(ET.tostring(expected))


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
def test_configure_one_port(lldpd1, lldpd, lldpcli, namespaces, links):
    links(namespaces(1), namespaces(2))
    with namespaces(2):
        lldpd()
        result = lldpcli(*("configure ports eth3 dot3 power "
                           "pse supported enabled paircontrol powerpairs "
                           "spare class class-3").split())
        assert result.returncode == 0
        time.sleep(3)
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "details")
        assert 'lldp.eth1.port.power.device-type' not in out
        assert out['lldp.eth3.port.power.device-type'] == 'PSE'
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert 'lldp.eth0.port.power.device-type' not in out
        assert out['lldp.eth2.port.descr'] == 'eth3'
        assert out['lldp.eth2.port.power.device-type'] == 'PSE'


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
def test_new_port_take_default(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        lldpd()
        result = lldpcli(*("configure dot3 power "
                           "pse supported enabled paircontrol powerpairs "
                           "spare class class-3").split())
        assert result.returncode == 0
        time.sleep(3)
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "details")
        assert out['lldp.eth1.port.power.device-type'] == 'PSE'
    with namespaces(1):
        # Check this worked
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth0.port.descr'] == 'eth1'
        assert out['lldp.eth0.port.power.device-type'] == 'PSE'
    links(namespaces(1), namespaces(2), 4)
    time.sleep(6)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out['lldp.eth2.port.descr'] == 'eth3'
        assert out['lldp.eth2.port.power.device-type'] == 'PSE'
    with namespaces(2):
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "details")
        assert out['lldp.eth3.port.power.device-type'] == 'PSE'


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
def test_port_keep_configuration_when_down(lldpd, lldpcli, namespaces, links):
    with namespaces(1):
        links.dummy('eth3')
        lldpd()
        result = lldpcli(*("configure ports eth3 dot3 power "
                           "pse supported enabled paircontrol powerpairs "
                           "spare class class-3").split())
        assert result.returncode == 0
        time.sleep(3)
        links.down('eth3')
        time.sleep(4)
        # eth3 configuration is kept because the port still exists.
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "details")
        assert out['lldp.eth3.port.power.device-type'] == 'PSE'

        links.up('eth3')
        time.sleep(4)
        # eth3 configuration is unchanged
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "details")
        assert out['lldp.eth3.port.power.device-type'] == 'PSE'


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
def test_port_forget_configuration(lldpd, lldpcli,
                                   namespaces, links):
    with namespaces(1):
        links.dummy('eth3')
        lldpd()
        result = lldpcli(*("configure dot3 power "
                           "pse supported enabled paircontrol powerpairs "
                           "spare class class-3").split())
        assert result.returncode == 0
        time.sleep(3)
        links.remove('eth3')
        time.sleep(4)
        # eth3 configuration was forgotten because it disappeared.
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "details")
        assert 'lldp.eth3.port.power.device-type' not in out


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    reason="Dot3 not supported")
def test_port_keep_configuration_of_permanent_ports(lldpd, lldpcli,
                                                    namespaces, links):
    with namespaces(1):
        links.dummy('eth3')
        links.dummy('noteth3')
        lldpd()
        result = lldpcli(*("configure system interface permanent e*").split())
        assert result.returncode == 0
        result = lldpcli(*("configure dot3 power "
                           "pse supported enabled paircontrol powerpairs "
                           "spare class class-3").split())
        assert result.returncode == 0
        time.sleep(3)
        links.remove('eth3')
        links.remove('noteth3')
        time.sleep(4)
        # eth3 configuration is kept because it matches the permanent
        # port pattern.
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "details")
        assert out['lldp.eth3.port.power.device-type'] == 'PSE'
        assert 'lldp.noteth3.port.power.device-type' not in out

        links.dummy('eth3')
        links.dummy('noteth3')
        time.sleep(4)
        # eth3 configuration is unchanged
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "details")
        assert out['lldp.eth3.port.power.device-type'] == 'PSE'
        # noteth3 inherited from default
        assert out['lldp.noteth3.port.power.device-type'] == 'PSE'


def test_watch(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        result = lldpcli("show", "neighbors")
        assert result.returncode == 0
        out = result.stdout.decode('ascii')
        assert "ns-2.example.com" in out

        # Put a link down and immediately watch for a change
        links.down('eth0')
        result = lldpcli("watch", "limit", "1")
        assert result.returncode == 0
        expected = out.replace('LLDP neighbors:', 'LLDP neighbor deleted:')
        expected = re.sub(r', Time: 0 day, 00:.*$', '', expected,
                          flags=re.MULTILINE)
        got = result.stdout.decode('ascii')
        got = re.sub(r', Time: 0 day, 00:.*$', '', got,
                     flags=re.MULTILINE)
        assert got == expected


@pytest.mark.skipif("'XML' not in config.lldpcli.outputs",
                    reason="XML not supported")
def test_watch_xml(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        result = lldpcli("-f", "xml", "show", "neighbors")
        assert result.returncode == 0
        expected = result.stdout.decode('ascii')
        expected = ET.fromstring(expected)
        assert [x.text
                for x in expected.findall("./interface/chassis/name")] == \
            ["ns-2.example.com"]

        # Put a link down and immediately watch for a change
        links.down('eth0')
        result = lldpcli("-f", "xml", "watch", "limit", "1")
        assert result.returncode == 0
        expected.tag = 'lldp-deleted'
        expected.set('label', 'LLDP neighbor deleted')
        expected.find('./interface').set('age', '')
        got = result.stdout.decode('ascii')
        got = ET.fromstring(got)
        got.find('./interface').set('age', '')
        assert canonicalize(ET.tostring(got)) == canonicalize(ET.tostring(expected))


@pytest.mark.skipif("'JSON' not in config.lldpcli.outputs",
                    reason="JSON not supported")
def test_watch_json(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        result = lldpcli("-f", "json", "show", "neighbors")
        assert result.returncode == 0
        expected = result.stdout.decode('ascii')
        expected = json.loads(expected)
        assert 'ns-2.example.com' in \
            expected['lldp']['interface']['eth0']['chassis']

        # Put a link down and immediately watch for a change
        links.down('eth0')
        result = lldpcli("-f", "json", "watch", "limit", "1")
        assert result.returncode == 0
        got = result.stdout.decode('ascii')
        got = json.loads(got)
        expected['lldp-deleted'] = expected['lldp']
        del expected['lldp']
        del expected['lldp-deleted']['interface']['eth0']['age']
        del got['lldp-deleted']['interface']['eth0']['age']
        assert got == expected


def test_return_code(lldpd1, lldpcli, namespaces):
    with namespaces(1):
        result = lldpcli("show", "neighbors")
        assert result.returncode == 0
        result = lldpcli("show", "interfaces")
        assert result.returncode == 0
        result = lldpcli("unknown", "command")
        assert result.returncode == 1


@pytest.mark.parametrize("command, name, expected", [
    ("configure system max-neighbors 10", "max-neighbors", 10),
    # get integral tx-delay from non-integral value (rounded up value)
    ("configure lldp tx-interval 1500ms", "tx-delay", 2),
    # get non-integral tx-delay-ms from non-integral value (exact value)
    ("configure lldp tx-interval 2500ms", "tx-delay-ms", 2500),
    ("configure lldp tx-interval 20", "tx-delay", 20),
    ("configure lldp tx-hold 5", "tx-hold", 5),
    ("configure lldp portidsubtype ifname", "lldp-portid-type", "ifname"),
    pytest.param("unconfigure med fast-start",
                 "lldpmed-faststart", "no",
                 marks=pytest.mark.skipif(
                     "'LLDP-MED' not in config.lldpd.features",
                     reason="LLDP-MED not supported")),
    pytest.param("configure med fast-start tx-interval 2",
                 "lldpmed-faststart-interval", 2,
                 marks=pytest.mark.skipif(
                     "'LLDP-MED' not in config.lldpd.features",
                     reason="LLDP-MED not supported")),
    ("configure system interface pattern eth*", "iface-pattern", "eth*"),
    ("configure system interface permanent eth*",
     "perm-iface-pattern", "eth*"),
    ("configure system ip management pattern 10.*", "mgmt-pattern", "10.*"),
    ("configure system chassisid squid", "cid-string", "squid"),
    ("configure system platform squid", "platform", "squid"),
    ("configure system description squid", "description", "squid"),
    ("configure system hostname squid", "hostname", "squid"),
    ("configure system interface description", "ifdescr-update", "yes"),
    ("configure system interface promiscuous", "iface-promisc", "yes"),
    ("configure system bond-slave-src-mac-type fixed",
     "bond-slave-src-mac-type", "fixed"),
    ("configure system description "
     "1234567890123456789012345678901234567890"
     "1234567890123456789012345678901234567890",
     "description",
     "1234567890123456789012345678901234567890"
     "1234567890123456789012345678901234567890"),
    ("configure lldp agent-type nearest-customer-bridge",
     "lldp-agent-type", "nearest customer bridge")])
def test_config_change(lldpd1, lldpcli, namespaces, command, name, expected):
    with namespaces(1):
        # Check initial value first
        out = lldpcli("-f", "keyvalue", "show", "configuration")
        assert out['configuration.config.{}'.format(name)] != str(expected)
        # Issue change and check new value
        result = lldpcli(*shlex.split(command))
        assert result.returncode == 0
        out = lldpcli("-f", "keyvalue", "show", "configuration")
        assert out['configuration.config.{}'.format(name)] == str(expected)


def test_config_capabilities(lldpd1, lldpcli, namespaces):
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "chassis")

        # Save values to check after unconfigure
        bridge = out['local-chassis.chassis.Bridge.enabled']
        router = out['local-chassis.chassis.Router.enabled']
        wlan = out['local-chassis.chassis.Wlan.enabled']
        station = out['local-chassis.chassis.Station.enabled']

        # Configure only bridge capability
        lldpcli("configure", "system", "capabilities", "enabled", "bridge")

        # Check only bridge capability on
        out = lldpcli("-f", "keyvalue", "show", "chassis")
        assert out['local-chassis.chassis.Bridge.enabled'] == "on"
        assert out['local-chassis.chassis.Router.enabled'] == "off"
        assert out['local-chassis.chassis.Wlan.enabled'] == "off"
        assert out['local-chassis.chassis.Station.enabled'] == "off"

        # Configure router and wlan capabilities.
        lldpcli("configure", "system", "capabilities", "enabled", "router,wlan")

        # This shoud enable only router and wlan and set to off the bridge capability again
        out = lldpcli("-f", "keyvalue", "show", "chassis")
        assert out['local-chassis.chassis.Bridge.enabled'] == "off"
        assert out['local-chassis.chassis.Router.enabled'] == "on"
        assert out['local-chassis.chassis.Wlan.enabled'] == "on"
        assert out['local-chassis.chassis.Station.enabled'] == "off"

        # Unconfigure system capabilities and use again the kernel information to enable capabilities
        lldpcli("unconfigure", "system", "capabilities", "enabled")

        # Check if the capabilities have the same values as before start the configurations
        out = lldpcli("-f", "keyvalue", "show", "chassis")
        assert out['local-chassis.chassis.Bridge.enabled'] == bridge
        assert out['local-chassis.chassis.Router.enabled'] == router
        assert out['local-chassis.chassis.Wlan.enabled'] == wlan
        assert out['local-chassis.chassis.Station.enabled'] == station
