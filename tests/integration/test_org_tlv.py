import os
import xml.etree.ElementTree as ET
import pytest
import shlex
import time

from fixtures.namespaces import mount_tmpfs

# OUIs reserved for the tests. They must not collide with the definitions
# shipped in org-tlvs.conf.d, otherwise the expectations below would depend
# on files we do not control here.
OUI = "00:11:22"
OTHER_OUI = "00:11:33"


def definition(oui, subtype, name, fields, vendor=None):
    """Build an org-tlv configuration section for a single subtype.

    A vendor section is prepended when ``vendor`` is given. Sections can be
    concatenated to describe several subtypes in one file.
    """
    return "{}\n[{}:{}]\nname = {}\nfields = {}\n".format(
        vendor and "[{}]\nvendor = {}\n".format(oui, vendor) or "",
        oui,
        subtype,
        name,
        fields,
    )


@pytest.fixture
def org_tlv_conf(request):
    """Install org-tlv definitions where lldpcli looks for them.

    lldpcli reads SYSCONFDIR/lldpd.d/org-tlvs.conf.d. A tmpfs is mounted over
    lldpd.d before anything is written, so the definition files stay in the
    calling mount namespace. Only the directories leading to it are real, and
    they are removed once the test is over. This has to be called from inside
    the namespace running lldpcli.
    """
    lldpd_d = os.path.join(request.config.lldpd.confdir, "lldpd.d")
    created = []

    def install(**files):
        # Creating a directory is not confined to the mount namespace, unlike
        # the tmpfs mounted over it, so remember what will have to be undone.
        path = lldpd_d
        while not os.path.isdir(path):
            created.append(path)
            path = os.path.dirname(path)
        for path in reversed(created):
            os.mkdir(path)
        mount_tmpfs(lldpd_d)
        orgdir = os.path.join(lldpd_d, "org-tlvs.conf.d")
        os.mkdir(orgdir)
        for name, content in files.items():
            with open(os.path.join(orgdir, "{}.conf".format(name)), "w") as f:
                f.write(content)
        return orgdir

    yield install

    # The tmpfs is gone with the namespace, leaving the directories empty.
    for path in created:
        try:
            os.rmdir(path)
        except OSError:
            pass


def emit(lldpd, lldpcli, *tlvs):
    """Start an lldpd advertising the given (oui, subtype, payload) TLVs.

    An empty payload advertises a TLV without any OUI information.
    """
    lldpd()
    for index, (oui, subtype, payload) in enumerate(tlvs):
        result = lldpcli(
            *shlex.split(
                "configure lldp custom-tlv {}oui {} subtype {}{}".format(
                    index and "add " or "",
                    oui.replace(":", ","),
                    subtype,
                    payload and " oui-info {}".format(payload) or "",
                )
            )
        )
        assert result.returncode == 0
    time.sleep(3)


def neighbors(lldpcli, prefix="lldp.eth0."):
    out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
    return {k[len(prefix) :]: v for k, v in out.items() if k.startswith(prefix)}


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
@pytest.mark.parametrize(
    "fields, oui_info, expected",
    [
        ("string", "41,42,43,31,32,33", "ABC123"),
        ("uint8", "07", "7"),
        ("uint16", "01,2C", "300"),
        ("uint32", "00,00,01,2C", "300"),
        ("ipv4", "C0,A8,01,0A", "192.168.1.10"),
        ("mac", "00,11,22,33,44,55", "00:11:22:33:44:55"),
        ("hex", "DE,AD,BE,EF", "DE,AD,BE,EF"),
    ],
)
def test_org_tlv_field_types(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf, fields, oui_info, expected
):
    """Each supported field type is decoded according to the definition."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, oui_info))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "Test Field", fields, vendor="Testvendor")
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.test-field"] == expected
    # The raw hex fallback must not be used when a definition matched.
    assert not [k for k in out if k.startswith("unknown-tlvs.")]


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_named_fields(lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf):
    """A definition with several named fields splits the payload."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 2, "01,00,50,C0,A8,01,0A"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(
                OUI,
                2,
                "Uplink",
                "uint8:status, uint16:port, ipv4:address",
                vendor="Testvendor",
            )
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.uplink.status"] == "1"
    assert out["testvendor-tlvs.uplink.port"] == "80"
    assert out["testvendor-tlvs.uplink.address"] == "192.168.1.10"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_same_vendor_shares_one_group(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """Several subtypes of one OUI are decoded under the same vendor group."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "07"), (OUI, 2, "01,00,50"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "Alpha", "uint8:alpha", vendor="Testvendor")
            + definition(OUI, 2, "Beta", "uint8:beta, uint16:port")
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.alpha.alpha"] == "7"
    assert out["testvendor-tlvs.beta.beta"] == "1"
    assert out["testvendor-tlvs.beta.port"] == "80"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_definitions_from_several_files(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """Every .conf file is loaded and each vendor gets its own group."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "41,42,43"), (OTHER_OUI, 1, "44,45,46"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "First", "string", vendor="Testvendor"),
            othervendor=definition(
                OTHER_OUI, 1, "Second", "string", vendor="Othervendor"
            ),
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.first"] == "ABC"
    assert out["othervendor-tlvs.second"] == "DEF"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_without_vendor_is_unknown(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """Without a vendor section the TLV is decoded under "Unknown TLVs"."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "41,42,43"))
    with namespaces(1):
        org_tlv_conf(testvendor=definition(OUI, 1, "Test Field", "string"))
        out = neighbors(lldpcli)
    assert out["unknown-tlvs.test-field"] == "ABC"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_no_definition_falls_back_to_hex(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """An unmatched TLV keeps the previous raw hex rendering."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 9, "45,45,45"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "Test Field", "string", vendor="Testvendor")
        )
        out = neighbors(lldpcli)
    assert out["unknown-tlvs.unknown-tlv.oui"] == "00,11,22"
    assert out["unknown-tlvs.unknown-tlv.subtype"] == "9"
    assert out["unknown-tlvs.unknown-tlv"] == "45,45,45"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_vendor_group_is_not_nested_in_unknown(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """A vendor group opened after an unknown one is a sibling, not a child."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OTHER_OUI, 1, "41,42"), (OUI, 1, "43,44"))
    with namespaces(1):
        org_tlv_conf(
            a=definition(OTHER_OUI, 1, "No vendor", "string"),
            b=definition(OUI, 1, "With vendor", "string", vendor="Testvendor"),
        )
        out = neighbors(lldpcli)
    assert out["unknown-tlvs.no-vendor"] == "AB"
    assert out["testvendor-tlvs.with-vendor"] == "CD"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_single_field_ignores_trailing_bytes(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """A single unlabelled field discards what follows the value."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "C0,A8,01,0A,DE,AD,BE,EF"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "Address", "ipv4", vendor="Testvendor")
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.address"] == "192.168.1.10"
    assert not [k for k in out if "extra" in k]


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_single_field_too_short_displays_nothing(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """A single unlabelled field wider than the payload hides the TLV."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "01,02"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "Number", "uint32", vendor="Testvendor")
        )
        out = neighbors(lldpcli)
    assert not [k for k in out if "tlv" in k]


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_named_fields_report_extra_bytes(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """Bytes left over by labelled fields are displayed apart."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "07,DE,AD"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "Alpha", "uint8:alpha", vendor="Testvendor")
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.alpha.alpha"] == "7"
    assert out["testvendor-tlvs.alpha.extra"] == "DE,AD"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_named_fields_stop_on_short_payload(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """A labelled field that does not fit is dropped along with the next ones."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "07,01"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(
                OUI,
                1,
                "Alpha",
                "uint8:alpha, uint32:beta, uint8:gamma",
                vendor="Testvendor",
            )
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.alpha.alpha"] == "7"
    assert "testvendor-tlvs.alpha.beta" not in out
    assert "testvendor-tlvs.alpha.gamma" not in out
    assert "testvendor-tlvs.alpha.extra" not in out


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_without_fields_shows_whole_payload(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """A definition with no fields displays the payload as extra bytes."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "41,42"))
    with namespaces(1):
        org_tlv_conf(
            testvendor="[{o}]\nvendor = Testvendor\n\n[{o}:1]\nname = Blob\n".format(
                o=OUI
            )
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.blob.extra"] == "41,42"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_unknown_field_type_is_skipped(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """An unknown type is dropped and the other fields are still decoded."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "07"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(
                OUI, 1, "Alpha", "bogus:nope, uint8:alpha", vendor="Testvendor"
            )
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.alpha.alpha"] == "7"
    assert "testvendor-tlvs.alpha.nope" not in out


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_definition_precedence(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """The last definition of a TLV wins, but the first vendor name does."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "41"))
    with namespaces(1):
        org_tlv_conf(
            a=definition(OUI, 1, "From a", "uint8:froma", vendor="Vendora"),
            b=definition(OUI, 1, "From b", "uint8:fromb", vendor="Vendorb"),
        )
        out = neighbors(lldpcli)
    assert out["vendora-tlvs.from-b.fromb"] == "65"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_ignores_files_without_conf_suffix(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """Only files suffixed with .conf are read."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "41,42"))
    with namespaces(1):
        orgdir = org_tlv_conf()
        with open(os.path.join(orgdir, "testvendor.txt"), "w") as f:
            f.write(definition(OUI, 1, "Ignored", "string", vendor="Testvendor"))
        out = neighbors(lldpcli)
    assert out["unknown-tlvs.unknown-tlv"] == "41,42"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_definition_without_name_is_ignored(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """A definition lacking a name is discarded, leaving the hex display."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "41,42"))
    with namespaces(1):
        org_tlv_conf(
            testvendor="[{o}]\nvendor = Testvendor\n\n[{o}:1]\nfields = string\n".format(
                o=OUI
            )
        )
        out = neighbors(lldpcli)
    assert out["unknown-tlvs.unknown-tlv"] == "41,42"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_name_and_vendor_label_the_output(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """The name and the vendor are the labels of the plain text output."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "41,42,43,31,32,33"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(
                OUI, 1, "Serial Number", "string", vendor="Testvendor"
            )
        )
        result = lldpcli("show", "neighbors", "details")
    assert result.returncode == 0
    out = result.stdout.decode("ascii")
    assert "Testvendor TLVs" in out
    labelled = [line for line in out.splitlines() if "Serial Number" in line]
    assert labelled and "ABC123" in labelled[0]


CISCO_OUI = "00:01:42"


def aci_policy_group(tier, uuid):
    """Encode one ACI policy group entry: tier, 4 reserved bytes, ASCII UUID."""
    return ",".join(
        "{:02X}".format(b) for b in bytes([tier, 0, 0, 0, 0]) + uuid.encode("ascii")
    )


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_cisco_aci_policy_groups(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """Cisco subtype 207 is decoded by code, without any definition."""
    epg = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9fa0b1c2"
    tenant = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
    other = "ffffffff-ffff-4fff-bfff-ffffffffffff"
    payload = ",".join(
        [
            aci_policy_group(3, epg),
            aci_policy_group(1, tenant),
            aci_policy_group(9, other),
            # A truncated entry is ignored.
            "05,00,00,00,00,41,42",
        ]
    )
    with namespaces(2):
        emit(lldpd, lldpcli, (CISCO_OUI, 207, payload))
    with namespaces(1):
        org_tlv_conf()
        out = neighbors(lldpcli)
        result = lldpcli("show", "neighbors", "details")
    assert out["cisco-tlvs.aci-policy-groups.policy-group"] == [epg, tenant, other]
    assert out["cisco-tlvs.aci-policy-groups.policy-group.tier"] == [
        "EPG",
        "Tenant",
        "Unknown",
    ]
    assert not [k for k in out if k.startswith("unknown-tlvs.")]
    assert result.returncode == 0
    text = result.stdout.decode("ascii")
    assert "Cisco TLVs" in text
    assert "ACI Policy Groups" in text
    for tier, uuid in (("EPG", epg), ("Tenant", tenant), ("Unknown", other)):
        labelled = [line for line in text.splitlines() if uuid in line]
        assert labelled and tier in labelled[0]


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_cisco_handler_is_not_nested_in_unknown(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """A TLV decoded by code after an unknown one is a sibling, not a child."""
    uuid = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9fa0b1c2"
    with namespaces(2):
        emit(
            lldpd,
            lldpcli,
            (OUI, 1, "41,42"),
            (CISCO_OUI, 207, aci_policy_group(3, uuid)),
        )
    with namespaces(1):
        org_tlv_conf()
        out = neighbors(lldpcli)
    assert out["unknown-tlvs.unknown-tlv"] == "41,42"
    assert out["cisco-tlvs.aci-policy-groups.policy-group"] == uuid


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
@pytest.mark.parametrize("fields", ["hex", "string", "hex:raw"])
def test_org_tlv_empty_payload_displays_nothing(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf, fields
):
    """A TLV without OUI information leaves its definition empty."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, ""))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "Nothing", fields, vendor="Testvendor")
        )
        out = neighbors(lldpcli)
    assert not [k for k in out if k.startswith("testvendor-tlvs.")]


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_undefined_subtype_is_unknown_after_vendor_group(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """An undefined subtype goes to "Unknown TLVs" whatever precedes it."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "41"), (OUI, 9, "45"))
    with namespaces(1):
        org_tlv_conf(
            testvendor=definition(OUI, 1, "First", "string", vendor="Testvendor")
        )
        out = neighbors(lldpcli)
    assert out["testvendor-tlvs.first"] == "A"
    assert out["unknown-tlvs.unknown-tlv.subtype"] == "9"
    assert out["unknown-tlvs.unknown-tlv"] == "45"
    assert not [k for k in out if k.startswith("testvendor-tlvs.unknown")]


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
def test_org_tlv_labels_are_turned_into_tags(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """Vendor, TLV and field names become lowercase, dash-separated tags."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "07"), (OUI, 2, "41"))
    with namespaces(1):
        org_tlv_conf(
            acme=definition(OUI, 1, "Port Info", "uint8:Port ID", vendor="Acme Corp.")
            + definition(OUI, 2, "9 Lives!", "string")
        )
        out = neighbors(lldpcli)
    assert out["acme-corp-tlvs.port-info.port-id"] == "7"
    assert out["acme-corp-tlvs.tlv-9-lives"] == "A"


@pytest.mark.skipif(
    "'Custom TLV' not in config.lldpd.features", reason="Custom TLV not supported"
)
@pytest.mark.skipif("'XML' not in config.lldpcli.outputs", reason="XML not supported")
def test_org_tlv_xml_output_is_well_formed(
    lldpd1, lldpd, lldpcli, namespaces, org_tlv_conf
):
    """Labels that are not valid XML names do not break the XML output."""
    with namespaces(2):
        emit(lldpd, lldpcli, (OUI, 1, "07"))
    with namespaces(1):
        org_tlv_conf(
            acme=definition(OUI, 1, "Port Info", "uint8:Port ID", vendor="Acme Corp.")
        )
        result = lldpcli("-f", "xml", "show", "neighbors", "details")
    assert result.returncode == 0
    xml = ET.fromstring(result.stdout)
    field = xml.find("./interface/acme-corp-tlvs/port-info/port-id")
    assert field is not None
    assert field.text == "7"
    assert field.attrib["label"] == "Port ID"
