import os
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
    calling mount namespace. The lldpd.d directory itself is created on the
    real filesystem when missing, like "make install" would, and is left
    empty. This has to be called from inside the namespace running lldpcli.
    """
    lldpd_d = os.path.join(request.config.lldpd.confdir, "lldpd.d")

    def install(**files):
        os.makedirs(lldpd_d, exist_ok=True)
        mount_tmpfs(lldpd_d)
        orgdir = os.path.join(lldpd_d, "org-tlvs.conf.d")
        os.mkdir(orgdir)
        for name, content in files.items():
            with open(os.path.join(orgdir, "{}.conf".format(name)), "w") as f:
                f.write(content)

    return install


def emit(lldpd, lldpcli, *tlvs):
    """Start an lldpd advertising the given (oui, subtype, payload) TLVs."""
    lldpd()
    for index, (oui, subtype, payload) in enumerate(tlvs):
        result = lldpcli(
            *shlex.split(
                "configure lldp custom-tlv {}oui {} subtype {} oui-info {}".format(
                    index and "add " or "", oui.replace(":", ","), subtype, payload
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
    assert out["testvendor-tlvs.value"] == expected
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
    assert out["testvendor-tlvs.org-tlv.status"] == "1"
    assert out["testvendor-tlvs.org-tlv.port"] == "80"
    assert out["testvendor-tlvs.org-tlv.address"] == "192.168.1.10"


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
    assert out["testvendor-tlvs.org-tlv.alpha"] == "7"
    assert out["testvendor-tlvs.org-tlv.beta"] == "1"
    assert out["testvendor-tlvs.org-tlv.port"] == "80"


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
    assert out["testvendor-tlvs.value"] == "ABC"
    assert out["othervendor-tlvs.value"] == "DEF"


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
    assert out["unknown-tlvs.value"] == "ABC"


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
