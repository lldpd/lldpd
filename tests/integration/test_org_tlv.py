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
        return orgdir

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
    assert out["unknown-tlvs.value"] == "AB"
    assert out["testvendor-tlvs.value"] == "CD"


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
    assert out["testvendor-tlvs.value"] == "192.168.1.10"
    assert "testvendor-tlvs.extra" not in out


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
    assert out["testvendor-tlvs.org-tlv.alpha"] == "7"
    assert out["testvendor-tlvs.org-tlv.extra"] == "DE,AD"


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
    assert out["testvendor-tlvs.org-tlv.alpha"] == "7"
    assert "testvendor-tlvs.org-tlv.beta" not in out
    assert "testvendor-tlvs.org-tlv.gamma" not in out
    assert "testvendor-tlvs.org-tlv.extra" not in out


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
    assert out["testvendor-tlvs.org-tlv.extra"] == "41,42"


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
    assert out["testvendor-tlvs.org-tlv.alpha"] == "7"
    assert "testvendor-tlvs.org-tlv.nope" not in out


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
    assert out["vendora-tlvs.org-tlv.fromb"] == "65"


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
