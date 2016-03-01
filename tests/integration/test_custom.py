import pytest
import shlex
import time


@pytest.mark.skipif('Custom TLV' not in pytest.config.lldpd.features,
                    reason="Custom TLV not supported")
@pytest.mark.parametrize("commands, expected", [
    (["oui 33,44,55 subtype 44"],
     {'unknown-tlv.oui': '33,44,55',
      'unknown-tlv.subtype': '44',
      'unknown-tlv.len': '0'}),
    (["oui 33,44,55 subtype 44 oui-info 45,45,45,45,45"],
     {'unknown-tlv.oui': '33,44,55',
      'unknown-tlv.subtype': '44',
      'unknown-tlv.len': '5',
      'unknown-tlv': '45,45,45,45,45'}),
    (["oui 33,44,55 subtype 44 oui-info 45,45,45,45,45",
      "add oui 33,44,55 subtype 44 oui-info 55,55,55,55,55",
      "add oui 33,44,55 subtype 55 oui-info 65,65,65,65,65"],
     {'unknown-tlv.oui': ['33,44,55', '33,44,55', '33,44,55'],
      'unknown-tlv.subtype': ['44', '44', '55'],
      'unknown-tlv.len': ['5', '5', '5'],
      'unknown-tlv': ['45,45,45,45,45',
                      '55,55,55,55,55',
                      '65,65,65,65,65']}),
    (["oui 33,44,55 subtype 44 oui-info 45,45,45,45,45",
      "add oui 33,44,55 subtype 55 oui-info 65,65,65,65,65",
      "replace oui 33,44,55 subtype 44 oui-info 66,66,66,66,66"],
     {'unknown-tlv.oui': ['33,44,55', '33,44,55'],
      'unknown-tlv.subtype': ['55', '44'],
      'unknown-tlv.len': ['5', '5'],
      'unknown-tlv': ['65,65,65,65,65',
                      '66,66,66,66,66']}),
    (["add oui 33,44,55 subtype 55 oui-info 65,65,65,65,65",
      "replace oui 33,44,55 subtype 44 oui-info 66,66,66,66,66"],
     {'unknown-tlv.oui': ['33,44,55', '33,44,55'],
      'unknown-tlv.subtype': ['55', '44'],
      'unknown-tlv.len': ['5', '5'],
      'unknown-tlv': ['65,65,65,65,65',
                      '66,66,66,66,66']}),
    (["oui 33,44,55 subtype 44 oui-info 45,45,45,45,45",
      "add oui 33,44,55 subtype 55 oui-info 55,55,55,55,55",
      "-oui 33,44,55 subtype 55"],
     {'unknown-tlv.oui': '33,44,55',
      'unknown-tlv.subtype': '44',
      'unknown-tlv.len': '5',
      'unknown-tlv': '45,45,45,45,45'}),
    (["oui 33,44,55 subtype 44 oui-info 45,45,45,45,45",
      "add oui 33,44,55 subtype 55 oui-info 65,65,65,65,65",
      "-"],
     {})])
def test_custom_tlv(lldpd1, lldpd, lldpcli, namespaces,
                    commands, expected):
    with namespaces(2):
        lldpd()
        for command in commands:
            result = lldpcli(
                *shlex.split("{}configure lldp custom-tlv {}".format(
                    command.startswith("-") and "un" or "",
                    command.lstrip("-"))))
            assert result.returncode == 0
        time.sleep(2)
    with namespaces(1):
        pfx = "lldp.eth0.unknown-tlvs."
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        out = {k[len(pfx):]: v
               for k, v in out.items()
               if k.startswith(pfx)}
        assert out == expected
