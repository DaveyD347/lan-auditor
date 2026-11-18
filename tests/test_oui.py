from lanaudit.oui import OUILookup, is_locally_administered, normalize_mac, parse_oui_text


def test_normalize_mac_formats():
    assert normalize_mac("b8-27-eb-12-34-56") == "B8:27:EB:12:34:56"
    assert normalize_mac("b827.eb12.3456") == "B8:27:EB:12:34:56"
    assert normalize_mac("nope") is None


def test_locally_administered():
    assert is_locally_administered("02:00:00:00:00:01")
    assert is_locally_administered("DA:A1:19:00:00:00")
    assert not is_locally_administered("B8:27:EB:00:00:00")


def test_builtin_lookup():
    oui = OUILookup.load(path="/nonexistent")
    assert len(oui) > 50
    assert oui.lookup("b8:27:eb:aa:bb:cc") == "Raspberry Pi Foundation"
    assert "randomised" in oui.lookup("de:ad:be:ef:00:01")
    assert oui.lookup(None) is None
    assert oui.lookup("00:00:00:00:00:00") is None


def test_parse_ieee_csv():
    text = 'Registry,Assignment,Organization Name,Organization Address\nMA-L,001122,"Acme, Inc.",1 Road\n'
    assert parse_oui_text(text) == {"001122": "Acme, Inc."}


def test_parse_ieee_txt():
    text = "00-11-22   (hex)\t\tAcme Corp\n001122     (base 16)\t\tAcme Corp\n"
    assert parse_oui_text(text) == {"001122": "Acme Corp"}


def test_parse_wireshark_manuf():
    text = "00:11:22\tAcme\tAcme Corporation Ltd\n00:55:DA:00/28\tSub\tSub Vendor\n"
    assert parse_oui_text(text) == {"001122": "Acme Corporation Ltd"}


def test_parse_simple_cache_with_quotes():
    assert parse_oui_text('001122,"Acme, ""Best"" Inc."\n') == {"001122": 'Acme, "Best" Inc.'}


def test_custom_file_overrides(tmp_path):
    f = tmp_path / "oui.csv"
    f.write_text("B827EB,Custom Pi\n")
    assert OUILookup.load(f).lookup("B8:27:EB:00:00:01") == "Custom Pi"
