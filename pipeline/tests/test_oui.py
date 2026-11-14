"""IEEE OUI listing: parsing, merge, size guard, carry-over."""

from __future__ import annotations

import pytest

from pipeline import oui
from pipeline.http import FetchError

from .conftest import FakeHttp

MAL = (
    b"Registry,Assignment,Organization Name,Organization Address\n"
    b'MA-L,0024D4,FREEBOX SAS,"16 rue de la Ville l\'Eveque Paris  FR 75008 "\n'
    b'MA-L,3C22FB,"Apple, Inc.",1 Infinite Loop Cupertino CA US 95014\n'
    b"MA-L,ZZZZZZ,Bad Hex,x\n"
    b"MA-L,00AA,Too Short,x\n"
    b"MA-M,70B3D51,Wrong Registry In File,x\n"
)
MAM = b"Registry,Assignment,Organization Name,Organization Address\nMA-M,70B3D51,Tiny   Vendor\tGmbH,x\n"


def test_parse_and_render():
    got = oui.parse_csv(b"\xef\xbb\xbf" + MAL, "MA-L")
    assert got == {"0024D4": "FREEBOX SAS", "3C22FB": "Apple, Inc."}
    assert oui.parse_csv(MAM, "MA-M") == {"70B3D51": "Tiny Vendor GmbH"}
    assert (
        oui.render({"3C22FB": "Apple, Inc.", "0024D4": "FREEBOX SAS"}) == b"0024D4\tFREEBOX SAS\n3C22FB\tApple, Inc.\n"
    )


def test_fetch_merges_and_guards():
    http = FakeHttp({oui.REGISTRIES["MA-L"]: MAL, oui.REGISTRIES["MA-M"]: MAM})
    data, n = oui.fetch(http, min_entries=2)
    assert n == 3
    assert data.splitlines()[-1] == b"70B3D51\tTiny Vendor GmbH"
    # MA-S missing is tolerated; MA-L too small or missing is not.
    with pytest.raises(FetchError):
        oui.fetch(http, min_entries=10)
    with pytest.raises(FetchError):
        oui.fetch(FakeHttp({}), min_entries=1)


def test_carry_over(tmp_path):
    assert oui.carry_over(tmp_path) == {}
    (tmp_path / "lan").mkdir()
    (tmp_path / "lan" / "oui.tsv").write_bytes(b"0024D4\tFREEBOX SAS\n")
    files = oui.carry_over(tmp_path)
    assert oui.count(files[oui.BUNDLE_PATH]) == 1
