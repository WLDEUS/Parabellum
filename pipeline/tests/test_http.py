"""Truncated HTTP bodies must never be parsed as complete (review finding L6)."""

import io

import pytest

from pipeline.abusech import maybe_unzip
from pipeline.domains import complete_lines, parse_list
from pipeline.http import FetchError, Http, TruncatedBody, check_complete

from .conftest import zip_bytes


class _Sock:
    """Just enough of a socket for ``http.client.HTTPResponse`` to parse a canned response."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def makefile(self, mode: str):
        return io.BytesIO(self._raw)


def _response(raw: bytes):
    import http.client

    resp = http.client.HTTPResponse(_Sock(raw), method="GET")  # type: ignore[arg-type]
    resp.begin()
    return resp


class _Opener:
    def __init__(self, *raws: bytes) -> None:
        self.raws = list(raws)
        self.calls = 0

    def open(self, req, timeout=None):
        self.calls += 1
        return _response(self.raws.pop(0) if len(self.raws) > 1 else self.raws[0])


def _client(*raws: bytes) -> tuple[Http, _Opener]:
    http = Http(retries=2, backoff=0)
    opener = _Opener(*raws)
    http._opener = opener  # type: ignore[assignment]
    return http, opener


CUT = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nads.example.com\nfoo.co"
FULL = b"HTTP/1.1 200 OK\r\nContent-Length: 29\r\n\r\nads.example.com\nfoo.com\nz.io\n"


def test_get_bytes_rejects_a_body_shorter_than_content_length():
    http, opener = _client(CUT)
    with pytest.raises(FetchError, match="truncated"):
        http.get_bytes("https://lists.test/ads.txt")
    assert opener.calls == 2  # retried like a reset connection


def test_get_bytes_retries_then_succeeds():
    http, opener = _client(CUT, FULL)
    assert http.get_bytes("https://lists.test/ads.txt") == b"ads.example.com\nfoo.com\nz.io\n"
    assert opener.calls == 2


def test_get_bytes_without_content_length_is_unchanged():
    http, _ = _client(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc")
    assert http.get_bytes("https://lists.test/x") == b"abc"


def test_cut_chunked_body_becomes_fetch_error():
    # http.client raises IncompleteRead (an HTTPException, not an OSError) for a cut chunked body.
    http, _ = _client(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nads.exa")
    with pytest.raises(FetchError):
        http.get_bytes("https://lists.test/x")


def test_download_rejects_truncated_body(tmp_path):
    http, _ = _client(CUT)
    dest = tmp_path / "list.txt"
    with pytest.raises(FetchError, match="truncated"):
        http.download("https://lists.test/ads.txt", dest)
    assert not dest.exists() and not (tmp_path / "list.txt.part").exists()
    http, _ = _client(FULL)
    http.download("https://lists.test/ads.txt", dest)
    assert dest.read_bytes() == b"ads.example.com\nfoo.com\nz.io\n"


def test_check_complete():
    class R:
        def __init__(self, headers):
            self.headers = headers

    check_complete(R({}), 5, "x")
    check_complete(R({"Content-Length": "5"}), 5, "x")
    check_complete(R({"Content-Length": "garbage"}), 5, "x")
    with pytest.raises(TruncatedBody):
        check_complete(R({"Content-Length": "6"}), 5, "x")


def test_complete_lines_drops_the_cut_last_line():
    assert complete_lines("") == ""
    assert complete_lines("a.com\nb.com\n") == "a.com\nb.com\n"
    assert complete_lines("a.com\r\nfoo.co") == "a.com\r\n"
    assert complete_lines("foo.co") == ""
    # The cut ``foo.co`` (from foo.com) would otherwise be a valid, wrong domain.
    assert parse_list(complete_lines("ads.example.com\nfoo.co"), "domains") == {"ads.example.com"}


def test_plain_abusech_export_drops_cut_row_but_zip_keeps_everything():
    text = "# header\nrow1\nrow2-cut"
    assert maybe_unzip(text.encode()) == "# header\nrow1\n"
    assert maybe_unzip(zip_bytes({"x.csv": text.encode()})) == text
