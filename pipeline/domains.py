"""Domain-list parsing and normalisation for ``dns/*.txt``.

Bundle semantics (see ``pb_core::db``): one lowercase domain per line, no wildcards, a domain also
blocks all its subdomains. Hence:

* every input format (plain domains, hosts files, adblock ``||domain^``, URLs) is reduced to bare
  hostnames, validated, lowercased and IDNA-encoded;
* IP addresses are dropped (DNS blocking cannot express them);
* a domain whose parent is already listed is redundant and pruned;
* shared platforms (github.com, drive.google.com, discord CDN…) are never blocked, nor any parent of
  them, because a single malicious URL there must not cut legitimate traffic;
* allowlisted domains and their subdomains are removed (the client applies the allowlist too).
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
# TLD: letters/digits/hyphens (xn-- allowed) but at least one letter, so numeric IPv4 never matches.
_TLD = r"(?=[a-z0-9-]*[a-z])(?!-)[a-z0-9-]{2,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_TLD}$")
_HOSTS_SINKS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255"}
_RESERVED_NAMES = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
}
_RESERVED_SUFFIXES = (".local", ".localhost", ".localdomain", ".arpa", ".internal", ".invalid", ".test", ".example")
MAX_DOMAIN_LEN = 253


def is_ip(host: str) -> bool:
    """True for IPv4/IPv6 literals (with or without brackets)."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_domain(raw: str) -> str | None:
    """Return the canonical form of ``raw`` (lowercase, IDNA, no wildcard/trailing dot) or None if invalid."""
    d = raw.strip().lower()
    if d.startswith("*."):
        d = d[2:]
    d = d.lstrip(".").rstrip(".")
    if not d or len(d) > MAX_DOMAIN_LEN or d in _RESERVED_NAMES or is_ip(d):
        return None
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not _DOMAIN_RE.match(d) or d.endswith(_RESERVED_SUFFIXES):
        return None
    return d


def host_from_url(url: str) -> str | None:
    """Hostname of an URL (``hxxp`` defanging tolerated); None for IPs or garbage."""
    u = url.strip()
    if not u:
        return None
    if "://" not in u:
        u = "http://" + u
    u = re.sub(r"^hxxp", "http", u, flags=re.IGNORECASE)
    try:
        host = urllib.parse.urlsplit(u).hostname
    except ValueError:
        return None
    if not host or is_ip(host):
        return None
    return normalize_domain(host)


def _strip_comment(line: str) -> str:
    for marker in ("#", "!"):
        idx = line.find(marker)
        if idx == 0:
            return ""
        if idx > 0 and marker == "#":
            line = line[:idx]
    return line.strip()


def _parse_adblock(line: str) -> str | None:
    # Only network rules that block a whole host: ||example.com^ (optionally $important / $all).
    if not line.startswith("||") or line.startswith("@@"):
        return None
    body = line[2:]
    opts = ""
    if "$" in body:
        body, opts = body.split("$", 1)
        if any(o not in ("important", "all", "doc", "document") for o in opts.split(",") if o):
            return None
    if not body.endswith("^"):
        return None
    body = body[:-1]
    if any(c in body for c in "/*?:|"):
        return None
    return normalize_domain(body)


def parse_list(text: str, fmt: str = "auto") -> set[str]:
    """Parse a blocklist in ``fmt`` (``domains``, ``hosts``, ``adblock``, ``urls`` or ``auto``)."""
    out: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", "[")):
            continue
        d: str | None
        if fmt == "adblock" or (fmt == "auto" and line.startswith("||")):
            d = _parse_adblock(line)
        elif fmt == "urls":
            d = host_from_url(line.split()[0])
        else:
            line = _strip_comment(line)
            if not line:
                continue
            parts = line.split()
            if fmt == "hosts" or (fmt == "auto" and len(parts) >= 2 and parts[0] in _HOSTS_SINKS):
                if len(parts) < 2 or parts[0] not in _HOSTS_SINKS:
                    continue
                d = normalize_domain(parts[1])
            else:
                if len(parts) != 1:
                    continue
                d = normalize_domain(parts[0])
        if d:
            out.add(d)
    return out


def ancestors(domain: str) -> Iterator[str]:
    """Proper parent domains with at least two labels: ``a.b.example.com`` -> ``b.example.com``, ``example.com``."""
    labels = domain.split(".")
    for i in range(1, len(labels) - 1):
        yield ".".join(labels[i:])


def is_under(domain: str, parent: str) -> bool:
    """True when ``domain`` equals ``parent`` or is one of its subdomains."""
    return domain == parent or domain.endswith("." + parent)


def prune_subdomains(domains: Iterable[str]) -> set[str]:
    """Drop every domain that has a listed ancestor (the ancestor already blocks it)."""
    s = set(domains)
    return {d for d in s if not any(a in s for a in ancestors(d))}


@dataclass
class Exclusions:
    """Domains that must never end up in a block list."""

    #: Allowlisted domains: they and their subdomains are never blocked.
    allow: set[str] = field(default_factory=set)
    #: Shared platforms: never block them nor any of their parents (``github.com``, ``drive.google.com``).
    shared_exact: set[str] = field(default_factory=set)
    #: Shared suffixes (``*.googleusercontent.com``): no host under them may be blocked either.
    shared_wildcard: set[str] = field(default_factory=set)

    @classmethod
    def from_lines(cls, allow_lines: Iterable[str], shared_lines: Iterable[str]) -> Exclusions:
        ex = cls()
        for line in allow_lines:
            entry = _strip_comment(line)
            d = normalize_domain(entry) if entry else None
            if d:
                ex.allow.add(d)
        for line in shared_lines:
            entry = _strip_comment(line)
            if not entry:
                continue
            target = ex.shared_wildcard if entry.startswith("*.") else ex.shared_exact
            d = normalize_domain(entry)
            if d:
                target.add(d)
        return ex

    def _shared_and_parents(self) -> set[str]:
        out = set(self.shared_exact) | set(self.shared_wildcard)
        for s in list(out):
            out.update(ancestors(s))
        return out

    def _excluded(self, domain: str, shared_parents: set[str]) -> bool:
        if domain in shared_parents:  # equals a shared host or would block one through a parent
            return True
        chain = [domain, *ancestors(domain)]
        return any(c in self.allow for c in chain) or any(c in self.shared_wildcard for c in chain)

    def excluded(self, domain: str) -> bool:
        """True when ``domain`` must not be blocked."""
        return self._excluded(domain, self._shared_and_parents())

    def apply(self, domains: Iterable[str]) -> tuple[set[str], int]:
        """Return (kept domains, number removed)."""
        shared_parents = self._shared_and_parents()
        kept: set[str] = set()
        removed = 0
        for d in domains:
            if self._excluded(d, shared_parents):
                removed += 1
            else:
                kept.add(d)
        return kept, removed


def render(domains: Iterable[str]) -> str:
    """Sorted, newline-terminated list (deterministic bundle content)."""
    items = sorted(set(domains))
    return "".join(f"{d}\n" for d in items)
