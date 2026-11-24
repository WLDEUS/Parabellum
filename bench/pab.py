#!/usr/bin/env python3
"""Parabellum Assurance Benchmark (PAB-1): measures the installed product on this Mac.

Methodology, thresholds and the parts that need a lab (VM, real samples, red team): docs/BENCHMARK.md.

    python3 bench/pab.py all                 # every local test that needs no sample and no sudo
    python3 bench/pab.py perf [--minutes 3]  # idle CPU / RAM of parabellumd, scan latency, UI instances
    python3 bench/pab.py tamper              # self-protection checks (non-destructive)
    python3 bench/pab.py evasion             # EICAR variants (archives, renaming, nesting, disk image)
    python3 bench/pab.py behavior            # benign persistence (LaunchAgent never loaded) -> alert
    python3 bench/pab.py fp [PATH...]        # false positives on installed apps (sudo: /Applications)
    python3 bench/pab.py efficacy DIR        # VM ONLY: detection rate on a folder of real samples

Results: bench-results/<UTC date-time>/scorecard.json and scorecard.md (git-ignored).

Safety: nothing here executes a sample. Scans use `scan --report-only` (no quarantine, no alert, no
action). Test files are written under ~/Library/Caches/ParabellumBench and removed at the end. The only
test that leaves a trace is `behavior` (a persistence alert, dismissed at the end). EICAR is the
industry's harmless test string; it is assembled at run time so this file is not itself detected.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import io
import json
import os
import platform
import shutil
import socket
import statistics
import stat
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile
from pathlib import Path

CLI = os.environ.get("PARABELLUM_CLI", "/usr/local/bin/parabellum")
SOCKET = os.environ.get("PARABELLUM_SOCKET", "/var/run/parabellum.sock")
ROOT = Path("/Library/Application Support/Parabellum")
APP = Path("/Applications/Parabellum.app")
WORK = Path.home() / "Library/Caches/ParabellumBench"

# Targets of the specification (docs/BENCHMARK.md §5).
TARGET_IDLE_CPU = 1.0  # % of one core, mean
TARGET_IDLE_RSS_MB = 150.0
TARGET_SCAN_P95_MS = 200.0  # < 10 MB file, CLI round trip included
TARGET_FP_RATE = 0.001  # 0.1 %


def eicar() -> bytes:
    # Assembled at run time (the literal would make this script a detection itself).
    parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"]
    return "".join(parts).encode()


# ----- helpers ------------------------------------------------------------------------------------


class Result:
    def __init__(self, test: str, name: str, ok: bool | None, value=None, target=None, note: str = ""):
        self.test, self.name, self.ok, self.value, self.target, self.note = test, name, ok, value, target, note

    def as_dict(self):
        return {k: getattr(self, k) for k in ("test", "name", "ok", "value", "target", "note")}


def run(args: list[str], timeout: int = 600, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)


def cli_json(args: list[str], sudo: bool = False, timeout: int = 3600):
    cmd = (["sudo"] if sudo else []) + [CLI, "--json", "--timeout", str(timeout)] + args
    p = run(cmd, timeout=timeout + 30)
    out = p.stdout.strip()
    if not out:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr.strip() or 'no output'}")
    return p.returncode, json.loads(out)


def scan_report_only(paths: list[str], sudo: bool = False):
    """(job detail, wall seconds)."""
    t0 = time.monotonic()
    _, detail = cli_json(["scan", "--report-only", *paths], sudo=sudo)
    return detail, time.monotonic() - t0


def pids(name: str) -> list[int]:
    p = run(["/usr/bin/pgrep", "-x", name])
    return [int(x) for x in p.stdout.split()] if p.returncode == 0 else []


def detected(detail: dict) -> set[str]:
    return {f["path"] for f in detail.get("findings", []) if f.get("verdict") in ("malicious", "suspicious")}


# ----- perf ---------------------------------------------------------------------------------------


def test_perf(minutes: float) -> list[Result]:
    out: list[Result] = []
    ui = pids("Parabellum")
    out.append(Result("perf", "instances de l'app (barre des menus)", len(ui) == 1, len(ui), 1,
                      "plus d'une : doublon au démarrage" if len(ui) > 1 else ""))
    daemon = pids("parabellumd")
    if len(daemon) != 1:
        out.append(Result("perf", "daemon parabellumd", False, len(daemon), 1, "absent ou en double"))
        return out
    pid = daemon[0]
    cpu, rss = [], []
    end = time.monotonic() + minutes * 60
    while time.monotonic() < end:
        p = run(["/bin/ps", "-o", "%cpu=,rss=", "-p", str(pid)])
        if p.returncode == 0 and p.stdout.split():
            c, r = p.stdout.split()[:2]
            cpu.append(float(c.replace(",", ".")))
            rss.append(int(r) / 1024)
        time.sleep(5)
    if cpu:
        m = statistics.fmean(cpu)
        out.append(Result("perf", "CPU au repos (moyenne, % d'un cœur)", m < TARGET_IDLE_CPU, round(m, 2),
                          f"< {TARGET_IDLE_CPU}", f"{len(cpu)} mesures sur {minutes} min"))
        out.append(Result("perf", "RAM au repos (max, Mo)", max(rss) < TARGET_IDLE_RSS_MB, round(max(rss), 1),
                          f"< {TARGET_IDLE_RSS_MB}", "RSS de parabellumd (ClamAV et osquery à part)"))
    # Scan latency of files under 10 MB (random content: worst case, no cache hit).
    WORK.mkdir(parents=True, exist_ok=True)
    lat = []
    for size_mb in (0.01, 1, 5, 9):
        for _ in range(5):
            f = WORK / f"lat-{uuid.uuid4().hex}.bin"
            f.write_bytes(os.urandom(int(size_mb * 1024 * 1024)))
            _, wall = scan_report_only([str(f)])
            lat.append(wall * 1000)
            f.unlink()
    lat.sort()
    p95 = lat[int(len(lat) * 0.95) - 1]
    out.append(Result("perf", "latence d'analyse p95 (< 10 Mo, ms)", p95 < TARGET_SCAN_P95_MS, round(p95),
                      f"< {TARGET_SCAN_P95_MS:.0f}", f"médiane {statistics.median(lat):.0f} ms, aller-retour CLI compris"))
    return out


# ----- tamper -------------------------------------------------------------------------------------


def raw_request(obj: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(SOCKET)
    s.sendall((json.dumps(obj) + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data.decode().splitlines()[0])


def test_tamper() -> list[Result]:
    out: list[Result] = []
    t = "tamper"
    try:
        st = os.stat(SOCKET)
        ok = st.st_uid == 0 and stat.S_IMODE(st.st_mode) & 0o007 == 0
        out.append(Result(t, "socket IPC root, fermée aux autres", ok, oct(stat.S_IMODE(st.st_mode)), "root:admin 0660"))
    except OSError as e:
        out.append(Result(t, "socket IPC", False, str(e)))
    # A process that is neither the app nor the CLI (this Python) must not change anything.
    # The request is harmless even if accepted (resume protection).
    try:
        r = raw_request({"id": 1, "cmd": "set_protection", "paused_minutes": 0})
        code = (r.get("error") or {}).get("code")
        out.append(Result(t, "commande modifiante depuis un binaire tiers refusée", not r.get("ok") and code == "permission_denied",
                          code or "acceptée", "permission_denied"))
        r = raw_request({"id": 2, "cmd": "set_dns", "enabled": False, "auth": base64.b64encode(os.urandom(32)).decode()})
        out.append(Result(t, "commande admin avec jeton forgé refusée", not r.get("ok"),
                          (r.get("error") or {}).get("code") or "acceptée", "refus"))
        r = raw_request({"id": 3, "cmd": "lan_status"})
        out.append(Result(t, "données sensibles (réseau local) refusées à un tiers", not r.get("ok"),
                          (r.get("error") or {}).get("code") or "acceptée", "refus"))
        # Oversized / garbage frames must be rejected, not crash the daemon.
        try:
            raw_request({"id": 4, "cmd": "x" * (2 << 20)})
        except Exception:
            pass
        out.append(Result(t, "daemon vivant après une trame géante", len(pids("parabellumd")) == 1, len(pids("parabellumd")), 1))
    except OSError as e:
        out.append(Result(t, "connexion à la socket", False, str(e)))
    for rel in ("bin/parabellumd", "db/current", "manifest.json"):
        target = ROOT / rel
        try:
            with open(target if target.is_file() else target / ".pab-write-test", "ab"):
                pass
            out.append(Result(t, f"écriture refusée : {rel}", False, "écriture possible"))
        except PermissionError:
            out.append(Result(t, f"écriture refusée : {rel}", True, "EACCES"))
        except OSError as e:
            out.append(Result(t, f"écriture refusée : {rel}", None, str(e), note="non applicable"))
    d = pids("parabellumd")
    if d:
        try:
            os.kill(d[0], 0)
            out.append(Result(t, "signal au daemon refusé à l'utilisateur", False, "autorisé"))
        except PermissionError:
            out.append(Result(t, "signal au daemon refusé à l'utilisateur", True, "EPERM"))
    for path in (ROOT / "bin/parabellumd", ROOT / "bin/parabellum", APP):
        if not path.exists():
            continue
        v = run(["/usr/bin/codesign", "--verify", "--strict", "--deep", str(path)])
        d_ = run(["/usr/bin/codesign", "-dv", str(path)])
        runtime = "runtime" in d_.stderr
        out.append(Result(t, f"signature + runtime renforcé : {path.name}", v.returncode == 0 and runtime,
                          "ok" if v.returncode == 0 else v.stderr.strip()[:120], "valide, flags=runtime"))
    try:
        _, status = cli_json(["status"])
        db = status.get("db", {})
        last = db.get("last_success") or db.get("built_at")
        age_h = (time.time() - last) / 3600 if last else None
        out.append(Result(t, "base de menaces signée présente et récente (h)", age_h is not None and age_h < 48,
                          None if age_h is None else round(age_h, 1), "< 48"))
        out.append(Result(t, "protection active", status.get("protection") == "active", status.get("protection"), "active",
                          "; ".join(status.get("issues", []))))
        _, alerts = cli_json(["alerts"])
        integrity = [a for a in alerts if "Parabellum" in a.get("title", "") and "modifi" in a.get("title", "")]
        out.append(Result(t, "aucune alerte d'intégrité ouverte", not integrity, len(integrity), 0))
    except Exception as e:  # noqa: BLE001
        out.append(Result(t, "état du daemon", False, str(e)))
    return out


# ----- evasion ------------------------------------------------------------------------------------


def zip_bytes(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return buf.getvalue()


def build_variants(root: Path) -> dict[str, tuple[Path, bool]]:
    """name -> (path, must_detect). Must-detect = a lab would count a miss as a failure."""
    e = eicar()
    v: dict[str, tuple[Path, bool]] = {}

    def put(name: str, data: bytes, must: bool, fname: str | None = None):
        p = root / name
        p.mkdir(parents=True, exist_ok=True)
        f = p / (fname or "sample.bin")
        f.write_bytes(data)
        v[name] = (f, must)

    put("plain", e, True, "eicar.com")
    put("renamed-jpg", e, True, "holiday.jpg")
    put("no-extension", e, True, "README")
    put("zip", zip_bytes("eicar.com", e), True, "a.zip")
    nested = e
    for i in range(3):
        nested = zip_bytes(f"layer{i}.zip" if i else "eicar.com", nested)
    put("zip-nested-3", nested, True, "nested.zip")
    deep = e
    for i in range(8):
        deep = zip_bytes(f"layer{i}.zip" if i else "eicar.com", deep)
    put("zip-nested-8", deep, False, "deep.zip")
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w:gz") as tf:
        info = tarfile.TarInfo("eicar.com")
        info.size = len(e)
        tf.addfile(info, io.BytesIO(e))
    put("tar-gz", tbuf.getvalue(), True, "a.tar.gz")
    put("gzip", gzip.compress(e), True, "eicar.com.gz")
    put("trailing-in-pdf", b"%PDF-1.4\n" + os.urandom(4096) + e, False, "doc.pdf")
    put("base64-in-script", b"#!/bin/sh\necho " + base64.b64encode(e) + b" | base64 -d > /dev/null\n", False, "x.sh")
    if platform.system() == "Darwin" and shutil.which("hdiutil"):
        src = root / "dmg-src"
        src.mkdir(parents=True, exist_ok=True)
        (src / "eicar.com").write_bytes(e)
        dmg = root / "dmg" / "image.dmg"
        dmg.parent.mkdir(parents=True, exist_ok=True)
        p = run(["hdiutil", "create", "-quiet", "-ov", "-fs", "HFS+", "-srcfolder", str(src), "-format", "UDZO", str(dmg)])
        shutil.rmtree(src, ignore_errors=True)
        if p.returncode == 0:
            v["dmg-udzo"] = (dmg, True)
    return v


def test_evasion() -> list[Result]:
    root = WORK / f"evasion-{uuid.uuid4().hex[:8]}"
    out: list[Result] = []
    try:
        variants = build_variants(root)
        detail, wall = scan_report_only([str(root)])
        hits = detected(detail)
        for name, (path, must) in variants.items():
            # The container itself or one of its members (`<container>!/<inner>`).
            found = any(h.startswith(str(path)) for h in hits)
            out.append(Result("evasion", name, found if must else (True if found else None), "détecté" if found else "manqué",
                              "doit être détecté" if must else "bonus", "" if must else "hors exigence (information)"))
        out.append(Result("evasion", "durée totale (s)", None, round(wall, 1)))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return out


# ----- behaviour ----------------------------------------------------------------------------------


def test_behavior(wait_s: int = 180) -> list[Result]:
    label = f"com.parabellum.bench.{uuid.uuid4().hex[:8]}"
    agents = Path.home() / "Library/LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    plist = agents / f"{label}.plist"
    # Never loaded (no launchctl): a file a persistence monitor must notice, nothing runs.
    plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
<key>RunAtLoad</key><false/>
</dict></plist>
""")
    t0 = time.monotonic()
    found = None
    try:
        while time.monotonic() - t0 < wait_s and found is None:
            time.sleep(5)
            _, alerts = cli_json(["alerts"])
            for a in alerts:
                if label in json.dumps(a):
                    found = a
                    break
    finally:
        plist.unlink(missing_ok=True)
    took = round(time.monotonic() - t0)
    if found:
        run([CLI, "resolve", str(found["id"]), "dismiss"])
    return [Result("behavior", "nouveau LaunchAgent signalé (s)", found is not None, took if found else "aucune alerte",
                   f"< {wait_s}", "T1543.001 Launch Agent (fichier jamais chargé)")]


# ----- false positives / efficacy -----------------------------------------------------------------


def test_fp(paths: list[str]) -> list[Result]:
    sudo = any(not p.startswith(str(Path.home())) for p in paths)
    detail, wall = scan_report_only(paths, sudo=sudo)
    files = detail["summary"]["files_scanned"]
    fps = sorted(detected(detail))
    rate = len(fps) / files if files else 0.0
    res = [Result("fp", "taux de faux positifs", rate < TARGET_FP_RATE, f"{len(fps)}/{files} ({rate:.4%})",
                  f"< {TARGET_FP_RATE:.1%}", f"{', '.join(paths)} en {wall:.0f} s")]
    for p in fps[:50]:
        res.append(Result("fp", "faux positif", False, p))
    return res


def test_efficacy(folder: str) -> list[Result]:
    if not os.environ.get("PAB_I_AM_IN_A_VM"):
        sys.exit("efficacy : uniquement dans une VM isolée (export PAB_I_AM_IN_A_VM=1). Voir docs/BENCHMARK.md.")
    files = [p for p in Path(folder).rglob("*") if p.is_file()]
    detail, wall = scan_report_only([folder], sudo=not folder.startswith(str(Path.home())))
    hits = detected(detail)
    caught = sum(1 for f in files if any(h == str(f) or h.startswith(str(f) + "!/") for h in hits))
    rate = caught / len(files) if files else 0.0
    res = [Result("efficacy", "détection statique (échantillons réels)", rate >= 0.99, f"{caught}/{len(files)} ({rate:.1%})",
                  ">= 99 %", f"{wall:.0f} s, sans exécution")]
    for f in files:
        if not any(h == str(f) or h.startswith(str(f) + "!/") for h in hits):
            res.append(Result("efficacy", "manqué", False, f.name))
    return res


# ----- report -------------------------------------------------------------------------------------


def write(results: list[Result], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "benchmark": "PAB-1",
        "date": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "macos": platform.mac_ver()[0],
        "machine": platform.machine(),
        "cli_version": run([CLI, "--version"]).stdout.strip() if Path(CLI).exists() else None,
    }
    required = [r for r in results if r.ok is not None]
    passed = sum(1 for r in required if r.ok)
    meta["score"] = f"{passed}/{len(required)}"
    (out_dir / "scorecard.json").write_text(json.dumps({"meta": meta, "results": [r.as_dict() for r in results]},
                                                       indent=2, ensure_ascii=False))
    lines = [f"# PAB-1 — {meta['date']}", "", f"macOS {meta['macos']} ({meta['machine']}), {meta['cli_version']}",
             "", f"**Score : {meta['score']} exigences tenues**", "",
             "| Test | Mesure | Résultat | Valeur | Cible | Note |", "|---|---|---|---|---|---|"]
    for r in results:
        mark = "✅" if r.ok else ("❌" if r.ok is False else "·")
        lines.append(f"| {r.test} | {r.name} | {mark} | {r.value if r.value is not None else ''} | {r.target or ''} | {r.note} |")
    (out_dir / "scorecard.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\n→ {out_dir}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("all")
    pa.add_argument("--minutes", type=float, default=3)
    pp = sub.add_parser("perf")
    pp.add_argument("--minutes", type=float, default=3)
    sub.add_parser("tamper")
    sub.add_parser("evasion")
    sub.add_parser("behavior")
    pf = sub.add_parser("fp")
    pf.add_argument("paths", nargs="*", default=["/Applications"])
    pe = sub.add_parser("efficacy")
    pe.add_argument("folder")
    ap.add_argument("--out", default="bench-results")
    a = ap.parse_args()
    if not Path(CLI).exists():
        sys.exit(f"CLI introuvable : {CLI} (installe Parabellum ou définis PARABELLUM_CLI)")
    results: list[Result] = []
    if a.cmd in ("all", "tamper"):
        results += test_tamper()
    if a.cmd in ("all", "perf"):
        results += test_perf(a.minutes)
    if a.cmd in ("all", "evasion"):
        results += test_evasion()
    if a.cmd in ("all", "behavior"):
        results += test_behavior()
    if a.cmd == "fp":
        results += test_fp(a.paths)
    if a.cmd == "efficacy":
        results += test_efficacy(a.folder)
    shutil.rmtree(WORK, ignore_errors=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    write(results, Path(a.out) / stamp)
    return 0 if all(r.ok is not False for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
