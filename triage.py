#!/usr/bin/env python3
import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import yara
except ImportError:
    yara = None
try:
    import pefile
except ImportError:
    pefile = None

MAX_READ = 200 * 1024 * 1024
HERE = Path(__file__).resolve().parent

USE_COLOR = sys.stdout.isatty()


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


RED, GREEN, YELLOW, CYAN, BOLD = "31", "32", "33", "36", "1"

# 1. Hashing
def compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((x / n) * math.log2(x / n) for x in counts if x)

# 2. ClamAV
def run_clamav(path: Path) -> dict:
    exe = shutil.which("clamscan")
    if not exe:
        return {"available": False, "detections": [], "raw": "clamscan not found"}
    proc = subprocess.run(
        [exe, "--no-summary", str(path)], capture_output=True, text=True, timeout=300
    )
    raw = (proc.stdout + proc.stderr).strip()
    detections = []
    for line in proc.stdout.splitlines():
        if line.endswith(" FOUND"):
            detections.append(line.rsplit(": ", 1)[1].removesuffix(" FOUND"))
    return {
        "available": True,
        "returncode": proc.returncode,  # 0 clean, 1 found, 2 error
        "detections": detections,
        "raw": raw,
    }


# 3. YARA
def run_yara(data: bytes, rules_dir: Path) -> dict:
    if yara is None:
        return {"available": False, "matches": [], "error": "yara-python not installed"}
    files = {p.stem: str(p) for p in sorted(rules_dir.glob("*.yar*"))}
    if not files:
        return {"available": False, "matches": [], "error": f"no rules in {rules_dir}"}
    try:
        rules = yara.compile(filepaths=files)
    except yara.SyntaxError as e:
        return {"available": False, "matches": [], "error": f"rule syntax error: {e}"}
    matches = []
    for m in rules.match(data=data):
        try:
            ids = sorted({s.identifier for s in m.strings})
        except AttributeError:
            ids = sorted({s[1] for s in m.strings})
        matches.append(
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "description": m.meta.get("description", ""),
                "severity": m.meta.get("severity", "low"),
                "matched_strings": ids,
            }
        )
    return {"available": True, "matches": matches}

# 4. Strings + IOC extraction
def extract_strings(data: bytes, min_len: int = 6) -> dict:
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    ascii_s = [m.group().decode("ascii") for m in ascii_re.finditer(data)]
    wide_s = [m.group().decode("utf-16le") for m in wide_re.finditer(data)]
    return {"ascii": ascii_s, "utf16": wide_s}


URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\^`{}|]+", re.I)
IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b")
EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b", re.I)

TLDS = set(
    "com net org info biz xyz top club online site tech shop store live cloud app dev "
    "io co me cc tv ws to pw tk ml ga cf gq su ru cn ir kp kr jp in br de fr nl uk us "
    "ua pl tr it es ch se no fi cz ro onion "
    "example test invalid localhost".split()  # RFC 2606 reserved -- used by this project's own canary file
)
BENIGN_DOMAIN_SUFFIXES = (
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com", "live.com",
    "digicert.com", "verisign.com", "globalsign.com", "symantec.com", "w3.org",
    "mozilla.org", "python.org", "openssl.org", "gnu.org", "apache.org",
    "example.com", "example.org", "example.net", "localhost",
)


def is_benign_domain(d: str) -> bool:
    return any(d == s or d.endswith("." + s) for s in BENIGN_DOMAIN_SUFFIXES)


def classify_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "ignore"
    if any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
        return "public"
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_reserved:
        return "ignore"
    if a.is_private or a.is_link_local:
        return "internal"
    return "public"


def defang(v: str) -> str:
    return (
        v.replace("http://", "hxxp://").replace("https://", "hxxps://")
        .replace("ftp://", "fxp://").replace(".", "[.]")
    )


def extract_iocs(strings: dict) -> dict:
    text = "\n".join(strings["ascii"] + strings["utf16"])
    lower = text.lower()

    urls = {u.rstrip(".,;)]'\"") for u in URL_RE.findall(text)}
    ips_public, ips_internal = set(), set()
    for ip in IPV4_RE.findall(text):
        kind = classify_ip(ip)
        if kind == "public":
            ips_public.add(ip)
        elif kind == "internal":
            ips_internal.add(ip)

    domains = set()
    for m in DOMAIN_RE.finditer(lower):
        d = m.group(0)
        if m.group(1) in TLDS and not is_benign_domain(d) and not IPV4_RE.fullmatch(d):
            domains.add(d)
    for u in urls:
        host = re.sub(r"^\w+://", "", u).split("/")[0].split(":")[0].lower()
        if host and not IPV4_RE.fullmatch(host) and not is_benign_domain(host):
            domains.add(host)

    emails = {e.lower() for e in EMAIL_RE.findall(text)}
    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ips_public": sorted(ips_public),
        "ips_internal": sorted(ips_internal),
        "emails": sorted(emails),
    }


SUSPICIOUS_APIS = {
    "process_injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                          "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
                          "NtWriteVirtualMemory"],
    "network": ["InternetOpenUrl", "InternetOpenA", "InternetOpenW", "URLDownloadToFile",
                "WinHttpOpen", "HttpSendRequest", "WSAStartup", "InternetReadFile"],
    "persistence": ["RegSetValueEx", "RegCreateKeyEx", "CreateServiceA", "CreateServiceW",
                    "SHGetSpecialFolderPath"],
    "anti_analysis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "NtQueryInformationProcess", "GetTickCount"],
    "execution": ["WinExec", "ShellExecute", "CreateProcessA", "CreateProcessW"],
    "crypto/ransom": ["CryptEncrypt", "CryptAcquireContext", "CryptGenKey"],
    "keylog/credential": ["SetWindowsHookEx", "GetAsyncKeyState", "LsaEnumerateLogonSessions"],
}

HINT_PATTERNS = {
    "registry_key_hint": re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[\w\\ .-]+", re.I),
    "run_key_hint": re.compile(r"CurrentVersion\\Run", re.I),
    "mutex_hint": re.compile(r"(?:Global|Local)\\[\w{-}.-]{4,}"),
}


def find_suspicious_apis(strings: dict) -> dict:
    blob = "\n".join(strings["ascii"] + strings["utf16"])
    found = {}
    for cat, apis in SUSPICIOUS_APIS.items():
        hits = sorted({a for a in apis if a in blob})
        if hits:
            found[cat] = hits
    return found


def find_hints(strings: dict) -> dict:
    blob = "\n".join(strings["ascii"] + strings["utf16"])
    return {k: sorted(set(p.findall(blob)))[:20] for k, p in HINT_PATTERNS.items()
            if p.search(blob)}

# 5. PE analysis (optional -- needs pefile)
def analyze_pe(data: bytes) -> dict:
    if data[:2] != b"MZ":
        return {"is_pe": False}
    if pefile is None:
        return {"is_pe": True, "parsed": False, "error": "pefile not installed"}
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as e:
        return {"is_pe": True, "parsed": False, "error": f"malformed PE: {e}"}
    sections = []
    for s in pe.sections:
        sections.append({
            "name": s.Name.rstrip(b"\x00").decode(errors="replace"),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 2),
        })
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode(errors="replace")
        imports[dll] = [i.name.decode(errors="replace") for i in entry.imports if i.name]
    ts = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc)
    return {
        "is_pe": True,
        "parsed": True,
        "compile_time": ts.isoformat(),
        "imphash": pe.get_imphash(),
        "sections": sections,
        "import_count": sum(len(v) for v in imports.values()),
        "imports": imports,
    }


# 6. VirusTotal (hash lookup only -- the file is NEVER uploaded)
class VirusTotal:
    BASE = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key, cache_path: Path, delay: float = 16.0):
        self.key, self.cache_path, self.delay = api_key, cache_path, delay
        self.cache = {}
        if cache_path.exists():
            try:
                self.cache = json.loads(cache_path.read_text())
            except json.JSONDecodeError:
                pass

    def lookup(self, sha256: str) -> dict:
        if sha256 in self.cache:
            return {**self.cache[sha256], "cached": True}
        req = urllib.request.Request(self.BASE + sha256, headers={"x-apikey": self.key})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                result = {"status": "not_found"}
            elif e.code == 429:
                return {"status": "error", "error": "rate limited (HTTP 429), retry later"}
            else:
                return {"status": "error", "error": f"HTTP {e.code}"}
        except (urllib.error.URLError, TimeoutError) as e:
            return {"status": "error", "error": f"network: {e}"}
        else:
            a = body["data"]["attributes"]
            engines = a.get("last_analysis_results", {})
            flagged = {n: v.get("result") for n, v in engines.items()
                       if v.get("category") in ("malicious", "suspicious")}
            ptc = a.get("popular_threat_classification", {})
            result = {
                "status": "found",
                "stats": a.get("last_analysis_stats", {}),
                "total_engines": len(engines),
                "flagged_engines": dict(sorted(flagged.items())),
                "threat_label": ptc.get("suggested_threat_label"),
                "names": a.get("names", [])[:10],
                "first_seen": a.get("first_submission_date"),
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        self.cache[sha256] = result
        self.cache_path.write_text(json.dumps(self.cache, indent=2))
        time.sleep(self.delay)  # free tier: 4 requests/minute
        return {**result, "cached": False}


# 7. Verdict + escalation logic
SEV_POINTS = {"high": 3, "medium": 2, "low": 1}

def build_verdict(report: dict) -> dict:
    score, reasons, escalate = 0, [], []
    clam, yr, vt, pe = report["clamav"], report["yara"], report["virustotal"], report["pe"]

    if clam["detections"]:
        score += 3
        reasons.append(f"ClamAV detected: {', '.join(clam['detections'])}")
    for m in yr["matches"]:
        score += SEV_POINTS.get(m["severity"], 1)
        reasons.append(f"YARA {m['rule']} ({m['severity']})")
    if vt.get("status") == "found":
        mal = vt["stats"].get("malicious", 0)
        total = vt["total_engines"] or 1
        ratio = mal / total
        if ratio >= 0.25:
            score += 3
        elif ratio >= 0.08:
            score += 1
        reasons.append(f"VirusTotal: {mal}/{vt['total_engines']} engines malicious ({ratio:.0%})")
    elif vt.get("status") == "not_found":
        reasons.append("VirusTotal: hash never seen before")

    vt_ratio = 0.0
    if vt.get("status") == "found":
        vt_ratio = vt["stats"].get("malicious", 0) / (vt["total_engines"] or 1)

    strong_sources = sum([
        bool(clam["detections"]),          # known-signature match
        bool(yr["matches"]),               # pattern/behavioural match
        vt_ratio >= 0.25,                  # meaningful industry consensus
    ])
    if strong_sources >= 2 and score >= 3:
        label = "CONFIRMED MALICIOUS"
    elif score >= 3:
        label = "LIKELY MALICIOUS"
    elif score >= 1:
        label = "SUSPICIOUS"
    else:
        label = "NO DETECTION (does not prove the file is clean)"

    # ---- escalation criteria ----
    if pe.get("parsed"):
        if any(s["entropy"] > 7.2 for s in pe["sections"]):
            escalate.append("High-entropy section: file is likely packed/obfuscated")
        if pe["import_count"] < 10:
            escalate.append("Very few imports: likely packed or loads APIs dynamically")
    if report["yara_packer_hit"]:
        escalate.append("Packer signature matched: behaviour cannot be seen statically")
    sources_hit = [bool(clam["detections"]), bool(yr["matches"]),
                   vt.get("status") == "found" and vt["stats"].get("malicious", 0) > 0]
    if any(sources_hit) and not all(x for x, ok in zip(sources_hit, [
            clam["available"], yr["available"], vt.get("status") == "found"]) if ok):
        escalate.append("Detection sources disagree (some hit, some clean)")
    if vt.get("status") == "not_found" and (yr["matches"] or clam["detections"]):
        escalate.append("Locally flagged but unknown to VirusTotal: possibly novel/targeted")
    cats = report["suspicious_apis"]
    if "crypto/ransom" in cats:
        escalate.append("Crypto APIs present: possible ransomware")
    if "keylog/credential" in cats:
        escalate.append("Credential/keylogging APIs present")
    if "process_injection" in cats:
        escalate.append("Process-injection APIs present")
    return {"score": score, "label": label, "reasons": reasons,
            "escalate": bool(escalate), "escalation_reasons": escalate}


# 8. Reporting
def blocklist_rows(report: dict) -> list:
    v, h, iocs, vt = report["verdict"], report["hashes"], report["iocs"], report["virustotal"]
    rows = []
    file_conf = "high" if v["score"] >= 3 else "medium" if v["score"] >= 1 else "none"
    if file_conf != "none":
        src = "+".join(filter(None, [
            "clamav" if report["clamav"]["detections"] else "",
            "yara" if report["yara"]["matches"] else "",
            "virustotal" if vt.get("status") == "found" and vt["stats"].get("malicious") else ""]))
        for k in ("sha256", "md5"):
            rows.append(["hash_" + k, h[k], file_conf, src, "block (EDR)"])
    for ip in iocs["ips_public"]:
        rows.append(["ip", ip, "low", "strings", "review, then block (firewall)"])
    for d in iocs["domains"]:
        rows.append(["domain", d, "low", "strings", "review, then block (DNS/proxy)"])
    for u in iocs["urls"]:
        rows.append(["url", u, "low", "strings", "review, then block (proxy)"])
    return rows


def write_reports(report: dict, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{Path(report['file']['name']).stem}_{report['hashes']['sha256'][:8]}"
    (out_dir / f"{stem}.json").write_text(json.dumps(report, indent=2))

    with open(out_dir / f"{stem}_blocklist.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "confidence", "source", "recommended_action"])
        w.writerows(blocklist_rows(report))

    (out_dir / f"{stem}_clamav.log").write_text(report["clamav"]["raw"] + "\n")
    (out_dir / f"{stem}.md").write_text(render_markdown(report))
    return stem


def render_markdown(r: dict) -> str:
    v, h, i, vt, pe = r["verdict"], r["hashes"], r["iocs"], r["virustotal"], r["pe"]
    L = [f"# Triage Report: {r['file']['name']}", "",
         f"*Generated {r['generated_utc']} -- static analysis only, sample never executed*", "",
         f"## Verdict: **{v['label']}** (score {v['score']})", ""]
    L += [f"- {x}" for x in v["reasons"]] or ["- No detections"]
    L += ["", f"**Escalate to external vendor: {'YES' if v['escalate'] else 'No'}**"]
    L += [f"- {x}" for x in v["escalation_reasons"]]
    L += ["", "## File", "", "| Property | Value |", "|---|---|",
          f"| Size | {r['file']['size']} bytes |", f"| Entropy | {r['file']['entropy']:.2f} |",
          f"| Type | {r['file']['type']} |", f"| MD5 | `{h['md5']}` |",
          f"| SHA1 | `{h['sha1']}` |", f"| SHA256 | `{h['sha256']}` |"]
    L += ["", "## ClamAV", ""]
    if not r["clamav"]["available"]:
        L.append("_clamscan not available_")
    else:
        L.append("Detections: " + (", ".join(r["clamav"]["detections"]) or "none"))
    L += ["", "## YARA", ""]
    if not r["yara"]["available"]:
        L.append(f"_YARA unavailable: {r['yara'].get('error')}_")
    elif not r["yara"]["matches"]:
        L.append("No rules matched.")
    else:
        L += ["| Rule | Severity | Description |", "|---|---|---|"]
        L += [f"| {m['rule']} | {m['severity']} | {m['description']} |" for m in r["yara"]["matches"]]
    L += ["", "## VirusTotal", ""]
    if vt.get("status") == "found":
        s = vt["stats"]
        L += [f"- Malicious: **{s.get('malicious', 0)}** / {vt['total_engines']} engines "
              f"(suspicious: {s.get('suspicious', 0)}, undetected: {s.get('undetected', 0)})",
              f"- Threat label: {vt.get('threat_label') or 'n/a'}", f"- Link: {vt['link']}", ""]
        L += ["| Engine | Verdict |", "|---|---|"]
        L += [f"| {e} | {res} |" for e, res in list(vt["flagged_engines"].items())[:25]]
    else:
        L.append(f"Status: {vt.get('status')} {vt.get('error', '')}")
    L += ["", "## Extracted IOCs (defanged)", ""]
    for label, key in [("Public IPs", "ips_public"), ("Internal IPs (informational)", "ips_internal"),
                       ("Domains", "domains"), ("URLs", "urls"), ("Emails", "emails")]:
        L.append(f"**{label}:** " + (", ".join(f"`{defang(x)}`" for x in i[key]) or "none"))
    L += ["", "## Suspicious API strings", ""]
    L += [f"- **{k}**: {', '.join(vs)}" for k, vs in r["suspicious_apis"].items()] or ["None"]
    if r["hints"]:
        L += ["", "## Hints for dynamic-only IOCs (unconfirmed)", ""]
        L += [f"- **{k}**: {', '.join(f'`{x}`' for x in vs)}" for k, vs in r["hints"].items()]
    if pe.get("parsed"):
        L += ["", "## PE details", "", f"- Compile time: {pe['compile_time']}",
              f"- Imphash: `{pe['imphash']}`", f"- Import count: {pe['import_count']}", "",
              "| Section | Raw size | Entropy |", "|---|---|---|"]
        L += [f"| {s['name']} | {s['raw_size']} | {s['entropy']} |" for s in pe["sections"]]
    L += ["", f"## Strings sample ({r['strings_total']} total)", "", "```"]
    L += r["strings_preview"] + ["```", ""]
    return "\n".join(L)


def print_summary(r: dict, stem: str, out_dir: Path):
    v = r["verdict"]
    colour = RED if v["score"] >= 3 else YELLOW if v["score"] >= 1 else GREEN
    print(c("=" * 64, CYAN))
    print(c(f" {r['file']['name']}", BOLD))
    print(c("=" * 64, CYAN))
    print(f" SHA256 : {r['hashes']['sha256']}")
    print(f" MD5    : {r['hashes']['md5']}")
    print(f" Size   : {r['file']['size']} bytes   Entropy: {r['file']['entropy']:.2f}   "
          f"Type: {r['file']['type']}")
    cl = r["clamav"]
    print(f" ClamAV : " + (", ".join(cl["detections"]) or "clean") if cl["available"]
          else " ClamAV : (not installed)")
    ym = r["yara"]
    print(" YARA   : " + (", ".join(m["rule"] for m in ym["matches"]) or "no matches")
          if ym["available"] else f" YARA   : ({ym.get('error')})")
    vt = r["virustotal"]
    if vt.get("status") == "found":
        print(f" VT     : {vt['stats'].get('malicious', 0)}/{vt['total_engines']} malicious"
              + (" (cached)" if vt.get("cached") else ""))
    else:
        print(f" VT     : {vt.get('status')} {vt.get('error', '')}")
    io = r["iocs"]
    print(f" IOCs   : {len(io['ips_public'])} public IP, {len(io['domains'])} domain, "
          f"{len(io['urls'])} URL, {len(io['ips_internal'])} internal IP")
    for k, vs in r["suspicious_apis"].items():
        print(f"   api/{k}: {', '.join(vs)}")
    print()
    print(c(f" VERDICT: {v['label']}", colour + ";" + BOLD if USE_COLOR else colour))
    if v["escalate"]:
        print(c(" ESCALATE to external vendor:", RED))
        for x in v["escalation_reasons"]:
            print(f"   - {x}")
    print(f"\n Reports written to {out_dir}/{stem}.{{json,md}} + _blocklist.csv + _clamav.log")


def sniff_type(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE/DOS executable"
    if data[:4] == b"\x7fELF":
        return "ELF executable"
    if data[:4] == b"PK\x03\x04":
        return "ZIP archive"
    if data[:4] == b"%PDF":
        return "PDF"
    return "unknown/data"


def analyze(path: Path, args) -> dict:
    if path.stat().st_size > MAX_READ:
        sys.exit(f"{path} too large (> {MAX_READ // 2**20} MB)")
    data = path.read_bytes()
    hashes = compute_hashes(data)
    strings = extract_strings(data, args.min_len)
    all_strings = strings["ascii"] + strings["utf16"]

    report = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "file": {"name": path.name, "size": len(data), "entropy": entropy(data),
                 "type": sniff_type(data)},
        "hashes": hashes,
        "clamav": run_clamav(path),
        "yara": run_yara(data, Path(args.rules)),
        "pe": analyze_pe(data),
        "iocs": extract_iocs(strings),
        "suspicious_apis": find_suspicious_apis(strings),
        "hints": find_hints(strings),
        "strings_total": len(all_strings),
        "strings_preview": all_strings[: args.preview],
        "strings_all_ascii": strings["ascii"],
        "strings_all_utf16": strings["utf16"],
    }
    report["yara_packer_hit"] = any("packer" in m["rule"].lower() for m in report["yara"]["matches"])

    key = args.vt_key or os.environ.get("VT_API_KEY")
    if args.offline or not key:
        report["virustotal"] = {"status": "skipped",
                                "error": "(offline mode)" if args.offline else "(no VT_API_KEY set)"}
    else:
        report["virustotal"] = VirusTotal(key, Path(args.out) / "vt_cache.json").lookup(hashes["sha256"])

    report["verdict"] = build_verdict(report)
    return report


def main():
    ap = argparse.ArgumentParser(description="DetectThis: static malware triage")
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--rules", default=str(HERE / "rules"), help="directory of .yar files")
    ap.add_argument("--out", default="reports", help="output directory")
    ap.add_argument("--offline", action="store_true", help="skip the VirusTotal lookup")
    ap.add_argument("--vt-key", help="VirusTotal API key (or set VT_API_KEY)")
    ap.add_argument("--min-len", type=int, default=6, help="minimum string length")
    ap.add_argument("--preview", type=int, default=40, help="strings shown in the report")
    args = ap.parse_args()

    out_dir = Path(args.out)
    for f in args.files:
        if not f.is_file():
            print(f"skip: {f} is not a file", file=sys.stderr)
            continue
        os.chmod(f, os.stat(f).st_mode & ~0o111)
        report = analyze(f, args)
        stem = write_reports(report, out_dir)
        print_summary(report, stem, out_dir)


if __name__ == "__main__":
    main()
