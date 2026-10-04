#!/usr/bin/env python3
import os
import shutil
import types
from datetime import datetime
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for

import triage

BASE = Path(__file__).resolve().parent
UPLOAD_DIR = BASE / "samples" / "uploads"
REPORT_DIR = BASE / "reports"
RULES_DIR = BASE / "rules"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET") or os.urandom(24).hex()
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024


def make_args(offline: bool):
    return types.SimpleNamespace(
        rules=str(RULES_DIR),
        out=str(REPORT_DIR),
        offline=offline,
        vt_key=os.environ.get("VT_API_KEY"),
        min_len=6,
        preview=60,
    )


def list_reports():
    items = []
    for p in sorted(REPORT_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.name == "vt_cache.json":
            continue
        try:
            r = triage.json.loads(p.read_text())
            v = r.get("verdict", {})
            items.append({
                "stem": p.stem,
                "name": r["file"]["name"],
                "sha256": r["hashes"]["sha256"],
                "label": v.get("label", "UNKNOWN"),
                "score": v.get("score", 0),
                "escalate": v.get("escalate", False),
                "generated": r.get("generated_utc", ""),
            })
        except (KeyError, TypeError, triage.json.JSONDecodeError):
            continue
    return items


def severity_class(label: str) -> str:
    if "MALICIOUS" in label:
        return "sev-mal"
    if "SUSPICIOUS" in label:
        return "sev-sus"
    return "sev-clean"


app.jinja_env.filters["sevclass"] = severity_class


@app.context_processor
def inject_status():
    return {
        "status": {
            "clamav": bool(shutil.which("clamscan")),
            "yara": triage.yara is not None,
        }
    }


@app.route("/")
def index():
    return render_template("index.html", reports=list_reports(), vt_configured=bool(os.environ.get("VT_API_KEY")))


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("sample")
    if not file or not file.filename:
        flash("Choose a file before submitting.", "error")
        return redirect(url_for("index"))

    offline = request.form.get("mode") == "offline"
    safe_name = Path(file.filename).name
    dest = UPLOAD_DIR / f"{int(datetime.now().timestamp())}_{safe_name}"
    file.save(dest)
    os.chmod(dest, os.stat(dest).st_mode & ~0o111)

    try:
        report = triage.analyze(dest, make_args(offline))
        stem = triage.write_reports(report, REPORT_DIR)
    except Exception as e:
        flash(f"Analysis failed: {e}", "error")
        return redirect(url_for("index"))

    return redirect(url_for("report_detail", stem=stem))


@app.route("/report/<stem>")
def report_detail(stem):
    safe_stem = Path(stem).name
    path = REPORT_DIR / f"{safe_stem}.json"
    if not path.exists():
        flash("That report no longer exists.", "error")
        return redirect(url_for("index"))
    report = triage.json.loads(path.read_text())

    blocklist_rows = []
    csv_path = REPORT_DIR / f"{safe_stem}_blocklist.csv"
    if csv_path.exists():
        import csv as csv_mod
        with open(csv_path) as f:
            blocklist_rows = list(csv_mod.DictReader(f))

    return render_template(
        "report.html",
        r=report,
        stem=safe_stem,
        reports=list_reports(),
        blocklist_rows=blocklist_rows,
        vt_configured=bool(os.environ.get("VT_API_KEY")),
    )


@app.route("/download/<stem>/<fmt>")
def download(stem, fmt):
    safe_stem = Path(stem).name
    ext = {"json": "json", "markdown": "md", "blocklist": "blocklist.csv", "clamlog": "clamav.log"}.get(fmt)
    if not ext:
        return "unknown format", 404
    path = REPORT_DIR / f"{safe_stem}_{ext}" if fmt in ("blocklist", "clamlog") else REPORT_DIR / f"{safe_stem}.{ext}"
    if not path.exists():
        return "not found", 404
    return send_file(path, as_attachment=True)


@app.route("/status")
def status():
    return {
        "clamav": bool(shutil.which("clamscan")),
        "yara": triage.yara is not None,
        "pefile": triage.pefile is not None,
        "vt_key_set": bool(os.environ.get("VT_API_KEY")),
    }


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
