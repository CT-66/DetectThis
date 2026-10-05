# DetectThis

A simple, static malware analysis tool.
Input a file, and it computes the hashes, extracts strings and other indicators of compromise. It scans these values with ClamAV, a few YARA rules, and checks the hashes against VirusTotal, and finally outputs a scored verdict with a blocklist-ready report.

Nothing is executed, only the sample's bytes are read.

It can be used with two interfaces, both based on the same engine: a CLI (`triage.py`) and a local Flask dashboard
(`app.py`) for browsing results in a browser with a neat dashboard.

<table>
  <tr>
    <td><video src="https://github.com/user-attachments/assets/6245e922-4676-4c9a-8c39-3293f6c516b3" alt="Flask Dashboard" width="1000"/></td>
    <td><video src="https://github.com/user-attachments/assets/40983356-cbea-4ce6-b76d-2bc99ade77b0" alt="CLI" width="1000"/></td>
  </tr>
  <tr>
    <td align="center">Flask Dashboard</td>
    <td align="center">CLI (Core Engine)</td>
  </tr>
</table>

## Important

- This tool is for **static analysis only**. It does not sandbox or detonate
  samples, and it is not a substitute for one.
- **Run it inside an isolated VM** with no access to anything you care about.
  You can never be too sure.
- Never execute a sample you're analyzing, regardless of what this tool reports. It's simple and not perfect.
- This tool gives you a **first-pass opinion**, not a guarantee. A clean result
  does not prove a file is safe.

## Features

- **Hashing & strings** — MD5/SHA1/SHA256, plus ASCII and UTF-16 string extraction.
- **ClamAV** signature scanning.
- **YARA** pattern matching with an example rule set (`rules/detectthis.yar`) —
  process-injection API combinations, packer markers, C2-style network
  indicators, persistence patterns. Can be replaced or extended for your own use cases.
- **IOC extraction** — IPs, domains, URLs, emails, with filtering for common
  false-positive sources (benign domain suffixes, reserved IP ranges, malformed
  "IP-shaped" strings).
- **VirusTotal cross-check** — hash-only lookup (the file is never uploaded),
  with local caching.
- **Suspicious API categorization** — process injection, persistence, network,
  anti-analysis, execution, crypto/ransomware, keylogging/credential-theft.
- **PE analysis** (when `pefile` is installed) — sections, entropy, imports, imphash.
- **Four-tier verdict**: `NO DETECTION` → `SUSPICIOUS` → `LIKELY MALICIOUS` →
  `CONFIRMED MALICIOUS`, where the top tier requires independent agreement
  across at least two detection sources, not just a high score from one.
- **Blocklist-ready output** — every run produces a CSV separating
  high-confidence indicators from low-confidence ones that need human review
  before they're used anywhere operationally.
- **Local Flask dashboard** — same engine, browsable UI, nothing leaves your machine.

## Dependencies

On Arch Linux:

```bash
sudo pacman -S clamav yara
```

On Ubuntu/Debian based distros:

```bash
sudo apt install clamav yara
```

## Setup

Update the local ClamAV database and setup a python virtual environment.

```bash
sudo freshclam
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

(Optional) Generate safe synthetic test files (EICAR + a self-built "canary" with known, planted IOCs -- useful for testing the pipeline before pointing it at anything real)

```bash
python make_canary.py
```

## Usage

```bash
# With VirusTotal (hash-only lookup; requires a VirusTotal API key)
# Add your API key in the .env file, or run it using an environment variable
export VT_API_KEY=your_key_here
python triage.py path/to/sample.exe

# Analyze a file, offline without VirusTotal
python triage.py samples/canary.bin --offline
```

Each run writes to `reports/`: `<name>.json`, `<name>.md`, `<name>_blocklist.csv`, and `<name>_clamav.log`.

### Dashboard

```bash
python app.py
```

Open `http://127.0.0.1:5000`. Upload a file (or tick "Offline mode" to skip
VirusTotal) and browse past runs from the queue on the left. This is a local
tool for your own use — it shells out to the local ClamAV binary and reads
local files directly, so it isn't meant to be exposed on a network. Keep it on
`127.0.0.1`, same as the CLI.

## Writing your own YARA rules

Custom rules can be placed in `rules/` alongside the default ruleset.

## Known limitations

- **This isn't dynamic analysis.** Don't expect it to accurately identify each type of malware.
- **Example YARA rules target native Win32 patterns.** They weren't
  written for .NET/MSIL. But it can be extended using custom rules.
- **Regex-based IOC extraction has false positives.** In particular, default
  .NET assembly manifest and version-resource fields can be misread as IPs
  (e.g. `1.0.0.0`) or domains (e.g. `System.IO`). Review network IOCs before
  using them operationally — the blocklist output is intentionally tiered by
  confidence for this reason.
- **Mutexes and registry keys found in strings are hints, not confirmed IOCs.**
  Static analysis can see a string that might look like a mutex or registry path;
  it can't confirm the sample actually creates it without running it.

## License

GPL-3.0
