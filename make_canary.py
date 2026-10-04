#!/usr/bin/env python3
"""
Generate SAFE test files with known ground truth. Nothing here is executable code:
the "canary" is just bytes (an MZ magic + planted strings), so it cannot run anywhere.

  samples/eicar.com.txt  - standard EICAR antivirus test string
  samples/canary.bin     - fake-PE blob with planted IOCs (ASCII + UTF-16)
"""
from pathlib import Path

out = Path(__file__).parent / "samples"
out.mkdir(exist_ok=True)

eicar = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
(out / "eicar.com.txt").write_text(eicar)

planted_ascii = [
    "DETECTTHIS_CANARY_MARKER_7f3a",
    "http://203.0.113.45:8080/gate.php",        # TEST-NET-3 documentation range (not routable)
    "evil-c2-server.example",                    # RFC 2606 reserved TLD -- guaranteed never to resolve
    "update.fake-cdn.example",                   # same -- safe to publish, never a real domain
    "192.168.10.50",                             # internal IP (informational only)
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "InternetOpenUrlA", "RegSetValueExA",
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Global\DetectThisCanaryMutex",
    "kernel32.dll", "www.microsoft.com",         # should be filtered as benign / non-domain
    "127.0.0.1",                                 # should be ignored
]
blob = b"MZ" + b"\x90\x00" * 30 + b"\x00" * 64
blob += b"\x00".join(s.encode() for s in planted_ascii) + b"\x00"
blob += b"\x00\x00\x00\x00" + "backup-c2.wide-string-test.example".encode("utf-16le") + b"\x00\x00"
blob += bytes(range(256)) * 4  # some binary noise
(out / "canary.bin").write_bytes(blob)
print("Wrote", out / "eicar.com.txt", "and", out / "canary.bin")
