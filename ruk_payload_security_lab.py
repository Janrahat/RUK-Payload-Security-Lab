#!/usr/bin/env python3
"""
RUK PAYLOAD SECURITY LAB
Defensive-only file inspection toolkit for Kali Linux and Termux.
Does not execute scanned files, exploit devices, or access remote systems.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    RED, GREEN, YELLOW, CYAN, MAGENTA, RESET = (
        Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.CYAN, Fore.MAGENTA, Style.RESET_ALL
    )
except ImportError:
    RED = GREEN = YELLOW = CYAN = MAGENTA = RESET = ""

APP_NAME = "RUK PAYLOAD SECURITY LAB"
MAX_TEXT_BYTES = 2 * 1024 * 1024

# Heuristic indicators only. A match is not proof that a file is malicious.
PATTERNS = [
    ("High", "Possible credential access", re.compile(r"(?:/etc/shadow|SAM\\s*database|Login Data|passwords?\\s*=)", re.I)),
    ("High", "Possible data transfer / exfiltration", re.compile(r"(?:curl|wget|Invoke-WebRequest)\\s+[^\\n]*(?:https?://)", re.I)),
    ("High", "Possible shell command execution", re.compile(r"(?:subprocess\\.(?:Popen|run|call)|os\\.system|eval\\s*\\(|exec\\s*\\()", re.I)),
    ("Medium", "Possible persistence / startup modification", re.compile(r"(?:crontab|systemd|/\\.bashrc|/\\.profile|RunOnce|Startup)", re.I)),
    ("Medium", "Possible encoded content", re.compile(r"(?:base64\\s+-(?:d|decode)|FromBase64String|b64decode)", re.I)),
    ("Medium", "Possible security control modification", re.compile(r"(?:setenforce\\s+0|iptables\\s+-F|ufw\\s+disable|DisableRealtimeMonitoring)", re.I)),
    ("Low", "Possible network socket use", re.compile(r"(?:socket\\.socket|nc\\s+-[el]|ncat\\s+-[el])", re.I)),
]

def banner():
    print(CYAN + r"""
 ____  _   _ _  __    ____  _   _  ____  ____  _____
|  _ \| | | | |/ /   |  _ \| | | |/ ___|/ ___|| ____|
| |_) | | | | ' /    | |_) | | | | |  _ \___ \|  _|
|  _ <| |_| | . \    |  __/| |_| | |_| |___) | |___
|_| \_\\___/|_|\_\   |_|    \___/ \____|____/|_____|
""" + RESET)
    print(MAGENTA + f"  {APP_NAME}" + RESET)
    print(YELLOW + "  Defensive analysis only • Never executes scanned files\n" + RESET)

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

def inspect_file(path: Path) -> dict:
    result = {
        "path": str(path.resolve()),
        "size_bytes": None,
        "sha256": None,
        "readable_as_text": False,
        "findings": [],
        "error": None,
    }
    try:
        result["size_bytes"] = path.stat().st_size
        result["sha256"] = sha256_file(path)
        if result["size_bytes"] > MAX_TEXT_BYTES:
            result["error"] = f"Text inspection skipped: file exceeds {MAX_TEXT_BYTES} bytes."
            return result
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        result["readable_as_text"] = True
        for line_no, line in enumerate(text.splitlines(), start=1):
            for severity, label, pattern in PATTERNS:
                if pattern.search(line):
                    result["findings"].append({
                        "severity": severity,
                        "indicator": label,
                        "line": line_no,
                        "snippet": line.strip()[:240],
                    })
    except (OSError, PermissionError) as exc:
        result["error"] = str(exc)
    return result

def show_result(result: dict):
    print(f"\n{CYAN}File:{RESET} {result['path']}")
    if result["size_bytes"] is not None:
        print(f"{CYAN}Size:{RESET} {result['size_bytes']} bytes")
    if result["sha256"]:
        print(f"{CYAN}SHA-256:{RESET} {result['sha256']}")
    if result["error"]:
        print(YELLOW + "Note: " + result["error"] + RESET)
    findings = result["findings"]
    if not findings:
        print(GREEN + "No configured indicators found. This does NOT guarantee the file is safe." + RESET)
        return
    print(YELLOW + f"Found {len(findings)} possible indicator(s):" + RESET)
    for item in findings:
        color = RED if item["severity"] == "High" else YELLOW
        print(f"  {color}[{item['severity']}]{RESET} line {item['line']}: {item['indicator']}")
        print(f"    {item['snippet']}")

def ask_file() -> Path | None:
    raw = input("Enter file path: ").strip().strip('"').strip("'")
    if not raw:
        print(RED + "No path entered." + RESET)
        return None
    path = Path(os.path.expanduser(raw))
    if not path.is_file():
        print(RED + "File not found or path is not a regular file." + RESET)
        return None
    return path

def scan_one():
    path = ask_file()
    if path:
        result = inspect_file(path)
        show_result(result)
        save = input("\nSave JSON report? [y/N]: ").strip().lower()
        if save == "y":
            write_report([result])

def scan_directory():
    raw = input("Enter directory path: ").strip().strip('"').strip("'")
    root = Path(os.path.expanduser(raw))
    if not root.is_dir():
        print(RED + "Directory not found." + RESET)
        return
    results = []
    count = 0
    for path in root.rglob("*"):
        if path.is_file():
            try:
                results.append(inspect_file(path))
                count += 1
                print(f"\rInspected files: {count}", end="", flush=True)
            except OSError:
                continue
    print()
    for result in results:
        if result["findings"] or result["error"]:
            show_result(result)
    print(GREEN + f"\nFinished. Inspected {len(results)} file(s)." + RESET)
    if input("Save JSON report? [y/N]: ").strip().lower() == "y":
        write_report(results)

def write_report(results: list[dict]):
    report = {
        "tool": APP_NAME,
        "created_at": datetime.now().astimezone().isoformat(),
        "note": "Heuristic indicators only; findings require human review.",
        "results": results,
    }
    filename = f"ruk-security-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    try:
        Path(filename).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(GREEN + f"Report saved: {Path(filename).resolve()}" + RESET)
    except OSError as exc:
        print(RED + f"Could not save report: {exc}" + RESET)

def hash_file():
    path = ask_file()
    if path:
        try:
            print(GREEN + "SHA-256: " + sha256_file(path) + RESET)
        except OSError as exc:
            print(RED + f"Could not hash file: {exc}" + RESET)

def about():
    print(f"""
{CYAN}{APP_NAME}{RESET}

Purpose:
  • Inspect a file or directory for simple suspicious text indicators.
  • Calculate SHA-256 hashes for integrity checking.
  • Export JSON reports for later review.

Important limitations:
  • This is a basic heuristic scanner, not a full antivirus engine.
  • It can produce false positives and miss sophisticated malware.
  • It never runs the files it scans.
  • Only scan files and devices you own or are authorized to assess.
""")

def main():
    while True:
        banner()
        print(f"{GREEN}[1]{RESET} Analyze one file")
        print(f"{GREEN}[2]{RESET} Scan a directory")
        print(f"{GREEN}[3]{RESET} Calculate SHA-256 hash")
        print(f"{GREEN}[4]{RESET} About / safety notes")
        print(f"{RED}[0]{RESET} Exit")
        choice = input(f"\n{MAGENTA}RUK-LAB > {RESET}").strip()
        if choice == "1":
            scan_one()
        elif choice == "2":
            scan_directory()
        elif choice == "3":
            hash_file()
        elif choice == "4":
            about()
        elif choice == "0":
            print(GREEN + "Goodbye. Stay safe." + RESET)
            break
        else:
            print(RED + "Invalid choice." + RESET)
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + YELLOW + "Stopped by user." + RESET)
        sys.exit(0)
