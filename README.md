# RUK PAYLOAD SECURITY LAB

A defensive, beginner-friendly file inspection toolkit designed for **Kali Linux** and **Termux**.

## Features

- Colorful terminal menu (uses `colorama` when installed)
- Scan one file for simple suspicious text indicators
- Recursively inspect a directory
- Calculate SHA-256 hashes
- Save JSON reports
- Never executes scanned files or contacts remote systems

## Kali Linux installation

```bash
sudo apt update
sudo apt install -y python3 python3-pip
python3 -m venv .venv
. .venv/bin/activate
pip install colorama
python3 ruk_payload_security_lab.py
```

If you do not want a virtual environment, the script also runs with the Python standard library; colors will simply be disabled if `colorama` is unavailable.

## Termux installation

Install Termux from a trusted source, then run:

```bash
pkg update
pkg install -y python
pip install colorama
python ruk_payload_security_lab.py
```

## Usage

Choose an option from the menu:
1. Analyze one file
2. Scan a directory
3. Calculate SHA-256 hash
4. Read the safety notes

Reports are written to the current working directory.

## Limitations

This is a basic heuristic scanner, not a complete antivirus product. Matches are indicators for human review, not proof of malware. It can produce false positives and miss sophisticated threats. Do not run suspicious files just because this scanner reports no findings.

Use only on files and devices you own or are authorized to assess.
