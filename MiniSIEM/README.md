# Mini SIEM Log Analyzer (C)

**Goal:** A fast, simple C tool that flags common indicators from logs:
- SSH auth brute-force attempts (counts `Failed password` per IP).
- Apache access scans (counts repeated `404` per IP).

This is part of my **C-Learning-Journey** capstone.

## Features (MVP)
- Parse large log files line-by-line (no full file read).
- Count suspicious events per IP.
- Threshold-based alerts (e.g., ≥5 failed logins).
- CLI flags: `--ssh`, `--apache`, `--both`, `--ssh-th`, `--404-th`.

## Build
```bash
make
