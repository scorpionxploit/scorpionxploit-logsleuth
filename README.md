# ScorpionXploit LogSleuth

> **Deconstructing threats. Demystifying defense.**  
> Defensive security log analysis & brute-force anomaly detection engine.

[![CI](https://github.com/scorpionxploit/scorpionxploit-logsleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/scorpionxploit/scorpionxploit-logsleuth/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-10B981.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-38BDF8.svg)](https://www.python.org/)

## Overview
**LogSleuth** is a standalone, lightweight defensive log analysis tool engineered by **Aditya Sharma (ScorpionXploit)**. It continuously processes Linux system logs (`auth.log`, `syslog`), web server access logs (Apache/Nginx), and security event streams to detect:

- Distributed and single-source SSH brute-force attempts
- Suspicious vulnerability scanner user-agents (SQLMap, Nikto, Gobuster)
- Threshold-based abnormal request bursts
- Structured JSON alert export for integration into SIEM / Webhooks

## Quickstart

```bash
# Clone the repository
git clone https://github.com/scorpionxploit/scorpionxploit-logsleuth.git
cd scorpionxploit-logsleuth

# Run analyzer on sample auth log
python -m logsleuth.detector --input /var/log/auth.log --threshold 5 --json
```

## Running Tests
```bash
pytest -v tests/
```

## Defensive Security Ethics
This tool is strictly designed for system administration, SOC monitoring, and defensive posture validation.
