"""
ScorpionXploit LogSleuth - Defensive Log Analysis & Anomaly Detection
Author: Aditya Sharma (scorpionxploit)
License: MIT
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Generator
import re
import json

SSH_FAILED_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<port>\d+)'
)

SUSPICIOUS_UA_PATTERNS = [
    re.compile(r'sqlmap', re.IGNORECASE),
    re.compile(r'nikto', re.IGNORECASE),
    re.compile(r'gobuster', re.IGNORECASE),
    re.compile(r'dirbuster', re.IGNORECASE),
    re.compile(r'nmap\s+scripting\s+engine', re.IGNORECASE),
]

@dataclass
class SecurityFinding:
    rule_id: str
    severity: str
    timestamp: str
    source_ip: str
    target_user: Optional[str]
    raw_entry: str
    details: Dict[str, str] = field(default_factory=dict)

class LogSleuthAnalyzer:
    def __init__(self, failure_threshold: int = 5):
        self.failure_threshold = failure_threshold
        self.ip_failure_counts: Dict[str, int] = {}
        self.findings: List[SecurityFinding] = []

    def analyze_auth_log_line(self, line: str) -> Optional[SecurityFinding]:
        match = SSH_FAILED_PATTERN.search(line)
        if not match:
            return None
        
        data = match.groupdict()
        ip = data['ip']
        self.ip_failure_counts[ip] = self.ip_failure_counts.get(ip, 0) + 1
        
        count = self.ip_failure_counts[ip]
        severity = "HIGH" if count >= self.failure_threshold else "LOW"

        finding = SecurityFinding(
            rule_id="SX-LOG-001-SSH-FAILED",
            severity=severity,
            timestamp=data['timestamp'],
            source_ip=ip,
            target_user=data.get('user'),
            raw_entry=line.strip(),
            details={
                "attempt_count": str(count),
                "threshold_exceeded": str(count >= self.failure_threshold)
            }
        )
        self.findings.append(finding)
        return finding

    def analyze_web_access_line(self, line: str) -> Optional[SecurityFinding]:
        for pattern in SUSPICIOUS_UA_PATTERNS:
            if pattern.search(line):
                # Simple extraction of first IP
                ip_match = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                ip = ip_match.group(1) if ip_match else "0.0.0.0"
                finding = SecurityFinding(
                    rule_id="SX-LOG-002-SUSPICIOUS-UA",
                    severity="MEDIUM",
                    timestamp=datetime.utcnow().isoformat(),
                    source_ip=ip,
                    target_user=None,
                    raw_entry=line.strip(),
                    details={"matched_pattern": pattern.pattern}
                )
                self.findings.append(finding)
                return finding
        return None

    def export_findings_json(self) -> str:
        return json.dumps([f.__dict__ for f in self.findings], indent=2)
