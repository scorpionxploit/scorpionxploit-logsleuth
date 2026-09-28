"""
Test suite for scorpionxploit-logsleuth
"""
import pytest
from logsleuth.detector import LogSleuthAnalyzer

SAMPLE_AUTH_LINES = [
    "Sep 28 01:14:02 server sshd[1042]: Failed password for root from 198.51.100.24 port 54122 ssh2",
    "Sep 28 01:14:05 server sshd[1043]: Failed password for invalid user admin from 198.51.100.24 port 54124 ssh2",
    "Sep 28 01:14:09 server sshd[1044]: Failed password for invalid user test from 198.51.100.24 port 54128 ssh2",
    "Sep 28 01:14:12 server sshd[1045]: Failed password for root from 198.51.100.24 port 54130 ssh2",
    "Sep 28 01:14:15 server sshd[1046]: Failed password for root from 198.51.100.24 port 54132 ssh2",
]

def test_parse_auth_log_failed_ssh():
    analyzer = LogSleuthAnalyzer(failure_threshold=5)
    f1 = analyzer.analyze_auth_log_line(SAMPLE_AUTH_LINES[0])
    assert f1 is not None
    assert f1.source_ip == "198.51.100.24"
    assert f1.target_user == "root"
    assert f1.severity == "LOW"

def test_sliding_window_burst_threshold():
    analyzer = LogSleuthAnalyzer(failure_threshold=5)
    for line in SAMPLE_AUTH_LINES:
        finding = analyzer.analyze_auth_log_line(line)
    
    assert finding is not None
    assert finding.severity == "HIGH"
    assert finding.details["attempt_count"] == "5"

def test_apache_malicious_user_agent_detection():
    analyzer = LogSleuthAnalyzer()
    web_line = '203.0.113.88 - - [28/Sep/2026:01:20:00 +0000] "GET /login.php HTTP/1.1" 200 452 "-" "sqlmap/1.6#stable"'
    finding = analyzer.analyze_web_access_line(web_line)
    assert finding is not None
    assert finding.source_ip == "203.0.113.88"
    assert finding.rule_id == "SX-LOG-002-SUSPICIOUS-UA"
