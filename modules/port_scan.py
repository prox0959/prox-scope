"""
modules/port_scan.py — High-Speed Multi-Threaded Port Scanner.
Scans common service, database, and administrative ports using raw TCP sockets.
Flags exposed sensitive ports (databases, remote desktop, SSH) with appropriate severity.
"""

import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

# Critical/common ports and their service names
TARGET_PORTS = {
    21:    ("FTP", LOW),
    22:    ("SSH", LOW),
    23:    ("Telnet", HIGH),
    25:    ("SMTP", LOW),
    53:    ("DNS", LOW),
    80:    ("HTTP", INFO),
    110:   ("POP3", LOW),
    143:   ("IMAP", LOW),
    443:   ("HTTPS", INFO),
    465:   ("SMTPS", LOW),
    587:   ("Submission", LOW),
    993:   ("IMAPS", LOW),
    995:   ("POP3S", LOW),
    1433:  ("MSSQL", CRITICAL),
    1521:  ("Oracle DB", CRITICAL),
    3306:  ("MySQL", CRITICAL),
    3389:  ("RDP (Remote Desktop)", HIGH),
    5432:  ("PostgreSQL", CRITICAL),
    6379:  ("Redis", CRITICAL),
    8080:  ("HTTP-Proxy / Alt", INFO),
    8443:  ("HTTPS-Alt", INFO),
    27017: ("MongoDB", CRITICAL),
}


def _check_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    """Attempt TCP socket handshake."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def scan(target: str, session: requests.Session) -> list:
    """Scan top service ports against target host."""
    findings = []
    parsed = urlparse(target)
    hostname = parsed.hostname

    if not hostname:
        return findings

    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return findings

    open_ports = {}

    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_port = {
            executor.submit(_check_port, ip, port): port
            for port in TARGET_PORTS
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
                if is_open:
                    service_name, severity = TARGET_PORTS[port]
                    open_ports[port] = (service_name, severity)
            except Exception:
                pass

    if not open_ports:
        return findings

    # Check for critical database/admin exposures
    critical_ports = []
    for port, (service, sev) in open_ports.items():
        if sev in (CRITICAL, HIGH):
            critical_ports.append(f"{service} (Port {port})")

    if critical_ports:
        findings.append(Finding(
            module="Port Scanner",
            severity=HIGH,
            title=f"Exposed Database/Administrative Ports: {', '.join(critical_ports)}",
            description="Sensitive services are directly accessible from the public internet. "
                        "Databases and management interfaces should be bound to localhost or behind a VPN.",
            evidence=f"Target: {ip} | Ports: {', '.join(critical_ports)}",
        ))

    # General open ports inventory
    all_open = [f"{port}/{service}" for port, (service, _) in sorted(open_ports.items())]
    findings.append(Finding(
        module="Port Scanner",
        severity=INFO,
        title=f"Port Inventory: {len(open_ports)} open ports discovered",
        description=f"Active public TCP services detected on target host ({ip}).",
        evidence=f"Open: {', '.join(all_open)}",
    ))

    return findings
