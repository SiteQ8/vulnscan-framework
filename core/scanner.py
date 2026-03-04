"""
Port & Service Scanner
Performs TCP/UDP port scanning with service banner grabbing and
version detection using a concurrent threading approach.
"""

import socket
import struct
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from utils.logger import get_logger

SERVICE_BANNERS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPC",
    135:  "MSRPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Cluster",
    27017: "MongoDB",
}

PROBE_PAYLOADS = {
    "HTTP":    b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "FTP":     b"",
    "SMTP":    b"EHLO vulnscan\r\n",
    "SSH":     b"",
    "generic": b"\r\n",
}

VULN_PORTS = {
    23:    {"name": "Telnet", "issue": "Plaintext protocol — credentials transmitted unencrypted", "severity": "high"},
    21:    {"name": "FTP", "issue": "FTP may allow anonymous login or plaintext auth", "severity": "medium"},
    139:   {"name": "NetBIOS", "issue": "NetBIOS session service exposed — SMB enumeration risk", "severity": "medium"},
    445:   {"name": "SMB", "issue": "SMB exposed — potential EternalBlue/MS17-010 risk", "severity": "high"},
    3389:  {"name": "RDP", "issue": "RDP exposed — BlueKeep CVE-2019-0708 risk, brute-force target", "severity": "high"},
    5900:  {"name": "VNC", "issue": "VNC exposed — potential unauthenticated access", "severity": "high"},
    6379:  {"name": "Redis", "issue": "Redis exposed — often unauthenticated by default", "severity": "critical"},
    9200:  {"name": "Elasticsearch", "issue": "Elasticsearch API exposed — data exfiltration risk", "severity": "critical"},
    27017: {"name": "MongoDB", "issue": "MongoDB exposed — often unauthenticated by default", "severity": "critical"},
    4444:  {"name": "Backdoor", "issue": "Port 4444 open — potential backdoor/Metasploit listener", "severity": "critical"},
    8888:  {"name": "Jupyter", "issue": "Jupyter Notebook exposed — potential RCE without auth", "severity": "critical"},
}


class PortScanner:
    """Multi-threaded TCP port scanner with service fingerprinting."""

    def __init__(
        self,
        target: str,
        port_range: str = "1-1000",
        threads: int = 100,
        timeout: int = 3,
        verbose: bool = False,
    ):
        self.target = target
        self.ip = self._resolve(target)
        self.ports = self._parse_port_range(port_range)
        self.threads = min(threads, 500)
        self.timeout = timeout
        self.logger = get_logger(verbose=verbose)

    def _resolve(self, target: str) -> str:
        host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return host

    def _parse_port_range(self, port_range: str) -> list:
        ports = []
        for part in port_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports

    def scan(self) -> dict:
        """Scan all ports and return results dict."""
        self.logger.info(f"  [*] Scanning {self.ip} — {len(self.ports)} ports | {self.threads} threads")
        results = {}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, port): port for port in self.ports}
            for future in as_completed(futures):
                port_result = future.result()
                if port_result:
                    port = futures[future]
                    results[port] = port_result
                    if port_result["state"] == "open":
                        vuln_note = ""
                        if port in VULN_PORTS:
                            vuln_note = f" ⚠  {VULN_PORTS[port]['issue']}"
                        self.logger.info(
                            f"  [OPEN] {port}/{port_result['protocol']} "
                            f"{port_result['service']} "
                            f"{port_result.get('version', '')}{vuln_note}"
                        )

        return results

    def _scan_port(self, port: int) -> Optional[dict]:
        """Attempt TCP connection to a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))

            if result == 0:
                service = SERVICE_BANNERS.get(port, "unknown")
                banner, version = self._grab_banner(sock, port)
                sock.close()

                port_data = {
                    "state": "open",
                    "protocol": "tcp",
                    "service": service,
                    "banner": banner,
                    "version": version,
                }

                # Add vulnerability info for known risky ports
                if port in VULN_PORTS:
                    port_data["vulnerability"] = VULN_PORTS[port]

                return port_data
            else:
                sock.close()
                return None

        except socket.timeout:
            return None
        except Exception:
            return None

    def _grab_banner(self, sock: socket.socket, port: int) -> tuple:
        """Grab service banner from open port."""
        banner = ""
        version = ""
        try:
            service = SERVICE_BANNERS.get(port, "generic")
            payload = PROBE_PAYLOADS.get(service, PROBE_PAYLOADS["generic"])

            if payload:
                sock.send(payload)

            sock.settimeout(2)
            data = sock.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
                version = self._extract_version(banner)

        except Exception:
            pass

        return banner, version

    def _extract_version(self, banner: str) -> str:
        """Extract version strings from service banners."""
        patterns = [
            r"([\d]+\.[\d]+\.[\d]+[\w.-]*)",
            r"(\bv[\d]+\.[\d]+[\w.-]*)",
            r"OpenSSH_([\w.]+)",
            r"Apache/([\d.]+)",
            r"nginx/([\d.]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(0)
        return ""

    def get_vuln_summary(self, results: dict) -> list:
        """Return list of vulnerabilities found via port scan."""
        vulns = []
        for port, data in results.items():
            if data.get("state") == "open" and "vulnerability" in data:
                v = data["vulnerability"].copy()
                v["port"] = port
                v["service"] = data["service"]
                v["banner"] = data.get("banner", "")
                v["source"] = "port_scan"
                vulns.append(v)
        return vulns
