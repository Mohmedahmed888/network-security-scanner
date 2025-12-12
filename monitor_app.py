"""
Advanced Network Monitor & Tracking App - GUI Version (PySide6)

Features:
- Auto-detect real network subnet from Default Gateway (e.g. 192.168.1.1 → 192.168.1).
- Discover hosts in the subnet using ping + ARP table.
- Show devices in a professional GUI table:
    [IP(with icon)] [Hostname] [Type] [Trusted/Rogue]
- Let the user choose which devices to scan, and which ports to scan.
- Show scan results and security advice in a detail box.

By: Mohamed Ahmed
"""

from __future__ import annotations

import socket
import subprocess
import platform
import re
import sys
import threading
import time
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QTextCharFormat
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QFrame, QSplitter,
    QProgressBar, QFileDialog
)

# ---------------------------
# 1) بيانات الخدمات والنصايح
# ---------------------------

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Mail)",
    53: "DNS",
    80: "HTTP (Web)",
    110: "POP3 (Mail)",
    139: "NetBIOS",
    143: "IMAP (Mail)",
    443: "HTTPS (Secure Web)",
    445: "SMB (File Sharing)",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)"
}

SECURITY_ADVICE = {
    21: "FTP is unencrypted. Use SFTP/FTPS or close this port if not needed.",
    22: "SSH is sensitive. Use strong passwords or keys and limit access.",
    23: "Telnet is very insecure (no encryption). Disable and use SSH instead.",
    25: "Mail server port. Make sure it's properly configured and not open to relay spam.",
    80: "HTTP is not encrypted. Prefer HTTPS (443) for sensitive data.",
    139: "NetBIOS file sharing. Close if file sharing is not required.",
    445: "SMB file sharing. Vulnerable in many attacks (e.g., WannaCry). Restrict or close.",
    3306: "MySQL database. Never expose to the Internet. Restrict access to local hosts.",
    3389: "RDP remote desktop. High-risk. Use VPN and strong authentication only."
}

# Vulnerability Database with detailed information
VULNERABILITIES = {
    21: [
        {
            "name": "FTP Anonymous Login", 
            "severity": "Medium", 
            "strength": "Weak",
            "description": "FTP server may allow anonymous login without authentication",
            "impact": "Unauthorized users can access FTP server and potentially upload/download files",
            "recommendation": "Disable anonymous login and require strong authentication"
        },
        {
            "name": "FTP Unencrypted Data", 
            "severity": "High", 
            "strength": "Weak",
            "description": "FTP transmits all data including passwords in plaintext over the network",
            "impact": "Sensitive data and credentials can be intercepted by attackers",
            "recommendation": "Use SFTP or FTPS instead of plain FTP"
        }
    ],
    22: [
        {
            "name": "SSH Weak Algorithms", 
            "severity": "Medium", 
            "strength": "Weak",
            "description": "SSH may use weak encryption algorithms or outdated protocols",
            "impact": "Encrypted connections may be compromised by attackers",
            "recommendation": "Configure SSH to use strong encryption algorithms only"
        },
        {
            "name": "SSH Brute Force Risk", 
            "severity": "High", 
            "strength": "Strong",
            "description": "SSH service exposed to brute force attacks due to default configuration",
            "impact": "Attackers can attempt to guess passwords and gain unauthorized access",
            "recommendation": "Implement fail2ban, use key-based authentication, and change default port"
        }
    ],
    23: [
        {
            "name": "Telnet Unencrypted", 
            "severity": "Critical", 
            "strength": "Very Weak",
            "description": "Telnet transmits all data including passwords completely unencrypted",
            "impact": "All traffic can be intercepted and credentials stolen by anyone on the network",
            "recommendation": "Immediately disable Telnet and use SSH instead"
        }
    ],
    80: [
        {
            "name": "HTTP Unencrypted", 
            "severity": "High", 
            "strength": "Weak",
            "description": "HTTP transmits all data without encryption over the network",
            "impact": "Sensitive information, session cookies, and user credentials can be intercepted",
            "recommendation": "Redirect HTTP to HTTPS and use SSL/TLS encryption"
        },
        {
            "name": "Web Server Vulnerabilities", 
            "severity": "Medium", 
            "strength": "Medium",
            "description": "Web server may have known vulnerabilities in installed version",
            "impact": "Attackers can exploit vulnerabilities to gain access or perform attacks",
            "recommendation": "Keep web server software updated to latest version"
        }
    ],
    443: [
        {
            "name": "SSL/TLS Weak Ciphers", 
            "severity": "Medium", 
            "strength": "Weak",
            "description": "HTTPS may use weak SSL/TLS ciphers or outdated protocols",
            "impact": "Encrypted connections may be broken using known cryptographic weaknesses",
            "recommendation": "Disable weak ciphers and use only strong TLS 1.2+ protocols"
        },
        {
            "name": "Certificate Issues", 
            "severity": "Low", 
            "strength": "Weak",
            "description": "SSL certificate may be expired, self-signed, or invalid",
            "impact": "Users may see security warnings or connections may be less secure",
            "recommendation": "Use valid SSL certificates from trusted certificate authority"
        }
    ],
    445: [
        {
            "name": "SMB EternalBlue", 
            "severity": "Critical", 
            "strength": "Very Strong",
            "description": "SMB vulnerable to EternalBlue exploit used by WannaCry ransomware",
            "impact": "Remote code execution possible, allowing complete system compromise",
            "recommendation": "Immediately apply MS17-010 patch or disable SMBv1 protocol"
        },
        {
            "name": "SMB Unauthenticated Access", 
            "severity": "High", 
            "strength": "Strong",
            "description": "SMB file sharing may allow unauthenticated guest access",
            "impact": "Unauthorized users can access shared files and folders",
            "recommendation": "Require authentication for SMB shares and disable guest access"
        }
    ],
    3389: [
        {
            "name": "RDP BlueKeep", 
            "severity": "Critical", 
            "strength": "Very Strong",
            "description": "RDP vulnerable to BlueKeep (CVE-2019-0708) remote code execution exploit",
            "impact": "Remote attackers can execute code without authentication, leading to full system control",
            "recommendation": "Apply security patch KB4499175 immediately or disable RDP if not needed"
        },
        {
            "name": "RDP Brute Force", 
            "severity": "High", 
            "strength": "Strong",
            "description": "RDP service exposed to brute force attacks on default port",
            "impact": "Attackers can attempt to guess passwords and gain remote desktop access",
            "recommendation": "Use strong passwords, enable Network Level Authentication, change default port, use VPN"
        },
        {
            "name": "RDP Weak Encryption", 
            "severity": "Medium", 
            "strength": "Weak",
            "description": "RDP may use weak encryption algorithms",
            "impact": "Remote desktop sessions may be less secure",
            "recommendation": "Configure RDP to use high-level encryption (FIPS 140-1 validated)"
        }
    ],
    3306: [
        {
            "name": "MySQL Weak Authentication", 
            "severity": "High", 
            "strength": "Medium",
            "description": "MySQL database may have weak authentication or default credentials",
            "impact": "Unauthorized access to database containing sensitive information",
            "recommendation": "Use strong passwords, create specific database users with minimal privileges"
        },
        {
            "name": "MySQL Remote Access", 
            "severity": "Critical", 
            "strength": "Strong",
            "description": "MySQL database exposed to network access",
            "impact": "Database accessible from internet, vulnerable to attacks and data theft",
            "recommendation": "Restrict MySQL access to localhost only, use firewall rules, never expose to internet"
        }
    ]
}

# عدّل القائمة دي حسب أجهزتك على الشبكة
TRUSTED_IPS = [
    "192.168.1.1",   # Router
    # "192.168.1.11"  # جهازك مثلا
]


# ---------------------------
# 2) دوال مساعدة (Network)
# ---------------------------

def is_rogue_device(ip: str) -> bool:
    return ip not in TRUSTED_IPS


def get_advice_for_port(port: int) -> str:
    return SECURITY_ADVICE.get(
        port,
        "No specific advice. Make sure this service is really needed and properly secured."
    )


def ping_ip(ip: str, timeout_ms: int = 800) -> bool:
    system = platform.system().lower()

    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW
    else:
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]
        startupinfo = None
        creationflags = 0

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
            creationflags=creationflags,
            shell=False
        )
        return result.returncode == 0
    except Exception:
        return False


def guess_device_type(ip: str, hostname: str) -> str:
    h = (hostname or "").lower()

    if ip.endswith(".1"):
        return "Router / Gateway"

    # ملاحظة: دي heuristics بسيطة من الاسم
    if "laptop" in h:
        return "Laptop"
    if "desktop" in h or "pc" in h:
        return "Computer"
    if "iphone" in h or "android" in h or "galaxy" in h or "redmi" in h:
        return "Mobile"
    if "tv" in h or "smart" in h:
        return "Smart TV"
    if "printer" in h:
        return "Printer"

    return "Unknown"


def discover_hosts(subnet_prefix: str) -> List[Dict[str, str]]:
    """
    يعمل scan بسيط على subnet prefix زي 192.168.1
    1) ping sweep
    2) ARP table
    """
    hosts: List[Dict[str, str]] = []

    # 1) ping sweep
    for last_octet in range(1, 255):
        ip = f"{subnet_prefix}.{last_octet}"
        if ping_ip(ip, timeout_ms=800):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Unknown"

            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "type": guess_device_type(ip, hostname)
            })

    known_ips = {h["ip"] for h in hosts}

    # 2) ARP table (يساعد يجيب أجهزة ما ردّتش ping لكن ظهرت في ARP)
    try:
        startupinfo = None
        creationflags = 0
        if platform.system().lower() == "windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW
        
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            startupinfo=startupinfo,
            creationflags=creationflags,
            shell=False
        )
        arp_out = result.stdout
        arp_ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", arp_out)

        for ip in arp_ips:
            if not ip.startswith(subnet_prefix + "."):
                continue
            if ip in known_ips:
                continue

            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Unknown"

            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "type": guess_device_type(ip, hostname)
            })
            known_ips.add(ip)

    except Exception:
        pass

    return hosts


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """Scan single port and return info if open"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Try to get service banner/version
            service_info = get_service_banner(sock, port, ip)
            sock.close()
            return {
                "port": port,
                "service": COMMON_PORTS.get(port, "Unknown"),
                "banner": service_info
            }
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except:
            pass
    return None


def get_service_banner(sock: socket.socket, port: int, ip: str) -> str:
    """Try to get service banner/version"""
    try:
        sock.settimeout(2.0)
        
        if port == 22:  # SSH
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if "SSH" in banner:
                    return banner.strip()[:100]
            except:
                pass
                
        elif port == 80:  # HTTP
            try:
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(2048).decode('utf-8', errors='ignore')
                if "Server:" in response:
                    for line in response.split('\n'):
                        if 'Server:' in line:
                            return line.strip()
            except:
                pass
                
        elif port == 443:  # HTTPS
            try:
                # SSL/TLS handshake would be needed, skip for now
                pass
            except:
                pass
                
        elif port == 21:  # FTP
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()[:100]
            except:
                pass
                
        elif port == 3306:  # MySQL
            try:
                # MySQL handshake
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()[:100]
            except:
                pass
                
        elif port == 3389:  # RDP
            try:
                # RDP connection attempt
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if banner:
                    return "RDP Service Detected"
            except:
                pass
                
    except Exception:
        pass
    return ""


def scan_host(ip: str, ports: List[int], timeout: float = 1.0, max_workers: int = 50) -> List[Dict[str, Any]]:
    """Scan multiple ports on a host using threading for better performance"""
    open_ports: List[Dict[str, Any]] = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return sorted(open_ports, key=lambda x: x["port"])


def check_vulnerabilities(ip: str, port: int, service: str, banner: str = "") -> List[Dict[str, Any]]:
    """Check for known vulnerabilities based on port and service"""
    vulnerabilities = []
    
    # Check database for known vulnerabilities
    if port in VULNERABILITIES:
        for vuln in VULNERABILITIES[port]:
            vulnerabilities.append({
                "port": port,
                "name": vuln["name"],
                "severity": vuln["severity"],
                "strength": vuln.get("strength", "Unknown"),
                "description": vuln.get("description", ""),
                "impact": vuln.get("impact", "Potential security risk"),
                "recommendation": vuln.get("recommendation", "Review and secure this service"),
                "service": service
            })
    
    # Additional checks based on banner
    if banner:
        banner_lower = banner.lower()
        
        # Check for old/unsafe versions
        if port == 445 and ("smb" in banner_lower or "samba" in banner_lower):
            if any(ver in banner_lower for ver in ["1.0", "2.0", "3.0"]):
                vulnerabilities.append({
                    "port": port,
                    "name": "Old SMB Version",
                    "severity": "High",
                    "strength": "Strong",
                    "description": f"Old SMB version detected in banner: {banner[:50]}",
                    "impact": "Older SMB versions contain known vulnerabilities and are easier to exploit",
                    "recommendation": "Update SMB to latest version and disable SMBv1",
                    "service": service
                })
        
        if port == 3389 and ("rdp" in banner_lower):
            vulnerabilities.append({
                "port": port,
                "name": "RDP Service Exposed",
                "severity": "High",
                "strength": "Strong",
                "description": "RDP service detected and exposed on default port",
                "impact": "RDP is a high-value target for attackers and commonly targeted for brute force",
                "recommendation": "Enable Network Level Authentication, use strong passwords, consider changing port",
                "service": service
            })
    
    return vulnerabilities


def get_default_gateway_subnet_prefix() -> Optional[str]:
    """
    Get subnet prefix from default gateway - Cross-platform
    Windows: ipconfig
    Linux: ip route or route -n
    """
    system = platform.system().lower()
    
    try:
        startupinfo = None
        creationflags = 0
        
        if "windows" in system:
            # Windows: use ipconfig
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW
            
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                startupinfo=startupinfo,
                creationflags=creationflags,
                shell=False
            )
            output = result.stdout
            gateways = re.findall(r"Default Gateway[^\:]*:\s*([\d\.]*)", output)
        else:
            # Linux/Mac: use ip route
            try:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=5
                )
                if result.returncode == 0:
                    match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
                    gateways = [match.group(1)] if match else []
                else:
                    gateways = []
            except (FileNotFoundError, subprocess.TimeoutExpired):
                try:
                    result = subprocess.run(
                        ["route", "-n", "get", "default"],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="ignore",
                        timeout=5
                    )
                    if result.returncode == 0:
                        match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", result.stdout)
                        gateways = [match.group(1)] if match else []
                    else:
                        gateways = []
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    gateways = []

        gateways = [g.strip() for g in gateways if g.strip() and g.strip() not in ["", "0.0.0.0"]]

        if not gateways:
            return None

        gateway_ip = gateways[0]
        parts = gateway_ip.split(".")
        if len(parts) != 4:
            return None

        return ".".join(parts[:3])

    except Exception:
        return None


# ---------------------------
# 3) UI Helpers
# ---------------------------

def parse_ports(text: str) -> List[int]:
    ports_text = (text or "").strip().lower()
    if not ports_text or ports_text == "all":
        return list(COMMON_PORTS.keys())

    ports: List[int] = []
    for part in ports_text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
        except ValueError:
            continue

    return ports


def item(text: str, center: bool = False) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    if center:
        it.setTextAlignment(Qt.AlignCenter)
    return it


def icon_for_device_type(device_type: str) -> str:
    t = (device_type or "").lower()

    if "router" in t or "gateway" in t:
        return "🌐"
    if "laptop" in t:
        return "💻"
    if "computer" in t or "pc" in t or "desktop" in t:
        return "🖥️"
    if "mobile" in t or "iphone" in t or "android" in t:
        return "📱"
    if "tv" in t:
        return "📺"
    if "printer" in t:
        return "🖨️"

    return "❓"


# ---------------------------
# 4) Threads (عشان UI ما يهنجش)
# ---------------------------

class DiscoverThread(QThread):
    done = Signal(str, list)   # subnet_prefix, hosts
    error = Signal(str)
    progress = Signal(int, int)  # current, total

    def run(self):
        try:
            subnet = get_default_gateway_subnet_prefix()
            if not subnet:
                self.error.emit("Could not detect subnet prefix. Check your network.")
                return

            hosts = []
            known_ips = set()
            
            # Ping sweep with progress
            total = 254
            for i, last_octet in enumerate(range(1, 255), 1):
                ip = f"{subnet}.{last_octet}"
                if ping_ip(ip, timeout_ms=800):
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = "Unknown"
                    
                    hosts.append({
                        "ip": ip,
                        "hostname": hostname,
                        "type": guess_device_type(ip, hostname)
                    })
                    known_ips.add(ip)
                
                if i % 10 == 0:
                    self.progress.emit(i, total)
            
            # ARP table - Cross-platform
            try:
                system = platform.system().lower()
                startupinfo = None
                creationflags = 0
                
                if "windows" in system:
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    creationflags = subprocess.CREATE_NO_WINDOW
                
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    startupinfo=startupinfo,
                    creationflags=creationflags,
                    shell=False,
                    timeout=10
                )
                arp_out = result.stdout
                arp_ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", arp_out)
                
                for ip in arp_ips:
                    if not ip.startswith(subnet + "."):
                        continue
                    if ip in known_ips:
                        continue
                    
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = "Unknown"
                    
                    hosts.append({
                        "ip": ip,
                        "hostname": hostname,
                        "type": guess_device_type(ip, hostname)
                    })
                    known_ips.add(ip)
            except Exception:
                pass
            
            self.progress.emit(total, total)
            self.done.emit(subnet, hosts)
        except Exception as e:
            self.error.emit(str(e))


class ScanThread(QThread):
    log = Signal(str, str)  # message, color
    done = Signal()
    error = Signal(str)
    progress = Signal(int, int)  # current, total

    def __init__(self, hosts: List[Dict[str, str]], ports: List[int]):
        super().__init__()
        self.hosts = hosts
        self.ports = ports

    def run(self):
        try:
            total = len(self.hosts)
            total_vulns = 0
            
            # Header
            self.log.emit("=" * 70, "header")
            self.log.emit("NETWORK SECURITY SCAN REPORT", "title")
            self.log.emit("=" * 70, "header")
            self.log.emit("", "info")
            
            for idx, host in enumerate(self.hosts, 1):
                ip = host["ip"]
                hostname = host.get("hostname", "Unknown")
                dev_type = host.get("type", "Unknown")

                self.log.emit("=" * 70, "header")
                self.log.emit(f"HOST #{idx}: {ip}", "success")
                self.log.emit(f"Hostname: {hostname}", "info")
                self.log.emit(f"Device Type: {dev_type}", "info")
                self.log.emit(f"Scanning {len(self.ports)} port(s)...", "info")
                
                open_ports = scan_host(ip, self.ports, timeout=1.0, max_workers=50)

                trust_status = "Trusted" if not is_rogue_device(ip) else "Rogue"
                color = "trusted" if trust_status == "Trusted" else "warning"
                self.log.emit(f"Trust Status: {trust_status}", color)
                self.log.emit("", "info")

                if not open_ports:
                    self.log.emit("Result: No open ports detected", "success")
                    self.log.emit("", "info")
                else:
                    self.log.emit(f"Result: {len(open_ports)} open port(s) found", "success")
                    self.log.emit("", "info")
                    
                    for p in open_ports:
                        port_num = p["port"]
                        service_name = p["service"]
                        banner = p.get("banner", "")
                        
                        self.log.emit("-" * 70, "info")
                        self.log.emit(f"PORT {port_num} ({service_name})", "success")
                        
                        if banner:
                            self.log.emit(f"Banner: {banner[:70]}", "info")
                        
                        # Check for vulnerabilities
                        vulns = check_vulnerabilities(ip, port_num, service_name, banner)
                        if vulns:
                            total_vulns += len(vulns)
                            self.log.emit(f"VULNERABILITIES: {len(vulns)} found", "error")
                            self.log.emit("", "info")
                            
                            for i, vuln in enumerate(vulns, 1):
                                severity_color = {
                                    "Critical": "error",
                                    "High": "error",
                                    "Medium": "warning",
                                    "Low": "advice"
                                }.get(vuln["severity"], "warning")
                                
                                strength = vuln.get("strength", "Unknown")
                                strength_icon = "🔥" if "Very Strong" in strength or "Strong" in strength else "⚡" if "Weak" in strength else "⚠️"
                                
                                self.log.emit(f"[{i}] {vuln['name']}", severity_color)
                                self.log.emit(f"    Severity: {vuln['severity']} | Strength: {strength_icon} {strength}", severity_color)
                                self.log.emit(f"    Description: {vuln.get('description', '')}", "info")
                                self.log.emit(f"    Impact: {vuln.get('impact', 'Potential security risk')}", "warning")
                                self.log.emit(f"    Recommendation: {vuln.get('recommendation', 'Review and secure')}", "advice")
                                
                                if i < len(vulns):
                                    self.log.emit("", "info")
                        else:
                            advice = get_advice_for_port(port_num)
                            self.log.emit("Status: Secure", "trusted")
                            self.log.emit(f"Note: {advice}", "advice")
                        
                        self.log.emit("", "info")

                self.progress.emit(idx, total)
            
            # Summary
            self.log.emit("", "info")
            self.log.emit("=" * 70, "header")
            self.log.emit("SCAN SUMMARY", "title")
            self.log.emit("=" * 70, "header")
            self.log.emit("", "info")
            
            if total_vulns > 0:
                self.log.emit(f"Total Vulnerabilities Found: {total_vulns}", "error")
                self.log.emit(f"Hosts Scanned: {total}", "info")
                self.log.emit("Action Required: Please review and patch vulnerabilities immediately", "error")
                self.log.emit("Priority: HIGH - Immediate action recommended", "error")
            else:
                self.log.emit("No vulnerabilities detected", "success")
                self.log.emit(f"Hosts Scanned: {total}", "info")
                self.log.emit("Network appears secure", "trusted")
                self.log.emit("Continue regular security monitoring", "advice")
            
            self.log.emit("", "info")
            self.log.emit("=" * 70, "header")

            self.done.emit()
        except Exception as e:
            self.error.emit(str(e))


# ---------------------------
# 5) Main Window (PySide6)
# ---------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Monitor & Tracking App (PySide6) — Mohamed Ahmed")
        self.resize(1200, 800)
        self.setMinimumSize(1000, 600)

        self.subnet_prefix: Optional[str] = None
        self.discovered_hosts: List[Dict[str, str]] = []
        self.filtered_hosts: List[Dict[str, str]] = []

        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)
        main.setContentsMargins(14, 14, 14, 14)
        main.setSpacing(10)

        # Header
        header = QFrame()
        header.setObjectName("header")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(14, 12, 14, 12)

        title = QLabel("Network Monitor & Tracking")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))

        self.subnet_label = QLabel("Subnet: (not detected yet)")
        self.subnet_label.setObjectName("muted")
        
        self.device_count_label = QLabel("Devices: 0")
        self.device_count_label.setObjectName("muted")

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("pill")

        hl.addWidget(title)
        hl.addSpacing(12)
        hl.addWidget(self.subnet_label)
        hl.addSpacing(12)
        hl.addWidget(self.device_count_label)
        hl.addStretch(1)
        hl.addWidget(self.status_label)
        main.addWidget(header)

        # Controls Section - Make it more visible
        controls = QFrame()
        controls.setObjectName("controls_frame")
        cl = QVBoxLayout(controls)
        cl.setContentsMargins(10, 10, 10, 10)
        cl.setSpacing(10)
        
        # Row 1: Discovery buttons and Search
        row1 = QHBoxLayout()
        row1.setSpacing(10)
        
        self.btn_discover = QPushButton("🔍 Detect Network & Discover Devices")
        self.btn_discover.setMinimumHeight(40)
        self.btn_discover.clicked.connect(self.on_discover_clicked)
        
        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setMinimumHeight(40)
        self.btn_refresh.clicked.connect(self.on_discover_clicked)
        
        self.btn_clear = QPushButton("🗑️ Clear Table")
        self.btn_clear.setMinimumHeight(40)
        self.btn_clear.clicked.connect(self.on_clear_table)
        
        row1.addWidget(self.btn_discover)
        row1.addWidget(self.btn_refresh)
        row1.addWidget(self.btn_clear)
        row1.addSpacing(30)
        
        # Search/Filter - Make it more prominent
        search_label = QLabel("🔎 Search:")
        search_label.setMinimumWidth(80)
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search by IP, hostname, or type...")
        self.search_entry.setMinimumHeight(40)
        self.search_entry.textChanged.connect(self.on_search_changed)
        
        row1.addWidget(search_label)
        row1.addWidget(self.search_entry, 2)
        cl.addLayout(row1)
        
        # Row 2: Ports and Scan buttons
        row2 = QHBoxLayout()
        row2.setSpacing(10)
        
        ports_label = QLabel("Ports:")
        ports_label.setMinimumWidth(60)
        self.ports_entry = QLineEdit()
        self.ports_entry.setPlaceholderText("Ports: 22,80,443  |  empty أو all = common ports")
        self.ports_entry.setMinimumHeight(40)
        
        self.btn_scan_selected = QPushButton("🎯 Scan Selected")
        self.btn_scan_selected.setMinimumHeight(40)
        self.btn_scan_selected.clicked.connect(self.on_scan_selected)
        
        self.btn_scan_all = QPushButton("🚀 Scan ALL Devices")
        self.btn_scan_all.setMinimumHeight(40)
        self.btn_scan_all.clicked.connect(self.on_scan_all)
        
        self.btn_export = QPushButton("💾 Export Results")
        self.btn_export.setMinimumHeight(40)
        self.btn_export.clicked.connect(self.on_export_results)
        
        row2.addWidget(ports_label)
        row2.addWidget(self.ports_entry, 1)
        row2.addWidget(self.btn_scan_selected)
        row2.addWidget(self.btn_scan_all)
        row2.addWidget(self.btn_export)
        cl.addLayout(row2)
        
        # Progress Bar - Make it more visible
        progress_label = QLabel("Progress:")
        progress_label.setObjectName("muted")
        progress_row = QHBoxLayout()
        progress_row.addWidget(progress_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setMinimumHeight(25)
        self.progress_bar.setTextVisible(True)
        progress_row.addWidget(self.progress_bar, 1)
        cl.addLayout(progress_row)
        
        main.addWidget(controls)

        # Splitter: Table + Output
        splitter = QSplitter(Qt.Vertical)

        self.table = QTableWidget(0, 4)
        
        # Create header items with explicit color - use blue/cyan color for better visibility
        headers = ["IP Address", "Hostname", "Device Type", "Trust Status"]
        for i, header_text in enumerate(headers):
            header_item = QTableWidgetItem(header_text)
            # Use a cyan/blue color that stands out on dark background
            header_item.setForeground(QColor("#58a6ff"))  # Light blue/cyan color
            header_item.setTextAlignment(Qt.AlignCenter)
            header_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
            self.table.setHorizontalHeaderItem(i, header_item)
        
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.MultiSelection)
        self.table.setAlternatingRowColors(True)
        # Set minimum column widths to ensure visibility
        self.table.setColumnWidth(0, 180)  # IP Address
        self.table.setColumnWidth(1, 200)  # Hostname
        self.table.setColumnWidth(2, 150)  # Device Type
        self.table.setColumnWidth(3, 120)  # Trust Status
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
        # Make sure all columns are visible
        self.table.horizontalHeader().setStretchLastSection(False)

        # Emoji font مرة واحدة
        self.table.setFont(QFont("Segoe UI Emoji", 10))
        
        # Ensure table is visible and properly sized
        self.table.setMinimumHeight(300)
        self.table.setShowGrid(True)
        self.table.verticalHeader().setVisible(True)
        self.table.horizontalHeader().setVisible(True)

        splitter.addWidget(self.table)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Security scan results will appear here...")
        self.output.setFont(QFont("Consolas", 11))
        self.output.setAcceptRichText(False)  # Use plain text with formatting
        splitter.addWidget(self.output)

        splitter.setSizes([500, 300])
        main.addWidget(splitter, 1)
        
        # Add a status bar at the bottom for additional info
        self.statusBar().setStyleSheet("""
            QStatusBar {
                background: #151925;
                color: #e7eaf3;
                border-top: 1px solid #22283a;
                padding: 5px;
            }
        """)
        self.statusBar().showMessage("Ready - Click '🔍 Detect Network & Discover Devices' to start")

        # Styles (Dark Pro - Enhanced)
        self.setStyleSheet("""
            QMainWindow { 
                background: #0f1115; 
            }
            #header { 
                background: linear-gradient(135deg, #1a1f2e 0%, #151925 100%);
                border: 1px solid #2a3441; 
                border-radius: 12px; 
            }
            QLabel { 
                color: #e7eaf3; 
            }
            QLabel#muted { 
                color: #aab2c5; 
            }
            QLabel#pill {
                background: linear-gradient(135deg, #1f6feb 0%, #0969da 100%);
                border-radius: 10px;
                padding: 6px 10px;
                color: white;
                font-weight: 600;
            }
            QLineEdit {
                background: #151925;
                border: 1px solid #22283a;
                border-radius: 10px;
                padding: 10px;
                color: #e7eaf3;
            }
            QLineEdit:focus {
                border: 2px solid #1f6feb;
                background: #1a1f2e;
            }
            QPushButton {
                background: #151925;
                border: 1px solid #22283a;
                border-radius: 10px;
                padding: 10px 12px;
                color: #e7eaf3;
                font-weight: 600;
                min-width: 100px;
            }
            QPushButton:hover { 
                border: 1px solid #1f6feb; 
                background: #1a1f2e;
            }
            QPushButton:pressed {
                background: #0f1115;
            }
            QPushButton:disabled {
                background: #0a0c10;
                border: 1px solid #1a1a1a;
                color: #666;
            }
            QTableWidget {
                background: #0f1115;
                border: 1px solid #22283a;
                border-radius: 12px;
                gridline-color: #22283a;
                color: #e7eaf3;
                selection-background-color: #1f6feb40;
                alternate-background-color: #151925;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background: #1f6feb40;
                color: #ffffff;
            }
            QTableWidget::item:hover {
                background: #1a1f2e;
            }
            QHeaderView {
                background: transparent;
            }
            QHeaderView::section {
                background: linear-gradient(135deg, #1a1f2e 0%, #151925 100%);
                border: 1px solid #22283a;
                border-bottom: 2px solid #2a3441;
                padding: 10px;
                font-weight: 700;
                color: #58a6ff;
                min-height: 30px;
            }
            QHeaderView::section:first {
                border-top-left-radius: 12px;
            }
            QHeaderView::section:last {
                border-top-right-radius: 12px;
            }
            QTableWidget QTableCornerButton::section {
                background: linear-gradient(135deg, #1a1f2e 0%, #151925 100%);
                border: 1px solid #22283a;
            }
            QTextEdit {
                background: #0b0d12;
                border: 2px solid #22283a;
                border-radius: 12px;
                color: #e7eaf3;
                padding: 15px;
                font-family: 'Segoe UI', Consolas, monospace;
                font-size: 12px;
                selection-background-color: #1f6feb40;
            }
            QTextEdit:focus {
                border: 2px solid #1f6feb;
            }
            QFrame#controls_frame {
                background: #151925;
                border: 1px solid #22283a;
                border-radius: 12px;
                padding: 10px;
            }
            QProgressBar {
                border: 2px solid #22283a;
                border-radius: 8px;
                background: #0f1115;
                height: 25px;
                text-align: center;
                color: white;
                font-weight: 600;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background: linear-gradient(135deg, #1f6feb 0%, #0969da 100%);
                border-radius: 6px;
            }
        """)

        # Init subnet label only (بدون اسكان)
        subnet = get_default_gateway_subnet_prefix()
        if subnet:
            self.subnet_prefix = subnet
            self.subnet_label.setText(f"Subnet: {subnet}.0/24 (detected)")

    # ---------- helpers ----------
    def set_busy(self, busy: bool, status: str):
        self.status_label.setText(status)
        self.statusBar().showMessage(f"Status: {status}")
        self.btn_discover.setDisabled(busy)
        self.btn_refresh.setDisabled(busy)
        self.btn_scan_selected.setDisabled(busy)
        self.btn_scan_all.setDisabled(busy)
        self.btn_export.setDisabled(busy)
        self.btn_clear.setDisabled(busy)
        
        if busy:
            self.progress_bar.setVisible(True)
        else:
            self.progress_bar.setVisible(False)
            self.progress_bar.setValue(0)
            if status == "Ready":
                self.statusBar().showMessage("Ready - Select devices and click scan to check ports")

    def log(self, msg: str, color: str = "info"):
        """Log with organized formatting using QTextCharFormat"""
        cursor = self.output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        
        # Define colors
        color_map = {
            "info": QColor("#aab2c5"),
            "success": QColor("#4ec9b0"),
            "warning": QColor("#f85149"),
            "error": QColor("#f85149"),
            "trusted": QColor("#4ec9b0"),
            "advice": QColor("#d29922"),
            "header": QColor("#58a6ff"),
            "title": QColor("#ffffff")
        }
        
        # Create format
        fmt = QTextCharFormat()
        fmt.setForeground(color_map.get(color, color_map["info"]))
        
        # Set font
        font = QFont("Consolas", 11)
        if color == "title" or "HOST #" in msg or "SCAN SUMMARY" in msg:
            font.setBold(True)
            font.setPointSize(12)
        fmt.setFont(font)
        
        # Apply format and insert text
        cursor.setCharFormat(fmt)
        cursor.insertText(msg + "\n")
        
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()

    def _create_format(self, color: str) -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        return fmt

    def clear_log(self):
        self.output.clear()
        self.output.setFont(QFont("Consolas", 11))

    def refresh_table(self, hosts: Optional[List[Dict[str, str]]] = None):
        """Refresh table with optional host list (for filtering)"""
        self.table.setRowCount(0)
        
        hosts_to_show = hosts if hosts is not None else self.discovered_hosts
        
        # Update device count label
        total_count = len(self.discovered_hosts)
        shown_count = len(hosts_to_show)
        if shown_count == total_count:
            self.device_count_label.setText(f"Devices: {total_count}")
        else:
            self.device_count_label.setText(f"Devices: {shown_count}/{total_count}")

        for host in hosts_to_show:
            ip = host["ip"]
            hostname = host.get("hostname", "Unknown")
            dev_type = host.get("type", "Unknown")
            trust = "Trusted" if not is_rogue_device(ip) else "Rogue"

            icon = icon_for_device_type(dev_type)
            ip_display = f"{icon}  {ip}"

            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row, 0, item(ip_display, center=False))
            self.table.setItem(row, 1, item(hostname))
            self.table.setItem(row, 2, item(dev_type, center=True))
            
            # Color code trust status
            trust_item = item(trust, center=True)
            if trust == "Trusted":
                trust_item.setForeground(QColor("#4ec9b0"))
            else:
                trust_item.setForeground(QColor("#f85149"))
            self.table.setItem(row, 3, trust_item)
        
        # Resize columns to fit content
        self.table.resizeColumnsToContents()
        # But keep minimum widths
        if self.table.columnWidth(0) < 180:
            self.table.setColumnWidth(0, 180)
        if self.table.columnWidth(2) < 150:
            self.table.setColumnWidth(2, 150)
        if self.table.columnWidth(3) < 120:
            self.table.setColumnWidth(3, 120)

    def get_selected_hosts(self) -> List[Dict[str, str]]:
        rows = {idx.row() for idx in self.table.selectionModel().selectedRows()}
        selected: List[Dict[str, str]] = []

        for r in sorted(rows):
            ip_text = self.table.item(r, 0).text()   # "📱  192.168.1.11"
            ip = ip_text.split()[-1]                # "192.168.1.11"

            hostname = self.table.item(r, 1).text()
            dev_type = self.table.item(r, 2).text()

            selected.append({"ip": ip, "hostname": hostname, "type": dev_type})

        return selected
    
    def on_search_changed(self, text: str):
        """Filter table based on search text"""
        if not text.strip():
            self.refresh_table()
            return
        
        search_lower = text.lower().strip()
        filtered = []
        
        for host in self.discovered_hosts:
            ip = host["ip"].lower()
            hostname = host.get("hostname", "Unknown").lower()
            dev_type = host.get("type", "Unknown").lower()
            
            if (search_lower in ip or 
                search_lower in hostname or 
                search_lower in dev_type):
                filtered.append(host)
        
        self.refresh_table(filtered)
    
    def on_clear_table(self):
        """Clear the table"""
        reply = QMessageBox.question(
            self, "Clear Table", 
            "Are you sure you want to clear the device table?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.discovered_hosts = []
            self.table.setRowCount(0)
            self.device_count_label.setText("Devices: 0")
            self.clear_log()
            self.log("Table cleared.", "info")
    
    def on_export_results(self):
        """Export scan results to file"""
        if not self.output.toPlainText().strip():
            QMessageBox.warning(self, "Warning", "No results to export. Run a scan first.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "network_scan_results.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("=" * 70 + "\n")
                    f.write("Network Monitor & Tracking - Scan Results\n")
                    f.write("=" * 70 + "\n\n")
                    f.write(f"Subnet: {self.subnet_prefix}.0/24\n")
                    f.write(f"Total Devices: {len(self.discovered_hosts)}\n")
                    f.write("=" * 70 + "\n\n")
                    f.write(self.output.toPlainText())
                
                self.log(f"Results exported to: {filename}", "success")
                QMessageBox.information(self, "Success", f"Results exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results:\n{str(e)}")
                self.log(f"Export error: {str(e)}", "error")

    # ---------- actions ----------
    def on_discover_clicked(self):
        self.clear_log()
        self.set_busy(True, "Discovering...")
        self.log("Starting network discovery...", "info")

        self.discover_thread = DiscoverThread()
        self.discover_thread.done.connect(self.on_discover_done)
        self.discover_thread.error.connect(self.on_error)
        self.discover_thread.progress.connect(self.on_discover_progress)
        self.discover_thread.start()
    
    def on_discover_progress(self, current: int, total: int):
        """Update progress bar during discovery"""
        percent = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(percent)
        self.progress_bar.setFormat(f"Scanning network: {percent}% ({current}/{total})")

    def on_discover_done(self, subnet: str, hosts: list):
        self.subnet_prefix = subnet
        self.subnet_label.setText(f"Subnet: {subnet}.0/24 (detected)")
        self.discovered_hosts = hosts or []

        if not self.discovered_hosts:
            self.log("[-] No hosts discovered.", "warning")
        else:
            self.log(f"[+] Discovered {len(self.discovered_hosts)} device(s).", "success")
            trusted_count = sum(1 for h in self.discovered_hosts if not is_rogue_device(h["ip"]))
            rogue_count = len(self.discovered_hosts) - trusted_count
            self.log(f"    - Trusted: {trusted_count} | Rogue: {rogue_count}", "info")

        self.refresh_table()
        self.set_busy(False, "Ready")

    def on_scan_selected(self):
        if not self.discovered_hosts:
            QMessageBox.warning(self, "Warning", "No devices discovered yet. Click Discover first.")
            return

        selected = self.get_selected_hosts()
        if not selected:
            QMessageBox.warning(self, "Warning", "No device selected. Select one or more rows from the table.")
            return

        ports = parse_ports(self.ports_entry.text())
        if not ports:
            QMessageBox.critical(self, "Error", "No valid ports specified.")
            return

        self.start_scan(selected, ports)

    def on_scan_all(self):
        if not self.discovered_hosts:
            QMessageBox.warning(self, "Warning", "No devices discovered yet. Click Discover first.")
            return

        ports = parse_ports(self.ports_entry.text())
        if not ports:
            QMessageBox.critical(self, "Error", "No valid ports specified.")
            return

        self.start_scan(self.discovered_hosts, ports)

    def start_scan(self, hosts: List[Dict[str, str]], ports: List[int]):
        self.clear_log()
        self.set_busy(True, "Scanning...")
        self.log(f"Starting port scan on {len(hosts)} device(s)...", "info")
        self.log(f"Scanning ports: {', '.join(map(str, ports))}", "info")
        self.log("=" * 60, "info")

        self.scan_thread = ScanThread(hosts, ports)
        self.scan_thread.log.connect(self.log)
        self.scan_thread.done.connect(self.on_scan_done)
        self.scan_thread.error.connect(self.on_error)
        self.scan_thread.progress.connect(self.on_scan_progress)
        self.scan_thread.start()
    
    def on_scan_progress(self, current: int, total: int):
        """Update progress bar during scan"""
        percent = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(percent)
        self.progress_bar.setFormat(f"Scanning devices: {percent}% ({current}/{total})")
    
    def on_scan_done(self):
        """Called when scan is finished"""
        self.set_busy(False, "Scan finished")
        self.log("=" * 60, "info")
        self.log("Scan completed!", "success")

    def on_error(self, msg: str):
        self.set_busy(False, "Error")
        QMessageBox.critical(self, "Error", msg)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
