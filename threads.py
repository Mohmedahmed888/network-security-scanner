"""
QThread classes for background operations
"""

from typing import List, Dict
from PySide6.QtCore import QThread, Signal
import socket

import network
import scanner
import config


class DiscoverThread(QThread):
    done = Signal(str, list)   # subnet_prefix, hosts
    error = Signal(str)
    progress = Signal(int, int)  # current, total

    def run(self):
        try:
            subnet = network.get_default_gateway_subnet_prefix()
            if not subnet:
                self.error.emit("Could not detect subnet prefix. Check your network.")
                return

            hosts = []
            known_ips = set()
            
            # Ping sweep with progress
            total = 254
            for i, last_octet in enumerate(range(1, 255), 1):
                ip = f"{subnet}.{last_octet}"
                if network.ping_ip(ip, timeout_ms=800):
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = "Unknown"
                    
                    hosts.append({
                        "ip": ip,
                        "hostname": hostname,
                        "type": network.guess_device_type(ip, hostname)
                    })
                    known_ips.add(ip)
                
                if i % 10 == 0:
                    self.progress.emit(i, total)
            
            # ARP table - Cross-platform
            try:
                import subprocess
                import re
                import platform
                
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
                        "type": network.guess_device_type(ip, hostname)
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
                
                open_ports = scanner.scan_host(ip, self.ports, timeout=1.0, max_workers=50)

                trust_status = "Trusted" if not config.is_rogue_device(ip) else "Rogue"
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
                        vulns = scanner.check_vulnerabilities(ip, port_num, service_name, banner)
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
                            advice = config.get_advice_for_port(port_num)
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


