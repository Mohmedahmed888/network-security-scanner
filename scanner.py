"""
Port Scanning and Vulnerability Detection
"""

import socket
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import config


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
        elif port == 21:  # FTP
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()[:100]
            except:
                pass
        elif port == 3306:  # MySQL
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()[:100]
            except:
                pass
        elif port == 3389:  # RDP
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if banner:
                    return "RDP Service Detected"
            except:
                pass
    except Exception:
        pass
    return ""


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """Scan single port and return info if open"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            service_info = get_service_banner(sock, port, ip)
            sock.close()
            return {
                "port": port,
                "service": config.COMMON_PORTS.get(port, "Unknown"),
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


def scan_host(ip: str, ports: List[int], timeout: float = 1.0, max_workers: int = 50) -> List[Dict[str, Any]]:
    """Scan multiple ports on a host using threading"""
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
    if port in config.VULNERABILITIES:
        for vuln in config.VULNERABILITIES[port]:
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


def parse_ports(text: str) -> List[int]:
    """Parse port string to list of integers"""
    ports_text = (text or "").strip().lower()
    if not ports_text or ports_text == "all":
        return list(config.COMMON_PORTS.keys())
    
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


