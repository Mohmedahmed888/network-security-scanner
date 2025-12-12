"""
Network Discovery and Scanning Functions
"""

import socket
import subprocess
import platform
import re
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import config


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
    """Discover hosts in subnet using ping sweep and ARP table"""
    hosts: List[Dict[str, str]] = []
    
    # Ping sweep
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
    
    # ARP table
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


def get_default_gateway_subnet_prefix() -> Optional[str]:
    """Get subnet prefix from default gateway"""
    try:
        startupinfo = None
        creationflags = 0
        if platform.system().lower() == "windows":
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
        gateways = [g.strip() for g in gateways if g.strip() not in ["", "0.0.0.0"]]
        
        if not gateways:
            return None
        
        gateway_ip = gateways[0]
        parts = gateway_ip.split(".")
        if len(parts) != 4:
            return None
        
        return ".".join(parts[:3])
    except Exception:
        return None


