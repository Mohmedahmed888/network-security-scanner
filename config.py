"""
Configuration and Data - Ports, Vulnerabilities, Trusted IPs
"""

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

TRUSTED_IPS = [
    "192.168.1.1",   # Router
]

def get_advice_for_port(port: int) -> str:
    return SECURITY_ADVICE.get(
        port,
        "No specific advice. Make sure this service is really needed and properly secured."
    )

def is_rogue_device(ip: str) -> bool:
    return ip not in TRUSTED_IPS


