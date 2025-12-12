# 🔒 Network Security Scanner

<div align="center">

**Advanced Network Monitor & Vulnerability Scanner**

A professional desktop application for discovering network devices, scanning ports, and detecting security vulnerabilities on local networks.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![PySide6](https://img.shields.io/badge/PySide6-6.5+-green.svg)](https://www.qt.io/qt-for-python)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](LICENSE)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Building Desktop App](#-building-desktop-app)
- [Contributing](#-contributing)
- [Author](#-author)
- [Disclaimer](#-disclaimer)

---

## ✨ Features

- 🔍 **Auto Network Detection** - Automatically detects subnet and default gateway
- 📡 **Device Discovery** - Discovers all devices using ping sweep and ARP table
- 🔒 **Port Scanning** - Fast multi-threaded port scanning (up to 50 concurrent threads)
- 🛡️ **Vulnerability Detection** - Detects known security vulnerabilities with detailed analysis
- 📊 **Security Analysis** - Provides severity ratings and security recommendations
- 🎨 **Modern Dark UI** - Beautiful, professional dark-themed interface
- 💾 **Export Results** - Export scan reports to text files
- 🖥️ **Standalone Executable** - Build as desktop application (.exe for Windows, binary for Linux)
- 🐧 **Cross-Platform** - Works on Windows and Linux

---

## 📸 Screenshots

<div align="center">

<img width="1492" height="991" alt="image" src="https://github.com/user-attachments/assets/e2a86b5c-78f3-427d-8e4e-5d29cea91dc3" />

</div>

---

## 🚀 Installation

### Requirements

- Python 3.8 or higher
- **Windows 10/11** or **Linux** (Ubuntu, Debian, Fedora, Arch, etc.)
- Network tools: ping, arp, ip/ipconfig

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install PySide6 pyinstaller Pillow
```

---

## 💻 Usage

### Run as Python Script

**Windows:**
```bash
python main.py
```

**Linux/Mac:**
```bash
python3 main.py
```

See [README_LINUX.md](README_LINUX.md) for detailed Linux setup instructions.

### Quick Start Guide

1. **Discover Devices**
   - Click "🔍 Detect Network & Discover Devices"
   - Wait for the scan to complete
   - View discovered devices in the table

2. **Configure Ports**
   - Enter ports to scan (e.g., `22,80,443`)
   - Leave empty for common ports scan
   - Or type `all` for all common ports

3. **Scan Selected Devices**
   - Select one or more devices from the table
   - Click "🎯 Scan Selected"
   - View detailed vulnerability reports

4. **Scan All Devices**
   - Click "🚀 Scan ALL Devices"
   - Comprehensive scan of all discovered devices

5. **Export Results**
   - Click "💾 Export Results"
   - Save scan reports to a text file

---

## 📁 Project Structure

```
network-security-scanner/
├── main.py                  # Application entry point with logo
├── monitor_app.py           # Main GUI window and logic
├── config.py                # Ports, vulnerabilities, and trusted IPs
├── network.py               # Network discovery functions
├── scanner.py               # Port scanning and vulnerability detection
├── threads.py               # Background thread classes
├── ui_utils.py              # UI helper functions
├── build_desktop_app.bat    # Build script for Windows executable
├── create_icon.py           # Icon generator
├── requirements.txt         # Python dependencies
└── screenshots/             # Application screenshots
```

---

## ⚙️ Configuration

Edit `config.py` to customize:

### Trusted IPs
Add your trusted device IPs to the whitelist:
```python
TRUSTED_IPS = [
    "192.168.1.1",   # Router
    "192.168.1.10",  # Your PC
]
```

### Vulnerability Database
Modify or add new vulnerabilities in the `VULNERABILITIES` dictionary.

### Security Advice
Update port-specific security recommendations in `SECURITY_ADVICE`.

---

## 🏗️ Building Desktop App

### Prerequisites

```bash
pip install pyinstaller Pillow
```

### Build Steps

1. **Create Icon** (optional):
   ```bash
   python create_icon.py
   ```

2. **Build Executable**:
   ```bash
   build_desktop_app.bat
   ```

   Or manually:
   ```bash
   pyinstaller --name="NetworkSecurityScanner" --onefile --windowed --icon=icon.ico main.py
   ```

3. **Result**:
   - Executable: `dist\NetworkSecurityScanner.exe`
   - Desktop shortcut created automatically
   - Run without Python installation required

---

## 🔧 Technical Details

### Supported Ports
- Common ports: 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389
- Custom ports: Enter any port range or specific ports

### Vulnerability Severity Levels
- **Critical** - Immediate action required
- **High** - Fix as soon as possible
- **Medium** - Should be addressed
- **Low** - Consider fixing

### Scan Performance
- Multi-threaded scanning (50 concurrent threads)
- Fast ping sweep with progress tracking
- ARP table integration for comprehensive device discovery

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is created for **educational and authorized security testing purposes only**.

---

## 👤 Author

**Mohamed Ahmed**

- GitHub: [@Mohmedahmed888](https://github.com/Mohmedahmed888)

---

## ⚠️ Disclaimer

**IMPORTANT**: This tool is intended for:

- ✅ Authorized security testing on networks you own
- ✅ Educational and research purposes
- ✅ Personal network security assessment

**DO NOT** use this tool to:

- ❌ Scan networks without authorization
- ❌ Perform unauthorized security testing
- ❌ Access systems without permission

**The authors are not responsible for any misuse of this software.**

---

## 📞 Support

If you encounter any issues or have questions:

1. Check existing [Issues](https://github.com/Mohmedahmed888/network-security-scanner/issues)
2. Create a new issue with detailed information
3. Include screenshots if applicable

---

<div align="center">

**⭐ If you find this project useful, please give it a star!**

Made with ❤️ by Mohamed Ahmed

</div>
