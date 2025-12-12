# 🔒 Network Security Scanner

Advanced Network Monitor & Vulnerability Scanner - Desktop Application

A professional network security tool for discovering devices, scanning ports, and detecting vulnerabilities on your local network.

## ✨ Features

- 🔍 **Auto-detect network subnet** - Automatically detects your network configuration
- 📡 **Device Discovery** - Discover all devices on your network using ping and ARP
- 🔒 **Port Scanning** - Fast multi-threaded port scanning
- 🛡️ **Vulnerability Detection** - Detects known security vulnerabilities
- 📊 **Security Analysis** - Detailed security recommendations for each vulnerability
- 💾 **Export Results** - Export scan results to text files
- 🎨 **Modern Dark UI** - Beautiful dark-themed interface
- 🖥️ **Desktop App** - Standalone executable for Windows

## Project Structure

```
├── main.py              # Main entry point with logo and splash screen
├── monitor_app.py       # Original main application (can be refactored later)
├── config.py            # Ports, vulnerabilities, and trusted IPs configuration
├── network.py           # Network discovery functions
├── scanner.py           # Port scanning and vulnerability detection
├── threads.py           # QThread classes for background operations
└── ui_utils.py          # UI helper functions
```

## Installation

Install required packages:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install PySide6 pyinstaller Pillow
```

## Usage

### Run as Python Script

Run the application:

```bash
python main.py
```

Or run the original version:

```bash
python monitor_app.py
```

### Build Desktop Application (.exe)

To create a standalone desktop executable:

1. **Double-click** `build_desktop_app.bat` 

   OR

2. **Run manually:**
   ```bash
   build_desktop_app.bat
   ```

This will:
- Create `icon.ico` for the application
- Build `NetworkSecurityScanner.exe` in the `dist` folder
- Create a desktop shortcut

After building, you'll find:
- **Executable**: `dist\NetworkSecurityScanner.exe`
- **Desktop Shortcut**: Created automatically on your desktop

You can now run the application directly from the .exe file or the desktop shortcut without needing Python installed!

## Configuration

Edit `config.py` to:
- Add trusted IPs
- Modify vulnerability database
- Update security advice

## 📦 Building Desktop Application

### Prerequisites
```bash
pip install -r requirements.txt
```

### Build Steps

1. **Create Icon:**
   ```bash
   python create_icon.py
   ```

2. **Build Executable:**
   ```bash
   build_desktop_app.bat
   ```

   Or manually:
   ```bash
   pyinstaller --name="NetworkSecurityScanner" --onefile --windowed --icon=icon.ico main.py
   ```

3. **Result:**
   - Executable: `dist\NetworkSecurityScanner.exe`
   - Desktop shortcut will be created automatically

## 🚀 Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-security-scanner.git
   cd network-security-scanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

## 📝 Configuration

Edit `config.py` to customize:
- **Trusted IPs** - Add your trusted devices
- **Vulnerability Database** - Modify or add new vulnerabilities
- **Security Advice** - Update recommendations

## 🛠️ Project Structure

```
├── main.py                  # Main entry point with logo
├── monitor_app.py           # Main application window
├── config.py                # Configuration and data
├── network.py               # Network discovery functions
├── scanner.py               # Port scanning and vulnerability detection
├── threads.py               # Background threads
├── ui_utils.py              # UI helper functions
├── build_desktop_app.bat    # Build script for Windows
├── create_icon.py           # Icon generator
└── requirements.txt         # Python dependencies
```

## 📸 Screenshots

*Add screenshots of your application here*

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is created for educational and security research purposes.

## 👤 Author

**Mohamed Ahmed**

## ⚠️ Disclaimer

This tool is for authorized security testing and educational purposes only. Only scan networks you own or have explicit permission to test.

---

⭐ If you find this project useful, please give it a star!

