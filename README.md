
# WiFi Arsenal -  WiFi Penetration Testing Suite

<div align="center">

```
██╗    ██╗██╗███████╗██╗     ██████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗     
██║    ██║██║██╔════╝██║    ██╔═══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║     
██║ █╗ ██║██║█████╗  ██║    ███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║     
██║███╗██║██║██╔══╝  ██║    ██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║     
╚███╔███╔╝██║██║     ██║    ██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
```

**A comprehensive WiFi penetration testing framework for security professionals**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/0x0806/wifi-arsenal)
[![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

</div>

## 🚨 **LEGAL DISCLAIMER**

**⚠️ THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

- Only use on networks you own or have explicit written permission to test
- Unauthorized access to computer networks is illegal in most jurisdictions
- Users are solely responsible for compliance with local laws and regulations
- The developers assume no liability for misuse of this software

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Attack Modules](#-attack-modules)
- [Dependencies](#-dependencies)
- [Configuration](#-configuration)
- [Examples](#-examples)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Changelog](#-changelog)
- [License](#-license)

## 🎯 Features

### Core Capabilities
- **Multi-Protocol Support**: WEP, WPA, WPA2, WPA3, WPS
- **Advanced Network Discovery**: Channel hopping, hidden network detection
- **Automated Attack Suite**: Handshake capture, PMKID attacks, WPS exploitation
- **Evil Twin Framework**: Captive portal generation, DNS spoofing
- **Mass Operations**: Bulk deauth attacks, multi-target scanning
- **Smart Wordlist Generation**: Pattern-based password lists
- **Comprehensive Reporting**: JSON/HTML reports with vulnerability analysis

### Technical Features
- **Enhanced Monitor Mode**: Multiple setup methods with fallback support
- **Bluetooth Integration**: Classic and BLE device scanning
- **MAC Address Spoofing**: Vendor-specific and random MAC generation
- **Real-time Monitoring**: Live attack progress and handshake detection
- **Flexible Cracking**: Aircrack-ng, Hashcat, John the Ripper integration
- **Modular Architecture**: Extensible attack modules and plugins

## 🛠 Installation

### Prerequisites
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y python3 python3-pip git
```

### Quick Installation
```bash
# Clone repository
git clone https://github.com/0x0806/wifi-arsenal.git
cd wifi-arsenal

# Install Python dependencies
pip3 install -r requirements.txt

# Install system dependencies (optional but recommended)
sudo apt install -y aircrack-ng reaver hashcat john hostapd dnsmasq
```

### Manual Dependencies
```bash
# Core WiFi tools
sudo apt install -y aircrack-ng airodump-ng aireplay-ng airmon-ng

# WPS tools
sudo apt install -y reaver wash pixiewps

# Password cracking
sudo apt install -y hashcat john-the-ripper

# Evil Twin components
sudo apt install -y hostapd dnsmasq

# Network utilities
sudo apt install -y macchanger iwconfig wireless-tools
```

## 🚀 Usage

### Basic Usage
```bash
# Run as root (required for monitor mode)
sudo python3 wifi_arsenal.py

# Or with limited privileges (some features disabled)
python3 wifi_arsenal.py
```

### Quick Start Guide
1. **Interface Setup**: Configure wireless interface for monitor mode
2. **Network Discovery**: Scan for available networks with security analysis
3. **Target Selection**: Choose targets based on vulnerability assessment
4. **Attack Execution**: Launch appropriate attacks (handshake, WPS, evil twin)
5. **Password Cracking**: Crack captured handshakes with wordlists
6. **Report Generation**: Generate comprehensive security reports

### Command Line Options
```bash
# Interactive mode (default)
python3 wifi_arsenal.py

# Automated scanning mode
python3 wifi_arsenal.py --scan --duration 300

# Specific interface
python3 wifi_arsenal.py --interface wlan0

# Silent mode with logging
python3 wifi_arsenal.py --silent --log-level debug
```

## 🎯 Attack Modules

### 1. Advanced Network Discovery
```python
# Features:
- Channel hopping for comprehensive coverage
- Hidden network detection
- Security analysis and vulnerability assessment
- Signal strength monitoring
- Client enumeration
```

### 2. Handshake Capture
```python
# Capabilities:
- Targeted client deauthentication
- Automated handshake verification
- Multiple capture formats (CAP, PCAP, HCCAPX)
- Real-time capture monitoring
```

### 3. PMKID Attack
```python
# Modern WPA2 bypass:
- Clientless attack method
- Faster than traditional handshake capture
- Compatible with hashcat mode 16800
- Automated PMKID extraction
```

### 4. WPS Exploitation
```python
# Attack vectors:
- Pixie Dust attack (PKE vulnerability)
- PIN bruteforce with rate limiting
- WPS lock detection and bypass
- Reaver integration with optimization
```

### 5. Enhanced Evil Twin
```python
# Components:
- Captive portal generation
- DNS spoofing configuration
- DHCP server setup
- SSL certificate generation
- Credential harvesting
```

### 6. Advanced Password Cracking
```python
# Multi-tool support:
- Aircrack-ng integration
- Hashcat GPU acceleration
- John the Ripper rules
- Smart wordlist generation
- Pattern-based attacks
```

## 📦 Dependencies

### Python Packages
```txt
scapy>=2.4.3
psutil>=5.8.0
requests>=2.25.1
colorama>=0.4.4
cryptography>=3.4.8
```

### System Tools
| Tool | Purpose | Required |
|------|---------|----------|
| `aircrack-ng` | WiFi security auditing | Yes |
| `reaver` | WPS attack tool | Optional |
| `hashcat` | GPU password cracking | Optional |
| `john` | Password cracking | Optional |
| `hostapd` | Evil twin AP creation | Optional |
| `dnsmasq` | DHCP/DNS server | Optional |
| `macchanger` | MAC address spoofing | Optional |

### Hardware Requirements
- **Wireless Adapter**: Monitor mode capable
- **CPU**: Multi-core recommended for cracking
- **RAM**: 4GB minimum, 8GB+ recommended
- **Storage**: 10GB free space for wordlists/captures

## ⚙️ Configuration

### Interface Configuration
```python
# Supported interface types:
- USB WiFi adapters (most common)
- PCIe WiFi cards
- Built-in laptop adapters (limited support)
- Virtual interfaces (testing)
```

### Recommended Hardware
```bash
# High-gain USB adapters:
- Alfa AWUS036ACS (802.11ac, high power)
- Panda PAU09 (budget option)
- TP-Link AC600 T2U Plus (dual-band)

# Powerful internal cards:
- Intel AX200 (802.11ax support)
- Qualcomm Atheros AR9271 (reliable)
```

## 💡 Examples

### Basic Network Assessment
```python
# 1. Start WiFi Arsenal
sudo python3 wifi_arsenal.py

# 2. Setup interface (Option 1)
# Select your wireless interface

# 3. Advanced network discovery (Option 2)
# Scan for 60 seconds with channel hopping

# 4. View results and select targets
# Choose networks with weak security
```

### Handshake Capture & Cracking
```python
# 1. Capture handshake (Option 3)
# Target specific WPA2 network

# 2. Generate smart wordlist (Option 11)
# Create targeted password list

# 3. Crack handshake (Option 5)
# Use generated wordlist
```

### WPS Attack Example
```python
# 1. Scan for WPS networks (Option 6)
# Identify vulnerable WPS implementations

# 2. Execute Pixie Dust attack
# Target networks with vulnerable WPS

# 3. Extract credentials
# Recover WPA2 password via WPS
```

### Evil Twin Setup
```python
# 1. Select target network (Option 7)
# Choose popular network to clone

# 2. Configure evil twin
# Setup captive portal and DNS

# 3. Launch attack
# Capture credentials from users
```

## 🔧 Troubleshooting

### Common Issues

#### Monitor Mode Problems
```bash
# Error: "Monitor mode setup failed"
# Solution:
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

#### Permission Errors
```bash
# Error: "Operation not permitted"
# Solution:
sudo python3 wifi_arsenal.py
# Or add user to required groups:
sudo usermod -a -G netdev $USER
```

#### Missing Dependencies
```bash
# Error: "Command not found"
# Solution:
sudo apt install aircrack-ng reaver hashcat
pip3 install -r requirements.txt
```

#### Interface Not Found
```bash
# Check available interfaces:
iwconfig
ip link show

# Verify wireless capability:
lsusb | grep -i wireless
lspci | grep -i network
```

### Performance Optimization
```bash
# Increase capture buffer:
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf

# Optimize for SSD:
echo 'vm.swappiness = 10' >> /etc/sysctl.conf

# CPU governor for performance:
echo 'performance' > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## 🏗 Architecture

### Project Structure
```
wifi_arsenal/
├── wifi_arsenal.py          # Main application
├── requirements.txt         # Python dependencies
├── README.md               # Documentation
├── LICENSE                 # License file
├── wifi_arsenal_results/   # Results directory
│   ├── handshakes/        # Captured handshakes
│   ├── wordlists/         # Generated wordlists
│   ├── logs/              # Activity logs
│   ├── reports/           # Security reports
│   └── evil_twin/         # Evil twin configs
└── docs/                  # Additional documentation
```

### Core Classes
- `WiFiArsenal`: Main application controller
- `NetworkScanner`: Advanced network discovery
- `AttackModule`: Base class for attack implementations
- `HandshakeCapture`: WPA handshake capture logic
- `WPSAttack`: WPS exploitation framework
- `EvilTwin`: Rogue AP implementation
- `ReportGenerator`: Security report creation

## 📊 Reports

### Generated Reports
- **JSON Format**: Machine-readable vulnerability data
- **HTML Format**: Human-readable security assessment
- **CSV Export**: Network inventory and findings
- **Log Files**: Detailed activity and error logs

### Report Contents
- Network discovery summary
- Vulnerability assessment
- Attack success rates
- Security recommendations
- Compliance checklist
- Executive summary

## 🤝 Contributing

### Development Setup
```bash
# Fork the repository
git clone https://github.com/yourusername/wifi-arsenal.git

# Create feature branch
git checkout -b feature/your-feature

# Install development dependencies
pip3 install -r requirements-dev.txt

# Run tests
python3 -m pytest tests/

# Submit pull request
```

### Contribution Guidelines
1. **Code Style**: Follow PEP 8 standards
2. **Documentation**: Update README and docstrings
3. **Testing**: Add tests for new features
4. **Legal**: Ensure ethical use cases only
5. **Security**: No backdoors or malicious code

## 📝 Changelog

### v2.0.0 (Current)
- ✨ Enhanced evil twin with captive portal
- 🚀 Advanced WPS attack suite
- 📊 Comprehensive reporting system
- 🔒 Improved security analysis
- 🎯 Smart wordlist generation
- 📱 Mobile-friendly interface detection

### v1.5.0
- 🔍 Advanced network discovery
- ⚡ PMKID attack implementation
- 🛡️ Enhanced monitor mode setup
- 📡 Bluetooth integration
- 🎨 Improved UI/UX

### v1.0.0
- 🎉 Initial release
- 📶 Basic network scanning
- 🔐 WPA/WPA2 handshake capture
- 💥 Deauthentication attacks
- 📋 Basic reporting

## 🛡️ Security Considerations

### Responsible Use
- Always obtain written authorization
- Document all testing activities
- Follow responsible disclosure practices
- Respect privacy and data protection laws
- Use only for legitimate security testing

### Legal Compliance
- **CFAA (US)**: Computer Fraud and Abuse Act
- **GDPR (EU)**: General Data Protection Regulation
- **Local Laws**: Comply with regional regulations
- **Professional Standards**: Follow industry best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 0x0806

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🔗 Links

- **GitHub**: [https://github.com/0x0806/wifi-arsenal](https://github.com/0x0806/wifi-arsenal)
- **Documentation**: [https://wifi-arsenal.readthedocs.io](https://wifi-arsenal.readthedocs.io)
- **Bug Reports**: [https://github.com/0x0806/wifi-arsenal/issues](https://github.com/0x0806/wifi-arsenal/issues)
- **Security**: [security@wifi-arsenal.com](mailto:security@wifi-arsenal.com)

## 🙏 Acknowledgments

- **Aircrack-ng Team**: For the foundational WiFi security tools
- **Reaver Developers**: For WPS attack implementation
- **Hashcat Team**: For GPU-accelerated password cracking
- **Security Community**: For responsible disclosure practices
- **Contributors**: All those who helped improve this project

---

<div align="center">

**⭐ If you find this project helpful, please consider giving it a star! ⭐**

**Made with ❤️ by [0x0806](https://github.com/0x0806)**

</div>
