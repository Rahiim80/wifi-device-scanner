#!/usr/bin/env python3
"""
wifi_device_scanner.py
Scan local network using ARP to list connected devices (IP, MAC, hostname).
Created by: Cyberrahiim (Version 1.0 - Official Release)
Run as root: sudo python3 wifi_device_scanner.py
"""

import socket
import ipaddress
import argparse
from scapy.all import ARP, Ether, srp  # requires scapy
import re

# ================================
#   CYBERRAHIIM BANNER
# ================================
def banner():
    print("\n")
    print("===============================================")
    print("     🔥 Cyberrahiim WiFi Device Scanner 🔥     ")
    print("     🛠 Version 1.0 – First Official Release   ")
    print("     👨‍💻 Developed by: Cyberrahiim            ")
    print("===============================================\n")

# Small list of common phone vendor MAC prefixes (not exhaustive).
PHONE_OUIS = {
    "00:17:F2": "Samsung",
    "FC:FB:FB": "Apple",
    "D4:61:9D": "Apple",
    "E4:5F:01": "Xiaomi",
    "3C:5A:B4": "Huawei",
    "84:3A:4B": "OnePlus",
    "18:AF:61": "Google",
    "A0:99:9B": "Realme",
    "F0:27:65": "OPPO",
    # Add more prefixes you know...
}

def normalize_mac(mac):
    return mac.upper().replace('-', ':').strip()

def guess_vendor_from_mac(mac):
    mac_n = normalize_mac(mac)
    parts = mac_n.split(':')
    if len(parts) >= 3:
        prefix = ":".join(parts[:3])
        if prefix in PHONE_OUIS:
            return PHONE_OUIS[prefix]
    compact = re.sub(r'[^0-9A-F]', '', mac_n)
    if len(compact) >= 6:
        pref = ":".join([compact[i:i+2] for i in range(0, 6, 2)])
        if pref in PHONE_OUIS:
            return PHONE_OUIS[pref]
    return None

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def make_network(target_net):
    if target_net:
        return ipaddress.ip_network(target_net, strict=False)
    local_ip = get_local_ip()
    return ipaddress.ip_network(local_ip + "/24", strict=False)

def arp_scan(network, timeout=2):
    if isinstance(network, ipaddress.IPv4Network):
        net_str = str(network)
    else:
        net_str = str(network)

    print(f"[+] Scanning network: {net_str}  (requires sudo/root)")

    arp = ARP(pdst=net_str)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    answered, unanswered = srp(packet, timeout=timeout, verbose=0)

    devices = []
    for snd, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = None
        vendor = guess_vendor_from_mac(mac)

        devices.append({
            "ip": ip,
            "mac": normalize_mac(mac),
            "hostname": hostname,
            "vendor_guess": vendor
        })

    return devices

def print_devices(devs):
    if not devs:
        print("No devices found.")
        return

    print("\nFound devices:")
    print(f"{'IP':<16} {'MAC':<20} {'Vendor (guess)':<15} {'Hostname'}")
    print("-" * 70)
    for d in devs:
        ip = d['ip']
        mac = d['mac']
        vendor = d['vendor_guess'] or "-"
        hn = d['hostname'] or "-"
        print(f"{ip:<16} {mac:<20} {vendor:<15} {hn}")

def main():
    banner()  # <-- SHOW CYBERRAHIIM BANNER

    parser = argparse.ArgumentParser(description="ARP scan local network to find connected devices (phones etc).")
    parser.add_argument("-n", "--network", help="Target network (e.g. 192.168.1.0/24). If omitted, uses local IP /24.", default=None)
    parser.add_argument("-t", "--timeout", help="ARP response timeout seconds (default 2).", default=2, type=int)
    args = parser.parse_args()

    network = make_network(args.network)
    devices = arp_scan(network, timeout=args.timeout)
    print_devices(devices)

    phones = [d for d in devices if d['vendor_guess'] is not None]
    if phones:
        print("\nProbable phones/devices:")
        for p in phones:
            print(f" - {p['ip']}  {p['mac']}  {p['vendor_guess']}  {p['hostname'] or ''}")
    else:
        print("\nNo phone vendors matched. Add more MAC prefixes manually.")

if __name__ == "__main__":
    main()
