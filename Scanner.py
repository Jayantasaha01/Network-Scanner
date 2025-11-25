#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp
import subprocess
import re

def detect_network():
    result = subprocess.check_output("ifconfig", shell=True).decode()
    matches = re.findall(r'inet (\d+\.\d+\.\d+)\.\d+', result)
    if not matches:
        raise Exception("Could not detect local IP")
    base = matches[0]  
    return f"{base}.0/24"

def arp_scan(network):
    print(f"Scanning: {network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered = srp(packet, timeout=2, verbose=0)[0]
    devices = [{"ip":r.psrc, "mac":r.hwsrc} for s, r in answered]
    return devices

if __name__ == "__main__":
    network = detect_network()
    print("Detected network:", network)

    devices = arp_scan(network)

    if not devices:
        print("No devices found. Try running with sudo.")
    else:
        print("\nDevices discovered:")
        for d in devices:
            print(f"{d['ip']}  →  {d['mac']}")
