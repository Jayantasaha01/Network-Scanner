#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp
import sys

def arp_scan(network):
    print(f"Scanning network: {network}")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 scanner.py 192.168.1.0/24")
        sys.exit(1)

    network = sys.argv[1]
    devices = arp_scan(network)

    if not devices:
        print("No devices found.")
    else:
        print("Discovered devices:")
        for d in devices:
            print(f"IP: {d['ip']}   MAC: {d['mac']}")
