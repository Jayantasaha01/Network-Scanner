#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp
import netifaces2 as netifaces

def get_local_network():
    """Auto-detect local network range from default interface."""
    gateways = netifaces.gateways()
    default_iface = gateways['default'][netifaces.AF_INET][1]
    
    addrs = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
    ip = addrs['addr']
    netmask = addrs['netmask']

    # convert netmask to CIDR
    mask_bits = sum([bin(int(x)).count("1") for x in netmask.split('.')])
    cidr = f"{ip}/{mask_bits}"
    return cidr

def arp_scan(network):
    print(f"Scanning network: {network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices

if __name__ == "__main__":
    network = get_local_network()
    print("Detected network:", network)

    devices = arp_scan(network)

    if not devices:
        print("No devices found. Try sudo:")
        print("sudo python3 scanner.py")
    else:
        print("\nDiscovered devices:")
        for d in devices:
            print(f"{d['ip']}  →  {d['mac']}")
