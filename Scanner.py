#!/usr/bin/env python3
import subprocess
import re

# Simple Vendor Database (prefix → vendor)
VENDORS = {
    "a4:5e:60": "Apple, Inc.",
    "d8:bb:c1": "Samsung Electronics",
    "f0:18:98": "Google, Inc.",
    "3c:5a:b4": "Amazon Technologies Inc.",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Huawei Technologies",
    "00:1a:79": "Cisco Systems",
    "00:1e:c2": "Dell Inc.",
    "f4:5c:89": "Microsoft Corporation",
    "00:24:e8": "Sony Corporation",
    "9c:d2:1e": "ASUSTek Computer Inc.",
    "e0:cb:4e": "TP-Link Technologies",
    "c0:25:e9": "Intel Corporate",
}

def lookup_vendor(mac):
    """Return vendor name based on MAC prefix."""
    prefix = mac[:8]  # first 3 octets
    return VENDORS.get(prefix, "Unknown Vendor")

def get_hostname(ip):
    """Resolve hostname via DNS or mDNS."""
    # Try DNS first
    try:
        output = subprocess.check_output(f"nslookup {ip}", shell=True, stderr=subprocess.DEVNULL).decode()
        match = re.search(r"name = ([^\s]+)\.", output)
        if match:
            return match.group(1)
    except:
        pass

    # Try mDNS (Apple devices, IoT devices, etc.)
    try:
        mdns = subprocess.check_output(f"dig +short -x {ip} @224.0.0.251 -p 5353",
                                       shell=True, stderr=subprocess.DEVNULL).decode().strip()
        if mdns:
            return mdns.rstrip(".")
    except:
        pass

    return "Unknown Host"

def scan_with_arp():
    """Parse ARP table for IP + MAC pairs."""
    try:
        output = subprocess.check_output("arp -a", shell=True).decode()
    except:
        print("Error running arp -a")
        return []

    devices = []

    for line in output.splitlines():
        match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\sat\s([0-9a-f:]{17})", line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2).lower()
            vendor = lookup_vendor(mac)
            hostname = get_hostname(ip)

            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname
            })

    return devices

if __name__ == "__main__":
    print("Scanning using ARP table...\n")

    devices = scan_with_arp()

    if not devices:
        print("No devices found. Try connecting to a different WiFi network.")
    else:
        print("Found devices:\n")
        for d in devices:
            print(f"{d['ip']}  →  {d['mac']}  →  {d['vendor']}  →  {d['hostname']}")
