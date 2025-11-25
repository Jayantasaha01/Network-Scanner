#!/usr/bin/env python3
import subprocess
import re

def scan_with_arp():
    try:
        output = subprocess.check_output("arp -a", shell=True).decode()
    except:
        print("Error running arp -a")
        return []

    devices = []
    lines = output.splitlines()

    for line in lines:
        match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\sat\s([0-9a-f:]{17})", line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2).lower()
            devices.append({"ip": ip, "mac": mac})

    return devices

if __name__ == "__main__":
    print("Scanning using ARP table...\n")

    devices = scan_with_arp()

    if not devices:
        print("No devices found. Try connecting to a different WiFi network.")
    else:
        print("Found devices:\n")
        for d in devices:
            print(f"{d['ip']}  →  {d['mac']}")