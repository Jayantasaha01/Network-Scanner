#!/usr/bin/env python3
import subprocess
import re
import ipaddress
import threading
import queue

def get_local_network():
    """Extract local network from ifconfig output."""
    output = subprocess.check_output("ifconfig", shell=True).decode()
    match = re.search(r"inet (\d+\.\d+\.\d+)\.(\d+)", output)
    if not match:
        raise Exception("Could not detect local IP")
    
    base_net = match.group(1)  # first 3 octets
    return f"{base_net}.0/24"

def ping_host(ip, out_queue):
    """Ping an IP once, quietly, and report if alive."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if result.returncode == 0:
        out_queue.put(ip)

def scan_network(network_cidr):
    """Ping sweep entire /24 range using threads."""
    net = ipaddress.IPv4Network(network_cidr, strict=False)
    live_hosts = []
    q = queue.Queue()
    threads = []

    print(f"Scanning {network_cidr} ...")

    for ip in net.hosts():
        t = threading.Thread(target=ping_host, args=(str(ip), q))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

    while not q.empty():
        live_hosts.append(q.get())

    return sorted(live_hosts)

def get_mac(ip):
    """Lookup MAC address from ARP table."""
    try:
        output = subprocess.check_output(f"arp -n {ip}", shell=True).decode()
        match = re.search(r" ([0-9a-f:]{17}) ", output, re.IGNORECASE)
        if match:
            return match.group(1)
    except:
        pass
    return "Unknown"

if __name__ == "__main__":
    print("Detecting network...")
    network = get_local_network()
    print("Detected:", network)

    live_hosts = scan_network(network)

    print("\nDiscovering devices...\n")
    if not live_hosts:
        print("No devices found.")
    else:
        for ip in live_hosts:
            mac = get_mac(ip)
            print(f"{ip}  →  {mac}")