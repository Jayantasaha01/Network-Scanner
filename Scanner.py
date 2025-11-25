## `scanner.py`
```python
#!/usr/bin/env python3
# Simple local ping sweep (no raw sockets dependency version)
import subprocess
import sys
from ipaddress import IPv4Network

def ping(ip):
    try:
        out = subprocess.run(["ping","-c","1","-W","1",str(ip)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return out.returncode == 0
    except Exception:
        return False

def sweep(network_cidr):
    net = IPv4Network(network_cidr)
    alive = []
    for ip in net.hosts():
        if ping(ip):
            alive.append(str(ip))
            print("Alive:", ip)
    print("Alive hosts:", alive)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py 192.168.1.0/24")
        sys.exit(1)
    sweep(sys.argv[1])
