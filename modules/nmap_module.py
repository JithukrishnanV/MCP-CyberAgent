import nmap
import requests
from ping3 import ping

def ping_host(host: str) -> str:
    try:
        response = ping(host, timeout=2)
        if response is None:
            return f"❌ No response from {host}. Host may be down or blocking ICMP."
        else:
            ms = round(response * 1000, 2)
            return f"🏓 Ping to {host} successful! Latency: {ms} ms"
    except Exception as e:
        return f"🚫 Error pinging {host}: {str(e)}"

def get_public_ip() -> str:
    try:
        ip = requests.get('https://api.ipify.org').text
        return f"🌐 Your public IP address is: {ip}"
    except Exception as e:
        return f"🚫 Could not retrieve IP: {str(e)}"

def scan_ip(ip_address: str) -> str:
    scanner = nmap.PortScanner()

    try:
        scanner.scan(ip_address, arguments='-T4 -F')  # Fast scan with default ports
        if ip_address not in scanner.all_hosts():
            return f"⚠️ No results found for {ip_address}. The host may be offline or unresponsive."

        output = [f"🔎 Nmap Scan Results for {ip_address}"]

        for proto in scanner[ip_address].all_protocols():
            ports = scanner[ip_address][proto].keys()
            output.append(f"\n🔧 Protocol: {proto.upper()}")
            for port in sorted(ports):
                service = scanner[ip_address][proto][port].get('name', 'unknown')
                state = scanner[ip_address][proto][port].get('state', 'unknown')
                output.append(f"  - Port {port}: {service} ({state})")

        return "\n".join(output)
    except Exception as e:
        return f"🚫 Nmap scan failed: {str(e)}"
