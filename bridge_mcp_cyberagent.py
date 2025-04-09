import sys
from mcp.server.fastmcp import FastMCP
from modules.virustotal_module import scan_hashes_from_ps1
from modules.nmap_module import scan_ip
from modules.nmap_module import get_public_ip
from modules.nmap_module import ping_host
from modules.shodan_module import shodan_host_info

# Initialize the tool
mcp = FastMCP("cyberagent")

@mcp.tool()
def scan_running_hashes() -> str:
    """
    Scan hashes from running processes using VirusTotal and return a summarized threat report.
    """
    return scan_hashes_from_ps1()

@mcp.tool()
def example_usage() -> str:
    """
    Example usage message for Claude users.
    """
    return (
        "You can try commands like:\n"
        "- 'Scan running processes for malware'\n"
        "- 'Check hashes of currently running apps with VirusTotal'"
    )

@mcp.tool()
def scan_ip_with_nmap(ip: str) -> str:
    """
    Scan an IP address using Nmap and return open ports and service details.
    """
    return scan_ip(ip)


@mcp.tool()
def whats_my_ip() -> str:
    """
    Returns the public IP address of this machine.
    """
    return get_public_ip()

@mcp.tool()
def ping(ip: str) -> str:
    """
    Perform ping to the given ip address
    """
    return ping_host(ip)

@mcp.tool()
def scan_with_shodan(ip: str) -> str:
    """
    Retrieves Shodan data for a given IP address: services, ports, banners.
    """
    return shodan_host_info(ip)


if __name__ == "__main__":
    mcp.run()
