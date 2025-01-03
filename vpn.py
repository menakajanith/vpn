import requests
import ipaddress
import socket
import subprocess

# 1. HTTP Response Check
def check_http_response(url):
    print(f"\nChecking HTTP Response for: {url}")
    try:
        response = requests.get(url)
        print(f"HTTP Status Code for {url}: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error checking {url}: {e}")
    print("-" * 50)

# 2. CIDR Subnet Scan
def scan_cidr_subnet(cidr):
    print(f"\nScanning CIDR Subnet: {cidr}")
    network = ipaddress.IPv4Network(cidr)
    for ip in network.hosts():
        print(f"Host: {ip}")
    print("-" * 50)

# 3. IP Range Scan
def scan_ip_range(start_ip, end_ip):
    print(f"\nScanning IP Range from {start_ip} to {end_ip}")
    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))
    for i in range(start_parts[3], end_parts[3] + 1):
        ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}"
        print(f"IP: {ip}")
    print("-" * 50)

# 4. Domain List Scanner
def domain_list_scanner(domain_list):
    print(f"\nScanning Domain List:")
    for domain in domain_list:
        try:
            ip = socket.gethostbyname(domain)
            print(f"{domain} resolved to {ip}")
        except socket.gaierror:
            print(f"{domain} could not be resolved")
    print("-" * 50)

# 5. Site Ping
def ping_site(site):
    print(f"\nPinging {site}...")
    try:
        response = subprocess.run(["ping", "-c", "4", site], capture_output=True, text=True)
        if response.returncode == 0:
            print(f"{site} is reachable")
        else:
            print(f"{site} is unreachable")
    except Exception as e:
        print(f"Error pinging {site}: {e}")
    print("-" * 50)

# Main Function to Execute Tasks
def main():
    print("Welcome to the Network Tools Script!")
    
    # User Input for HTTP Response Check
    url = input("Enter URL to check HTTP Response (e.g., http://example.com): ")
    check_http_response(url)

    # User Input for CIDR Subnet Scan
    cidr = input("Enter CIDR Subnet to scan (e.g., 192.168.1.0/24): ")
    scan_cidr_subnet(cidr)

    # User Input for IP Range Scan
    start_ip = input("Enter start IP (e.g., 192.168.1.1): ")
    end_ip = input("Enter end IP (e.g., 192.168.1.10): ")
    scan_ip_range(start_ip, end_ip)

    # User Input for Domain List Scanner
    domains = input("Enter comma-separated domain names to scan (e.g., example.com, nonexistentdomain.com): ").split(',')
    domain_list_scanner([domain.strip() for domain in domains])

    # User Input for Site Ping
    site = input("Enter a site to ping (e.g., google.com): ")
    ping_site(site)

if __name__ == "__main__":
    main()
