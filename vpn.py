import requests
import ipaddress
import subprocess
import socket

# 1. HTTP Response Check
def check_http_response(url):
    print("\n1. HTTP Response Check")
    try:
        response = requests.get(url)
        print(f"HTTP Status Code for {url}: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error checking {url}: {e}")
    print("-" * 50)

# 2. CIDR Subnet Scan
def scan_cidr_subnet(cidr):
    print("\n2. CIDR Subnet Scan")
    network = ipaddress.IPv4Network(cidr)
    print(f"Scanning CIDR Subnet: {cidr}")
    for ip in network.hosts():
        print(f"Host: {ip}")
    print("-" * 50)

# 3. IP Range Scan
def scan_ip_range(start_ip, end_ip):
    print("\n3. IP Range Scan")
    print(f"Scanning IP Range from {start_ip} to {end_ip}")
    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))
    for i in range(start_parts[3], end_parts[3] + 1):
        ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}"
        print(f"IP: {ip}")
    print("-" * 50)

# 4. Domain List Scanner
def domain_list_scanner(domain_list):
    print("\n4. Domain List Scanner")
    for domain in domain_list:
        try:
            ip = socket.gethostbyname(domain)
            print(f"{domain} resolved to {ip}")
        except socket.gaierror:
            print(f"{domain} could not be resolved")
    print("-" * 50)

# 5. Site Ping
def ping_site(site):
    print("\n5. Site Ping Check")
    try:
        print(f"Pinging {site}...")
        response = subprocess.run(["ping", "-c", "4", site], capture_output=True, text=True)
        if response.returncode == 0:
            print(f"{site} is reachable")
        else:
            print(f"{site} is unreachable")
    except Exception as e:
        print(f"Error pinging {site}: {e}")
    print("-" * 50)

# Main Function to Run All Tasks
def main():
    # HTTP Response Check
    check_http_response("http://example.com")
    
    # CIDR Subnet Scan
    scan_cidr_subnet("192.168.1.0/24")

    # IP Range Scan
    scan_ip_range("192.168.1.1", "192.168.1.10")

    # Domain List Scanner
    domain_list_scanner(["example.com", "nonexistentdomain.com"])

    # Site Ping Check
    ping_site("google.com")

if __name__ == "__main__":
    main()
