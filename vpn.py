import requests
import ipaddress
import socket
import subprocess
import dns.resolver

# 1. HTTP Response Check
def check_http_response(url):
    try:
        response = requests.get(url)
        return f"HTTP Status Code for {url}: {response.status_code}"
    except requests.RequestException as e:
        return f"Error checking {url}: {e}"

# 2. CIDR Subnet Scan
def scan_cidr_subnet(cidr):
    network = ipaddress.IPv4Network(cidr)
    result = []
    for ip in network.hosts():
        result.append(f"Host: {ip}")
    return "\n".join(result)

# 3. IP Range Scan
def scan_ip_range(start_ip, end_ip):
    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))
    result = []
    for i in range(start_parts[3], end_parts[3] + 1):
        ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}"
        result.append(f"IP: {ip}")
    return "\n".join(result)

# 4. Domain List Scanner (IP + DNS Records)
def get_domain_info(domain):
    result = {}
    try:
        # Get A records (IP addresses)
        ip = socket.gethostbyname(domain)
        result['IP'] = ip
        
        # Get DNS records using dns.resolver (MX, TXT, CNAME, etc.)
        dns_records = {}
        
        # MX (Mail Exchange) records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_records['MX'] = [str(record.exchange) for record in mx_records]
        except dns.resolver.NoAnswer:
            dns_records['MX'] = None
        
        # TXT (Text) records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            dns_records['TXT'] = [str(record) for record in txt_records]
        except dns.resolver.NoAnswer:
            dns_records['TXT'] = None
        
        # AAAA (IPv6) records
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            dns_records['AAAA'] = [str(record) for record in aaaa_records]
        except dns.resolver.NoAnswer:
            dns_records['AAAA'] = None
        
        # CNAME (Canonical Name) records
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            dns_records['CNAME'] = [str(record.target) for record in cname_records]
        except dns.resolver.NoAnswer:
            dns_records['CNAME'] = None
        
        result['DNS'] = dns_records
        return result
    except (socket.gaierror, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        result['Error'] = f"{domain} could not be resolved: {str(e)}"
        return result

def domain_list_scanner_with_details(domain_list):
    result = []
    for domain in domain_list:
        domain_info = get_domain_info(domain)
        if 'Error' in domain_info:
            result.append(f"{domain} - Error: {domain_info['Error']}")
        else:
            ip_info = f"{domain} resolved to IP: {domain_info['IP']}"
            result.append(ip_info)
            for record_type, records in domain_info['DNS'].items():
                if records:
                    result.append(f"{domain} {record_type} records: {', '.join(records)}")
                else:
                    result.append(f"{domain} {record_type} records not found.")
    return "\n".join(result)

# 5. Site Ping
def ping_site(site):
    try:
        response = subprocess.run(["ping", "-c", "4", site], capture_output=True, text=True)
        if response.returncode == 0:
            return f"{site} is reachable"
        else:
            return f"{site} is unreachable"
    except Exception as e:
        return f"Error pinging {site}: {e}"

# Main function for interactive menu
def main():
    while True:
        print("\nSelect an option:")
        print("1. HTTP Response Check")
        print("2. CIDR Subnet Scan")
        print("3. IP Range Scan")
        print("4. Domain List Scanner (IP + DNS)")
        print("5. Site Ping")
        print("6. Exit")

        choice = input("\nEnter your choice: ")

        if choice == '1':
            url = input("Enter URL to check HTTP Response: ")
            print(check_http_response(url))
        elif choice == '2':
            cidr = input("Enter CIDR Subnet to scan (e.g., 192.168.1.0/24): ")
            print(scan_cidr_subnet(cidr))
        elif choice == '3':
            start_ip = input("Enter start IP (e.g., 192.168.1.1): ")
            end_ip = input("Enter end IP (e.g., 192.168.1.10): ")
            print(scan_ip_range(start_ip, end_ip))
        elif choice == '4':
            domains = input("Enter comma-separated domain names: ").split(',')
            print(domain_list_scanner_with_details([domain.strip() for domain in domains]))
        elif choice == '5':
            site = input("Enter a site to ping (e.g., google.com): ")
            print(ping_site(site))
        elif choice == '6':
            print("Exiting the program...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
