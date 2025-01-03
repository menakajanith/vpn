import dns.resolver
import socket

# Function to get both IP and DNS records
def get_domain_info(domain):
    try:
        # Get A records (IP addresses)
        a_records = dns.resolver.resolve(domain, 'A')
        ip_addresses = [str(record) for record in a_records]
        
        # Get additional DNS records (e.g., MX, TXT, etc.)
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
        
        return ip_addresses, dns_records

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        return None, f"{domain} could not be resolved: {e}"
    except Exception as e:
        return None, f"Error resolving {domain}: {str(e)}"

# Function to display domain information
def domain_list_scanner_with_details(domain_list):
    result = []
    for domain in domain_list:
        ip_addresses, dns_records = get_domain_info(domain)
        
        if ip_addresses:
            result.append(f"{domain} resolved to IP addresses: {', '.join(ip_addresses)}")
            for record_type, records in dns_records.items():
                if records:
                    result.append(f"{domain} {record_type} records: {', '.join(records)}")
                else:
                    result.append(f"{domain} {record_type} records not found.")
        else:
            result.append(dns_records)  # Error message when domain can't be resolved
    
    return "\n".join(result)

# Testing with domains
domains = ["google.com", "example.com", "nonexistentdomain.com"]
print(domain_list_scanner_with_details(domains))
