import requests
import re


def is_interesting_subdomain(subdomain):
    # Define a list of common services/protocols
    common_services = ['mail', 'ftp', 'admin', 'vpn', 'test', 'dev', 'secure',
                       'portal', 'backup', 'internal', 'legacy', 'api', 'intranet', 'owa', 'git']

    # Check if any part of the subdomain contains a common service
    if any(service in subdomain for service in common_services):
        return True
    return False


def get_country_code_from_ip(ip_address):
    url = f'https://ipinfo.io/{ip_address}'
    response = requests.get(url)
    data = response.json()
    return data.get('country')


def extract_ip_addresses(line):
    # Define a regex pattern to find IP addresses
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b[0-9a-fA-F:]+\b'
    # Find all IP addresses in the line
    ip_addresses = re.findall(ip_pattern, line)
    if not len(ip_addresses):
        return None
    return ".".join(ip_addresses)


def extract_subdomains(main_domain, line):
    # Define a regex pattern to find subdomains
    subdomain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(
        main_domain) + r'\b'
    # Find all subdomains in the line
    subdomains = re.findall(subdomain_pattern, line)
    if not len(subdomains):
        return None
    # Remove "92m" from subdomains
    subdomains = [subdomain.replace('92m', '') for subdomain in subdomains]
    return ".".join(subdomains)
