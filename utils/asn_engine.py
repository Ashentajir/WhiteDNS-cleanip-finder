import os
import csv
import ipaddress
import re
from utils import paths

# ==========================================
# ASN DATA CACHE
# ==========================================
ASN_DATA_V4 = {i: [] for i in range(256)} 
ASN_DATA_V6 = []
ASN_LOADED = False
MAX_IPV4_EXPANSION = 65536
MAX_IPV6_SAMPLES = 256


def _expand_network(net):
    """Expand small networks and sample broad IPv6 ASN aggregates safely."""
    if net.version == 4:
        if net.num_addresses > MAX_IPV4_EXPANSION:
            return [str(ip) for _, ip in zip(range(MAX_IPV4_EXPANSION), net.hosts())]
        return [str(ip) for ip in net]

    if net.num_addresses <= MAX_IPV6_SAMPLES:
        return [str(ip) for ip in net]
    if net.prefixlen >= 64:
        start = int(net.network_address)
        return [str(ipaddress.IPv6Address(start + offset)) for offset in range(MAX_IPV6_SAMPLES)]

    variable_subnet_bits = 64 - net.prefixlen
    subnet_count = min(MAX_IPV6_SAMPLES, 1 << variable_subnet_bits)
    max_subnet_index = (1 << variable_subnet_bits) - 1
    common_host_ids = (1, 0x53, 0, 2, 3, 0x35, 0x1111, 0x8888)
    start = int(net.network_address)
    samples = []
    for index in range(MAX_IPV6_SAMPLES):
        subnet_slot = index % subnet_count
        host_round = index // subnet_count
        subnet_index = 0 if subnet_count == 1 else (max_subnet_index * subnet_slot) // (subnet_count - 1)
        host_id = common_host_ids[host_round] if host_round < len(common_host_ids) else host_round - len(common_host_ids) + 4
        candidate = ipaddress.IPv6Address(start + (subnet_index << 64) + host_id)
        if candidate in net:
            samples.append(str(candidate))
    return samples

def load_asn_data():
    """Loads ASN datasets into memory for fast IP lookups."""
    global ASN_LOADED
    if ASN_LOADED: return
    
    v4_path = paths.root_path("IranASNs", "filtered_ipv4.csv")
    if os.path.exists(v4_path):
        with open(v4_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None) # Skip header
            for row in reader:
                if len(row) >= 9:
                    try:
                        net = ipaddress.IPv4Network(row[0], strict=False)
                        first_octet = int(net.network_address.exploded.split('.')[0])
                        ASN_DATA_V4[first_octet].append((net, row[5], row[6], row[8]))
                    except Exception: 
                        pass
                        
    v6_path = paths.root_path("IranASNs", "filtered_ipv6.csv")
    if os.path.exists(v6_path):
        with open(v6_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None) # Skip header
            for row in reader:
                if len(row) >= 9:
                    try:
                        net = ipaddress.IPv6Network(row[0], strict=False)
                        ASN_DATA_V6.append((net, row[5], row[6], row[8]))
                    except Exception: 
                        pass
                        
    ASN_LOADED = True

def get_asn_info(ip_str):
    """Takes an IP string and returns a tuple: (asn, as_name, as_type)"""
    if not ASN_LOADED: 
        load_asn_data()
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            # Optimize lookups by checking only the subnets mapped to the IP's first octet
            first_octet = int(ip_str.split('.')[0])
            for net, asn, name, as_type in ASN_DATA_V4.get(first_octet, []):
                if ip_obj in net: 
                    return asn, name, as_type
        else:
            for net, asn, name, as_type in ASN_DATA_V6:
                if ip_obj in net: 
                    return asn, name, as_type
    except Exception:
        pass
    return None, "Unknown ASN", "Unknown"

def search_asns_by_regex(pattern_str, silent=False):
    """
    Searches for ASNs matching a regex pattern against ASN numbers and names.
    Returns list of subnets that match the pattern.
    """
    if not ASN_LOADED:
        load_asn_data()
    
    try:
        pattern = re.compile(pattern_str, re.IGNORECASE)
    except re.error as e:
        if not silent:
            print(f"[-] Invalid regex pattern: {e}")
        return []
    
    subnets = []
    matched_asns = set()
    
    # Search IPv4 ASNs
    for octet_list in ASN_DATA_V4.values():
        for net, asn, name, as_type in octet_list:
            # Match against ASN number or name
            if pattern.search(asn) or pattern.search(name):
                matched_asns.add(asn.upper())
                subnets.append(net)
    
    # Search IPv6 ASNs
    for net, asn, name, as_type in ASN_DATA_V6:
        if pattern.search(asn) or pattern.search(name):
            matched_asns.add(asn.upper())
            subnets.append(net)
    
    return subnets

def expand_target(target, silent=False):
    """
    Expands an AS Number (e.g. AS12345), CIDR, single IP, or regex pattern into a list of individual IP strings.
    Supports regex patterns with 'regex:' prefix for ASN matching.
    Protects against memory overflow from massive IPv6/IPv4 blocks.
    """
    target = target.strip()
    upper_target = target.upper()
    
    # Check if the target is a regex pattern for ASN search
    if target.startswith('regex:'):
        pattern_str = target[6:].strip()
        subnets = search_asns_by_regex(pattern_str, silent=silent)
        if not subnets and not silent:
            print(f"[-] No ASNs found matching regex: {pattern_str}")
            return []
        
        asn_ips = []
        total_ips = sum(net.num_addresses for net in subnets if net.version == 4)
        if total_ips > 1000000 and not silent:
            print(f"[*] Warning: Regex matched ASNs contain {total_ips} IPs. Expansion may take a moment...")
        
        for net in subnets:
            if net.version == 6 and net.num_addresses > MAX_IPV6_SAMPLES and not silent:
                print(f"[*] Sampling {MAX_IPV6_SAMPLES} representative IPv6 addresses from {net}.")
            elif net.num_addresses > MAX_IPV4_EXPANSION and not silent:
                if not silent:
                    print(f"[*] Warning: Subnet {net} is massive. Truncating to {MAX_IPV4_EXPANSION} IPs.")
            asn_ips.extend(_expand_network(net))
        
        return asn_ips
    
    # Check if the target is an ASN (starts with 'AS' and followed by digits)
    if upper_target.startswith('AS') and upper_target[2:].isdigit():
        if not ASN_LOADED: 
            load_asn_data()
            
        asn_ips = []
        subnets = []
        
        for octet_list in ASN_DATA_V4.values():
            for net, asn, name, as_type in octet_list:
                if asn.upper() == upper_target: 
                    subnets.append(net)
                    
        for net, asn, name, as_type in ASN_DATA_V6:
            if asn.upper() == upper_target: 
                subnets.append(net)
                
        if not subnets and not silent:
            print(f"[-] No subnets found for {upper_target} in database.")
            return []
            
        total_ips = sum(net.num_addresses for net in subnets if net.version == 4)
        if total_ips > 1000000 and not silent: 
            print(f"[*] Warning: {upper_target} contains {total_ips} IPs. Expansion may take a moment...")
            
        for net in subnets:
            if net.version == 6 and net.num_addresses > MAX_IPV6_SAMPLES and not silent:
                print(f"[*] Sampling {MAX_IPV6_SAMPLES} representative IPv6 addresses from {net}.")
            elif net.num_addresses > MAX_IPV4_EXPANSION:
                if not silent: 
                    print(f"[*] Warning: Subnet {net} is massive. Truncating to {MAX_IPV4_EXPANSION} IPs.")
            asn_ips.extend(_expand_network(net))
            
        return asn_ips
        
    # Standard IP or CIDR expansion
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.version == 6 and net.num_addresses > MAX_IPV6_SAMPLES:
            if not silent:
                print(f"[*] Sampling {MAX_IPV6_SAMPLES} representative IPv6 addresses from {target}.")
        elif net.num_addresses > MAX_IPV4_EXPANSION:
            if not silent: 
                print(f"[*] Warning: Subnet {target} is massive. Truncating to {MAX_IPV4_EXPANSION} IPs.")
        return _expand_network(net)
    except ValueError: 
        return [target] # Treat as a raw domain or invalid string if parsing fails
