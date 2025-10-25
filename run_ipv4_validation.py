#!/usr/bin/env python3
import csv
import json
import sys
from pathlib import Path

class DataRgent:
    def __init__(self, ai: bool = True):
        self.anomalies = []
        self.ai = ai
        self.ai_client = None

        # Add AI initialization here later once deterministic stuff is figured out
        
        # Statistics
        self.stats = {
            'total_records': 0,
            'ai_calls': 0,
            'anomalies_detected': 0
        }

    # IP Validation
    def validate_ip(self, ip_str):
        # Validate and normalize IP address (IPv4 and IPv6).
        if not ip_str or ip_str.strip().upper() in ('N/A', ''):
            return {
                'valid': False,
                'normalized': '',
                'version': '',
                'subnet_cidr': '',
                'reverse_ptr': '',
                'reason': 'missing'
            }
        
        ip_clean = ip_str.strip()

        # Try IPv4 first
        result = self.validate_ipv4(ip_clean)
        if result['valid'] or 'normalized' in result:
            return result
        
        # Try IPv6 only if IPv4 check indicated this might be IPv6
        if result['reason'] in ('ipv6_format'):
            result = self.validate_ipv6(ip_clean)
            if result['valid']:
                return result
            
        # If IPv6 check went through, probably IPv4 error
        if 'reason' in result and result['reason'] not in ('ipv6_format'):
            return result
        
        return {
            'valid': False,
            'normalized': ip_clean,
            'version': '',
            'subnet_cidr': '',
            'reverse_ptr': '',
            'reason': 'invalid_format'
        }
    
    def validate_ipv4(self, ip_str):
        # Validate IPv4 address
        if ':' in ip_str:
            return {'valid': False, 'reason': 'ipv6_format'}
        
        octets = ip_str.split('.')
        if len(octets) != 4:
            return {'valid': False, 'reason': 'wrong_octet_count', 'normalized': ip_str, 'version': '', 'subnet_cidr': '', 'reverse_ptr': ''}
        
        canonical_octets = []
        for octet in octets:
            if not octet:
                return {'valid': False, 'reason': 'empty_octet', 'normalized': ip_str, 'version': '', 'subnet_cidr': '', 'reverse_ptr': ''}
            
            if not octet.lstrip('+-').isdigit():
                return {'valid': False, 'reason': 'non_numeric_octet', 'normalized': ip_str, 'version': '', 'subnet_cidr': '', 'reverse_ptr': ''}
            
            try:
                value = int(octet, 10)
            except ValueError:
                return {'valid': False, 'reason': 'invalid_number', 'normalized': ip_str, 'version': '', 'subnet_cidr': '', 'reverse_ptr': ''}
            
            if value < 0 or value > 255:
                return {'valid': False, 'reason': 'octet_out_of_range', 'normalized': ip_str, 'version': '', 'subnet_cidr': '', 'reverse_ptr': ''}
            
            canonical_octets.append(str(value))

        canonical = '.'.join(canonical_octets)
        ip_type = self.classify_ipv4(canonical)
        subnet = self.default_subnet_ipv4(canonical, ip_type)
        reverse_ptr = self.generate_reverse_ptr_ipv4(canonical)

        return {
            'valid': True,
            'normalized': canonical,
            'version': '4',
            'subnet_cidr': subnet,
            'reverse_ptr': reverse_ptr,
            'ip_type': ip_type,
            'reason': 'ok'
        }

    def validate_ipv6(self, ip_str):

def classify_ipv4_type(ip):
    # Simple classification for context; not required for validity
    o = list(map(int, ip.split(".")))
    if o[0] == 10:
        return "private_rfc1918"
    if o[0] == 172 and 16 <= o[1] <= 31:
        return "private_rfc1918"
    if o[0] == 192 and o[1] == 168:
        return "private_rfc1918"
    if o[0] == 169 and o[1] == 254:
        return "link_local_apipa"
    if o[0] == 127:
        return "loopback"
    return "public_or_other"
    
def default_subnet(ip):
    # Heuristic: /24 for RFC1918, else None (you can adapt this)
    iptype = classify_ipv4_type(ip)
    if iptype == "private_rfc1918":
        parts = list(map(int, ip.split(".")))
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ""

def process(input_csv, out_csv, anomalies_json):
    anomalies = []
    with open(input_csv, newline="") as f, open(out_csv, "w", newline="") as g:
        reader = csv.DictReader(f)
        fieldnames = [
            "ip","ip_valid","ip_version","subnet_cidr","normalization_steps","source_row_id"
        ] + [c for c in reader.fieldnames if c not in ("ip","source_row_id")]
        writer = csv.DictWriter(g, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            raw_ip = row.get("ip","")
            valid, canonical, reason = ipv4_validate_and_normalize(raw_ip)
            steps = []
            steps.append("ip_trim")
            if reason == "ok":
                steps.append("ip_parse")
                steps.append("ip_normalize")
                ip_out = canonical
                ip_valid = "true"
                ip_version = "4"
                subnet = default_subnet(ip_out)
            else:
                # keep original as-is, flag invalid
                ip_out = str(raw_ip).strip()
                ip_valid = "false"
                ip_version = ""
                subnet = ""
                anomalies.append({
                    "source_row_id": row.get("source_row_id"),
                    "issues": [{"field":"ip","type": reason, "value": raw_ip}],
                    "recommended_actions": ["Correct IP or mark record for review"]
                })
                # add a specific step for the reason
                steps.append(f"ip_invalid_{reason}")
            out_row = {
                "ip": ip_out,
                "ip_valid": ip_valid,
                "ip_version": ip_version,
                "subnet_cidr": subnet,
                "normalization_steps": "|".join(steps),
                "source_row_id": row.get("source_row_id")
            }
            # pass-through other fields
            for k,v in row.items():
                if k not in ("ip","source_row_id"):
                    out_row[k] = v
            writer.writerow(out_row)
    with open(anomalies_json, "w") as h:
        json.dump(anomalies, h, indent=2)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        input_csv = "inventory_raw.csv"
    else:
        input_csv = sys.argv[1]
    output_csv = "inventory_clean.csv"
    anomalies_json = "anomalies.json"

    if not Path(input_csv).exists():
        print(f"Error: Input file '{input_csv}' not found.")
        sys.exit(1)

    dataRgent = DataRgent(ai=True)
    dataRgent.process(input_csv, output_csv, anomalies_json)

    print(f"Wrote {output_csv} and {anomalies_json}")
