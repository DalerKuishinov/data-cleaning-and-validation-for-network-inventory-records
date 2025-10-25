#!/usr/bin/env python3
import csv
import json
import re
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional

class DataRgent:
    def __init__(self, ai: bool = True):
        self.anomalies = []
        self.ai = ai
        self.ai_client = None

        # Add AI initialization here later once deterministic stuff is figured out
        
        # Statistics
        self.stats = {
            "total_records": 0,
            "ai_calls": 0,
            "anomalies_detected": 0
        }

    # IP Validation
    def validate_ip(self, ip_str):
        # Validate and normalize IP address (IPv4 and IPv6).
        if not ip_str or ip_str.strip().upper() in ("N/A", ""):
            return {
                "valid": False,
                "normalized": "",
                "version": "",
                "subnet_cidr": "",
                "reverse_ptr": "",
                "reason": "missing"
            }
        
        ip_clean = ip_str.strip()

        # Try IPv4 first
        result = self.validate_ipv4(ip_clean)
        if result["valid"] or "normalized" in result:
            return result
        
        # Try IPv6 only if IPv4 check indicated this might be IPv6
        if result["reason"] in ("ipv6_format"):
            result = self.validate_ipv6(ip_clean)
            if result["valid"]:
                return result
            
        # If IPv6 check went through, probably IPv4 error
        if "reason" in result and result["reason"] not in ("ipv6_format"):
            return result
        
        return {
            "valid": False,
            "normalized": ip_clean,
            "version": "",
            "subnet_cidr": "",
            "reverse_ptr": "",
            "reason": "invalid_format"
        }
    
    def validate_ipv4(self, ip_str):
        # Validate IPv4 address
        if ":" in ip_str:
            return {"valid": False, "reason": "ipv6_format"}
        
        octets = ip_str.split(".")
        if len(octets) != 4:
            return {"valid": False, "reason": "wrong_octet_count", "normalized": ip_str, "version": "", "subnet_cidr": "", "reverse_ptr": ""}
        
        canonical_octets = []
        for octet in octets:
            if not octet:
                return {"valid": False, "reason": "empty_octet", "normalized": ip_str, "version": "", "subnet_cidr": "", "reverse_ptr": ""}
            
            if not octet.lstrip("+-").isdigit():
                return {"valid": False, "reason": "non_numeric_octet", "normalized": ip_str, "version": "", "subnet_cidr": "", "reverse_ptr": ""}
            
            try:
                value = int(octet, 10)
            except ValueError:
                return {"valid": False, "reason": "invalid_number", "normalized": ip_str, "version": "", "subnet_cidr": "", "reverse_ptr": ""}
            
            if value < 0 or value > 255:
                return {"valid": False, "reason": "octet_out_of_range", "normalized": ip_str, "version": "", "subnet_cidr": "", "reverse_ptr": ""}
            
            canonical_octets.append(str(value))

        canonical = ".".join(canonical_octets)
        ip_type = self.classify_ipv4(canonical)
        subnet = self.default_subnet_ipv4(canonical, ip_type)
        reverse_ptr = self.generate_reverse_ptr_ipv4(canonical)

        return {
            "valid": True,
            "normalized": canonical,
            "version": "4",
            "subnet_cidr": subnet,
            "reverse_ptr": reverse_ptr,
            "ip_type": ip_type,
            "reason": "ok"
        }

    def validate_ipv6(self, ip_str):
        # Validate IPv6 address
        if "%" in ip_str:
            ip_part = ip_str.split("%")[0]
        else:
            ip_part = ip_str
        
        try:
            import ipaddress
            ip_obj = ipaddress.IPv6Address(ip_part)
            return {
                "valid": True,
                "normalized": str(ip_obj),
                "version": "6",
                "subnet_cidr": f"{ip_obj}/64",
                "reverse_ptr": "",
                "reason": "ok"
            }
        except ValueError:
            return {"valid": False, "reason": "invalid_ipv6"}
        
    def classify_ipv4_type(self, ip):
        # Simple classification for context; not required for validity
        octets = list(map(int, ip.split(".")))
        if octets[0] == 10:
            return "private_rfc1918"
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return "private_rfc1918"
        if octets[0] == 192 and octets[1] == 168:
            return "private_rfc1918"
        if octets[0] == 169 and octets[1] == 254:
            return "link_local_apipa"
        if octets[0] == 127:
            return "loopback"
        return "public_or_other"
    
    def default_subnet_ipv4(self, ip: str, ip_type):
        # Generate default subnet based on IP type.
        if ip_type == "private_rfc1918":
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""
    
    def generate_reverse_ptr_ipv4(self, ip):
        # Generate reverse DNS PTR record
        parts = ip.split(".")
        return f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
    
    # MAC Validation

    def validate_mac(self, mac_str):
        # Validate and normalize MAC Address
        if not mac_str or mac_str.strip() == "":
            return {'valid': False, 'normalized': "", 'reason': 'missing'}
        
        mac_clean = mac_str.strip()
        mac_no_separator = re.sub(r'[-:.]', '', mac_clean)

        if not re.match(r'^[0-9a-fA-F]{12}$', mac_no_separator):
            return {'valid': False, 'normalized': mac_clean, 'reason': 'invalid_format'}
        
        normalized = ':'.join([mac_no_separator[i:i+2].lower() for i in range(0, 12, 2)])
        return {'valid': True, 'normalized': normalized, 'reason': 'ok'}
    
    # Hostname Validation

    def validate_hostname(self, hostname_str):
        # Validate hostname according to RFC 952/1123 syntax
        if not hostname_str or hostname_str.strip() == "":
            return {'valid': False, 'normalized': '', 'reason': 'missing'}
        
        hostname = hostname_str.strip().lower()

        if len(hostname) > 253:
            return {'valid': False, 'normalized': hostname, 'reason': 'too_long'}
        
        labels = hostname.split('.')
        for label in labels:
            if not label:
                return {'valid': False, 'normalized': hostname, 'reason': 'empty_label'}
            if len(label) > 63:
                return {'valid': False, 'normalized': hostname, 'reason': 'label_too_long'}
            if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label):
                return {'valid': False, 'normalized': hostname, 'reason': 'invalid_characters'}
            
        return {'valid': True, 'normalized': hostname, 'reason': 'ok'}
    
    def validate_fqdn(self, fqdn_str, hostname):
        # Validate FQDN and check whether consistent with hostname
        if not fqdn_str or fqdn_str.strip() == "":
            return {'valid': False, 'normalized': '', 'consistent': False, 'reason': 'missing'}
        
        fqdn = fqdn_str.strip().lower()

        if '.' not in fqdn:
            return {'valid': False, 'normalized': fqdn, 'consistent': False, 'reason': 'not_fully_qualified'}
        
        hostname_check = self.validate_hostname(fqdn)
        if not hostname_check['valid']:
            return {'valid': False, 'normalized': fqdn, 'consistent': False, 'reason': hostname_check['reason']}
        
        consistent = False
        if hostname:
            hostname_norm = hostname.lower()
            consistent = fqdn.startswith(hostname_norm + '.')
        
        return {'valid': True, 'normalized': fqdn, 'consistent': consistent, 'reason': 'ok'}
    
    # Owner Validation

    def parse_owner(self, owner_str):
        # Parse owner field for name, email, and team
        if not owner_str or owner_str.strip() == '':
            return {'owner': '', 'owner_email': '', 'owner_team': ''}
        
        owner = owner_str.strip()
        email = ''
        team = ''
        name = owner
        
        email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', owner)
        if email_match:
            email = email_match.group(0).lower()
            name = owner.replace(email, '').strip()
        
        team_match = re.search(r'\(([^)]+)\)', name)
        if team_match:
            team = team_match.group(1).strip()
            name = re.sub(r'\([^)]+\)', '', name).strip()
        
        return {'owner': name if name else owner, 'owner_email': email, 'owner_team': team}
    
    # Site Normalization
    
    # Main Processing
    def process(self, input_csv, output_csv, anomalies_json):
        # Main Processing pipeline
        print(f"Processing {input_csv}...")

        with open(input_csv, 'r', newline='') as f:
            reader = csv.DictReader(f)
            raw_records = list(reader)

        self.stats['total_records'] = len(raw_records)

        processed_records = []
        ambigious_records = []

        for row in raw_records:
            record = self.process_record_deterministic(row)
            processed_records.append(record)

            if record['needs_ai_classification']:
                ambigious_records.append({
                    'index': len(processed_records) - 1,
                    'hostname': record['hostname'],
                    'device_type': row.get('device_type', ''),
                    'notes': row.get('notes', ''),
                    'ip': record['ip']
                })

        if ambigious_records:
            print(f"  Using AI to classify {len(ambigious_records)} ambiguous device types...")
            classifications = self.classify_device_type_with_ai(ambigious_records)
            
            for amb_record, classification in zip(ambigious_records, classifications):
                idx = amb_record['index']
                processed_records[idx]['device_type'] = classification['device_type']
                processed_records[idx]['device_type_confidence'] = classification['device_type_confidence']
        
        self._write_output(processed_records, output_csv, anomalies_json)
        
        print(f"Processing complete!")
        print(f"Total records: {self.stats['total_records']}")
        print(f"Anomalies detected: {self.stats['anomalies_detected']}")
        print(f"AI API calls: {self.stats['ai_calls']}")
        print(f"Output: {output_csv}")
        print(f"Anomalies: {anomalies_json}")

    def process_record_deterministic(self, row):
        # Process a single record with deterministic rules
        source_row_id = row.get('source_row_id', '') # Return empty string if can't find
        steps = []

        raw_ip = row.get('ip', '')
        ip_result = self.validate_ip(raw_ip)
        steps.append('ip_validation')
        if not ip_result['valid']:
            self.add_anomaly(source_row_id, 'ip', ip_result['reason'], raw_ip)

        return {
            'source_row_id': source_row_id,
            'ip': ip_result['normalized'],
            'ip_valid': 'true' if ip_result['valid'] else 'false',
            'ip_version': ip_result['version'],
            'subnet_cidr': ip_result['subnet_cidr'],
            'reverse_ptr': ip_result['reverse_ptr'],
        }


    # def classify_device_type_with_ai(self, records):

        

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
