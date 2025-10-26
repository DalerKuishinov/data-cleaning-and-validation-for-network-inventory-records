import csv
import json
import re
import sys
import os
from pathlib import Path
from typing import Dict, List

# Try to import Groq client
GROQ_AVAILABLE = False

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    pass

# Configuration
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
LLM_TEMPERATURE = 0.1  # Low temperature for consistency
BATCH_SIZE = 10  # Process ambiguous cases in batches

class DataRgent:
    def __init__(self, ai: bool = True):
        self.anomalies = []
        self.ai = ai
        self.ai_client = None

        # Try to initialize Groq
        if self.ai and GROQ_AVAILABLE and GROQ_API_KEY:
            try:
                self.ai_client = Groq(api_key=GROQ_API_KEY)
            except Exception as e:
                print(f"Groq initialization failed: {e}")
                self.ai = False
        
        if self.ai and not self.ai_client:
            print("Groq API not configured. Using rule-based fallback")
            self.ai = False
        
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
        ip_type = self.classify_ipv4_type(canonical)
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
    
    # Groq stuff
    def classify_device_type_with_ai(self, records):
        # Use LLM to classify ambigious device types
        if not self.ai or not records:
            return [self.classify_device_type_rule_based(r) for r in records]
        
        self.stats['ai_calls'] += 1

        # Preparing context
        cases = []
        for idx, record in enumerate(records):
            cases.append({
                'id': idx,
                'hostname': record.get('hostname', ''),
                'device_type_raw': record.get('device_type', ''),
                'notes': record.get('notes', ''),
                'ip': record.get('ip', '')
            })

        prompt = self.build_device_classification_prompt(cases)

        try:
            response = self.call_groq(prompt)
            print (f"AI Response: {response}")

            # Parse JSON response
            json_match = re.search(r'```json\s*(\[.*?\])\s*```', response, re.DOTALL)
            if json_match:
                response = json_match.group(1)
            
            classifications = json.loads(response)

            results = []
            for record, classification in zip(records, classifications):
                results.append({
                    'device_type': classification['device_type'],
                    'device_type_confidence': classification['confidence'],
                    'ai_reasoning': classification.get('reasoning', '')
                })

            return results
        except Exception as e:
            print(f"AI classification failed: {e}")
            return [self.classify_device_type_rule_based(r) for r in records]

    def call_groq(self, prompt):
        # Call Groq API
        response = self.ai_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=LLM_TEMPERATURE,
            max_tokens=2000
        )
        return response.choices[0].message.content

    def build_device_classification_prompt(self, cases):
        # Build prompt for device type classification
        prompt = f"""You are a network inventory data classifier. Classify each device into one of these categories:
- server
- workstation
- printer
- switch
- router
- iot
- unknown

For each device, provide:
1. device_type: one of the categories above
2. confidence: "high", "medium", or "low"
3. reasoning: brief explanation (1 sentence)

Input records:
{json.dumps(cases, indent=2)}

Return ONLY a JSON array with this structure:
[
  {{"id": 0, "device_type": "server", "confidence": "high", "reasoning": "hostname pattern srv- indicates server"}},
  ...
]

Rules:
- Use hostname patterns (srv-, host-, gw-, sw-, etc.)
- Consider device_type_raw if present but verify it makes sense
- Check notes for clues
- IP type can help (servers often have static IPs)
- Be conservative: use "unknown" if uncertain"""
        
        return prompt

    def classify_device_type_rule_based(self, record: Dict) -> Dict:
        # Rule-based device type classification as fallback if LLM calls fail
        hostname = record.get('hostname', '').lower()
        device_type_raw = record.get('device_type', '').lower()
        notes = record.get('notes', '').lower()
        
        valid_types = ['server', 'workstation', 'printer', 'switch', 'router', 'iot']
        if device_type_raw in valid_types:
            return {'device_type': device_type_raw, 'device_type_confidence': 'high', 'ai_reasoning': 'explicit_type_provided'}
        
        patterns = {
            'server': ['srv', 'host', 'db', 'web', 'app'],
            'switch': ['sw', 'switch'],
            'router': ['rtr', 'router', 'gw', 'gateway'],
            'printer': ['printer', 'print'],
            'iot': ['iot', 'cam', 'sensor']
        }
        
        for device_type, keywords in patterns.items():
            if any(kw in hostname for kw in keywords):
                return {'device_type': device_type, 'device_type_confidence': 'medium', 'ai_reasoning': f'hostname_pattern_{device_type}'}
        
        if 'camera' in notes or 'poe' in notes:
            return {'device_type': 'iot', 'device_type_confidence': 'medium', 'ai_reasoning': 'notes_indicate_iot'}
        
        return {'device_type': 'unknown', 'device_type_confidence': 'low', 'ai_reasoning': 'insufficient_information'}
    
    # Site Normalization
    def normalize_site(self, site_str):
        # Normalize site names
        if not site_str or site_str.strip().upper() in ('N/A', 'NULL', ''):
            return ''
        
        site = site_str.strip()
        site_lower = site.lower()
        site_clean = re.sub(r'\s+campus$', '', site_lower, flags=re.IGNORECASE)
        site_clean = re.sub(r'\bbldg\b\.?', 'building', site_clean)
        site_clean = re.sub(r'\bhq\b', 'hq', site_clean)
        site_clean = site_clean.title()
        site_clean = re.sub(r'[-_\s]+', '-', site_clean)
        
        return site_clean
    
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
        
        self.write_output(processed_records, output_csv, anomalies_json)
        
        print(f"Processing complete!")
        print(f"Total records: {self.stats['total_records']}")
        print(f"Anomalies detected: {self.stats['anomalies_detected']}")
        print(f"AI API calls: {self.stats['ai_calls']}")
        print(f"Output: {output_csv}")
        print(f"Anomalies: {anomalies_json}")

    def process_record_deterministic(self, row):
        # Process a single record with deterministic rules
        source_row_id = row.get('source_row_id', '')
        steps = []
        
        raw_ip = row.get('ip', '')
        ip_result = self.validate_ip(raw_ip)
        steps.append('ip_validation')
        if not ip_result['valid']:
            self.add_anomaly(source_row_id, 'ip', ip_result['reason'], raw_ip)
        
        mac_result = self.validate_mac(row.get('mac', ''))
        steps.append('mac_validation')
        if mac_result['valid']:
            steps.append('mac_normalization')
        elif row.get('mac', '').strip():
            self.add_anomaly(source_row_id, 'mac', mac_result['reason'], row.get('mac', ''))
        
        hostname_result = self.validate_hostname(row.get('hostname', ''))
        steps.append('hostname_validation')
        if hostname_result['valid']:
            steps.append('hostname_normalization')
        elif row.get('hostname', '').strip():
            self.add_anomaly(source_row_id, 'hostname', hostname_result['reason'], row.get('hostname', ''))
        
        fqdn_result = self.validate_fqdn(row.get('fqdn', ''), hostname_result['normalized'])
        steps.append('fqdn_validation')
        if fqdn_result['valid']:
            steps.append('fqdn_normalization')
        
        owner_result = self.parse_owner(row.get('owner', ''))
        steps.append('owner_parsing')
        
        device_type_raw = row.get('device_type', '').strip()
        needs_ai = not device_type_raw or device_type_raw.lower() not in [
            'server', 'workstation', 'printer', 'switch', 'router', 'iot'
        ]
        
        if not needs_ai:
            device_classification = self.classify_device_type_rule_based(row)
            steps.append('device_type_rule_classification')
        else:
            device_classification = {
                'device_type': device_type_raw,
                'device_type_confidence': 'low',
                'ai_reasoning': 'pending_ai_classification'
            }
            steps.append('device_type_pending_ai')
        
        site_normalized = self.normalize_site(row.get('site', ''))
        steps.append('site_normalization')
        
        return {
            'source_row_id': source_row_id,
            'ip': ip_result['normalized'],
            'ip_valid': 'true' if ip_result['valid'] else 'false',
            'ip_version': ip_result['version'],
            'subnet_cidr': ip_result['subnet_cidr'],
            'reverse_ptr': ip_result['reverse_ptr'],
            'hostname': hostname_result['normalized'],
            'hostname_valid': 'true' if hostname_result['valid'] else 'false',
            'fqdn': fqdn_result['normalized'],
            'fqdn_consistent': 'true' if fqdn_result['consistent'] else 'false',
            'mac': mac_result['normalized'],
            'mac_valid': 'true' if mac_result['valid'] else 'false',
            'owner': owner_result['owner'],
            'owner_email': owner_result['owner_email'],
            'owner_team': owner_result['owner_team'],
            'device_type': device_classification['device_type'],
            'device_type_confidence': device_classification['device_type_confidence'],
            'site': site_normalized,
            'site_normalized': site_normalized,
            'normalization_steps': '|'.join(steps),
            'needs_ai_classification': needs_ai
        }
    
    def add_anomaly(self, source_row_id, field, issue_type, value):
        # Add an anomaly
        self.stats['anomalies_detected'] += 1

        existing = next((a for a in self.anomalies if a['source_row_id'] == source_row_id), None) # CHeck if source row exists already

        if existing:
            existing['issues'].append({'field': field, 'type': issue_type, 'value': value})
        else:
            self.anomalies.append({
                'source_row_id': source_row_id,
                'issues': [{'field': field, 'type': issue_type, 'value': value}],
                'recommended_actions': self.get_recommended_actions(field, issue_type)
            })

    def get_recommended_actions(self, field: str, issue_type: str) -> List[str]:
        # Get recommended actions for an anomaly
        actions_map = {
            'ip': {
                'missing': ['Populate IP address field', 'Mark record for manual review'],
                'invalid_format': ['Correct IP address format', 'Verify with network team'],
                'octet_out_of_range': ['Correct IP octet values (0-255)', 'Check source data'],
                'wrong_octet_count': ['Correct IP address to have exactly 4 octets', 'Verify source data'],
                'non_numeric_octet': ['Remove non-numeric characters from IP address', 'Check source data'],
                'ipv6_format': ['Convert to IPv4 or use proper IPv6 validation', 'Verify IP version'],
            },
            'mac': {
                'invalid_format': ['Correct MAC address format (12 hex digits)', 'Verify with asset management'],
            },
            'hostname': {
                'invalid_characters': ['Remove invalid characters from hostname', 'Follow RFC 1123 naming rules'],
                'too_long': ['Shorten hostname to 253 characters or less'],
            }
        }
        
        field_actions = actions_map.get(field, {})
        return field_actions.get(issue_type, [f'Review and correct {field} field value'])
    
    def write_output(self, records: List[Dict], output_csv: str, anomalies_json: str):
        """Write cleaned data and anomalies to files."""
        fieldnames = [
            'ip', 'ip_valid', 'ip_version', 'subnet_cidr', 'reverse_ptr',
            'hostname', 'hostname_valid',
            'fqdn', 'fqdn_consistent',
            'mac', 'mac_valid',
            'owner', 'owner_email', 'owner_team',
            'device_type', 'device_type_confidence',
            'site', 'site_normalized',
            'source_row_id', 'normalization_steps'
        ]
        
        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(records)
        
        with open(anomalies_json, 'w') as f:
            json.dump(self.anomalies, f, indent=2)

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
