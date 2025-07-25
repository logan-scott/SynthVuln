import argparse
import json
import random
import uuid
import yaml
import csv
import sqlite3
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os

class FindingsGenerator:
    _vulnerability_cache = None
    _cache_timestamp = None
    
    def __init__(
        self,
        asset_file: str = '',
        config_file: str = 'configs/generator_config.yaml',
        num_findings: int = 10,
        bias_recent: bool = True,
    ):
        self.config_file = config_file
        self.num_findings = num_findings
        self.bias_recent = bias_recent
        self.config = self._load_config()
        
        # Use config default if no asset file specified
        self.asset_file = asset_file if asset_file else self.config.get('default_paths', {}).get('asset_output', 'data/raw/assets.json')
        
        self.assets = self._load_assets()
        self.vulnerabilities = self._load_vulnerabilities()
        
        # Load detection tools and other config from the shared config
        findings_config = self.config.get('findings_config', {})
        self.detection_tools = findings_config.get('detection_tools', [
            "Nessus", "Qualys", "OpenVAS", "Nexpose", "Tenable.io"
        ])
        self.severity_weights = findings_config.get('severity_weights', {
            'CRITICAL': 5, 'HIGH': 15, 'MEDIUM': 35, 'LOW': 45
        })
        self.recent_bias_config = findings_config.get('recent_bias', {
            'enabled': True, 'cutoff_years': 2, 'multiplier': 3.0
        })
        self.vulnerability_counts = findings_config.get('vulnerability_counts', {
            'min': 1, 'max': 8
        })

    def _load_assets(self) -> List[Dict[str, Any]]:
        try:
            # Detect format based on file extension
            file_ext = self.asset_file.lower().split('.')[-1]
            
            if file_ext == 'json':
                return self._load_assets_json()
            elif file_ext == 'csv':
                return self._load_assets_csv()
            elif file_ext in ['sql', 'db', 'sqlite']:
                return self._load_assets_sql()
            else:
                # Default to JSON if extension is unknown
                print(f"Unknown file extension '{file_ext}', attempting JSON format...")
                return self._load_assets_json()
        except Exception as e:
            print(f"Error loading assets: {e}")
            return []
    
    def _load_assets_json(self) -> List[Dict[str, Any]]:
        """Load assets from JSON file"""
        with open(self.asset_file, 'r') as f:
            return json.load(f)
    
    def _load_assets_csv(self) -> List[Dict[str, Any]]:
        """Load assets from CSV file"""
        assets = []
        with open(self.asset_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert CSV row back to asset format
                asset = {
                    'uuid': row['uuid'],
                    'domain_name': row['domain_name'],
                    'hostname': row['hostname'],
                    'user_accounts': row['user_accounts'].split(';') if row['user_accounts'] else [],
                    'privileged_user_accounts': row['privileged_user_accounts'].split(';') if row['privileged_user_accounts'] else [],
                    'type': row['type'],
                    'internet_exposed': row['internet_exposed'].lower() == 'true',
                    'public_ip': row['public_ip'] if row['public_ip'] else None,
                    'internal_ip': row['internal_ip'],
                    'open_ports': [int(p) for p in row['open_ports'].split(';')] if row['open_ports'] else [],
                    'endpoint_security_installed': row['endpoint_security_installed'].lower() == 'true',
                    'local_firewall_active': row['local_firewall_active'].lower() == 'true',
                    'location': row['location']
                }
                assets.append(asset)
        return assets
    
    def _load_assets_sql(self) -> List[Dict[str, Any]]:
        """Load assets from SQL database file"""
        assets = []
        
        # Check if it's a SQLite database file
        if self.asset_file.endswith('.db') or self.asset_file.endswith('.sqlite'):
            conn = sqlite3.connect(self.asset_file)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            
            try:
                cursor.execute("SELECT * FROM assets")
                rows = cursor.fetchall()
                
                for row in rows:
                    asset = {
                        'uuid': row['uuid'],
                        'domain_name': row['domain_name'],
                        'hostname': row['hostname'],
                        'user_accounts': row['user_accounts'].split(';') if row['user_accounts'] else [],
                        'privileged_user_accounts': row['privileged_user_accounts'].split(';') if row['privileged_user_accounts'] else [],
                        'type': row['type'],
                        'internet_exposed': bool(row['internet_exposed']),
                        'public_ip': row['public_ip'] if row['public_ip'] != 'NULL' else None,
                        'internal_ip': row['internal_ip'],
                        'open_ports': [int(p) for p in row['open_ports'].split(';')] if row['open_ports'] else [],
                        'endpoint_security_installed': bool(row['endpoint_security_installed']),
                        'local_firewall_active': bool(row['local_firewall_active']),
                        'location': row['location']
                    }
                    assets.append(asset)
            finally:
                conn.close()
        else:
            # Assume it's a SQL script file - this is more complex and would require
            # parsing SQL INSERT statements. For now, raise an error.
            raise ValueError("SQL script files (.sql) are not supported for input. Use SQLite database files (.db, .sqlite) instead.")
        
        return assets
    
    def _load_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def _load_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Load vulnerabilities from data sources using caching and optimized approach"""
        
        # Check if we have cached vulnerabilities (valid for 1 hour)
        current_time = time.time()
        if (FindingsGenerator._vulnerability_cache is not None and 
            FindingsGenerator._cache_timestamp is not None and 
            current_time - FindingsGenerator._cache_timestamp < 3600):  # 1 hour cache
            print(f"Using cached vulnerabilities ({len(FindingsGenerator._vulnerability_cache)} available)")
            return FindingsGenerator._vulnerability_cache
        
        try:
            print("Loading vulnerability data...")
            
            # Load NVD data using streaming approach
            nvd_base = self.config.get('default_paths', {}).get('nvd_data_dir', 'data/raw/nvd')
            vulnerabilities = self._stream_nvd_vulnerabilities(nvd_base)
            
            # Cache the results
            FindingsGenerator._vulnerability_cache = vulnerabilities
            FindingsGenerator._cache_timestamp = current_time
            
            print(f"Loaded {len(vulnerabilities)} vulnerabilities from NVD database")
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error loading vulnerabilities: {e}")
            # Fallback to sample CVEs
            fallback_vulns = [
                {"id": "CVE-2023-1234", "severity": "HIGH", "base_score": 8.5, "description": "Sample vulnerability", "year": 2023},
                {"id": "CVE-2023-5678", "severity": "CRITICAL", "base_score": 9.8, "description": "Sample critical vulnerability", "year": 2023},
                {"id": "CVE-2023-9012", "severity": "MEDIUM", "base_score": 6.5, "description": "Sample medium vulnerability", "year": 2023},
                {"id": "CVE-2023-3456", "severity": "LOW", "base_score": 3.2, "description": "Sample low vulnerability", "year": 2023},
                {"id": "CVE-2023-7890", "severity": "HIGH", "base_score": 8.1, "description": "Sample high vulnerability", "year": 2023}
            ]
            # Cache fallback as well
            FindingsGenerator._vulnerability_cache = fallback_vulns
            FindingsGenerator._cache_timestamp = current_time
            return fallback_vulns
    
    def _stream_nvd_vulnerabilities(self, nvd_base: str) -> List[Dict[str, Any]]:
        """Stream NVD vulnerabilities without loading entire dataset into memory"""
        vulnerabilities = []
        
        if not os.path.exists(nvd_base):
            print(f"Warning: NVD database path not found: {nvd_base}")
            return vulnerabilities
        
        # Get all year directories and sort them in reverse order (newest first)
        year_dirs = [d for d in os.listdir(nvd_base) if d.startswith('CVE-') and os.path.isdir(os.path.join(nvd_base, d))]
        year_dirs.sort(reverse=True)
        
        if not year_dirs:
            print("No CVE year directories found")
            return vulnerabilities
        
        # Calculate target vulnerabilities needed (limit for performance)
        max_vulns_config = self.config.get('findings_config', {}).get('max_unique_vulns', 5000)
        max_unique_vulns = min(self.num_findings * 10, max_vulns_config)
        target_total = max_unique_vulns
        
        if self.bias_recent:
            # Calculate year weights (more recent years get higher weights)
            year_weights = self._calculate_year_weights(year_dirs)
            target_per_year = self._distribute_targets_by_weight(year_weights, target_total)
        else:
            # Equal distribution across years
            target_per_year = {year: target_total // len(year_dirs) for year in year_dirs}
        
        print(f"Streaming vulnerabilities from {len(year_dirs)} years...")
        
        # Stream vulnerabilities from each year
        for year_dir in year_dirs:
            if len(vulnerabilities) >= target_total:
                break
                
            year_target = target_per_year.get(year_dir, 0)
            if year_target == 0:
                continue
                
            year_vulns = self._stream_year_vulnerabilities(nvd_base, year_dir, year_target)
            vulnerabilities.extend(year_vulns)
            
            if len(vulnerabilities) % 1000 == 0:
                print(f"Streamed {len(vulnerabilities)} vulnerabilities so far...")
        
        return vulnerabilities[:target_total]
    
    def _calculate_year_weights(self, year_dirs: List[str]) -> Dict[str, float]:
        """Calculate weights for each year based on recency"""
        year_weights = {}
        
        # Get year weights from config
        config_weights = self.config.get('findings_config', {}).get('recent_bias', {}).get('year_weights', {})
        
        # Default weights if config is missing
        default_weights = {
            '2025_and_later': 0.4,
            '2024': 0.3,
            '2023': 0.2,
            '2020_to_2022': 0.05,
            '2015_to_2019': 0.03,
            'before_2015': 0.02,
            'malformed': 0.01
        }
        
        # Use config weights or fall back to defaults
        weights = {**default_weights, **config_weights}
        
        for year_dir in year_dirs:
            try:
                year = int(year_dir.split('-')[1])
                if year >= 2025:
                    weight = weights['2025_and_later']
                elif year >= 2024:
                    weight = weights['2024']
                elif year >= 2023:
                    weight = weights['2023']
                elif year >= 2020:
                    weight = weights['2020_to_2022']
                elif year >= 2015:
                    weight = weights['2015_to_2019']
                else:
                    weight = weights['before_2015']
                
                year_weights[year_dir] = weight
            except (ValueError, IndexError):
                year_weights[year_dir] = weights['malformed']
        
        return year_weights
    
    def _distribute_targets_by_weight(self, year_weights: Dict[str, float], target_total: int) -> Dict[str, int]:
        """Distribute target counts across years based on weights"""
        total_weight = sum(year_weights.values())
        target_per_year = {}
        
        for year_dir, weight in year_weights.items():
            if total_weight > 0:
                target_count = max(1, int(target_total * weight / total_weight))
            else:
                target_count = target_total // len(year_weights)
            target_per_year[year_dir] = target_count
        
        return target_per_year
    
    def _stream_year_vulnerabilities(self, nvd_base: str, year_dir: str, target_count: int) -> List[Dict[str, Any]]:
        """Stream vulnerabilities from a specific year directory"""
        year_vulns = []
        year_path = os.path.join(nvd_base, year_dir)
        
        try:
            year = int(year_dir.split('-')[1])
        except (ValueError, IndexError):
            year = 1999  # Default year for malformed directories
        
        # Get range directories and sort them
        range_dirs = [d for d in os.listdir(year_path) if os.path.isdir(os.path.join(year_path, d))]
        
        if self.bias_recent:
            range_dirs.sort(reverse=True)  # Higher CVE numbers first
        else:
            range_dirs.sort()
        
        # Iterate through range directories (limit for performance)
        dirs_to_process = range_dirs[:min(len(range_dirs), 10)]  # Limit to 10 range directories max
        
        for i, range_dir in enumerate(dirs_to_process):
            if len(year_vulns) >= target_count:
                break
                
            range_path = os.path.join(year_path, range_dir)
            
            # Get NVD files and sort them
            nvd_files = [f for f in os.listdir(range_path) if f.endswith('.json')]
            
            if self.bias_recent:
                nvd_files.sort(reverse=True)
            else:
                nvd_files.sort()
            
            # Process individual NVD JSON files (limit processing for performance)
            files_to_process = nvd_files[:min(len(nvd_files), target_count * 2)]  # Limit file processing
            
            for nvd_file in files_to_process:
                if len(year_vulns) >= target_count:
                    break
                    
                nvd_path = os.path.join(range_path, nvd_file)
                
                try:
                    with open(nvd_path, 'r', encoding='utf-8') as f:
                        nvd_data = json.load(f)
                        
                    # Skip rejected vulnerabilities
                    if nvd_data.get('vulnStatus') == 'Rejected':
                        continue
                        
                    cve_id = nvd_data.get('id', '')
                    if not cve_id:
                        continue
                    
                    # Extract CVSS score and severity
                    base_score = 0.0
                    severity = 'UNKNOWN'
                    description = ''
                    
                    metrics = nvd_data.get('metrics', {})
                    
                    # Try CVSS v3.1 first
                    cvss_v31 = metrics.get('cvssMetricV31', [])
                    if cvss_v31 and len(cvss_v31) > 0:
                        cvss_data = cvss_v31[0].get('cvssData', {})
                        base_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    # Try CVSS v4.0 if available
                    elif metrics.get('cvssMetricV40', []):
                        cvss_v40 = metrics.get('cvssMetricV40', [])
                        if cvss_v40 and len(cvss_v40) > 0:
                            cvss_data = cvss_v40[0].get('cvssData', {})
                            base_score = cvss_data.get('baseScore', 0.0)
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    else:
                        # Fallback to CVSS v2.0
                        cvss_v2 = metrics.get('cvssMetricV2', [])
                        if cvss_v2 and len(cvss_v2) > 0:
                            cvss_data = cvss_v2[0].get('cvssData', {})
                            base_score = cvss_data.get('baseScore', 0.0)
                            severity = cvss_v2[0].get('baseSeverity', 'UNKNOWN')
                            
                            # If no severity in v2, derive from score
                            if not severity or severity == 'UNKNOWN':
                                if base_score >= 9.0:
                                    severity = 'CRITICAL'
                                elif base_score >= 7.0:
                                    severity = 'HIGH'
                                elif base_score >= 4.0:
                                    severity = 'MEDIUM'
                                else:
                                    severity = 'LOW'
                    
                    # Extract description
                    descriptions = nvd_data.get('descriptions', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    year_vulns.append({
                        'id': cve_id,
                        'severity': severity,
                        'base_score': base_score,
                        'description': description,
                        'year': year
                    })
                    
                except Exception as e:
                    # Skip malformed files
                    continue
        
        return year_vulns
    


    def generate_findings(self, 
                         num_findings: int = 0,
                         detection_probability: float = 0.7,
                         false_positive_rate: float = 0.1) -> List[Dict[str, Any]]:
        if num_findings == 0:
            num_findings = self.num_findings
            
        if not self.assets:
            raise ValueError("No assets loaded")

        findings = []
        base_timestamp = datetime.now() - timedelta(days=30)
        
        # Pull from available vulns
        available_vulns = self.vulnerabilities

        # Generate findings until the requested number
        while len(findings) < num_findings:
            # Randomly select an asset
            asset = random.choice(self.assets)
            
            # Determine if this is a true finding or false positive
            is_false_positive = random.random() < false_positive_rate

            # Only proceed if detection probability check passes
            if random.random() < detection_probability:
                finding = {
                    "finding_id": str(uuid.uuid4()),
                    "asset_uuid": asset["uuid"],
                    "timestamp": (base_timestamp + timedelta(
                        days=random.randint(0, 30),
                        hours=random.randint(0, 23),
                        minutes=random.randint(0, 59)
                    )).isoformat(),
                    "detection_tool": random.choice(self.detection_tools),
                    "is_false_positive": is_false_positive
                }

                if available_vulns:
                    cve = random.choice(available_vulns)
                    finding.update({
                        "cve_id": cve["id"],
                        "severity": cve["severity"],
                        "base_score": cve["base_score"],
                        "description": cve.get("description", "")
                    })
                else:
                    # Fallback if no vulnerabilities available
                    finding.update({
                        "cve_id": "CVE-0000-0000",
                        "severity": "UNKNOWN",
                        "base_score": 0.0,
                        "description": "Sample vulnerability"
                    })

                findings.append(finding)

        return findings

    def save_findings(self, findings: List[Dict[str, Any]], output_file: str = ''):
        """Save findings to JSON file"""
        # Use config default if no output file specified
        if not output_file:
            output_file = self.config.get('default_paths', {}).get('findings_output', 'data/raw/findings.json')
        
        # Create directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir:  # Only create directory if path is not empty
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        
        print(f"Generated {len(findings)} findings and saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Generate vulnerability findings')
    parser.add_argument('--count', type=int, default=10, 
                       help='Number of findings to generate (default: 10)')
    parser.add_argument('--no-bias-recent', action='store_true', 
                       help='Disable bias towards recent CVEs')
    parser.add_argument('--output', type=str, default='',
                       help='Output file path (uses config default if not specified)')
    parser.add_argument('--input-file', type=str, default='',
                       help='Input asset file path (JSON, CSV, or SQLite database). Supports .json, .csv, .db, .sqlite extensions')
    args = parser.parse_args()
    
    generator = FindingsGenerator(
        asset_file=args.input_file,
        num_findings=args.count,
        bias_recent=not args.no_bias_recent
    )
    findings = generator.generate_findings(
        num_findings=args.count,
        detection_probability=0.7,
        false_positive_rate=0.1
    )
    generator.save_findings(findings, args.output)
    
    # Statistics
    print("\n" + "=" * 60)
    print(f"FINDINGS GENERATION STATISTICS (Total: {len(findings)} findings)")
    print("=" * 60)
    if findings:
        cve_years = []
        for finding in findings:
            cve_id = finding.get('cve_id', '')
            if '-' in cve_id:
                try:
                    year = int(cve_id.split('-')[1])
                    cve_years.append(year)
                except ValueError:
                    pass
        
        if cve_years:
            print(f"CVE year range: {min(cve_years)} - {max(cve_years)}")
            print(f"Average CVE year: {sum(cve_years) / len(cve_years):.1f}")
            recent_count = sum(1 for year in cve_years if year >= 2020)
            print(f"Recent CVEs (2020+): {recent_count}/{len(cve_years)} ({recent_count/len(cve_years)*100:.1f}%)")

if __name__ == "__main__":
    main()