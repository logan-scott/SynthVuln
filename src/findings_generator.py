import argparse
import csv
import json
import os
import random
import re
import sqlite3
import time
import uuid
import yaml
from datetime import datetime, timedelta
from typing import List, Dict, Any
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from utils.util import setup_logging, load_config

class FindingsGenerator:
    """Generator for synthetic vulnerability findings.
    
    This class generates realistic vulnerability findings for testing and simulation purposes.
    It supports multiple input/output formats (JSON, CSV, SQL) and provides configurable
    vulnerability detection scenarios.
    
    Attributes:
        _vulnerability_cache: Class-level cache for vulnerability data
        _cache_timestamp: Timestamp of cached vulnerability data
    """
    _vulnerability_cache = None
    _cache_timestamp = None
    
    def __init__(self, config_file: str = "configs/generator_config.yaml"):
        """Initialize the FindingsGenerator.
        
        Args:
            config_file: Path to YAML configuration file containing generator settings
        """
        self.logger = setup_logging('findings_generator.log', __name__)
        self.config = load_config(config_file, self.logger, use_fallback=True)
        self._initialize_settings()
        
    def _initialize_settings(self):
        """
        Initialize all settings and load required data.
        
        Loads configuration for detection tools, severity weights, recent bias settings,
        vulnerability count ranges, and performance settings from the configuration file.
        """
        # Set random seed for reproducible output if specified
        random_seed = self.config.get('random_seed')
        if random_seed is not None:
            random.seed(random_seed)
            self.logger.info(f"Random seed set to {random_seed} for reproducible output")
        else:
            self.logger.info("No random seed specified, using random generation")
        
        self.default_paths = self.config.get('default_paths', {})
        
        # Load findings-specific configuration
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
        
        # Load performance configuration
        perf_config = self.config.get('performance_config', {})
        self.cache_duration = perf_config.get('cache_duration_seconds', 3600)
        self.max_directory_depth = perf_config.get('max_directory_scan_depth', 10)
        self.progress_interval = perf_config.get('progress_report_interval', 100)
        self.max_unique_vulns = findings_config.get('max_unique_vulns', 5000)
        self.vuln_batch_size = perf_config.get('vuln_processing_batch_size', 500)
        self.max_retries = perf_config.get('max_retries', 3)
        
        # Load vulnerability reintroduction configuration
        self.reintroduction_config = findings_config.get('reintroduction', {
            'probability': 0.15, 'min_gap_days': 30, 'max_gap_days': 365
        })
        
        # Load CPE configuration and mapping
        self._load_cpe_configuration()
        
    def _load_cpe_configuration(self):
        """Load CPE configuration and mapping for vulnerability matching."""
        self.cpe_config = self.config.get('cpe_config', {})
        self.cpe_mapping = None
        
        # Check if CPE-based vulnerability matching is enabled
        cpe_vuln_config = self.cpe_config.get('cpe_based_vulnerability_matching', {})
        if not cpe_vuln_config.get('enabled', False):
            self.logger.info("CPE-based vulnerability matching is disabled")
            return
        
        # Load CPE mapping file
        cpe_mapping_path = self.default_paths.get('cpe_mapping_config')
        if not cpe_mapping_path:
            self.logger.warning("CPE mapping config path not found in configuration")
            return
        
        try:
            with open(cpe_mapping_path, 'r', encoding='utf-8') as f:
                self.cpe_mapping = json.load(f)
            self.logger.info(f"Successfully loaded CPE mapping from {cpe_mapping_path}")
            
            # Log CPE mapping statistics
            if self.cpe_mapping:
                cpe_count = len(self.cpe_mapping.get('cpe_index', {}))
                self.logger.info(f"CPE mapping loaded with {cpe_count} CPEs")
                
        except FileNotFoundError:
            self.logger.warning(f"CPE mapping file not found: {cpe_mapping_path}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing CPE mapping JSON: {e}")
        except Exception as e:
            self.logger.error(f"Error loading CPE mapping: {e}")
        
    def initialize_for_generation(self, asset_file: str = '', num_findings: int = 10, bias_recent: bool = True):
        """Initialize generator for findings generation with specific parameters.
        
        Args:
            asset_file: Path to asset file (JSON, CSV, or SQL). Uses config default if empty
            num_findings: Number of findings to generate
            bias_recent: Whether to bias selection toward recent vulnerabilities
        """
        self.num_findings = num_findings
        self.bias_recent = bias_recent
        
        # Use config default if no asset file specified
        self.asset_file = asset_file if asset_file else self.default_paths.get('asset_output', 'data/outputs/assets.json')
        
        self.assets = self._load_assets()
        self.vulnerabilities = self._load_vulnerabilities()

    def _load_assets(self) -> List[Dict[str, Any]]:
        """Load assets from file, auto-detecting format based on extension.
        
        Returns:
            List of asset dictionaries loaded from the specified file
            
        Raises:
            Logs errors for file not found, permission denied, or other exceptions
        """
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
                self.logger.warning(f"Unknown file extension '{file_ext}', attempting JSON format...")
                return self._load_assets_json()
        except FileNotFoundError:
            self.logger.error(f"Asset file not found: {self.asset_file}")
            return []
        except PermissionError:
            self.logger.error(f"Permission denied accessing asset file: {self.asset_file}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error loading assets from {self.asset_file}: {e}")
            return []
    
    def _load_assets_json(self) -> List[Dict[str, Any]]:
        """Load assets from JSON file.
        
        Returns:
            List of asset dictionaries parsed from JSON file
            
        Raises:
            Logs JSONDecodeError for invalid JSON or other file reading errors
        """
        try:
            with open(self.asset_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in asset file {self.asset_file}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error loading assets from JSON {self.asset_file}: {e}")
            return []
    
    def _load_assets_csv(self) -> List[Dict[str, Any]]:
        """Load assets from CSV file.
        
        Converts CSV rows back to asset dictionary format, handling type conversions
        for boolean fields, lists, and numeric values.
        
        Returns:
            List of asset dictionaries converted from CSV rows
            
        Raises:
            Logs warnings for malformed rows and errors for file reading issues
        """
        assets = []
        try:
            with open(self.asset_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row_num, row in enumerate(reader, start=2):  # Start at 2 to account for header
                    try:
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
                            'location': row['location'],
                            'cloud_provider': row.get('cloud_provider') if row.get('cloud_provider') else None
                        }
                        assets.append(asset)
                    except (KeyError, ValueError) as e:
                        self.logger.warning(f"Error processing CSV row {row_num} in {self.asset_file}: {e}")
                        continue
        except Exception as e:
            self.logger.error(f"Error reading CSV asset file {self.asset_file}: {e}")
            return []
        return assets
    
    def _load_assets_sql(self) -> List[Dict[str, Any]]:
        """Load assets from SQL database or script file.
        
        Supports both SQLite database files (.db, .sqlite) and SQL script files (.sql)
        containing INSERT statements.
        
        Returns:
            List of asset dictionaries loaded from SQL source
            
        Raises:
            Logs database connection errors, SQL execution errors, and parsing errors
        """
        assets = []
        
        # Check if it's a SQLite database file
        if self.asset_file.endswith('.db') or self.asset_file.endswith('.sqlite'):
            try:
                conn = sqlite3.connect(self.asset_file)
                conn.row_factory = sqlite3.Row  # Enable column access by name
                cursor = conn.cursor()
                
                try:
                    cursor.execute("SELECT * FROM assets")
                    rows = cursor.fetchall()
                    
                    for i, row in enumerate(rows):
                        try:
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
                                'location': row['location'],
                                'cloud_provider': row.get('cloud_provider') if row.get('cloud_provider') and row.get('cloud_provider') != 'NULL' else None
                            }
                            assets.append(asset)
                        except (KeyError, ValueError, TypeError) as e:
                            self.logger.warning(f"Error processing SQL row {i+1} in {self.asset_file}: {e}")
                            continue
                except sqlite3.Error as e:
                    self.logger.error(f"Database error reading assets from {self.asset_file}: {e}")
                    return []
                finally:
                    conn.close()
            except sqlite3.Error as e:
                self.logger.error(f"Error connecting to SQLite database {self.asset_file}: {e}")
                return []
        else:
            try:
                with open(self.asset_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Parse INSERT statements (handle both formats: with and without column names)
                insert_pattern = r"INSERT INTO assets(?:\s+\([^)]+\))?\s+VALUES\s+\(([^)]+)\);"
                matches = re.findall(insert_pattern, content, re.IGNORECASE)
                
                for i, match in enumerate(matches):
                    try:
                        # Parse values from SQL INSERT
                        values = [v.strip().strip("'") for v in match.split(',')]
                        if len(values) >= 13:  # Ensure we have all required fields
                            asset = {
                                'uuid': values[0],
                                'domain_name': values[1],
                                'hostname': values[2],
                                'user_accounts': values[3].split(';') if values[3] else [],
                                'privileged_user_accounts': values[4].split(';') if values[4] else [],
                                'type': values[5],
                                'os_family': values[6] if len(values) > 16 else 'Unknown',
                                'os_version': values[7] if len(values) > 16 else 'Unknown',
                                'lifecycle_stage': values[8] if len(values) > 16 else 'Production',
                                'internet_exposed': values[9 if len(values) > 16 else 6].lower() == 'true',
                                'public_ip': values[10 if len(values) > 16 else 7] if values[10 if len(values) > 16 else 7] != 'NULL' else None,
                                'internal_ip': values[11 if len(values) > 16 else 8],
                                'open_ports': [int(p) for p in values[12 if len(values) > 16 else 9].split(';')] if values[12 if len(values) > 16 else 9] else [],
                                'endpoint_security_installed': values[13 if len(values) > 16 else 10].lower() == 'true',
                                'local_firewall_active': values[14 if len(values) > 16 else 11].lower() == 'true',
                                'location': values[15 if len(values) > 16 else 12],
                                'cloud_provider': values[16] if len(values) > 16 and values[16] != 'NULL' else None
                            }
                            assets.append(asset)
                        else:
                            self.logger.warning(f"Insufficient fields in SQL INSERT statement {i+1} in {self.asset_file}")
                    except (ValueError, IndexError) as e:
                        self.logger.warning(f"Error parsing SQL INSERT statement {i+1} in {self.asset_file}: {e}")
                        continue
            except Exception as e:
                self.logger.error(f"Error reading SQL script file {self.asset_file}: {e}")
                return []
        
        return assets
    

    
    def _load_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Load vulnerabilities from data sources using caching and optimized approach.
        
        Uses class-level caching to avoid reloading vulnerability data within 1 hour.
        Falls back to sample CVEs if NVD data is unavailable.
        
        Returns:
            List of vulnerability dictionaries with id, severity, base_score, description, year
            
        Raises:
            Logs errors for data loading issues and uses fallback data
        """
        
        # Check if we have cached vulnerabilities (valid for 1 hour)
        current_time = time.time()
        if (FindingsGenerator._vulnerability_cache is not None and 
            FindingsGenerator._cache_timestamp is not None and 
            current_time - FindingsGenerator._cache_timestamp < 3600):  # 1 hour cache
            self.logger.info(f"Using cached vulnerabilities ({len(FindingsGenerator._vulnerability_cache)} available)")
            return FindingsGenerator._vulnerability_cache
        
        try:
            self.logger.info("Loading vulnerability data...")
            
            # Load NVD data using streaming approach
            nvd_base = self.config.get('default_paths', {}).get('nvd_data_dir', 'data/inputs/nvd')
            vulnerabilities = self._stream_nvd_vulnerabilities(nvd_base)
            
            # Cache the results
            FindingsGenerator._vulnerability_cache = vulnerabilities
            FindingsGenerator._cache_timestamp = current_time
            
            self.logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from NVD database")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error loading vulnerabilities: {e}")
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
        """Stream NVD vulnerabilities without loading entire dataset into memory.
        
        First checks for flat JSON file format (nvd_vulnerabilities.json), then
        processes vulnerabilities year by year, applying recent bias if configured.
        Limits total vulnerabilities loaded for performance.
        
        Args:
            nvd_base: Base directory path containing NVD data organized by year
            
        Returns:
            List of vulnerability dictionaries up to configured maximum
        """
        vulnerabilities = []
        
        if not os.path.exists(nvd_base):
            self.logger.warning(f"Warning: NVD database path not found: {nvd_base}")
            return vulnerabilities
        
        # First, check for flat JSON file format (from our NVD integration)
        nvd_json_file = os.path.join(nvd_base, 'nvd_vulnerabilities.json')
        if os.path.exists(nvd_json_file):
            try:
                with open(nvd_json_file, 'r', encoding='utf-8') as f:
                    flat_vulnerabilities = json.load(f)
                self.logger.info(f"Loaded {len(flat_vulnerabilities)} vulnerabilities from flat JSON file")
                return flat_vulnerabilities
            except Exception as e:
                self.logger.warning(f"Error loading flat JSON file {nvd_json_file}: {e}")
                # Continue to directory-based approach
        
        # Get all year directories and sort them in reverse order (newest first)
        year_dirs = [d for d in os.listdir(nvd_base) if d.startswith('CVE-') and os.path.isdir(os.path.join(nvd_base, d))]
        year_dirs.sort(reverse=True)
        
        if not year_dirs:
            self.logger.warning("No CVE year directories found")
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
        
        # Stream vulnerabilities from each year
        for year_dir in year_dirs:
            if len(vulnerabilities) >= target_total:
                break
                
            year_target = target_per_year.get(year_dir, 0)
            if year_target == 0:
                continue
                
            year_vulns = self._stream_year_vulnerabilities(nvd_base, year_dir, year_target)
            vulnerabilities.extend(year_vulns)
        
        self.logger.info(f"Streaming vulnerabilities completed: {len(year_dirs)}/{len(year_dirs)} items - Completed streaming {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities[:target_total]
    
    def _calculate_year_weights(self, year_dirs: List[str]) -> Dict[str, float]:
        """Calculate weights for each year based on recency.
        
        Assigns higher weights to more recent years for biased vulnerability selection.
        Uses configuration settings or defaults for weight distribution.
        
        Args:
            year_dirs: List of year directory names (e.g., ['CVE-2023', 'CVE-2022'])
            
        Returns:
            Dictionary mapping year directories to their selection weights
        """
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
        """Distribute target counts across years based on weights.
        
        Converts relative weights to absolute target counts for each year,
        ensuring at least 1 vulnerability per year if possible.
        
        Args:
            year_weights: Dictionary mapping year directories to selection weights
            target_total: Total number of vulnerabilities to distribute
            
        Returns:
            Dictionary mapping year directories to target vulnerability counts
        """
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
        """Stream vulnerabilities from a specific year directory.
        
        Processes JSON files within a year directory to extract vulnerability data,
        randomly sampling up to the target count.
        
        Args:
            nvd_base: Base directory path containing NVD data
            year_dir: Specific year directory name (e.g., 'CVE-2023')
            target_count: Maximum number of vulnerabilities to extract from this year
            
        Returns:
            List of vulnerability dictionaries from the specified year
        """
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
        dirs_to_process = range_dirs[:min(len(range_dirs), self.max_directory_depth)]  # Use configured directory limit
        
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
                    
                    # Extract CPE information from configurations
                    cpes = []
                    configurations = nvd_data.get('configurations', [])
                    for config in configurations:
                        nodes = config.get('nodes', [])
                        for node in nodes:
                            cpe_match_list = node.get('cpeMatch', [])
                            for cpe_match in cpe_match_list:
                                cpe_criteria = cpe_match.get('criteria', '')
                                if cpe_criteria and cpe_match.get('vulnerable', False):
                                    cpes.append(cpe_criteria)
                    
                    year_vulns.append({
                        'id': cve_id,
                        'severity': severity,
                        'base_score': base_score,
                        'description': description,
                        'year': year,
                        'cpes': cpes
                    })
                    
                except FileNotFoundError:
                    self.logger.warning(f"Vulnerability file not found: {nvd_path}")
                    continue
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Invalid JSON in vulnerability file {nvd_path}: {e}")
                    continue
                except KeyError as e:
                    self.logger.warning(f"Missing required field in vulnerability file {nvd_path}: {e}")
                    continue
                except Exception as e:
                    self.logger.error(f"Unexpected error processing vulnerability file {nvd_path}: {e}")
                    continue
        
        return year_vulns

    def generate_findings(self, 
                         num_findings: int = 0,
                         detection_probability: float = 0.7,
                         false_positive_rate: float = 0.1) -> List[Dict[str, Any]]:
        """Generate synthetic vulnerability findings for loaded assets.
        
        Creates realistic findings by randomly selecting assets and vulnerabilities,
        applying detection probability and false positive rates.
        
        Args:
            num_findings: Number of findings to generate (0 uses instance default)
            detection_probability: Probability of detecting a real vulnerability (0.0-1.0)
            false_positive_rate: Rate of false positive findings (0.0-1.0)
            
        Returns:
            List of finding dictionaries with asset, vulnerability, and detection metadata
            
        Raises:
            ValueError: If no assets are loaded
        """
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
                    "detection_tool": random.choice(self.detection_tools),
                    "is_false_positive": is_false_positive
                }

                # Try CPE-based vulnerability matching first
                cpe_vulns = self._get_cpe_based_vulnerabilities(asset)
                
                if cpe_vulns and not is_false_positive:
                    # Use CPE-matched vulnerability
                    cve = random.choice(cpe_vulns)
                    finding["cpe_matched"] = True
                    self.logger.debug(f"Using CPE-matched vulnerability {cve['id']} for asset {asset['uuid']}")
                elif available_vulns:
                    # Fall back to random vulnerability selection
                    cve = random.choice(available_vulns)
                    finding["cpe_matched"] = False
                else:
                    cve = None
                
                if cve:
                    finding.update({
                        "cve_id": cve["id"],
                        "severity": cve["severity"],
                        "base_score": cve["base_score"],
                        "description": cve.get("description", "")
                    })
                    
                    # Extract CVE year from CVE ID (format: CVE-YYYY-NNNN)
                    cve_year = 2020  # Default fallback year
                    try:
                        if cve["id"].startswith("CVE-"):
                            year_part = cve["id"].split("-")[1]
                            cve_year = int(year_part)
                    except (IndexError, ValueError):
                        pass  # Use default year if parsing fails
                    
                    # Generate the three timestamps
                    timestamps = self._generate_timestamps(cve_year, base_timestamp)
                    finding.update(timestamps)
                else:
                    # Fallback if no vulnerabilities available
                    finding.update({
                        "cve_id": "CVE-0000-0000",
                        "severity": "UNKNOWN",
                        "base_score": 0.0,
                        "description": "Sample vulnerability"
                    })
                    
                    # Generate timestamps with default year
                    timestamps = self._generate_timestamps(2020, base_timestamp)
                    finding.update(timestamps)

                findings.append(finding)

        self.logger.info(f"Findings generation completed: {len(findings)}/{num_findings} items - Generated {len(findings)} findings")
        return findings
    
    def _get_cpe_based_vulnerabilities(self, asset: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get vulnerabilities that match the asset's installed software CPEs.
        
        Args:
            asset: Asset dictionary containing installed software with CPE information
            
        Returns:
            List of vulnerabilities that match the asset's software CPEs
        """
        if not self.cpe_mapping or not self.cpe_config.get('cpe_based_vulnerability_matching', {}).get('enabled', False):
            return []
        
        # Extract CPEs from asset's installed software
        asset_cpes = set()
        installed_software = asset.get('installed_software', [])
        
        for software in installed_software:
            cpe = software.get('cpe')
            if cpe:
                asset_cpes.add(cpe)
        
        if not asset_cpes:
            return []
        
        # Find vulnerabilities that match these CPEs
        matching_vulns = []
        cpe_vuln_config = self.cpe_config.get('cpe_based_vulnerability_matching', {})
        max_vulns_per_asset = cpe_vuln_config.get('max_vulnerabilities_per_asset', 20)
        
        for vuln in self.vulnerabilities:
            # Check if vulnerability has CPE information (handle both formats)
            vuln_cpes = vuln.get('cpes', [])
            cpe_matches = vuln.get('cpe_matches', [])
            
            # Extract CPE criteria from cpe_matches if cpes is empty
            if not vuln_cpes and cpe_matches:
                vuln_cpes = [match.get('criteria', '') for match in cpe_matches if match.get('vulnerable', False)]
            
            if not vuln_cpes:
                continue
            
            # Check for CPE matches
            for vuln_cpe in vuln_cpes:
                if vuln_cpe and self._cpe_matches_asset(vuln_cpe, asset_cpes):
                    matching_vulns.append(vuln)
                    break  # Found a match, no need to check other CPEs for this vuln
            
            # Limit the number of vulnerabilities per asset
            if len(matching_vulns) >= max_vulns_per_asset:
                break
        
        return matching_vulns
    
    def _cpe_matches_asset(self, vuln_cpe: str, asset_cpes: set) -> bool:
        """Check if a vulnerability CPE matches any of the asset's CPEs.
        
        Args:
            vuln_cpe: CPE string from vulnerability
            asset_cpes: Set of CPE strings from asset's installed software
            
        Returns:
            True if there's a match, False otherwise
        """
        # Direct match
        if vuln_cpe in asset_cpes:
            return True
        
        # Parse CPE components for partial matching
        try:
            vuln_parts = self._parse_cpe(vuln_cpe)
            
            for asset_cpe in asset_cpes:
                asset_parts = self._parse_cpe(asset_cpe)
                
                # Check if vendor and product match (ignore version for broader matching)
                if (vuln_parts.get('vendor') == asset_parts.get('vendor') and
                    vuln_parts.get('product') == asset_parts.get('product')):
                    
                    # Apply version matching logic
                    if self._version_matches(vuln_parts.get('version', ''), asset_parts.get('version', '')):
                        return True
        
        except Exception:
            # If parsing fails, fall back to string comparison
            pass
        
        return False
    
    def _parse_cpe(self, cpe_string: str) -> Dict[str, str]:
        """Parse CPE string into components.
        
        Args:
            cpe_string: CPE string to parse
            
        Returns:
            Dictionary with CPE components
        """
        # Simple CPE parsing for cpe:2.3:a:vendor:product:version format
        parts = cpe_string.split(':')
        if len(parts) >= 6:
            return {
                'vendor': parts[3] if parts[3] != '*' else '',
                'product': parts[4] if parts[4] != '*' else '',
                'version': parts[5] if parts[5] != '*' else '',
            }
        return {}
    
    def _version_matches(self, vuln_version: str, asset_version: str) -> bool:
        """Check if vulnerability version affects the asset version.
        
        Args:
            vuln_version: Version from vulnerability CPE
            asset_version: Version from asset software
            
        Returns:
            True if the asset version is affected by the vulnerability
        """
        if not vuln_version or not asset_version:
            return True  # If version info is missing, assume match
        
        if vuln_version == '*' or asset_version == '*':
            return True  # Wildcard matches all
        
        # For now, use exact match or wildcard
        # This could be enhanced with version range checking
        return vuln_version == asset_version or vuln_version == '*'
    
    def _generate_timestamps(self, cve_year: int, base_timestamp: datetime) -> Dict[str, str]:
        """Generate the three timestamp fields for a vulnerability finding.
        
        Args:
            cve_year: The year the CVE was published
            base_timestamp: Base timestamp for generation
            
        Returns:
            Dictionary containing absolute_first_detected, first_detected, and last_detected timestamps
        """
        # Ensure absolute_first_detected is never before CVE year
        cve_start_date = datetime(cve_year, 1, 1)
        earliest_detection = max(cve_start_date, base_timestamp - timedelta(days=365))
        
        # Generate absolute_first_detected (when vulnerability was very first detected)
        absolute_first_detected = earliest_detection + timedelta(
            days=random.randint(0, 180),  # Within 6 months of CVE or base timestamp
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Determine if this is a reintroduced vulnerability
        is_reintroduced = random.random() < self.reintroduction_config['probability']
        
        if is_reintroduced:
            # Generate first_detected after a gap (vulnerability was remediated and reintroduced)
            gap_days = random.randint(
                self.reintroduction_config['min_gap_days'],
                self.reintroduction_config['max_gap_days']
            )
            first_detected = absolute_first_detected + timedelta(
                days=gap_days,
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
        else:
            # first_detected is the same as absolute_first_detected
            first_detected = absolute_first_detected
        
        # Generate last_detected (very high likelihood of being today's date)
        # 90% chance it's today (same day as base_timestamp), 10% chance it's within last 3 days
        if random.random() < 0.9:
            # Today's detection (same day as base_timestamp)
            days_ago = 0
        else:
            # Recent detection (within last 3 days)
            days_ago = random.randint(1, 3)
            
        last_detected = base_timestamp - timedelta(
            days=days_ago,
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Ensure last_detected is not before first_detected
        if last_detected < first_detected:
            last_detected = first_detected + timedelta(
                days=random.randint(1, 30),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
        
        return {
            "absolute_first_detected": absolute_first_detected.isoformat(),
            "first_detected": first_detected.isoformat(),
            "last_detected": last_detected.isoformat()
        }

    def save_findings(self, findings: List[Dict[str, Any]], output_file: str = '', output_format: str = 'json'):
        """Save findings to file in specified format.
        
        Supports JSON, CSV, and SQL output formats with automatic directory creation.
        
        Args:
            findings: List of finding dictionaries to save
            output_file: Output file path (uses config default if empty)
            output_format: Output format ('json', 'csv', or 'sql')
            
        Raises:
            ValueError: If output format is not supported
        """
        # Use config default if no output file specified
        if not output_file:
            output_file = self.config.get('default_paths', {}).get('findings_output', 'data/outputs/findings.json')
        
        # Create directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir:  # Only create directory if path is not empty
            os.makedirs(output_dir, exist_ok=True)
        
        if output_format.lower() == "json":
            self._save_as_json(findings, output_file)
        elif output_format.lower() == "csv":
            self._save_as_csv(findings, output_file)
        elif output_format.lower() == "sql":
            self._save_as_sql(findings, output_file)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        print(f"Generated {len(findings)} findings and saved to {output_file} ({output_format.upper()} format)")
    
    def _save_as_json(self, findings: List[Dict[str, Any]], output_file: str):
        """Save findings as JSON format.
        
        Args:
            findings: List of finding dictionaries to save
            output_file: Path to output JSON file
        """
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
    
    def _save_as_csv(self, findings: List[Dict[str, Any]], output_file: str):
        """Save findings as CSV format.
        
        Flattens nested finding data and sanitizes text fields for CSV compatibility.
        
        Args:
            findings: List of finding dictionaries to save
            output_file: Path to output CSV file
        """
        if not findings:
            return
        
        # Flatten the data for CSV export
        flattened_findings = []
        for finding in findings:
            flattened = {
                'finding_id': finding['finding_id'],
                'asset_uuid': finding['asset_uuid'],
                'absolute_first_detected': finding.get('absolute_first_detected', ''),
                'first_detected': finding.get('first_detected', ''),
                'last_detected': finding.get('last_detected', ''),
                'detection_tool': finding['detection_tool'],
                'is_false_positive': finding['is_false_positive'],
                'cve_id': finding.get('cve_id', ''),
                'severity': finding.get('severity', ''),
                'base_score': finding.get('base_score', 0.0),
                'description': finding.get('description', '').replace('\n', ' ').replace('\r', '')
            }
            flattened_findings.append(flattened)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=flattened_findings[0].keys())
            writer.writeheader()
            writer.writerows(flattened_findings)
    
    def _save_as_sql(self, findings: List[Dict[str, Any]], output_file: str):
        """Save findings as SQL INSERT statements.
        
        Generates CREATE TABLE statement followed by INSERT statements for all findings.
        
        Args:
            findings: List of finding dictionaries to save
            output_file: Path to output SQL file
        """
        if not findings:
            return
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write table creation statement
            f.write("-- Vulnerability findings table\n")
            f.write("CREATE TABLE IF NOT EXISTS findings (\n")
            f.write("    finding_id VARCHAR(36) PRIMARY KEY,\n")
            f.write("    asset_uuid VARCHAR(36),\n")
            f.write("    absolute_first_detected DATETIME,\n")
            f.write("    first_detected DATETIME,\n")
            f.write("    last_detected DATETIME,\n")
            f.write("    detection_tool VARCHAR(100),\n")
            f.write("    is_false_positive BOOLEAN,\n")
            f.write("    cve_id VARCHAR(20),\n")
            f.write("    severity VARCHAR(20),\n")
            f.write("    base_score DECIMAL(3,1),\n")
            f.write("    description TEXT\n")
            f.write(");\n\n")
            
            # Write INSERT statements
            f.write("-- Findings data\n")
            for finding in findings:
                description = finding.get('description', '').replace("'", "''")
                
                f.write(f"INSERT INTO findings VALUES (\n")
                f.write(f"    '{finding['finding_id']}',\n")
                f.write(f"    '{finding['asset_uuid']}',\n")
                f.write(f"    '{finding.get('absolute_first_detected', '')}',\n")
                f.write(f"    '{finding.get('first_detected', '')}',\n")
                f.write(f"    '{finding.get('last_detected', '')}',\n")
                f.write(f"    '{finding['detection_tool']}',\n")
                f.write(f"    {str(finding['is_false_positive']).lower()},\n")
                f.write(f"    '{finding.get('cve_id', '')}',\n")
                f.write(f"    '{finding.get('severity', '')}',\n")
                f.write(f"    {finding.get('base_score', 0.0)},\n")
                f.write(f"    '{description}'\n")
                f.write(");\n")

def main():
    """Main entry point for the findings generator CLI.
    
    Parses command line arguments and orchestrates the findings generation process.
    Supports configurable output formats, input sources, and generation parameters.
    
    Command line options:
        --count: Number of findings to generate
        --no-bias-recent: Disable bias towards recent CVEs
        --output: Output file path
        --output-format: Output format (json, csv, sql)
        --input: Input asset file path
    """
    parser = argparse.ArgumentParser(description='Generate vulnerability findings')
    parser.add_argument('--count', type=int, default=10, 
                       help='Number of findings to generate (default: 10)')
    parser.add_argument('--no-bias-recent', action='store_true', 
                       help='Disable bias towards recent CVEs')
    parser.add_argument('--output', type=str, default='',
                       help='Output file path (uses config default if not specified)')
    parser.add_argument('--output-format', type=str, choices=['json', 'csv', 'sql'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--input', type=str, default='',
                       help='Input asset file path (JSON, CSV, or SQLite database). Supports .json, .csv, .db, .sqlite extensions')
    args = parser.parse_args()
    
    generator = FindingsGenerator()
    generator.initialize_for_generation(
        asset_file=args.input,
        num_findings=args.count,
        bias_recent=not args.no_bias_recent
    )
    
    # Use config default if no output specified, but adjust extension based on format
    if args.output:
        output_file = args.output
    else:
        default_output = generator.config.get('default_paths', {}).get('findings_output', 'data/outputs/findings.json')
        # Change extension based on format
        if args.output_format == 'csv':
            output_file = default_output.replace('.json', '.csv')
        elif args.output_format == 'sql':
            output_file = default_output.replace('.json', '.sql')
        else:
            output_file = default_output
    
    findings = generator.generate_findings(
        num_findings=args.count,
        detection_probability=0.7,
        false_positive_rate=0.1
    )
    generator.save_findings(findings, output_file, args.output_format)
    
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