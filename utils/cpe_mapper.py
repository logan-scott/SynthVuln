#!/usr/bin/env python3
"""
CPE Mapper Utility

Reads NVD CPE data and generates a mapping configuration file for asset generation.
Maps CPEs to asset types based on OS families and system types.
"""

import argparse
import json
import os
import re
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.util import setup_logging, load_config

class CPEMapper:
    """Maps NVD CPEs to asset types and generates configuration files."""
    
    def __init__(self, config_path: str):
        """Initialize the CPE mapper with configuration.
        
        Args:
            config_path: Path to the generator configuration file
        """
        self.logger = setup_logging('cpe_mapper.log', __name__)
        self.config = load_config(config_path, self.logger)
        self._initialize_settings()
    
    def _initialize_settings(self):
        """Initialize settings from configuration."""
        cpe_config = self.config.get('cpe_mapper', {})
        
        # Default OS family keywords
        self.os_family_keywords = cpe_config.get('os_family_keywords', {
            'linux': ['linux', 'ubuntu', 'debian', 'centos', 'alpine', 'redhat', 'suse', 'fedora', 'rhel', 'opensuse', 'mint'],
            'windows': ['windows', 'microsoft', 'win', 'winnt', 'win32', 'win64'],
            'mac': ['mac', 'darwin', 'osx', 'macos', 'apple'],
            'unix': ['unix', 'solaris', 'aix', 'hpux', 'freebsd', 'openbsd', 'netbsd'],
            'embedded': ['embedded', 'firmware', 'rtos', 'iot'],
            'mobile': ['mobile', 'android', 'ios', 'iphone', 'ipad']
        })
        
        # Default system type keywords
        self.system_type_keywords = cpe_config.get('system_type_keywords', {
            'server': ['server', 'daemon', 'service', 'httpd', 'nginx', 'apache', 'database', 'mysql', 'postgresql', 'srv', 'svc'],
            'workstation': ['desktop', 'workstation', 'client', 'browser', 'office', 'editor', 'ide', 'viewer'],
            'network': ['router', 'switch', 'firewall', 'proxy', 'gateway', 'vpn', 'dns', 'dhcp'],
            'mobile': ['mobile', 'android', 'ios', 'phone', 'tablet', 'smartphone'],
            'application': ['app', 'application', 'software', 'program', 'tool', 'utility']
        })
        
        # Default tag keywords
        self.tag_keywords = cpe_config.get('tag_keywords', {
            'db': ['database', 'mysql', 'postgresql', 'oracle', 'mongodb', 'redis', 'sqlite', 'db'],
            'webserver': ['apache', 'nginx', 'httpd', 'iis', 'tomcat', 'jetty', 'lighttpd'],
            'runtime': ['java', 'python', 'node', 'php', 'ruby', 'dotnet', 'perl', 'go'],
            'crypto': ['openssl', 'crypto', 'ssl', 'tls', 'encryption', 'cipher'],
            'library': ['lib', 'library', 'framework', 'sdk', 'api'],
            'network': ['ftp', 'ssh', 'telnet', 'smtp', 'pop', 'imap', 'snmp'],
            'media': ['player', 'viewer', 'editor', 'codec', 'multimedia'],
            'security': ['antivirus', 'firewall', 'scanner', 'monitor', 'protection']
        })
        
        # Exclusion keywords
        self.exclusions = cpe_config.get('exclusions', [
            'test', 'demo', 'sample', 'example', 'deprecated'
        ])
        
        # Normalization map for common product names
        self.normalize_map = cpe_config.get('normalize_map', {
            'httpd': 'apache',
            'mysqld': 'mysql',
            'sshd': 'ssh'
        })
        
        self.min_confidence = cpe_config.get('min_confidence', 0.1)
        self.sample_limit = cpe_config.get('sample_limit', 50000)
    
    def _parse_cpe(self, cpe_string: str) -> Optional[Dict[str, str]]:
        """Parse a CPE string into components.
        
        Args:
            cpe_string: CPE 2.3 formatted string
            
        Returns:
            Dictionary with CPE components or None if invalid
        """
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        if not cpe_string.startswith('cpe:2.3:'):
            return None
        
        parts = cpe_string.split(':')
        if len(parts) < 6:
            return None
        
        def _get(idx: int) -> str:
            return parts[idx] if len(parts) > idx and parts[idx] else '*'
        
        return {
            'part': _get(2),
            'vendor': _get(3),
            'product': _get(4),
            'version': _get(5),
            'update': _get(6),
            'edition': _get(7),
            'language': _get(8),
            'sw_edition': _get(9),
            'target_sw': _get(10),
            'target_hw': _get(11),
            'other': _get(12)
        }
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for matching.
        
        Args:
            text: Text to normalize
            
        Returns:
            Normalized lowercase text
        """
        if not text or text == '*':
            return ''
        
        # Convert to lowercase and remove special characters
        normalized = re.sub(r'[^a-z0-9_]', '', text.lower())
        
        # Apply normalization map
        return self.normalize_map.get(normalized, normalized)
    
    def _extract_tokens(self, cpe_parts: Dict[str, str]) -> Set[str]:
        """Extract searchable tokens from CPE parts.
        
        Args:
            cpe_parts: Parsed CPE components
            
        Returns:
            Set of normalized tokens
        """
        tokens = set()
        
        # Consider a broader set of fields for token extraction
        fields = ['vendor', 'product', 'version', 'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other']
        for field in fields:
            value = cpe_parts.get(field, '')
            if value and value not in ('*', '-'):
                # Add full normalized token
                normalized = self._normalize_text(value)
                if normalized:
                    tokens.add(normalized)
                    # Split on underscores to add granular tokens
                    for part in normalized.split('_'):
                        if part:
                            tokens.add(part)
                # Also add original raw lower case
                tokens.add(value.lower())
        
        return tokens
    
    def _match_os_families(self, tokens: Set[str]) -> List[str]:
        """Match tokens against OS family keywords.
        
        Args:
            tokens: Set of tokens to match
            
        Returns:
            List of matching OS families
        """
        matches = []
        
        for os_family, keywords in self.os_family_keywords.items():
            for keyword in keywords:
                if keyword.lower() in tokens:
                    matches.append(os_family)
                    break
        
        return matches
    
    def _match_system_types(self, tokens: Set[str]) -> List[str]:
        """Match tokens against system type keywords.
        
        Args:
            tokens: Set of tokens to match
            
        Returns:
            List of matching system types
        """
        matches = []
        
        for system_type, keywords in self.system_type_keywords.items():
            for keyword in keywords:
                if keyword.lower() in tokens:
                    matches.append(system_type)
                    break
        
        return matches
    
    def _match_tags(self, tokens: Set[str]) -> List[str]:
        """Match tokens against tag keywords.
        
        Args:
            tokens: Set of tokens to match
            
        Returns:
            List of matching tags
        """
        matches = []
        
        for tag, keywords in self.tag_keywords.items():
            for keyword in keywords:
                if keyword.lower() in tokens:
                    matches.append(tag)
                    break
        
        return matches
    
    def _calculate_confidence(self, os_families: List[str], system_types: List[str], tags: List[str]) -> float:
        """Calculate confidence score based on matches.
        
        Args:
            os_families: List of matched OS families
            system_types: List of matched system types
            tags: List of matched tags
            
        Returns:
            Confidence score between 0 and 1
        """
        score = 0.15  # Base confidence for any valid CPE
        
        # OS family match adds significant confidence
        if os_families:
            score += 0.4
        
        # System type match adds moderate confidence
        if system_types:
            score += 0.3
        
        # Tags add minor confidence
        if tags:
            score += 0.15 * min(len(tags), 2)  # Cap at 2 tags
        
        return min(score, 1.0)
    
    def _should_exclude(self, tokens: Set[str]) -> bool:
        """Check if CPE should be excluded based on exclusion keywords.
        
        Args:
            tokens: Set of tokens to check
            
        Returns:
            True if CPE should be excluded
        """
        for exclusion in self.exclusions:
            if exclusion.lower() in tokens:
                return True
        return False
    
    def _process_cpe(self, cpe_string: str) -> Optional[Dict[str, Any]]:
        """Process a single CPE and extract metadata.
        
        Args:
            cpe_string: CPE string to process
            
        Returns:
            CPE metadata dictionary or None if excluded
        """
        # Parse CPE
        cpe_parts = self._parse_cpe(cpe_string)
        if not cpe_parts:
            return None
        
        # Extract tokens
        tokens = self._extract_tokens(cpe_parts)
        if not tokens:
            return None
        
        # Check exclusions
        if self._should_exclude(tokens):
            return None
        
        # Match against categories
        os_families = self._match_os_families(tokens)
        system_types = self._match_system_types(tokens)
        tags = self._match_tags(tokens)
        
        # Calculate confidence
        confidence = self._calculate_confidence(os_families, system_types, tags)
        
        # Filter by minimum confidence
        if confidence < self.min_confidence:
            return None
        
        return {
            'vendor': cpe_parts['vendor'],
            'product': cpe_parts['product'],
            'version': cpe_parts['version'] if cpe_parts['version'] != '*' else None,
            'os_families': os_families,
            'system_types': system_types,
            'tags': tags,
            'confidence': confidence,
            'canonical_tokens': list(tokens)
        }
    
    def _build_indexes(self, cpe_index: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Build secondary indexes for efficient lookup.
        
        Args:
            cpe_index: Main CPE index
            
        Returns:
            Dictionary containing various indexes
        """
        index_by_os = defaultdict(list)
        index_by_system_type = defaultdict(list)
        pools_by_asset_type = defaultdict(list)
        
        for cpe_string, metadata in cpe_index.items():
            # Index by OS family
            for os_family in metadata['os_families']:
                index_by_os[os_family].append(cpe_string)
            
            # Index by system type
            for system_type in metadata['system_types']:
                index_by_system_type[system_type].append(cpe_string)
            
            # Build asset type pools (combinations of OS and system type)
            for os_family in metadata['os_families']:
                for system_type in metadata['system_types']:
                    asset_key = f"{os_family}_{system_type}"
                    pools_by_asset_type[asset_key].append(cpe_string)
        
        return {
            'index_by_os': dict(index_by_os),
            'index_by_system_type': dict(index_by_system_type),
            'pools_by_asset_type': dict(pools_by_asset_type)
        }
    
    def build_mapping(self, nvd_cpes_path: str, output_path: str, force: bool = False, sample_limit: Optional[int] = None) -> None:
        """Build CPE mapping configuration file.
        
        Args:
            nvd_cpes_path: Path to NVD CPEs JSON file
            output_path: Path for output YAML file
            force: Whether to overwrite existing output file
            sample_limit: Maximum number of CPEs to process
        """
        # Check if output exists and force is not set
        if os.path.exists(output_path) and not force:
            self.logger.info(f"Output file {output_path} already exists. Use --force to overwrite.")
            return
        
        # Load NVD CPEs
        if not os.path.exists(nvd_cpes_path):
            self.logger.error(f"NVD CPEs file not found: {nvd_cpes_path}")
            raise FileNotFoundError(f"NVD CPEs file not found: {nvd_cpes_path}")
        
        self.logger.info(f"Loading CPEs from {nvd_cpes_path}")
        
        try:
            with open(nvd_cpes_path, 'r', encoding='utf-8') as f:
                nvd_data = json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading NVD CPEs: {e}")
            raise
        
        # Extract CPE list from NVD data
        if isinstance(nvd_data, list):
            cpe_list = nvd_data
        elif isinstance(nvd_data, dict) and 'cpes' in nvd_data:
            cpe_list = nvd_data['cpes']
        else:
            self.logger.error("Invalid NVD CPE data format")
            raise ValueError("Invalid NVD CPE data format")
        
        # Apply sample limit
        original_count = len(cpe_list)
        if sample_limit and len(cpe_list) > sample_limit:
            import random
            cpe_list = random.sample(cpe_list, sample_limit)
            self.logger.info(f"Sampling {sample_limit} CPEs from {original_count} total")
        else:
            self.logger.info(f"Processing all {original_count} CPEs (no sampling needed)")
        
        # Process CPEs
        self.logger.info(f"Processing {len(cpe_list)} CPEs")
        cpe_index = {}
        processed_count = 0
        excluded_count = 0
        
        for i, cpe_data in enumerate(cpe_list):
            if i % 1000 == 0:
                self.logger.info(f"Processed {i}/{len(cpe_list)} CPEs")
            
            # Extract CPE string
            if isinstance(cpe_data, str):
                cpe_string = cpe_data
            elif isinstance(cpe_data, dict):
                cpe_string = cpe_data.get('cpe23Uri') or cpe_data.get('cpeName') or cpe_data.get('cpe_name') or cpe_data.get('cpe')
                if not cpe_string and i < 5:  # Debug first few entries
                    self.logger.debug(f"CPE data keys: {list(cpe_data.keys())}")
            else:
                if i < 5:  # Debug first few entries
                    self.logger.debug(f"Unexpected CPE data type: {type(cpe_data)}")
                continue
            
            if not cpe_string:
                if i < 5:  # Debug first few entries
                    self.logger.debug(f"No CPE string found in: {cpe_data}")
                continue
            
            # Process CPE
            metadata = self._process_cpe(cpe_string)
            if metadata:
                cpe_index[cpe_string] = metadata
                processed_count += 1
            else:
                excluded_count += 1
        
        # Build indexes
        self.logger.info("Building secondary indexes")
        indexes = self._build_indexes(cpe_index)
        
        # Create output structure
        output_data = {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'nvd_source': nvd_cpes_path,
            'total_cpes': len(cpe_index),
            'processed_count': processed_count,
            'excluded_count': excluded_count,
            'cpe_index': cpe_index,
            **indexes
        }
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Write output file
        self.logger.info(f"Writing mapping to {output_path}")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        # Log summary statistics
        self.logger.info(f"CPE mapping complete:")
        self.logger.info(f"  Total CPEs processed: {processed_count}")
        self.logger.info(f"  CPEs excluded: {excluded_count}")
        self.logger.info(f"  OS families: {len(indexes['index_by_os'])}")
        self.logger.info(f"  System types: {len(indexes['index_by_system_type'])}")
        self.logger.info(f"  Asset type pools: {len(indexes['pools_by_asset_type'])}")

def build_cpe_mapping(nvd_cpes_path: str, config_path: str, output_path: str, *, force: bool = False, sample_limit: Optional[int] = None) -> None:
    """Programmatic API for building CPE mapping.
    
    Args:
        nvd_cpes_path: Path to NVD CPEs JSON file
        config_path: Path to generator configuration file
        output_path: Path for output YAML file
        force: Whether to overwrite existing output file
        sample_limit: Maximum number of CPEs to process
    """
    mapper = CPEMapper(config_path)
    mapper.build_mapping(nvd_cpes_path, output_path, force=force, sample_limit=sample_limit)

def main():
    """Command line interface for CPE mapper."""
    parser = argparse.ArgumentParser(description='Map NVD CPEs to asset types')
    parser.add_argument('--input', default='data/inputs/nvd_cpes.json',
                       help='Path to NVD CPEs JSON file')
    parser.add_argument('--config', default='configs/generator_config.yaml',
                       help='Path to generator configuration file')
    parser.add_argument('--output', default='configs/cpe_mapping_config.json',
                       help='Path for output mapping file')
    parser.add_argument('--force', action='store_true',
                       help='Overwrite existing output file')
    parser.add_argument('--min-confidence', type=float,
                       help='Minimum confidence threshold')
    parser.add_argument('--sample-limit', type=int,
                       help='Maximum number of CPEs to process')
    
    args = parser.parse_args()
    
    try:
        # Create mapper
        mapper = CPEMapper(args.config)
        
        # Override config values with command line arguments
        if args.min_confidence is not None:
            mapper.min_confidence = args.min_confidence
        if args.sample_limit is not None:
            mapper.sample_limit = args.sample_limit
        
        # Build mapping
        mapper.build_mapping(args.input, args.output, force=args.force, sample_limit=args.sample_limit)
        
        print(f"CPE mapping successfully generated: {args.output}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()