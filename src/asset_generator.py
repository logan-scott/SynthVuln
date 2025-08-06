import argparse
import csv
import ipaddress
import json
import random
import uuid
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from utils.util import setup_logging, load_config

class AssetGenerator:
    """
    A generator for creating synthetic asset inventory data.
    
    This class generates realistic asset data including various asset types (Desktop, Laptop, Server),
    locations, network configurations, and security settings. It supports multiple output formats
    including JSON, CSV, and SQL.
    
    Attributes:
        config (Dict[str, Any]): Configuration loaded from YAML file
        asset_types (List[str]): Available asset types
        locations (List[str]): Available asset locations
        common_ports (List[int]): Common network ports
        asset_location_mapping (Dict[str, List[str]]): Valid locations per asset type
        asset_port_mapping (Dict[str, List[int]]): Valid ports per asset type
        asset_internet_exposure_base (Dict[str, float]): Base internet exposure probability per asset type
        location_exposure_multiplier (Dict[str, float]): Location-based exposure multipliers
        asset_type_distribution (Dict[str, float]): Asset type distribution weights
        default_paths (Dict[str, str]): Default file paths from configuration
    """
    
    def __init__(self, config_file: str = "configs/generator_config.yaml"):
        """
        Initialize the AssetGenerator with configuration and logging.
        
        Args:
            config_file (str): Path to the YAML configuration file
        """
        self.logger = setup_logging('asset_generator.log', __name__)
        self.config = load_config(config_file, self.logger)
        self._initialize_settings()
    
    def _initialize_settings(self):
        """
        Initialize generator settings from configuration.
        
        This method extracts and sets up all configuration parameters needed
        for asset generation, including asset types, locations, port mappings,
        and distribution weights.
        """
        self.default_paths = self.config.get('default_paths', {})

        # Load asset types, locations, and common ports
        self.asset_types = self.config.get('asset_types', [])
        self.locations = self.config.get('locations', [])
        self.common_ports = self.config.get('common_ports', [])
        
        # Load mappings from config
        self.asset_location_mapping = self.config.get('asset_location_mapping', {})
        self.asset_port_mapping = self.config.get('asset_port_mapping', {})
        self.asset_internet_exposure_base = self.config.get('asset_internet_exposure_base', {})
        self.location_exposure_multiplier = self.config.get('location_exposure_multiplier', {})
        self.asset_type_distribution = self.config.get('asset_type_distribution', {})
        
        # Load operating system configuration
        self.operating_systems = self.config.get('operating_systems', {})
        self.asset_os_mapping = self.config.get('asset_os_mapping', {})
        self.os_distribution_by_asset = self.config.get('os_distribution_by_asset', {})
        
        # Load lifecycle stage configuration
        self.lifecycle_stages = self.config.get('lifecycle_stages', [])
        self.lifecycle_stage_distribution = self.config.get('lifecycle_stage_distribution', {})
        
        # Load security features configuration
        self.security_features = self.config.get('security_features', {})
        
        # Load internal network configuration
        self.internal_networks = self.config.get('internal_networks', {})
        
        # Load performance configuration
        perf_config = self.config.get('performance_config', {})
        self.default_asset_count = perf_config.get('default_asset_count', 10)
        self.max_asset_batch_size = perf_config.get('max_asset_batch_size', 1000)
        self.progress_interval = perf_config.get('progress_report_interval', 100)
        self.hostname_adjective_count = perf_config.get('hostname_adjective_count', 50)
        self.hostname_noun_count = perf_config.get('hostname_noun_count', 100)
        
        self.logger.info(f"Initialized AssetGenerator with {len(self.asset_types)} asset types and {len(self.locations)} locations")
        self.logger.info(f"Performance settings: default_count={self.default_asset_count}, batch_size={self.max_asset_batch_size}, progress_interval={self.progress_interval}")

    def generate_user_accounts(self, is_privileged: bool = False, count: int = 0) -> List[str]:
        """
        Generate a list of user account names.
        
        Args:
            is_privileged (bool): Whether to generate privileged (admin) accounts
            count (int): Number of accounts to generate. If 0, uses random count
                        (1-5 for privileged, 2-10 for regular users)
                        
        Returns:
            List[str]: List of generated user account names
        """
        if count == 0:
            count = random.randint(1, 5) if is_privileged else random.randint(2, 10)
        
        prefix = "admin" if is_privileged else "user"
        return [f"{prefix}{i}" for i in range(1, count + 1)]

    def select_operating_system(self, asset_type: str) -> Dict[str, str]:
        """
        Select an appropriate operating system for the given asset type.
        
        Args:
            asset_type (str): The type of asset (Desktop, Server, etc.)
            
        Returns:
            Dict[str, str]: Dictionary containing 'os_family' and 'os_version'
        """
        # Get valid OS families for this asset type
        valid_os_families = self.asset_os_mapping.get(asset_type, ['Windows', 'Linux'])
        
        # Get distribution weights for this asset type
        os_weights = self.os_distribution_by_asset.get(asset_type, {})
        
        # Filter weights to only include valid OS families
        filtered_weights = {family: weight for family, weight in os_weights.items() 
                           if family in valid_os_families}
        
        # If no weights found, use equal distribution
        if not filtered_weights:
            os_family = random.choice(valid_os_families)
        else:
            # Select OS family based on weights
            families = list(filtered_weights.keys())
            weights = list(filtered_weights.values())
            os_family = random.choices(families, weights=weights, k=1)[0]
        
        # Select specific OS version from the chosen family
        available_versions = self.operating_systems.get(os_family, [f"{os_family} Generic"])
        os_version = random.choice(available_versions)
        
        return {
            'os_family': os_family,
            'os_version': os_version
        }

    def select_lifecycle_stage(self) -> str:
        """
        Select a lifecycle stage based on configured distribution weights.
        
        Returns:
            str: Selected lifecycle stage
        """
        if not self.lifecycle_stages or not self.lifecycle_stage_distribution:
            # Fallback to default if no configuration
            return 'Production'
        
        # Create weighted choices based on distribution
        stages = list(self.lifecycle_stage_distribution.keys())
        weights = list(self.lifecycle_stage_distribution.values())
        
        # Use random.choices for weighted selection
        selected_stage = random.choices(stages, weights=weights, k=1)[0]
        
        return selected_stage
    
    def supports_endpoint_security(self, asset_type):
        """Check if an asset type supports endpoint security."""
        endpoint_config = self.security_features.get('endpoint_security', {})
        applicable_types = endpoint_config.get('applicable_asset_types', [])
        return asset_type in applicable_types
    
    def supports_local_firewall(self, asset_type):
        """Check if an asset type supports local firewall."""
        firewall_config = self.security_features.get('local_firewall', {})
        applicable_types = firewall_config.get('applicable_asset_types', [])
        return asset_type in applicable_types
    
    def get_endpoint_security_probability(self):
        """Get the probability for endpoint security installation."""
        endpoint_config = self.security_features.get('endpoint_security', {})
        return endpoint_config.get('default_probability', 0.8)
    
    def get_local_firewall_probability(self):
        """Get the probability for local firewall activation."""
        firewall_config = self.security_features.get('local_firewall', {})
        return firewall_config.get('default_probability', 0.7)
    
    def select_internal_network(self, asset_type):
        """Select an appropriate internal network for the given asset type."""
        if not self.internal_networks:
            return None
        
        # Find networks that support this asset type
        applicable_networks = []
        for network_name, network_config in self.internal_networks.items():
            applicable_types = network_config.get('applicable_asset_types', [])
            if asset_type in applicable_types:
                applicable_networks.append((network_name, network_config))
        
        if not applicable_networks:
            # Fallback to corporate network if available, otherwise first network
            if 'corporate' in self.internal_networks:
                return ('corporate', self.internal_networks['corporate'])
            elif self.internal_networks:
                first_network = list(self.internal_networks.items())[0]
                return first_network
            return None
        
        # Randomly select from applicable networks
        return random.choice(applicable_networks)
    
    def generate_ip_from_cidr(self, cidr_range):
        """Generate a random IP address from a CIDR range."""
        try:
            network = ipaddress.IPv4Network(cidr_range, strict=False)
            # Get all host addresses (excluding network and broadcast)
            hosts = list(network.hosts())
            if hosts:
                return str(random.choice(hosts))
            else:
                # For /32 or very small networks, use the network address
                return str(network.network_address)
        except (ipaddress.AddressValueError, ValueError):
            # Fallback to default range if CIDR parsing fails
            return f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
    
    def select_internal_ip(self, asset_type):
        """Select an internal IP address based on asset type and network configuration."""
        network_info = self.select_internal_network(asset_type)
        
        if not network_info:
            # Fallback to default IP generation
            return f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        
        network_name, network_config = network_info
        ip_ranges = network_config.get('ip_ranges', [])
        
        if not ip_ranges:
            # Fallback to default IP generation
            return f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        
        # Randomly select an IP range and generate an IP from it
        selected_range = random.choice(ip_ranges)
        return self.generate_ip_from_cidr(selected_range)

    def generate_single_asset(self) -> Dict[str, Any]:
        """
        Generate a single synthetic asset with realistic properties.
        
        This method creates an asset with properties based on configuration weights
        and realistic relationships between asset type, location, and security settings.
        Internet exposure probability is calculated based on asset type and location.
        
        Returns:
            Dict[str, Any]: Asset dictionary containing:
                - uuid: Unique identifier
                - domain_name: Domain name
                - hostname: Asset hostname
                - user_accounts: List of regular user accounts
                - privileged_user_accounts: List of privileged user accounts
                - type: Asset type (Desktop, Laptop, Server, etc.)
                - os_family: Operating system family (Windows, Linux, etc.)
                - os_version: Specific OS version
                - internet_exposed: Boolean indicating internet exposure
                - public_ip: Public IP address (if internet exposed)
                - internal_ip: Internal IP address
                - open_ports: List of open network ports
                - endpoint_security_installed: Boolean for endpoint security
                - local_firewall_active: Boolean for firewall status
                - location: Asset location
        """
        # Select asset type based on realistic distribution weights
        asset_types = list(self.asset_type_distribution.keys())
        weights = list(self.asset_type_distribution.values())
        asset_type = random.choices(asset_types, weights=weights, k=1)[0]
        
        # Get valid locations and ports for this asset type
        valid_locations = self.asset_location_mapping.get(asset_type, self.locations)
        valid_ports = self.asset_port_mapping.get(asset_type, self.common_ports)
        location = random.choice(valid_locations)
        
        # Select operating system for this asset type
        os_info = self.select_operating_system(asset_type)
        
        # Select lifecycle stage
        lifecycle_stage = self.select_lifecycle_stage()
        
        # Calculate internet exposure probability based on asset type and location
        base_probability = self.asset_internet_exposure_base.get(asset_type, 0.3)
        location_multiplier = self.location_exposure_multiplier.get(location, 1.0)
        exposure_probability = min(base_probability * location_multiplier, 1.0)  # Cap at 100%
        is_internet_exposed = random.random() < exposure_probability
        
        # Select ports from valid options (2-4 ports for most assets)
        num_ports = min(random.randint(2, 4), len(valid_ports))
        open_ports = random.sample(valid_ports, num_ports)
        
        asset = {
            "uuid": str(uuid.uuid4()),
            "domain_name": f"domain{random.randint(1,5)}.local",
            "hostname": f"{asset_type.lower().replace(' ', '-')}-{random.randint(1000,9999)}",
            "user_accounts": self.generate_user_accounts(),
            "privileged_user_accounts": self.generate_user_accounts(is_privileged=True),
            "type": asset_type,
            "os_family": os_info['os_family'],
            "os_version": os_info['os_version'],
            "lifecycle_stage": lifecycle_stage,
            "internet_exposed": is_internet_exposed,
            "public_ip": f"203.0.{random.randint(1,255)}.{random.randint(1,255)}" if is_internet_exposed else None,
            "internal_ip": self.select_internal_ip(asset_type),
            "open_ports": open_ports,
            "endpoint_security_installed": self.supports_endpoint_security(asset_type) and random.random() < self.get_endpoint_security_probability(),
            "local_firewall_active": self.supports_local_firewall(asset_type) and random.random() < self.get_local_firewall_probability(),
            "location": location
        }
        return asset

    def generate_assets(self, count: int, output_file: str = "", output_format: str = "json") -> List[Dict[str, Any]]:
        """
        Generate multiple synthetic assets and optionally save to file.
        
        Args:
            count (int): Number of assets to generate
            output_file (str): Optional output file path. If empty, assets are not saved
            output_format (str): Output format - 'json', 'csv', or 'sql'
            
        Returns:
            List[Dict[str, Any]]: List of generated asset dictionaries
            
        Raises:
            ValueError: If unsupported output format is specified
            OSError: If file operations fail
        """
        self.logger.info(f"Generating {count} assets")
        
        assets = []
        for i in range(count):
            asset = self.generate_single_asset()
            assets.append(asset)
            
            # Simple progress logging
            if (i + 1) % self.progress_interval == 0 or (i + 1) == count:
                self.logger.info(f"Generated {i + 1}/{count} assets ({((i + 1)/count)*100:.1f}%)")
        
        self.logger.info(f"Successfully generated {len(assets)} assets")
        
        if output_file:
            try:
                output_path = Path(output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                if output_format.lower() == "json":
                    self._save_as_json(assets, output_file)
                elif output_format.lower() == "csv":
                    self._save_as_csv(assets, output_file)
                elif output_format.lower() == "sql":
                    self._save_as_sql(assets, output_file)
                else:
                    raise ValueError(f"Unsupported output format: {output_format}")
                    
                self.logger.info(f"Successfully saved {len(assets)} assets to {output_file} in {output_format.upper()} format")
            except PermissionError:
                self.logger.error(f"Permission denied writing to {output_file}")
                raise
            except OSError as e:
                self.logger.error(f"File operation failed for {output_file}: {e}")
                raise
            except Exception as e:
                self.logger.error(f"Unexpected error saving assets to {output_file}: {e}")
                raise
        
        return assets
    
    def _save_as_json(self, assets: List[Dict[str, Any]], output_file: str):
        """
        Save assets in JSON format.
        
        Args:
            assets (List[Dict[str, Any]]): List of asset dictionaries to save
            output_file (str): Path to output JSON file
            
        Raises:
            OSError: If file writing fails
            json.JSONEncodeError: If assets cannot be serialized to JSON
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(assets, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Failed to write JSON file {output_file}: {e}")
            raise
    
    def _save_as_csv(self, assets: List[Dict[str, Any]], output_file: str):
        """
        Save assets in CSV format with flattened data structure.
        
        This method flattens complex fields (lists) into semicolon-separated strings
        to make them suitable for CSV format.
        
        Args:
            assets (List[Dict[str, Any]]): List of asset dictionaries to save
            output_file (str): Path to output CSV file
            
        Raises:
            OSError: If file writing fails
            KeyError: If required asset fields are missing
        """
        if not assets:
            self.logger.warning("No assets to save to CSV")
            return
        
        try:
            # Flatten the data for CSV export
            flattened_assets = []
            for i, asset in enumerate(assets):
                try:
                    flattened = {
                        'uuid': asset['uuid'],
                        'domain_name': asset['domain_name'],
                        'hostname': asset['hostname'],
                        'user_accounts': ';'.join(asset['user_accounts']),
                        'privileged_user_accounts': ';'.join(asset['privileged_user_accounts']),
                        'type': asset['type'],
                        'os_family': asset['os_family'],
                        'os_version': asset['os_version'],
                        'lifecycle_stage': asset['lifecycle_stage'],
                        'internet_exposed': asset['internet_exposed'],
                        'public_ip': asset['public_ip'] or '',
                        'internal_ip': asset['internal_ip'],
                        'open_ports': ';'.join(map(str, asset['open_ports'])),
                        'endpoint_security_installed': asset['endpoint_security_installed'],
                        'local_firewall_active': asset['local_firewall_active'],
                        'location': asset['location']
                    }
                    flattened_assets.append(flattened)
                except KeyError as e:
                    self.logger.warning(f"Asset {i} missing required field {e}, skipping")
                    continue
                except (TypeError, ValueError) as e:
                    self.logger.warning(f"Error processing asset {i}: {e}, skipping")
                    continue
            
            if not flattened_assets:
                self.logger.error("No valid assets to write to CSV")
                return
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=flattened_assets[0].keys())
                writer.writeheader()
                writer.writerows(flattened_assets)
                
        except OSError as e:
            self.logger.error(f"Failed to write CSV file {output_file}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error saving CSV file {output_file}: {e}")
            raise
    
    def _save_as_sql(self, assets: List[Dict[str, Any]], output_file: str):
        """
        Save assets as SQL CREATE TABLE and INSERT statements.
        
        This method generates a complete SQL script with table creation
        and INSERT statements for all assets. String values are properly
        escaped to prevent SQL injection.
        
        Args:
            assets (List[Dict[str, Any]]): List of asset dictionaries to save
            output_file (str): Path to output SQL file
            
        Raises:
            OSError: If file writing fails
            KeyError: If required asset fields are missing
        """
        if not assets:
            self.logger.warning("No assets to save to SQL")
            return
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # Write table creation statement
                f.write("-- Asset inventory table\n")
                f.write("CREATE TABLE IF NOT EXISTS assets (\n")
                f.write("    uuid VARCHAR(36) PRIMARY KEY,\n")
                f.write("    domain_name VARCHAR(255),\n")
                f.write("    hostname VARCHAR(255),\n")
                f.write("    user_accounts TEXT,\n")
                f.write("    privileged_user_accounts TEXT,\n")
                f.write("    type VARCHAR(100),\n")
                f.write("    os_family VARCHAR(50),\n")
                f.write("    os_version VARCHAR(100),\n")
                f.write("    lifecycle_stage VARCHAR(50),\n")
                f.write("    internet_exposed BOOLEAN,\n")
                f.write("    public_ip VARCHAR(15),\n")
                f.write("    internal_ip VARCHAR(15),\n")
                f.write("    open_ports TEXT,\n")
                f.write("    endpoint_security_installed BOOLEAN,\n")
                f.write("    local_firewall_active BOOLEAN,\n")
                f.write("    location VARCHAR(100)\n")
                f.write(");\n\n")
                
                # Write INSERT statements
                f.write("-- Asset data\n")
                for i, asset in enumerate(assets):
                    try:
                        user_accounts = ';'.join(asset['user_accounts']).replace("'", "''")
                        privileged_accounts = ';'.join(asset['privileged_user_accounts']).replace("'", "''")
                        open_ports = ';'.join(map(str, asset['open_ports']))
                        public_ip = asset['public_ip'] or 'NULL'
                        
                        # Escape single quotes in string fields
                        domain_name = str(asset['domain_name']).replace("'", "''")
                        hostname = str(asset['hostname']).replace("'", "''")
                        asset_type = str(asset['type']).replace("'", "''")
                        os_family = str(asset['os_family']).replace("'", "''")
                        os_version = str(asset['os_version']).replace("'", "''")
                        lifecycle_stage = str(asset['lifecycle_stage']).replace("'", "''")
                        location = str(asset['location']).replace("'", "''")
                        internal_ip = str(asset['internal_ip']).replace("'", "''")
                        
                        f.write(f"INSERT INTO assets VALUES (\n")
                        f.write(f"    '{asset['uuid']}',\n")
                        f.write(f"    '{domain_name}',\n")
                        f.write(f"    '{hostname}',\n")
                        f.write(f"    '{user_accounts}',\n")
                        f.write(f"    '{privileged_accounts}',\n")
                        f.write(f"    '{asset_type}',\n")
                        f.write(f"    '{os_family}',\n")
                        f.write(f"    '{os_version}',\n")
                        f.write(f"    '{lifecycle_stage}',\n")
                        f.write(f"    {str(asset['internet_exposed']).lower()},\n")
                        f.write(f"    {'NULL' if public_ip == 'NULL' else f"'{public_ip}'"},\n")
                        f.write(f"    '{internal_ip}',\n")
                        f.write(f"    '{open_ports}',\n")
                        f.write(f"    {str(asset['endpoint_security_installed']).lower()},\n")
                        f.write(f"    {str(asset['local_firewall_active']).lower()},\n")
                        f.write(f"    '{location}'\n")
                        f.write(");\n")
                    except KeyError as e:
                        self.logger.warning(f"Asset {i} missing required field {e}, skipping")
                        continue
                    except (TypeError, ValueError) as e:
                        self.logger.warning(f"Error processing asset {i} for SQL: {e}, skipping")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Unexpected error saving SQL file {output_file}: {e}")
            raise

def main():
    """
    Command-line interface for the AssetGenerator.
    
    This function provides a CLI for generating synthetic asset inventory data
    with configurable count, output file, and format options. It also displays
    comprehensive statistics about the generated assets including type distribution,
    location distribution, internet exposure rates, security features, and port statistics.
    
    Command-line Arguments:
        --count: Number of assets to generate (default: 10)
        --output: Output file path (optional, uses config default if not specified)
        --output-format: Output format - json, csv, or sql (default: json)
    
    The function automatically adjusts file extensions based on the selected format
    and provides detailed generation statistics upon completion.
    """
    parser = argparse.ArgumentParser(description='Generate synthetic asset inventory')
    parser.add_argument('--count', type=int, default=10, help='Number of assets to generate (default from config)')
    parser.add_argument('--output', type=str, default='', 
                        help='Output file path')
    parser.add_argument('--output-format', type=str, choices=['json', 'csv', 'sql'], default='json',
                        help='Output format: json (default), csv, or sql')
    args = parser.parse_args()

    generator = AssetGenerator()
    
    # Use config default if count is still 10 (default)
    if args.count == 10:
        args.count = generator.default_asset_count
    
    # Use config default if no output specified, but adjust extension based on format
    if args.output:
        output_file = args.output
    else:
        default_output = generator.default_paths.get('asset_output', 'data/raw/assets.json')
        # Change extension based on format
        if args.output_format == 'csv':
            output_file = default_output.replace('.json', '.csv')
        elif args.output_format == 'sql':
            output_file = default_output.replace('.json', '.sql')
        else:
            output_file = default_output
    
    assets = generator.generate_assets(args.count, output_file, args.output_format)
    print(f"Generated {len(assets)} assets and saved to {output_file} ({args.output_format.upper()} format)")
    
    # Statistics
    print("\n" + "=" * 60)
    print(f"ASSET GENERATION STATISTICS (Total: {len(assets)} assets)")
    print("=" * 60)
    
    # Asset type distribution
    asset_types = Counter(asset['type'] for asset in assets)
    print("\nAsset Type Distribution:")
    print("-" * 30)
    for asset_type, count in asset_types.most_common():
        percentage = (count / len(assets)) * 100
        print(f"{asset_type:<20}: {count:>3} ({percentage:>5.1f}%)")
    
    # Location distribution
    locations = Counter(asset['location'] for asset in assets)
    print("\nLocation Distribution:")
    print("-" * 21)
    for location, count in locations.most_common():
        percentage = (count / len(assets)) * 100
        print(f"{location:<15}: {count:>3} ({percentage:>5.1f}%)")
    
    # Internet exposure statistics
    internet_exposed = sum(1 for asset in assets if asset['internet_exposed'])
    exposure_rate = (internet_exposed / len(assets)) * 100
    print(f"\nInternet Exposure:")
    print("-" * 18)
    print(f"Exposed         : {internet_exposed:>3} ({exposure_rate:>5.1f}%)")
    print(f"Internal only   : {len(assets) - internet_exposed:>3} ({100 - exposure_rate:>5.1f}%)")
    
    # Security features
    endpoint_security = sum(1 for asset in assets if asset['endpoint_security_installed'])
    firewall_active = sum(1 for asset in assets if asset['local_firewall_active'])
    print(f"\nSecurity Features:")
    print("-" * 18)
    print(f"Endpoint Security: {endpoint_security:>3} ({(endpoint_security/len(assets))*100:>5.1f}%)")
    print(f"Local Firewall   : {firewall_active:>3} ({(firewall_active/len(assets))*100:>5.1f}%)")
    
    # Port statistics
    all_ports = [port for asset in assets for port in asset['open_ports']]
    unique_ports = len(set(all_ports))
    avg_ports = len(all_ports) / len(assets)
    print(f"\nPort Statistics:")
    print("-" * 16)
    print(f"Total open ports : {len(all_ports)}")
    print(f"Unique ports     : {unique_ports}")
    print(f"Avg ports/asset  : {avg_ports:.1f}")
    
    print("\n" + "=" * 60)

if __name__ == '__main__':
    main()