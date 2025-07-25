import argparse
import json
import uuid
import random
import yaml
import csv
from typing import List, Dict, Any
from pathlib import Path
from collections import Counter

class AssetGenerator:
    def __init__(self, config_file: str = "configs/generator_config.yaml"):
        self.config = self._load_config(config_file)
        self.asset_types = self.config.get('asset_types', [])
        self.locations = self.config.get('locations', [])
        self.common_ports = self.config.get('common_ports', [])
        
        # Load mappings from config
        self.asset_location_mapping = self.config.get('asset_location_mapping', {})
        self.asset_port_mapping = self.config.get('asset_port_mapping', {})
        self.asset_internet_exposure_base = self.config.get('asset_internet_exposure_base', {})
        self.location_exposure_multiplier = self.config.get('location_exposure_multiplier', {})
        self.asset_type_distribution = self.config.get('asset_type_distribution', {})
        
        # Get default paths
        self.default_paths = self.config.get('default_paths', {})
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config file {config_file}: {e}")
            print("Using fallback configuration...")
            return self._get_fallback_config()
    
    def _get_fallback_config(self) -> Dict[str, Any]:
        """Provide fallback configuration if config file cannot be loaded"""
        return {
            'asset_types': ["Desktop", "Laptop", "Server"],
            'locations': ["Remote", "Internal", "Data center", "Cloud"],
            'common_ports': [22, 80, 443, 3389, 8080],
            'asset_location_mapping': {
                "Desktop": ["Remote", "Internal"],
                "Laptop": ["Remote", "Internal"],
                "Server": ["Internal", "Data center", "Cloud"]
            },
            'asset_port_mapping': {
                "Desktop": [22, 3389],
                "Laptop": [22, 3389],
                "Server": [22, 80, 443]
            },
            'asset_internet_exposure_base': {
                "Desktop": 0.05,
                "Laptop": 0.10,
                "Server": 0.25
            },
            'location_exposure_multiplier': {
                "Remote": 1.5,
                "Internal": 0.3,
                "Data center": 0.8,
                "Cloud": 1.2
            },
            'asset_type_distribution': {
                "Desktop": 40.0,
                "Laptop": 35.0,
                "Server": 25.0
            },
            'default_paths': {
                'asset_output': 'data/raw/assets.json'
            }
        }

    def generate_user_accounts(self, is_privileged: bool = False, count: int = 0) -> List[str]:
        if count == 0:
            count = random.randint(1, 5) if is_privileged else random.randint(2, 10)
        
        prefix = "admin" if is_privileged else "user"
        return [f"{prefix}{i}" for i in range(1, count + 1)]

    def generate_single_asset(self) -> Dict[str, Any]:
        # Select asset type based on realistic distribution weights
        asset_types = list(self.asset_type_distribution.keys())
        weights = list(self.asset_type_distribution.values())
        asset_type = random.choices(asset_types, weights=weights, k=1)[0]
        
        # Get valid locations and ports for this asset type
        valid_locations = self.asset_location_mapping.get(asset_type, self.locations)
        valid_ports = self.asset_port_mapping.get(asset_type, self.common_ports)
        location = random.choice(valid_locations)
        
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
            "internet_exposed": is_internet_exposed,
            "public_ip": f"203.0.{random.randint(1,255)}.{random.randint(1,255)}" if is_internet_exposed else None,
            "internal_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            "open_ports": open_ports,
            "endpoint_security_installed": random.random() < 0.8,  # 80% chance of having security
            "local_firewall_active": random.random() < 0.7,  # 70% chance of active firewall
            "location": location
        }
        return asset

    def generate_assets(self, count: int, output_file: str = "", output_format: str = "json") -> List[Dict[str, Any]]:
        assets = [self.generate_single_asset() for _ in range(count)]
        
        if output_file:
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
        
        return assets
    
    def _save_as_json(self, assets: List[Dict[str, Any]], output_file: str):
        """Save assets as JSON format"""
        with open(output_file, 'w') as f:
            json.dump(assets, f, indent=2)
    
    def _save_as_csv(self, assets: List[Dict[str, Any]], output_file: str):
        """Save assets as CSV format"""
        if not assets:
            return
        
        # Flatten the data for CSV export
        flattened_assets = []
        for asset in assets:
            flattened = {
                'uuid': asset['uuid'],
                'domain_name': asset['domain_name'],
                'hostname': asset['hostname'],
                'user_accounts': ';'.join(asset['user_accounts']),
                'privileged_user_accounts': ';'.join(asset['privileged_user_accounts']),
                'type': asset['type'],
                'internet_exposed': asset['internet_exposed'],
                'public_ip': asset['public_ip'] or '',
                'internal_ip': asset['internal_ip'],
                'open_ports': ';'.join(map(str, asset['open_ports'])),
                'endpoint_security_installed': asset['endpoint_security_installed'],
                'local_firewall_active': asset['local_firewall_active'],
                'location': asset['location']
            }
            flattened_assets.append(flattened)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=flattened_assets[0].keys())
            writer.writeheader()
            writer.writerows(flattened_assets)
    
    def _save_as_sql(self, assets: List[Dict[str, Any]], output_file: str):
        """Save assets as SQL INSERT statements"""
        if not assets:
            return
        
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
            for asset in assets:
                user_accounts = ';'.join(asset['user_accounts']).replace("'", "''")
                privileged_accounts = ';'.join(asset['privileged_user_accounts']).replace("'", "''")
                open_ports = ';'.join(map(str, asset['open_ports']))
                public_ip = asset['public_ip'] or 'NULL'
                
                f.write(f"INSERT INTO assets VALUES (\n")
                f.write(f"    '{asset['uuid']}',\n")
                f.write(f"    '{asset['domain_name']}',\n")
                f.write(f"    '{asset['hostname']}',\n")
                f.write(f"    '{user_accounts}',\n")
                f.write(f"    '{privileged_accounts}',\n")
                f.write(f"    '{asset['type']}',\n")
                f.write(f"    {str(asset['internet_exposed']).lower()},\n")
                f.write(f"    {'NULL' if public_ip == 'NULL' else f"'{public_ip}'"},\n")
                f.write(f"    '{asset['internal_ip']}',\n")
                f.write(f"    '{open_ports}',\n")
                f.write(f"    {str(asset['endpoint_security_installed']).lower()},\n")
                f.write(f"    {str(asset['local_firewall_active']).lower()},\n")
                f.write(f"    '{asset['location']}'\n")
                f.write(");\n")

def main():
    parser = argparse.ArgumentParser(description='Generate synthetic asset inventory')
    parser.add_argument('--count', type=int, default=10, help='Number of assets to generate')
    parser.add_argument('--output', type=str, default='', 
                        help='Output file path')
    parser.add_argument('--output-format', type=str, choices=['json', 'csv', 'sql'], default='json',
                        help='Output format: json (default), csv, or sql')
    args = parser.parse_args()

    generator = AssetGenerator()
    
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