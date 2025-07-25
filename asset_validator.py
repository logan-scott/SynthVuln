from typing import List, Dict, Any
from pathlib import Path
import json

def validate_asset(asset: Dict[str, Any]) -> List[str]:
    errors = []
    required_fields = {
        'uuid': str,
        'domain_name': str,
        'hostname': str,
        'user_accounts': list,
        'privileged_user_accounts': list,
        'type': str,
        'internet_exposed': bool,
        'internal_ip': str,
        'open_ports': list,
        'endpoint_security_installed': bool,
        'local_firewall_active': bool,
        'location': str
    }

    for field, field_type in required_fields.items():
        if field not in asset:
            errors.append(f"Missing required field: {field}")
        elif not isinstance(asset[field], field_type):
            errors.append(f"Invalid type for {field}: expected {field_type}, got {type(asset[field])}")

    if asset.get('internet_exposed') and not asset.get('public_ip'):
        errors.append("Internet exposed asset must have public IP")

    return errors

def validate_asset_file(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r') as f:
            assets = json.load(f)
    except Exception as e:
        return [f"Failed to load JSON file: {str(e)}"]

    if not isinstance(assets, list):
        return ["Root element must be an array"]

    all_errors = []
    for i, asset in enumerate(assets):
        errors = validate_asset(asset)
        if errors:
            all_errors.append(f"Asset {i}: {', '.join(errors)}")

    return all_errors

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Validate asset inventory JSON file')
    parser.add_argument('file', type=str, help='Path to asset inventory JSON file')
    args = parser.parse_args()

    errors = validate_asset_file(args.file)
    if errors:
        print("Validation errors found:")
        for error in errors:
            print(f"- {error}")
    else:
        print("Asset inventory is valid!")

if __name__ == '__main__':
    main()