"""This simple utility converts JSON files to CSV files."""

import json
import sys
import csv
import os


def convert(json_file, csv_file=None) -> str:
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        if not data:
            raise ValueError("JSON file is empty or contains no data")
        
        if csv_file is None:
            base_name = os.path.splitext(json_file)[0]
            csv_file = f"{base_name}.csv"
        
        if isinstance(data, list):
            if not data:
                raise ValueError("JSON array is empty")
            if isinstance(data[0], dict):
                headers = data[0].keys()
                rows = data
            else:
                headers = ['value']
                rows = [{'value': item} for item in data]
        elif isinstance(data, dict):
            headers = data.keys()
            rows = [data]
        else:
            headers = ['value']
            rows = [{'value': data}]
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                processed_row = {}
                for key, value in row.items():
                    if isinstance(value, (dict, list)):
                        processed_row[key] = json.dumps(value)
                    else:
                        processed_row[key] = value
                writer.writerow(processed_row)
        
        return csv_file
    except json.JSONDecodeError:
        print(f"Error: {json_file} is not a valid JSON file.")
        raise
    except FileNotFoundError:
        print(f"Error: {json_file} not found.")
        raise
    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python json_to_csv.py <json_file> [csv_file]")
        sys.exit(1)
    
    json_file = sys.argv[1]
    csv_file = sys.argv[2] if len(sys.argv) == 3 else None
    
    try:
        output_file = convert(json_file, csv_file)
        print(f"Successfully converted {json_file} to {output_file}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
