"""
This is a simple program to count the number of JSON entities in a file.
"""

import json
import sys


def count(file) -> int:
    try:
        with open(file, 'r') as f:
            data = json.load(f)
            return len(data)
    except json.JSONDecodeError:
        print(f"Error: {file} is not a valid JSON file.")
        raise
    except FileNotFoundError:
        print(f"Error: {file} not found.")
        raise
    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python json_counter.py <file>")
        sys.exit(1)
    file = sys.argv[1]
    try:
        n = count(file)
        print(f"Number of entities in {file}: {n}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

