# SynthVuln Generator

A comprehensive synthetic vulnerability data generator that creates realistic asset inventories and vulnerability findings for testing and simulation purposes.

## Overview

The SynthVuln Generator provides a unified interface for running asset and findings generators with three different modes:

1. **Interactive Mode** - User-friendly question-based interface
2. **Default Mode** - Run both generators with default settings
3. **Run Mode** - Command-line interface for programmatic usage

## Usage

### Interactive Mode (Default)
```bash
python generate.py
```
Provides a user-friendly question-based interface where you can:
- Choose which generators to run (assets only, findings only, or both)
- Configure generation parameters interactively
- Set output files and formats
- Configure findings generator options

### Default Mode
```bash
python generate.py --default
```
Runs both generators with default settings:
- Generates 10 assets in JSON format
- Generates 10 findings in JSON format
- Uses default output paths from configuration

### Run Mode
```bash
python generate.py --run [options]
```
Command-line interface for programmatic usage with full control over all parameters.

#### Run Mode Options
- `--count-assets N` - Number of assets to generate
- `--count-findings N` - Number of findings to generate
- `--output-assets FILE` - Asset output file path
- `--output-findings FILE` - Findings output file path
- `--input-assets FILE` - Input asset file for findings generator
- `--output-format {json,csv,sql}` - Output format (default: json)
- `--no-bias-recent` - Disable bias towards recent CVEs

## Examples

### Basic Examples
```bash
# Interactive mode
python generate.py

# Default mode
python generate.py --default

# Generate 1000 assets and 10000 findings in JSON format
python generate.py --run --count-assets 1000 --count-findings 10000 --output-format json
```

### Advanced Examples
```bash
# Generate assets in CSV format
python generate.py --run --count-assets 500 --output-assets data/assets.csv --output-format csv

# Generate findings using existing assets
python generate.py --run --count-findings 5000 --input-assets data/assets.json --output-findings data/findings.sql --output-format sql

# Generate both with custom paths and SQL format
python generate.py --run --count-assets 1000 --count-findings 10000 --output-assets /data/outputs/assets.json --output-findings /data/outputs/findings.sql --output-format sql
```

## Output Formats

### JSON Format
- Human-readable structured data
- Easy to parse and integrate with other tools
- Default format for most use cases

### CSV Format
- Tabular data suitable for spreadsheet applications
- Easy to import into databases
- Good for data analysis and reporting

### SQL Format
- Ready-to-execute SQL INSERT statements
- Direct database import capability
- Includes table creation statements

## Features

### Asset Generator
- Generates realistic asset inventory data
- Supports 24+ asset types (Desktop, Laptop, Server, etc.)
- 4 location types (Remote, Internal, Data center, Cloud)
- Realistic network configurations and security settings
- Configurable asset type distributions

### Findings Generator
- Creates synthetic vulnerability findings
- Supports bias towards recent CVEs
- Configurable detection and false positive rates
- Links findings to generated or existing assets
- Realistic vulnerability data based on NVD database

### Smart Integration
- Automatic format conversion when needed
- Seamless chaining of asset and findings generation
- Intelligent default path handling
- Error handling and validation

## Configuration

The generators use configuration from `configs/generator_config.yaml` which includes:
- Default file paths
- Asset type definitions and distributions
- Location and network configurations
- Vulnerability detection settings
- Performance tuning parameters

## Requirements

- Python 3.7+
- Required packages are imported from the src modules
- Configuration file: `configs/generator_config.yaml`

## File Structure

```
SynthVuln/
├── generate.py              # Main entry point
├── src/
│   ├── asset_generator.py   # Asset generation logic
│   └── findings_generator.py # Findings generation logic
├── configs/
│   └── generator_config.yaml # Configuration file
├── utils/
│   └── util.py             # Utility functions
└── data/
    └── raw/                # Default output directory
```

## Error Handling

The generator includes comprehensive error handling:
- Validates command-line arguments
- Creates output directories automatically
- Handles format conversion between generators
- Provides clear error messages and logging
- Supports graceful cancellation (Ctrl+C)

## Logging

Detailed logging is provided for:
- Generation progress and statistics
- Configuration loading
- File operations
- Error conditions and warnings

Logs are written to separate files for each generator component.