#!/usr/bin/env python3
"""
SynthVuln Entry Point

This program provides a unified interface for running the asset and findings generators
with three different modes:
1. Interactive mode - User-friendly question-based interface
2. Default mode - Run both generators with default settings
3. Run mode - Command-line interface for programmatic usage

Usage:
    python generate.py                                    # Interactive mode
    python generate.py --default                          # Default mode
    python generate.py --run [options]                    # Run mode
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

# Add src directory to path for imports
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

from asset_generator import AssetGenerator
from findings_generator import FindingsGenerator
from integrations.nvd import main as nvd


class SynthVulnGenerator:
    """Main controller for the SynthVuln generation system."""
    
    def __init__(self):
        """Initialize the generator controller."""
        self.asset_generator = None
        self.findings_generator = None
        
    def interactive_mode(self):
        """Run the generator in interactive question mode."""
        print("\n" + "=" * 60)
        print("SynthVuln Generator - Interactive Mode")
        print("=" * 60)
        
        # Ask which generators to run
        print("\nWhich generators would you like to run?")
        print("1. Asset Generator only")
        print("2. Findings Generator only")
        print("3. Both generators (recommended)")
        print("4. NVD Integration - CVEs only")
        print("5. NVD Integration - CPEs only")
        print("6. NVD Integration - Both CVEs and CPEs")
        print("7. NVD Integration (CVEs + CPEs) + Both generators")
        
        while True:
            try:
                choice = input("\nEnter your choice (1-7): ").strip()
                if choice in ['1', '2', '3', '4', '5', '6', '7']:
                    break
                print("Please enter 1, 2, 3, 4, 5, 6, or 7.")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return
        
        run_nvd = choice in ['4', '5', '6', '7']
        nvd_collection_type = 'both'  # default
        if choice == '4':
            nvd_collection_type = 'cves'
        elif choice == '5':
            nvd_collection_type = 'cpes'
        elif choice in ['6', '7']:
            nvd_collection_type = 'both'
            
        run_assets = choice in ['1', '3', '7']
        run_findings = choice in ['2', '3', '7']
        
        # Asset generator configuration
        asset_count = 10
        asset_output = ""
        asset_format = "json"
        
        if run_assets:
            print("\n" + "-" * 40)
            print("Asset Generator Configuration")
            print("-" * 40)
            
            # Get asset count
            while True:
                try:
                    count_input = input("Number of assets to generate (default: 10): ").strip()
                    if not count_input:
                        asset_count = 10
                        break
                    asset_count = int(count_input)
                    if asset_count > 0:
                        break
                    print("Please enter a positive number.")
                except ValueError:
                    print("Please enter a valid number.")
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    return
            
            # Get output file
            asset_output = input("Asset output file (press Enter for default): ").strip()
            
            # Get output format
            print("\nOutput format options:")
            print("1. JSON (default)")
            print("2. CSV")
            print("3. SQL")
            
            while True:
                try:
                    format_choice = input("Choose format (1-3, default: 1): ").strip()
                    if not format_choice or format_choice == '1':
                        asset_format = "json"
                        break
                    elif format_choice == '2':
                        asset_format = "csv"
                        break
                    elif format_choice == '3':
                        asset_format = "sql"
                        break
                    print("Please enter 1, 2, or 3.")
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    return
        
        # Findings generator configuration
        findings_count = 10
        findings_output = ""
        findings_format = "json"
        findings_input = ""
        bias_recent = True
        
        if run_findings:
            print("\n" + "-" * 40)
            print("Findings Generator Configuration")
            print("-" * 40)
            
            # Get findings count
            while True:
                try:
                    count_input = input("Number of findings to generate (default: 10): ").strip()
                    if not count_input:
                        findings_count = 10
                        break
                    findings_count = int(count_input)
                    if findings_count > 0:
                        break
                    print("Please enter a positive number.")
                except ValueError:
                    print("Please enter a valid number.")
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    return
            
            # Get input file (if running findings only)
            if not run_assets:
                findings_input = input("Input asset file (press Enter for default): ").strip()
            
            # Get output file
            findings_output = input("Findings output file (press Enter for default): ").strip()
            
            # Get output format
            print("\nOutput format options:")
            print("1. JSON (default)")
            print("2. CSV")
            print("3. SQL")
            
            while True:
                try:
                    format_choice = input("Choose format (1-3, default: 1): ").strip()
                    if not format_choice or format_choice == '1':
                        findings_format = "json"
                        break
                    elif format_choice == '2':
                        findings_format = "csv"
                        break
                    elif format_choice == '3':
                        findings_format = "sql"
                        break
                    print("Please enter 1, 2, or 3.")
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    return
            
            # Ask about recent bias
            while True:
                try:
                    bias_input = input("Bias towards recent CVEs? (Y/n, default: Y): ").strip().lower()
                    if not bias_input or bias_input in ['y', 'yes']:
                        bias_recent = True
                        break
                    elif bias_input in ['n', 'no']:
                        bias_recent = False
                        break
                    print("Please enter Y or N.")
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    return
        
        # Execute generators
        print("\n" + "=" * 60)
        print("Starting Generation...")
        print("=" * 60)
        
        # Run NVD integration if requested
        if run_nvd:
            print(f"\nRunning NVD Integration ({nvd_collection_type.upper()})...")
            self._run_nvd_integration(nvd_collection_type)
        
        asset_output_file = None
        if run_assets:
            print("\nRunning Asset Generator...")
            asset_output_file = self._run_asset_generator(asset_count, asset_output, asset_format)
            
        if run_findings:
            print("\nRunning Findings Generator...")
            # If we just generated assets and no specific input was provided, use the generated assets
            if run_assets and not findings_input and asset_output_file:
                findings_input = asset_output_file
            self._run_findings_generator(findings_count, findings_output, findings_format, findings_input, bias_recent)
        
        print("\n" + "=" * 60)
        print("Generation Complete!")
        print("=" * 60)
    
    def default_mode(self):
        """Run both generators with default settings."""
        print("\n" + "=" * 60)
        print("SynthVuln Generator - Default Mode")
        print("=" * 60)
        
        print("\nRunning Asset Generator with default settings...")
        asset_output_file = self._run_asset_generator()
        
        print("\nRunning Findings Generator with default settings...")
        self._run_findings_generator(input_file=asset_output_file if asset_output_file else '')
        
        print("\n" + "=" * 60)
        print("Generation Complete!")
        print("=" * 60)
    
    def run_mode(self, args):
        """Run generators based on command-line arguments."""
        print("\n" + "=" * 60)
        print("SynthVuln Generator - Run Mode")
        print("=" * 60)
        
        # Run NVD integration if requested
        if hasattr(args, 'nvd_integration') and args.nvd_integration:
            collection_type = getattr(args, 'nvd_collection_type', 'both')
            print(f"\nRunning NVD Integration ({collection_type.upper()})...")
            self._run_nvd_integration(collection_type)
        
        asset_output_file = None
        
        # Run asset generator if requested
        if hasattr(args, 'count_assets') and args.count_assets:
            print("\nRunning Asset Generator...")
            asset_output_file = self._run_asset_generator(
                count=args.count_assets,
                output_file=getattr(args, 'output_assets', ''),
                output_format=getattr(args, 'output_format', 'json')
            )
        
        # Run findings generator if requested
        if hasattr(args, 'count_findings') and args.count_findings:
            print("\nRunning Findings Generator...")
            input_file = getattr(args, 'input_assets', '')
            # If we just generated assets and no specific input was provided, use the generated assets
            if asset_output_file and not input_file:
                input_file = asset_output_file
                
            self._run_findings_generator(
                count=args.count_findings,
                output_file=getattr(args, 'output_findings', ''),
                output_format=getattr(args, 'output_format', 'json'),
                input_file=input_file,
                bias_recent=not getattr(args, 'no_bias_recent', False)
            )
        
        print("\n" + "=" * 60)
        print("Generation Complete!")
        print("=" * 60)
    
    def _run_asset_generator(self, count: int = 10, output_file: str = '', output_format: str = 'json') -> Optional[str]:
        """Run the asset generator with specified parameters."""
        try:
            if not self.asset_generator:
                self.asset_generator = AssetGenerator()
            
            # Use config defaults if not specified
            if count == 10:
                count = self.asset_generator.default_asset_count
            
            if not output_file:
                default_output = self.asset_generator.default_paths.get('asset_output', 'data/raw/assets.json')
                if output_format == 'csv':
                    output_file = default_output.replace('.json', '.csv')
                elif output_format == 'sql':
                    output_file = default_output.replace('.json', '.sql')
                else:
                    output_file = default_output
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            assets = self.asset_generator.generate_assets(count, output_file, output_format)
            print(f"Generated {len(assets)} assets and saved to {output_file} ({output_format.upper()} format)")
            
            return output_file
            
        except Exception as e:
            print(f"Error running asset generator: {e}")
            return None
    
    def _run_findings_generator(self, count: int = 10, output_file: str = '', output_format: str = 'json', 
                               input_file: str = '', bias_recent: bool = True) -> Optional[str]:
        """Run the findings generator with specified parameters."""
        try:
            if not self.findings_generator:
                self.findings_generator = FindingsGenerator()
            
            # Initialize the generator
            self.findings_generator.initialize_for_generation(
                asset_file=input_file,
                num_findings=count,
                bias_recent=bias_recent
            )
            
            # Use config defaults if not specified
            if not output_file:
                default_output = self.findings_generator.config.get('default_paths', {}).get('findings_output', 'data/raw/findings.json')
                if output_format == 'csv':
                    output_file = default_output.replace('.json', '.csv')
                elif output_format == 'sql':
                    output_file = default_output.replace('.json', '.sql')
                else:
                    output_file = default_output
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            findings = self.findings_generator.generate_findings(
                num_findings=count,
                detection_probability=0.7,
                false_positive_rate=0.1
            )
            
            self.findings_generator.save_findings(findings, output_file, output_format)
            print(f"Generated {len(findings)} findings and saved to {output_file} ({output_format.upper()} format)")
            
            return output_file
            
        except Exception as e:
            print(f"Error running findings generator: {e}")
            return None
    
    def _run_nvd_integration(self, collection_type: str = 'both') -> bool:
        """Run the NVD integration to fetch vulnerability and/or CPE data.
        
        Args:
            collection_type (str): Type of data to collect - 'cves', 'cpes', or 'both'
        """
        try:
            # Import the NVD integration module
            nvd_path = os.path.join(os.path.dirname(__file__), 'integrations')
            sys.path.insert(0, nvd_path)
            
            # Run the NVD integration with specified collection type
            nvd(collection_type)
            print("NVD integration completed successfully!")
            return True
            
        except Exception as e:
            print(f"Error running NVD integration: {e}")
            return False


def main():
    """Main entry point for the SynthVuln generator."""
    parser = argparse.ArgumentParser(
        description='SynthVuln Generator - Unified interface for asset and findings generation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  Interactive Mode (default): python generate.py
    - User-friendly question-based interface
    - Allows selection of generators and configuration options
    
  Default Mode: python generate.py --default
    - Runs both generators with default settings
    - Quick start option for standard use cases
    
  Run Mode: python generate.py --run [options]
    - Command-line interface for programmatic usage
    - Supports all configuration options via arguments
    
Examples:
  python generate.py
  python generate.py --default
  python generate.py --run --count-assets 1000 --count-findings 10000 --output-format json
  python generate.py --run --count-assets 500 --output-assets data/assets.csv --output-format csv
  python generate.py --run --count-findings 5000 --input-assets data/assets.json --output-findings data/findings.sql --output-format sql
  python generate.py --run --nvd-integration
  python generate.py --run --nvd-integration --count-assets 100 --count-findings 500
"""
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--default', action='store_true',
                           help='Run both generators with default settings')
    mode_group.add_argument('--run', action='store_true',
                           help='Run mode with command-line arguments')
    
    # Run mode arguments
    parser.add_argument('--count-assets', type=int, metavar='N',
                       help='Number of assets to generate')
    parser.add_argument('--count-findings', type=int, metavar='N',
                       help='Number of findings to generate')
    parser.add_argument('--output-assets', type=str, metavar='FILE',
                       help='Asset output file path')
    parser.add_argument('--output-findings', type=str, metavar='FILE',
                       help='Findings output file path')
    parser.add_argument('--input-assets', type=str, metavar='FILE',
                       help='Input asset file for findings generator')
    parser.add_argument('--output-format', type=str, choices=['json', 'csv', 'sql'], default='json',
                       help='Output format for generated files (default: json)')
    parser.add_argument('--no-bias-recent', action='store_true',
                       help='Disable bias towards recent CVEs in findings generation')
    parser.add_argument('--nvd-integration', action='store_true',
                       help='Run NVD integration to fetch vulnerability data')
    parser.add_argument('--nvd-collection-type', type=str, choices=['cves', 'cpes', 'both'], default='both',
                       help='Type of NVD data to collect: cves, cpes, or both (default: both)')
    
    args = parser.parse_args()
    
    generator = SynthVulnGenerator()
    
    try:
        if args.default:
            generator.default_mode()
        elif args.run:
            # Validate run mode arguments
            if not args.count_assets and not args.count_findings and not getattr(args, 'nvd_integration', False):
                print("Error: Run mode requires at least --count-assets, --count-findings, or --nvd-integration")
                parser.print_help()
                sys.exit(1)
            generator.run_mode(args)
        else:
            # Interactive mode (default)
            generator.interactive_mode()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()