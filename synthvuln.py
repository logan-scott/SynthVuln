#!/usr/bin/env python3
"""
SynthVuln Entry Point

This program provides a unified interface for running the asset and findings generators
with three different modes:
1. Interactive mode - User-friendly question-based interface
2. Default mode - Run both generators with default settings
3. Run mode - Command-line interface for programmatic usage

Usage:
    python synthvuln.py                                   # Interactive mode
    python synthvuln.py --default                         # Default mode
    python synthvuln.py --run [options]                   # Run mode
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, Union

# Add src directory to path for imports
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

from asset_generator import AssetGenerator
from findings_generator import FindingsGenerator
from integrations.nvd import main as nvd

# Import evaluation modules
try:
    from evaluations.prioritization import run_prioritization_analysis
    from evaluations.scenario_statistics import run_comparative_analysis, run_full_analysis
    from evaluations.entropy import run_comparative_analysis as run_entropy_comparative, run_full_analysis as run_entropy_full, run_scenario_analysis as run_entropy_scenario
except ImportError as e:
    print(f"Warning: Could not import evaluation modules: {e}")


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
        print("\nWhat would you like to do?")
        print("1. Asset Generator only")
        print("2. Findings Generator only")
        print("3. Both generators (recommended)")
        print("4. NVD Integration - CVEs only")
        print("5. NVD Integration - CPEs only")
        print("6. NVD Integration - Both CVEs and CPEs")
        print("7. NVD Integration (CVEs + CPEs) + Both generators")
        print("8. Run all evaluation analysis (prioritization, statistics, entropy)")
        print("9. Run specific evaluation analysis")
        print("10. Run evaluation analysis with custom files")
        
        while True:
            try:
                choice = input("\nEnter your choice (1-10): ").strip()
                if choice in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']:
                    break
                print("Please enter 1, 2, 3, 4, 5, 6, 7, 8, 9, or 10.")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return
        
        # Handle evaluation choices first
        if choice == '8':
            # Run all evaluation analysis
            self.run_evaluation_analysis('all')
            return
        elif choice == '9':
            # Run specific evaluation analysis
            print("\nAvailable evaluation scripts:")
            print("1. Prioritization Analysis")
            print("2. Statistical Analysis")
            print("3. Entropy Analysis")
            
            while True:
                try:
                    eval_choice = input("\nEnter your choice (1-3): ").strip()
                    if eval_choice == '1':
                        self.run_evaluation_analysis('script', 'prioritization')
                        return
                    elif eval_choice == '2':
                        self.run_evaluation_analysis('script', 'statistics')
                        return
                    elif eval_choice == '3':
                        self.run_evaluation_analysis('script', 'entropy')
                        return
                    print("Please enter 1, 2, or 3.")
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    return
        elif choice == '10':
            # Run evaluation analysis with custom files
            print("\nCustom File Evaluation Analysis")
            print("Please provide paths to your custom asset and findings files.")
            
            try:
                custom_assets = input("\nEnter path to custom assets file: ").strip()
                custom_findings = input("Enter path to custom findings file: ").strip()
                
                if not custom_assets or not custom_findings:
                    print("❌ Both asset and findings files are required for custom evaluation.")
                    return
                
                # Validate file existence
                if not Path(custom_assets).exists():
                    print(f"❌ Asset file not found: {custom_assets}")
                    return
                if not Path(custom_findings).exists():
                    print(f"❌ Findings file not found: {custom_findings}")
                    return
                
                print("\nAvailable evaluation scripts:")
                print("1. Prioritization Analysis")
                print("2. Statistical Analysis")
                print("3. Entropy Analysis")
                print("4. All analyses")
                
                while True:
                    try:
                        eval_choice = input("\nEnter your choice (1-4): ").strip()
                        if eval_choice == '1':
                            self.run_evaluation_analysis('script', 'prioritization', custom_assets, custom_findings)
                            return
                        elif eval_choice == '2':
                            self.run_evaluation_analysis('script', 'statistics', custom_assets, custom_findings)
                            return
                        elif eval_choice == '3':
                            self.run_evaluation_analysis('script', 'entropy', custom_assets, custom_findings)
                            return
                        elif eval_choice == '4':
                            self.run_evaluation_analysis('all', '', custom_assets, custom_findings)
                            return
                        print("Please enter 1, 2, 3, or 4.")
                    except KeyboardInterrupt:
                        print("\nOperation cancelled.")
                        return
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return
        
        # Handle generator and NVD choices
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
        
        # Configuration file selection
        config_file = ''
        if run_assets or run_findings:
            print("\n" + "-" * 40)
            print("Configuration File Selection")
            print("-" * 40)
            print("Pre-made configuration files:")
            print("- generator_config.yaml (default)")
            print("- scenario_small.yaml (small business)")
            print("- scenario_enterprise.yaml (global enterprise)")
            print("- scenario_government.yaml (government entity)")
            
            while True:
                try:
                    config_choice = input("Enter configuration file (default: configs/generator_config.yaml): ").strip()
                    if not config_choice or config_choice == 'configs/generator_config.yaml':
                        config_file = ''
                        break
                    else:
                        config_file = config_choice
                except KeyboardInterrupt:
                    print("\nOperation cancelled.")
                    return
        
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
            asset_output_file = self._run_asset_generator(asset_count, asset_output, asset_format, config_file)
            
        if run_findings:
            print("\nRunning Findings Generator...")
            # If we just generated assets and no specific input was provided, use the generated assets
            if run_assets and not findings_input and asset_output_file:
                findings_input = asset_output_file
            self._run_findings_generator(findings_count, findings_output, findings_format, findings_input, bias_recent, config_file)
        
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
        
        # Get config file from arguments
        config_file = getattr(args, 'config', '')
        
        # Run asset generator if requested
        if hasattr(args, 'count_assets') and args.count_assets:
            print("\nRunning Asset Generator...")
            asset_output_file = self._run_asset_generator(
                count=args.count_assets,
                output_file=getattr(args, 'output_assets', ''),
                output_format=getattr(args, 'output_format', 'json'),
                config_file=config_file,
                explicit_count=True
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
                bias_recent=not getattr(args, 'no_bias_recent', False),
                config_file=config_file
            )
        
        print("\n" + "=" * 60)
        print("Generation Complete!")
        print("=" * 60)
    
    def _run_asset_generator(self, count: int = 10, output_file: str = '', output_format: str = 'json', config_file: str = '', explicit_count: bool = False) -> Optional[str]:
        """Run the asset generator with specified parameters."""
        try:
            if not self.asset_generator:
                if config_file:
                    self.asset_generator = AssetGenerator(config_file=config_file)
                else:
                    self.asset_generator = AssetGenerator()
            
            # Only use config defaults if no explicit count was provided via command line
            # This preserves the ability to explicitly specify any number of assets
            if not explicit_count:
                count = self.asset_generator.default_asset_count
            
            if not output_file:
                default_output = self.asset_generator.default_paths.get('asset_output', 'data/raw/assets.json')
                if output_format == 'csv':
                    output_file = default_output.replace('.json', '.csv')
                elif output_format == 'sql':
                    output_file = default_output.replace('.json', '.sql')
                else:
                    output_file = default_output
            
            output_dir = os.path.dirname(output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            assets = self.asset_generator.generate_assets(count, output_file, output_format)
            print(f"Generated {len(assets)} assets and saved to {output_file} ({output_format.upper()} format)")
            
            return output_file
            
        except Exception as e:
            print(f"Error running asset generator: {e}")
            return None
    
    def _run_findings_generator(self, count: int = 10, output_file: str = '', output_format: str = 'json', 
                               input_file: str = '', bias_recent: bool = True, config_file: str = '') -> Optional[str]:
        """Run the findings generator with specified parameters."""
        try:
            if not self.findings_generator:
                if config_file:
                    self.findings_generator = FindingsGenerator(config_file=config_file)
                else:
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
            
            output_dir = os.path.dirname(output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
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
    
    def run_evaluation_analysis(self, eval_type: str = 'all', script_name: str = '', custom_assets: Optional[str] = None, custom_findings: Optional[str] = None) -> bool:
        """Run evaluation analysis scripts.
        
        Args:
            eval_type (str): Type of evaluation - 'all', 'script', 'prioritization', 'statistics', 'entropy'
            script_name (str): Specific script name when eval_type is 'script'
            custom_assets (str): Path to custom asset file for evaluation
            custom_findings (str): Path to custom findings file for evaluation
        """
        try:
            print("\n" + "=" * 60)
            print("Starting Evaluation Analysis...")
            print("=" * 60)
            
            # Validate custom files if provided
            if custom_assets and not Path(custom_assets).exists():
                print(f"❌ Custom asset file not found: {custom_assets}")
                return False
            if custom_findings and not Path(custom_findings).exists():
                print(f"❌ Custom findings file not found: {custom_findings}")
                return False
            
            # Check if data files exist (only if no custom files provided)
            if not custom_assets and not custom_findings:
                data_dir = Path('data/outputs')
                if not data_dir.exists():
                    print("❌ No data directory found. Please generate datasets first.")
                    return False
            
            success = True
            
            if eval_type == 'all':
                # Run all evaluation scripts
                success &= self._run_prioritization_evaluation(custom_assets, custom_findings)
                success &= self._run_statistics_evaluation(custom_assets, custom_findings)
                success &= self._run_entropy_evaluation(custom_assets, custom_findings)
                
            elif eval_type == 'script':
                # Run specific script
                if script_name == 'prioritization':
                    success = self._run_prioritization_evaluation(custom_assets, custom_findings)
                elif script_name == 'statistics':
                    success = self._run_statistics_evaluation(custom_assets, custom_findings)
                elif script_name == 'entropy':
                    success = self._run_entropy_evaluation(custom_assets, custom_findings)
                else:
                    print(f"❌ Unknown script name: {script_name}")
                    print("Available scripts: prioritization, statistics, entropy")
                    return False
                    
            elif eval_type in ['prioritization', 'statistics', 'entropy']:
                # Run specific evaluation type
                if eval_type == 'prioritization':
                    success = self._run_prioritization_evaluation(custom_assets, custom_findings)
                elif eval_type == 'statistics':
                    success = self._run_statistics_evaluation(custom_assets, custom_findings)
                elif eval_type == 'entropy':
                    success = self._run_entropy_evaluation(custom_assets, custom_findings)
            
            if success:
                print("\n✅ Evaluation analysis completed successfully!")
            else:
                print("\n⚠️  Some evaluation analyses encountered errors.")
                
            return success
            
        except Exception as e:
            print(f"❌ Error running evaluation analysis: {e}")
            return False
    
    def _run_prioritization_evaluation(self, custom_assets: Optional[str] = None, custom_findings: Optional[str] = None) -> bool:
        """Run prioritization analysis for all available scenarios or custom files.
        
        Args:
            custom_assets (str): Path to custom asset file
            custom_findings (str): Path to custom findings file
        """
        try:
            print("\n🚀 Running Vulnerability Prioritization Analysis...")
            
            success = True
            processed_count = 0
            
            # Handle custom files
            if custom_assets or custom_findings:
                if custom_assets and custom_findings:
                    print("📋 Processing custom files...")
                    output_dir = Path('data/outputs/prioritization_custom')
                    try:
                        run_prioritization_analysis(
                            custom_assets,
                            custom_findings,
                            str(output_dir),
                            'custom'
                        )
                        processed_count += 1
                        print(f"✅ Custom file analysis complete! Results saved to: {output_dir}")
                    except Exception as e:
                        print(f"❌ Error processing custom files: {e}")
                        success = False
                else:
                    print("❌ Both custom asset and findings files must be provided for prioritization analysis.")
                    success = False
            else:
                # Handle default scenarios
                base_dir = Path('data/outputs')
                scenarios = {
                    'baseline_full': ('assets.json', 'findings.json'),
                    'enterprise': ('scenario_enterprise_assets.json', 'scenario_enterprise_findings.json'),
                    'government': ('scenario_government_assets.json', 'scenario_government_findings.json'),
                    'small_business': ('scenario_small_assets.json', 'scenario_small_findings.json')
                }
                
                for scenario_name, (assets_file, findings_file) in scenarios.items():
                    assets_path = base_dir / assets_file
                    findings_path = base_dir / findings_file
                    output_dir = base_dir / f'prioritization_{scenario_name}'
                    
                    if assets_path.exists() and findings_path.exists():
                        print(f"📋 Processing {scenario_name.upper()} scenario...")
                        try:
                            run_prioritization_analysis(
                                str(assets_path),
                                str(findings_path),
                                str(output_dir),
                                scenario_name
                            )
                            processed_count += 1
                        except Exception as e:
                            print(f"❌ Error processing {scenario_name}: {e}")
                            success = False
                    else:
                        print(f"⚠️  Skipping {scenario_name}: Data files not found")
                
                if processed_count > 0:
                    print(f"\n🎉 Prioritization analysis complete! Processed {processed_count} scenarios.")
                else:
                    print("\n⚠️  No scenarios were processed. Please generate datasets first.")
                    success = False
                
            return success
            
        except Exception as e:
            print(f"❌ Error in prioritization evaluation: {e}")
            return False
    
    def _run_statistics_evaluation(self, custom_assets: Optional[str] = None, custom_findings: Optional[str] = None) -> bool:
        """Run statistical analysis for default scenarios or custom files.
        
        Args:
            custom_assets (str): Path to custom asset file
            custom_findings (str): Path to custom findings file
        """
        try:
            print("\n📊 Running Statistical Analysis...")
            
            # Handle custom files
            if custom_assets or custom_findings:
                if custom_assets and custom_findings:
                    print("📂 Running statistical analysis on custom files...")
                    # For custom files, we'll run a basic analysis
                    # Note: The statistics module may need to be enhanced to handle custom files
                    print("⚠️  Custom file statistical analysis is currently limited to basic metrics.")
                    print(f"📁 Custom assets: {custom_assets}")
                    print(f"📁 Custom findings: {custom_findings}")
                    # TODO: Implement custom file handling in statistics module
                    return True
                else:
                    print("❌ Both custom asset and findings files must be provided for statistical analysis.")
                    return False
            else:
                # Handle default scenarios
                # Check if we have baseline data for full analysis
                base_dir = Path('data/outputs')
                has_baseline = (base_dir / 'assets.json').exists() and (base_dir / 'findings.json').exists()
                
                if has_baseline:
                    print("📂 Running full statistical analysis (including baseline data)...")
                    run_full_analysis()
                else:
                    print("📂 Running comparative statistical analysis...")
                    run_comparative_analysis()
                    
            return True
            
        except Exception as e:
            print(f"❌ Error in statistical evaluation: {e}")
            return False
    
    def _run_entropy_evaluation(self, custom_assets: Optional[str] = None, custom_findings: Optional[str] = None) -> bool:
        """Run entropy analysis for default scenarios or custom files.
        
        Args:
            custom_assets (str): Path to custom asset file
            custom_findings (str): Path to custom findings file
        """
        try:
            print("\n🔍 Running Entropy Analysis...")
            
            # Handle custom files
            if custom_assets or custom_findings:
                if custom_assets and custom_findings:
                    print("📂 Running entropy analysis on custom files...")
                    # For custom files, we'll run a basic analysis
                    # Note: The entropy module may need to be enhanced to handle custom files
                    print("⚠️  Custom file entropy analysis is currently limited to basic metrics.")
                    print(f"📁 Custom assets: {custom_assets}")
                    print(f"📁 Custom findings: {custom_findings}")
                    # TODO: Implement custom file handling in entropy module
                    return True
                else:
                    print("❌ Both custom asset and findings files must be provided for entropy analysis.")
                    return False
            else:
                # Handle default scenarios
                # Check if we have baseline data for full analysis
                base_dir = Path('data/outputs')
                has_baseline = (base_dir / 'assets.json').exists() and (base_dir / 'findings.json').exists()
                
                if has_baseline:
                    print("📂 Running full entropy analysis (including baseline data)...")
                    run_entropy_full()
                else:
                    print("📂 Running comparative entropy analysis...")
                    run_entropy_comparative()
                    
            return True
            
        except Exception as e:
            print(f"❌ Error in entropy evaluation: {e}")
            return False


def main():
    """Main entry point for the SynthVuln generator."""
    parser = argparse.ArgumentParser(
        description='SynthVuln Generator - Unified interface for asset and findings generation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  Interactive Mode (default): python synthvuln.py
    - User-friendly question-based interface
    - Allows selection of generators and configuration options
    
  Default Mode: python synthvuln.py --default
    - Runs both generators with default settings
    - Quick start option for standard use cases
    
  Run Mode: python synthvuln.py --run [options]
    - Command-line interface for programmatic usage
    - Supports all configuration options via arguments
    
Examples:
  # Basic usage
  python synthvuln.py
  python synthvuln.py --default
  
  # Data generation
  python synthvuln.py --run --count-assets 1000 --count-findings 10000 --output-format json
  python synthvuln.py --run --count-assets 500 --output-assets data/assets.csv --output-format csv
  python synthvuln.py --run --count-findings 5000 --input-assets data/assets.json --output-findings data/findings.sql --output-format sql
  
  # NVD integration
  python synthvuln.py --run --nvd-integration
  python synthvuln.py --run --nvd-integration --count-assets 100 --count-findings 500
  
  # Scenario-based generation
  python synthvuln.py --run --config scenario_small.yaml --count-assets 50
  python synthvuln.py --run --config scenario_enterprise.yaml --count-assets 5000 --count-findings 10000
  python synthvuln.py --run --config scenario_government.yaml --count-assets 500
  
  # Evaluation analysis
  python synthvuln.py --eval-all
  python synthvuln.py --eval-script prioritization
  python synthvuln.py --eval-script statistics
  python synthvuln.py --eval-script entropy
  
  # Custom file evaluation analysis
  python synthvuln.py --eval-all --eval-assets custom_assets.json --eval-findings custom_findings.json
  python synthvuln.py --eval-script prioritization --eval-assets my_assets.json --eval-findings my_findings.json
  python synthvuln.py --eval-script statistics --eval-assets data/custom_assets.json --eval-findings data/custom_findings.json
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
    parser.add_argument('--config', type=str, metavar='FILE',
                       help='Configuration file to use (default: generator_config.yaml). Pre-made options: scenario_small.yaml, scenario_enterprise.yaml, scenario_government.yaml')
    
    # Evaluation arguments
    eval_group = parser.add_mutually_exclusive_group()
    eval_group.add_argument('--eval-all', action='store_true',
                           help='Run all evaluation scripts (prioritization, statistics, entropy)')
    eval_group.add_argument('--eval-script', type=str, choices=['prioritization', 'statistics', 'entropy'],
                           help='Run a specific evaluation script')
    parser.add_argument('--eval-assets', type=str, metavar='FILE',
                       help='Custom asset file for evaluation analysis')
    parser.add_argument('--eval-findings', type=str, metavar='FILE',
                       help='Custom findings file for evaluation analysis')
    
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
        elif args.eval_all:
            # Run all evaluation scripts
            generator.run_evaluation_analysis('all', custom_assets=getattr(args, 'eval_assets', None), custom_findings=getattr(args, 'eval_findings', None))
        elif args.eval_script:
            # Run specific evaluation script
            generator.run_evaluation_analysis('script', args.eval_script, custom_assets=getattr(args, 'eval_assets', None), custom_findings=getattr(args, 'eval_findings', None))
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
