#!/usr/bin/env python3
"""
Shannon Entropy Analysis for SynthVuln Scenarios

This script computes Shannon entropy of categorical distributions across
different vulnerability scenarios to analyze data diversity and randomness.
"""

import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import entropy
from collections import Counter
import os
import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.util import load_config

def calculate_shannon_entropy(data, base=2):
    """
    Calculate Shannon entropy for a categorical distribution.
    
    Args:
        data: List or array of categorical values
        base: Logarithm base (2 for bits, e for nats)
    
    Returns:
        float: Shannon entropy value
    """
    if len(data) == 0:
        return 0.0
    
    # Count frequencies
    value_counts = Counter(data)
    total_count = len(data)
    
    # Calculate probabilities
    probabilities = [count / total_count for count in value_counts.values()]
    
    # Calculate Shannon entropy
    return entropy(probabilities, base=base)

def calculate_normalized_entropy(data):
    """
    Calculate normalized Shannon entropy (0 to 1 scale).
    
    Args:
        data: List or array of categorical values
    
    Returns:
        float: Normalized entropy (0 = no diversity, 1 = maximum diversity)
    """
    if len(data) == 0:
        return 0.0
    
    # Calculate Shannon entropy
    h = calculate_shannon_entropy(data, base=2)
    
    # Calculate maximum possible entropy (log2 of number of unique values)
    unique_values = len(set(data))
    if unique_values <= 1:
        return 0.0
    
    max_entropy = np.log2(unique_values)
    
    # Normalize
    return h / max_entropy if max_entropy > 0 else 0.0

def load_scenario_data(scenario_name):
    """
    Load assets and findings data for a specific scenario.
    
    Args:
        scenario_name: Name of the scenario (e.g., 'enterprise', 'government', 'small')
    
    Returns:
        tuple: (assets_df, findings_df) or (None, None) if files don't exist
    """
    base_path = Path('data/outputs')
    
    assets_file = base_path / f'scenario_{scenario_name}_assets.json'
    findings_file = base_path / f'scenario_{scenario_name}_findings.json'
    
    try:
        # Load assets
        if assets_file.exists():
            with open(assets_file, 'r') as f:
                assets = json.load(f)
            assets_df = pd.DataFrame(assets)
        else:
            print(f"Warning: {assets_file} not found")
            assets_df = pd.DataFrame()
        
        # Load findings
        if findings_file.exists():
            with open(findings_file, 'r') as f:
                findings = json.load(f)
            findings_df = pd.DataFrame(findings)
        else:
            print(f"Warning: {findings_file} not found")
            findings_df = pd.DataFrame()
        
        return assets_df, findings_df
    
    except Exception as e:
        print(f"Error loading {scenario_name} data: {e}")
        return pd.DataFrame(), pd.DataFrame()

def analyze_categorical_entropy(df, categorical_columns, scenario_name):
    """
    Analyze entropy for categorical columns in a DataFrame.
    
    Args:
        df: DataFrame to analyze
        categorical_columns: List of column names to analyze
        scenario_name: Name of the scenario for reporting
    
    Returns:
        dict: Entropy analysis results
    """
    results = {
        'scenario': scenario_name,
        'total_records': len(df),
        'columns': {}
    }
    
    for col in categorical_columns:
        if col in df.columns and not df[col].empty:
            data = df[col].dropna().astype(str)
            
            if len(data) > 0:
                shannon_entropy = calculate_shannon_entropy(data)
                normalized_entropy = calculate_normalized_entropy(data)
                unique_values = len(data.unique())
                most_common = data.value_counts().head(3).to_dict()
                
                results['columns'][col] = {
                    'shannon_entropy': round(float(shannon_entropy), 4),
                    'normalized_entropy': round(float(normalized_entropy), 4),
                    'unique_values': unique_values,
                    'total_values': len(data),
                    'most_common': most_common
                }
            else:
                results['columns'][col] = {
                    'shannon_entropy': 0.0,
                    'normalized_entropy': 0.0,
                    'unique_values': 0,
                    'total_values': 0,
                    'most_common': {}
                }
    
    return results

def compare_scenarios_entropy(scenarios_data):
    """
    Compare entropy across different scenarios.
    
    Args:
        scenarios_data: Dict of scenario entropy results
    
    Returns:
        pd.DataFrame: Comparison table
    """
    comparison_data = []
    
    for scenario_name, scenario_data in scenarios_data.items():
        for col_name, col_data in scenario_data['columns'].items():
            comparison_data.append({
                'scenario': scenario_name,
                'column': col_name,
                'shannon_entropy': col_data['shannon_entropy'],
                'normalized_entropy': col_data['normalized_entropy'],
                'unique_values': col_data['unique_values'],
                'total_values': col_data['total_values']
            })
    
    return pd.DataFrame(comparison_data)

def create_entropy_visualizations(comparison_df, output_dir):
    """
    Create visualizations for entropy analysis.
    
    Args:
        comparison_df: DataFrame with entropy comparison data
        output_dir: Directory to save plots
    """
    if comparison_df.empty:
        print("No data available for visualization")
        return
    
    # Set up the plotting style
    plt.style.use('seaborn-v0_8')
    sns.set_palette('husl')
    
    # 1. Shannon Entropy Comparison
    plt.figure(figsize=(12, 8))
    
    # Pivot for heatmap
    entropy_pivot = comparison_df.pivot(index='column', columns='scenario', values='shannon_entropy')
    
    sns.heatmap(entropy_pivot, annot=True, cmap='viridis', fmt='.3f')
    plt.title('Shannon Entropy Comparison Across Scenarios')
    plt.xlabel('Scenario')
    plt.ylabel('Column')
    plt.tight_layout()
    plt.savefig(output_dir / 'shannon_entropy_heatmap.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    # 2. Normalized Entropy Comparison
    plt.figure(figsize=(12, 8))
    
    normalized_pivot = comparison_df.pivot(index='column', columns='scenario', values='normalized_entropy')
    
    sns.heatmap(normalized_pivot, annot=True, cmap='plasma', fmt='.3f', vmin=0, vmax=1)
    plt.title('Normalized Entropy Comparison Across Scenarios')
    plt.xlabel('Scenario')
    plt.ylabel('Column')
    plt.tight_layout()
    plt.savefig(output_dir / 'normalized_entropy_heatmap.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    # 3. Bar plot for each column
    unique_columns = comparison_df['column'].unique()
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    axes = axes.flatten()
    
    for i, col in enumerate(unique_columns[:4]):  # Show first 4 columns
        if i < len(axes):
            col_data = comparison_df[comparison_df['column'] == col]
            
            axes[i].bar(col_data['scenario'], col_data['normalized_entropy'])
            axes[i].set_title(f'Normalized Entropy: {col}')
            axes[i].set_ylabel('Normalized Entropy')
            axes[i].set_ylim(0, 1)
            
            # Add value labels on bars
            for j, v in enumerate(col_data['normalized_entropy']):
                axes[i].text(j, v + 0.01, f'{v:.3f}', ha='center', va='bottom')
    
    # Hide unused subplots
    for i in range(len(unique_columns), len(axes)):
        axes[i].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(output_dir / 'entropy_by_column.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    # 4. Diversity Score Summary
    plt.figure(figsize=(10, 6))
    
    # Calculate average normalized entropy per scenario
    avg_entropy = comparison_df.groupby('scenario')['normalized_entropy'].mean().reset_index()
    
    bars = plt.bar(avg_entropy['scenario'], avg_entropy['normalized_entropy'])
    plt.title('Average Data Diversity Score by Scenario')
    plt.xlabel('Scenario')
    plt.ylabel('Average Normalized Entropy')
    plt.ylim(0, 1)
    
    # Add value labels
    for bar, value in zip(bars, avg_entropy['normalized_entropy']):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
                f'{value:.3f}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(output_dir / 'average_diversity_score.png', dpi=300, bbox_inches='tight')
    plt.show()

def generate_entropy_report(scenarios_data, comparison_df, output_file):
    """
    Generate a comprehensive entropy analysis report.
    
    Args:
        scenarios_data: Dict of scenario entropy results
        comparison_df: DataFrame with entropy comparison data
        output_file: Path to save the report
    """
    report_lines = [
        "=" * 80,
        "SHANNON ENTROPY ANALYSIS REPORT",
        "=" * 80,
        "",
        f"Generated on: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "OVERVIEW:",
        "-" * 40,
        "Shannon entropy measures the diversity and randomness of categorical data.",
        "Higher entropy indicates more diverse/random distributions.",
        "Normalized entropy ranges from 0 (no diversity) to 1 (maximum diversity).",
        "",
    ]
    
    # Summary statistics
    if not comparison_df.empty:
        avg_entropy_by_scenario = comparison_df.groupby('scenario')['normalized_entropy'].agg(['mean', 'std']).round(4)
        
        report_lines.extend([
            "SCENARIO SUMMARY:",
            "-" * 40,
        ])
        
        for scenario in avg_entropy_by_scenario.index:
            mean_entropy = avg_entropy_by_scenario.loc[scenario, 'mean']
            std_entropy = avg_entropy_by_scenario.loc[scenario, 'std']
            total_records = scenarios_data.get(scenario, {}).get('total_records', 0)
            
            report_lines.extend([
                f"{scenario.upper()} Scenario:",
                f"  Total Records: {total_records:,}",
                f"  Average Normalized Entropy: {mean_entropy:.4f} ± {std_entropy:.4f}",
                f"  Diversity Level: {get_diversity_level(mean_entropy)}",
                ""
            ])
    
    # Detailed analysis by column
    report_lines.extend([
        "DETAILED ANALYSIS BY COLUMN:",
        "=" * 80,
    ])
    
    for scenario_name, scenario_data in scenarios_data.items():
        report_lines.extend([
            f"{scenario_name.upper()} SCENARIO:",
            "-" * 40,
        ])
        
        for col_name, col_data in scenario_data['columns'].items():
            shannon_ent = col_data['shannon_entropy']
            norm_ent = col_data['normalized_entropy']
            unique_vals = col_data['unique_values']
            total_vals = col_data['total_values']
            
            report_lines.extend([
                f"Column: {col_name}",
                f"  Shannon Entropy: {shannon_ent:.4f} bits",
                f"  Normalized Entropy: {norm_ent:.4f}",
                f"  Unique Values: {unique_vals:,}",
                f"  Total Values: {total_vals:,}",
                f"  Diversity Level: {get_diversity_level(norm_ent)}",
            ])
            
            # Most common values
            if col_data['most_common']:
                report_lines.append("  Most Common Values:")
                for value, count in col_data['most_common'].items():
                    percentage = (count / total_vals) * 100 if total_vals > 0 else 0
                    report_lines.append(f"    {value}: {count:,} ({percentage:.1f}%)")
            
            report_lines.append("")
        
        report_lines.append("")
    
    # Recommendations
    report_lines.extend([
        "RECOMMENDATIONS:",
        "=" * 80,
        get_entropy_recommendations(comparison_df),
        "",
        "=" * 80,
        "End of Report",
        "=" * 80
    ])
    
    # Write report
    with open(output_file, 'w') as f:
        f.write('\n'.join(report_lines))
    
    print(f"Entropy analysis report saved to: {output_file}")

def get_diversity_level(normalized_entropy):
    """
    Categorize diversity level based on normalized entropy.
    
    Args:
        normalized_entropy: Normalized entropy value (0-1)
    
    Returns:
        str: Diversity level description
    """
    if normalized_entropy >= 0.8:
        return "Very High Diversity"
    elif normalized_entropy >= 0.6:
        return "High Diversity"
    elif normalized_entropy >= 0.4:
        return "Moderate Diversity"
    elif normalized_entropy >= 0.2:
        return "Low Diversity"
    else:
        return "Very Low Diversity"

def get_entropy_recommendations(comparison_df):
    """
    Generate recommendations based on entropy analysis.
    
    Args:
        comparison_df: DataFrame with entropy comparison data
    
    Returns:
        str: Recommendations text
    """
    if comparison_df.empty:
        return "No data available for recommendations."
    
    recommendations = []
    
    # Find columns with low diversity
    low_diversity = comparison_df[comparison_df['normalized_entropy'] < 0.3]
    if not low_diversity.empty:
        recommendations.append(
            "• Low Diversity Detected: The following columns show low diversity and may need "
            "more varied data generation:"
        )
        for _, row in low_diversity.iterrows():
            recommendations.append(
                f"  - {row['scenario']}.{row['column']}: {row['normalized_entropy']:.3f}"
            )
        recommendations.append("")
    
    # Find scenarios with inconsistent diversity
    scenario_avg = comparison_df.groupby('scenario')['normalized_entropy'].mean()
    if len(scenario_avg) > 1:
        diversity_range = scenario_avg.max() - scenario_avg.min()
        if diversity_range > 0.2:
            recommendations.append(
                "• Inconsistent Diversity: Significant differences in data diversity between scenarios. "
                "Consider reviewing data generation parameters for consistency."
            )
            recommendations.append("")
    
    # General recommendations
    recommendations.extend([
        "• High entropy values (>0.8) indicate good data diversity and realistic distributions.",
        "• Low entropy values (<0.3) may indicate over-concentration in certain categories.",
        "• Consider balancing data generation to achieve moderate to high entropy across all scenarios.",
        "• Monitor entropy over time to ensure data quality remains consistent."
    ])
    
    return '\n'.join(recommendations)

def load_scenario_config(scenario_name):
    """
    Load scenario-specific configuration and merge with default config.
    
    Args:
        scenario_name: Name of the scenario (enterprise, government, small)
    
    Returns:
        dict: Merged configuration
    """
    # Load default configuration
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_config_path = os.path.join(base_dir, 'configs', 'generator_config.yaml')
    default_config = load_config(default_config_path)
    
    # Load scenario-specific configuration
    scenario_config_path = os.path.join(base_dir, 'configs', f'scenario_{scenario_name}.yaml')
    scenario_config = load_config(scenario_config_path)
    
    # Merge configurations (scenario-specific overrides default)
    merged_config = {**default_config, **scenario_config}
    
    return merged_config

def run_scenario_analysis(scenario_name, output_dir="data/outputs"):
    """
    Run entropy analysis for a specific scenario.
    
    Args:
        scenario_name: Name of the scenario to analyze
        output_dir: Directory to save outputs
    
    Returns:
        dict: Analysis results for the scenario
    """
    print(f"\nAnalyzing {scenario_name} scenario...")
    
    # Load scenario configuration
    config = load_scenario_config(scenario_name)
    print(f"Loaded {scenario_name} configuration with {len(config.get('asset_types', []))} asset types and {len(config.get('locations', []))} locations")
    
    # Define categorical columns to analyze
    asset_columns = [
        'type', 'os_family', 'location', 
        'lifecycle_stage', 'internet_exposed'
    ]
    
    findings_columns = [
        'detection_tool', 'severity', 'cve_id'
    ]
    
    # Load and analyze scenario data
    assets_df, findings_df = load_scenario_data(scenario_name)
    scenario_results = {}
    
    # Analyze assets
    if not assets_df.empty:
        asset_results = analyze_categorical_entropy(assets_df, asset_columns, f"{scenario_name}_assets")
        scenario_results[f"{scenario_name}_assets"] = asset_results
        print(f"  Assets: {len(assets_df):,} records analyzed")
    
    # Analyze findings
    if not findings_df.empty:
        findings_results = analyze_categorical_entropy(findings_df, findings_columns, f"{scenario_name}_findings")
        scenario_results[f"{scenario_name}_findings"] = findings_results
        print(f"  Findings: {len(findings_df):,} records analyzed")
    
    # Create scenario-specific output directory
    scenario_output_dir = Path(output_dir) / f"entropy_{scenario_name}"
    scenario_output_dir.mkdir(parents=True, exist_ok=True)
    
    if scenario_results:
        # Create comparison DataFrame for this scenario
        comparison_df = compare_scenarios_entropy(scenario_results)
        
        # Generate visualizations
        print(f"  Generating {scenario_name} visualizations...")
        create_entropy_visualizations(comparison_df, scenario_output_dir)
        
        # Generate report
        print(f"  Generating {scenario_name} entropy analysis report...")
        report_file = scenario_output_dir / f'entropy_analysis_report_{scenario_name}.txt'
        generate_entropy_report(scenario_results, comparison_df, report_file)
        
        # Save detailed results
        results_file = scenario_output_dir / f'entropy_analysis_results_{scenario_name}.json'
        with open(results_file, 'w') as f:
            json.dump(scenario_results, f, indent=2)
        
        print(f"  {scenario_name.capitalize()} results saved to: {scenario_output_dir}")
    
    return scenario_results

def run_comparative_analysis(output_dir="data/outputs"):
    """
    Run comparative entropy analysis across all scenarios.
    
    Args:
        output_dir: Directory to save outputs
    """
    print("Starting Comparative Shannon Entropy Analysis...")
    print("=" * 60)
    
    # Define scenarios to analyze
    scenarios = [
        {'name': 'enterprise', 'description': 'Enterprise Environment'},
        {'name': 'government', 'description': 'Government Environment'},
        {'name': 'small', 'description': 'Small Business Environment'}
    ]
    
    # Run analysis for each scenario
    all_scenarios_data = {}
    
    for scenario in scenarios:
        scenario_name = scenario['name']
        scenario_results = run_scenario_analysis(scenario_name, output_dir)
        all_scenarios_data.update(scenario_results)
    
    if not all_scenarios_data:
        print("No data found for analysis. Please ensure scenario files exist.")
        return
    
    # Create comparative analysis
    print("\nGenerating comparative analysis...")
    comparison_df = compare_scenarios_entropy(all_scenarios_data)
    
    # Create comparative output directory
    comparative_output_dir = Path(output_dir) / "entropy_comparative"
    comparative_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate comparative visualizations
    print("Generating comparative visualizations...")
    create_entropy_visualizations(comparison_df, comparative_output_dir)
    
    # Generate comparative report
    print("Generating comparative entropy analysis report...")
    report_file = comparative_output_dir / 'entropy_comparative_analysis_report.txt'
    generate_entropy_report(all_scenarios_data, comparison_df, report_file)
    
    # Save comparative results
    results_file = comparative_output_dir / 'entropy_comparative_analysis_results.json'
    with open(results_file, 'w') as f:
        json.dump(all_scenarios_data, f, indent=2)
    
    print(f"\nComparative results saved to: {comparative_output_dir}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("COMPARATIVE ENTROPY ANALYSIS SUMMARY")
    print("=" * 60)
    
    if not comparison_df.empty:
        for scenario in comparison_df['scenario'].unique():
            scenario_data = comparison_df[comparison_df['scenario'] == scenario]
            avg_entropy = scenario_data['normalized_entropy'].mean()
            print(f"{scenario}: Average Diversity = {avg_entropy:.3f} ({get_diversity_level(avg_entropy)})")
    
    print("\nComparative analysis complete!")

def run_full_analysis(output_dir="data/outputs"):
    """
    Run full entropy analysis across all scenarios plus baseline data.
    
    Args:
        output_dir: Directory to save outputs
    """
    print("Starting Full Shannon Entropy Analysis...")
    print("=" * 60)
    
    # Define scenarios to analyze including baseline
    scenarios = [
        {'name': 'enterprise', 'description': 'Enterprise Environment'},
        {'name': 'government', 'description': 'Government Environment'},
        {'name': 'small', 'description': 'Small Business Environment'},
        {'name': 'baseline', 'description': 'Baseline Configuration'}
    ]
    
    # Run analysis for each scenario including baseline
    all_scenarios_data = {}
    
    for scenario in scenarios:
        scenario_name = scenario['name']
        if scenario_name == 'baseline':
            # Handle baseline data differently
            scenario_results = run_baseline_analysis(output_dir)
        else:
            scenario_results = run_scenario_analysis(scenario_name, output_dir)
        all_scenarios_data.update(scenario_results)
    
    if not all_scenarios_data:
        print("No data found for analysis. Please ensure scenario files exist.")
        return
    
    # Create comparative analysis
    print("\nGenerating full analysis comparison...")
    comparison_df = compare_scenarios_entropy(all_scenarios_data)
    
    # Create full output directory
    full_output_dir = Path(output_dir) / "entropy_full"
    full_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate full visualizations
    print("Generating full analysis visualizations...")
    create_entropy_visualizations(comparison_df, full_output_dir)
    
    # Generate full report
    print("Generating full entropy analysis report...")
    report_file = full_output_dir / 'entropy_full_analysis_report.txt'
    generate_entropy_report(all_scenarios_data, comparison_df, report_file)
    
    # Save full results
    results_file = full_output_dir / 'entropy_full_analysis_results.json'
    with open(results_file, 'w') as f:
        json.dump(all_scenarios_data, f, indent=2)
    
    print(f"\nFull results saved to: {full_output_dir}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("FULL ENTROPY ANALYSIS SUMMARY")
    print("=" * 60)
    
    if not comparison_df.empty:
        for scenario in comparison_df['scenario'].unique():
            scenario_data = comparison_df[comparison_df['scenario'] == scenario]
            avg_entropy = scenario_data['normalized_entropy'].mean()
            print(f"{scenario}: Average Diversity = {avg_entropy:.3f} ({get_diversity_level(avg_entropy)})")
    
    print("\nFull entropy analysis completed successfully!")

def run_baseline_analysis(output_dir="data/outputs"):
    """
    Run entropy analysis for baseline data.
    
    Args:
        output_dir: Directory to save outputs
    
    Returns:
        dict: Analysis results for baseline data
    """
    print("\nAnalyzing baseline data...")
    
    # Define categorical columns to analyze
    asset_columns = [
        'type', 'os_family', 'location', 
        'lifecycle_stage', 'internet_exposed'
    ]
    
    findings_columns = [
        'detection_tool', 'severity', 'cve_id'
    ]
    
    # Load baseline data
    baseline_results = {}
    
    try:
        # Load baseline assets
        assets_file = Path(output_dir) / "assets.json"
        if assets_file.exists():
            with open(assets_file, 'r') as f:
                assets_data = json.load(f)
            assets_df = pd.DataFrame(assets_data)
            
            if not assets_df.empty:
                asset_results = analyze_categorical_entropy(assets_df, asset_columns, "baseline_assets")
                baseline_results["baseline_assets"] = asset_results
                print(f"  Baseline Assets: {len(assets_df):,} records analyzed")
        
        # Load baseline findings
        findings_file = Path(output_dir) / "findings.json"
        if findings_file.exists():
            with open(findings_file, 'r') as f:
                findings_data = json.load(f)
            findings_df = pd.DataFrame(findings_data)
            
            if not findings_df.empty:
                findings_results = analyze_categorical_entropy(findings_df, findings_columns, "baseline_findings")
                baseline_results["baseline_findings"] = findings_results
                print(f"  Baseline Findings: {len(findings_df):,} records analyzed")
    
    except Exception as e:
        print(f"Error loading baseline data: {e}")
    
    return baseline_results

def main():
    """
    Main function to run entropy analysis.
    """
    parser = argparse.ArgumentParser(description='Shannon Entropy Analysis for Vulnerability Scenarios')
    parser.add_argument('--scenario', choices=['enterprise', 'government', 'small'], 
                       help='Run analysis for a specific scenario')
    parser.add_argument('--comparative', action='store_true', 
                       help='Run comparative analysis across all scenarios')
    parser.add_argument('--full', action='store_true', 
                       help='Run full analysis across all scenarios plus baseline data')
    parser.add_argument('--output-dir', default='data/outputs', 
                       help='Output directory for results')
    
    args = parser.parse_args()
    
    if args.scenario:
        # Run single scenario analysis
        run_scenario_analysis(args.scenario, args.output_dir)
    elif args.comparative:
        # Run comparative analysis
        run_comparative_analysis(args.output_dir)
    elif args.full:
        # Run full analysis
        run_full_analysis(args.output_dir)
    else:
        # Default: run comparative analysis
        run_comparative_analysis(args.output_dir)

if __name__ == "__main__":
    main()