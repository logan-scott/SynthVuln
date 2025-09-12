#!/usr/bin/env python3
"""
Statistical Analysis of Synthetic Vulnerability Datasets

This module performs comprehensive descriptive and inferential statistical analysis
on the generated scenario datasets (small business, enterprise, government).

Features:
- Descriptive statistics for asset distributions
- Comparative analysis across scenarios
- Statistical significance testing
- Vulnerability pattern analysis
- Risk distribution analysis
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Any
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from scipy.stats import chi2_contingency, kruskal
import warnings
import argparse
warnings.filterwarnings('ignore')

# Set style for better plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class ScenarioStatistics:
    """Statistical analysis class for vulnerability scenario datasets."""
    
    def __init__(self, data_dir: str = "data/outputs"):
        """Initialize with data directory path."""
        self.data_dir = Path(data_dir)
        self.scenarios = {}
        self.dataframes = {}
        self.findings = {}
        self.findings_dataframes = {}
        
    def load_scenarios(self) -> None:
        """Load all scenario datasets."""
        scenario_files = {
            'small': 'scenario_small_assets.json',
            'enterprise': 'scenario_enterprise_assets.json', 
            'government': 'scenario_government_assets.json'
        }
        
        for scenario_name, filename in scenario_files.items():
            file_path = self.data_dir / filename
            if file_path.exists():
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    self.scenarios[scenario_name] = data
                    # Convert to DataFrame for easier analysis
                    self.dataframes[scenario_name] = pd.DataFrame(data)
                print(f"✅ Loaded {scenario_name}: {len(data)} assets")
            else:
                print(f"❌ File not found: {filename}")
    
    def load_scenarios_with_baseline(self) -> None:
        """Load all scenario datasets including baseline data."""
        # First load regular scenarios
        self.load_scenarios()
        
        # Load baseline data
        baseline_assets_file = self.data_dir / "assets.json"
        baseline_findings_file = self.data_dir / "findings.json"
        
        if baseline_assets_file.exists():
            with open(baseline_assets_file, 'r') as f:
                data = json.load(f)
                self.scenarios['baseline'] = data
                self.dataframes['baseline'] = pd.DataFrame(data)
            print(f"✅ Loaded baseline: {len(data)} assets")
        else:
            print("❌ Baseline assets file not found: assets.json")
        
        if baseline_findings_file.exists():
            with open(baseline_findings_file, 'r') as f:
                data = json.load(f)
                self.findings['baseline'] = data
                self.findings_dataframes['baseline'] = pd.DataFrame(data)
            print(f"✅ Loaded baseline findings: {len(data)} vulnerabilities")
        else:
            print("❌ Baseline findings file not found: findings.json")
        
        # Load findings files
        findings_files = {
            'small': 'scenario_small_findings.json',
            'enterprise': 'scenario_enterprise_findings.json', 
            'government': 'scenario_government_findings.json'
        }
        
        for scenario_name, filename in findings_files.items():
            file_path = self.data_dir / filename
            if file_path.exists():
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    self.findings[scenario_name] = data
                    # Convert to DataFrame for easier analysis
                    self.findings_dataframes[scenario_name] = pd.DataFrame(data)
                print(f"✅ Loaded {scenario_name} findings: {len(data)} vulnerabilities")
            else:
                print(f"❌ Findings file not found: {filename}")
    
    def basic_descriptive_stats(self) -> Dict[str, Any]:
        """Generate basic descriptive statistics for all scenarios."""
        stats_summary = {}
        
        for scenario_name, df in self.dataframes.items():
            stats = {
                'total_assets': len(df),
                'asset_types': df['type'].value_counts().to_dict(),
                'os_families': df['os_family'].value_counts().to_dict(),
                'locations': df['location'].value_counts().to_dict(),
                'internet_exposed': df['internet_exposed'].sum(),
                'internet_exposure_rate': df['internet_exposed'].mean(),
                'endpoint_security_rate': df['endpoint_security_installed'].mean(),
                'firewall_active_rate': df['local_firewall_active'].mean(),
                'avg_open_ports': df['open_ports'].apply(len).mean(),
                'total_software_packages': df['installed_software'].apply(len).sum(),
                'avg_software_per_asset': df['installed_software'].apply(len).mean()
            }
            
            # CVSS statistics are now handled in vulnerability_analysis() method
            
            stats_summary[scenario_name] = stats
        
        return stats_summary
    
    def comparative_analysis(self) -> Dict[str, Any]:
        """Perform comparative analysis across scenarios."""
        comparison = {}
        
        # Asset type distribution comparison
        asset_type_comparison = {}
        for scenario_name, df in self.dataframes.items():
            asset_type_comparison[scenario_name] = df['type'].value_counts(normalize=True)
        
        comparison['asset_type_distributions'] = asset_type_comparison
        
        # OS family distribution comparison
        os_comparison = {}
        for scenario_name, df in self.dataframes.items():
            os_comparison[scenario_name] = df['os_family'].value_counts(normalize=True)
        
        comparison['os_distributions'] = os_comparison
        
        # Security posture comparison
        security_comparison = {}
        for scenario_name, df in self.dataframes.items():
            security_comparison[scenario_name] = {
                'internet_exposure_rate': df['internet_exposed'].mean(),
                'endpoint_security_rate': df['endpoint_security_installed'].mean(),
                'firewall_active_rate': df['local_firewall_active'].mean(),
                'avg_open_ports': df['open_ports'].apply(len).mean(),
                'avg_software_packages': df['installed_software'].apply(len).mean()
            }
        
        comparison['security_posture'] = security_comparison
        
        return comparison
    
    def statistical_significance_tests(self) -> Dict[str, Any]:
        """Perform statistical significance tests between scenarios."""
        test_results = {}
        
        # Prepare data for testing
        scenario_names = list(self.dataframes.keys())
        
        # Test internet exposure rates
        exposure_data = [df['internet_exposed'].astype(int) for df in self.dataframes.values()]
        if len(exposure_data) >= 2:
            # Chi-square test for internet exposure
            exposure_contingency = []
            for df in self.dataframes.values():
                exposed = df['internet_exposed'].sum()
                not_exposed = len(df) - exposed
                exposure_contingency.append([exposed, not_exposed])
            
            chi2, p_value, dof, expected = chi2_contingency(exposure_contingency)
            test_results['internet_exposure_chi2'] = {
                'chi2_statistic': float(np.asarray(chi2).item()),
                'p_value': float(np.asarray(p_value).item()),
                'degrees_of_freedom': int(np.asarray(dof).item()),
                'significant': bool(float(np.asarray(p_value).item()) < 0.05)
            }
        
        # Test software package counts using Kruskal-Wallis (non-parametric)
        software_counts = [df['installed_software'].apply(len) for df in self.dataframes.values()]
        if len(software_counts) >= 2:
            kruskal_stat, kruskal_p = kruskal(*software_counts)
            test_results['software_counts_kruskal'] = {
                'statistic': kruskal_stat,
                'p_value': kruskal_p,
                'significant': kruskal_p < 0.05
            }
        
        # Test open port counts
        port_counts = [df['open_ports'].apply(len) for df in self.dataframes.values()]
        if len(port_counts) >= 2:
            kruskal_stat, kruskal_p = kruskal(*port_counts)
            test_results['open_ports_kruskal'] = {
                'statistic': kruskal_stat,
                'p_value': kruskal_p,
                'significant': kruskal_p < 0.05
            }
        
        return test_results
    
    def vulnerability_pattern_analysis(self) -> Dict[str, Any]:
        """Analyze vulnerability patterns across scenarios."""
        patterns = {}
        
        for scenario_name, df in self.dataframes.items():
            # Extract all vulnerabilities
            all_vulns = []
            for vulns in df['vulnerabilities']:
                all_vulns.extend(vulns)
            
            if not all_vulns:
                patterns[scenario_name] = {'total_vulnerabilities': 0}
                continue
            
            vuln_df = pd.DataFrame(all_vulns)
            
            scenario_patterns = {
                'total_vulnerabilities': len(all_vulns),
                'unique_cves': len(vuln_df['cve_id'].unique()) if 'cve_id' in vuln_df.columns else 0,
                'severity_distribution': vuln_df['severity'].value_counts().to_dict() if 'severity' in vuln_df.columns else {},
                'avg_cvss_score': vuln_df['cvss_score'].mean() if 'cvss_score' in vuln_df.columns else None,
                'cvss_score_distribution': {
                    'low (0-3.9)': len(vuln_df[vuln_df['cvss_score'] < 4]) if 'cvss_score' in vuln_df.columns else 0,
                    'medium (4-6.9)': len(vuln_df[(vuln_df['cvss_score'] >= 4) & (vuln_df['cvss_score'] < 7)]) if 'cvss_score' in vuln_df.columns else 0,
                    'high (7-8.9)': len(vuln_df[(vuln_df['cvss_score'] >= 7) & (vuln_df['cvss_score'] < 9)]) if 'cvss_score' in vuln_df.columns else 0,
                    'critical (9-10)': len(vuln_df[vuln_df['cvss_score'] >= 9]) if 'cvss_score' in vuln_df.columns else 0
                }
            }
            
            patterns[scenario_name] = scenario_patterns
        
        return patterns
    
    def generate_visualizations(self, output_dir: str = "data/outputs/scenario_statistics") -> None:
        """Generate statistical visualizations."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # 1. Asset type distribution comparison
        plt.figure(figsize=(15, 8))
        
        # Prepare data for stacked bar chart
        all_asset_types = set()
        for df in self.dataframes.values():
            all_asset_types.update(df['type'].unique())
        
        asset_type_data = {}
        for scenario_name, df in self.dataframes.items():
            type_counts = df['type'].value_counts()
            asset_type_data[scenario_name] = [type_counts.get(asset_type, 0) for asset_type in all_asset_types]
        
        x = np.arange(len(all_asset_types))
        width = 0.25
        
        for i, (scenario_name, counts) in enumerate(asset_type_data.items()):
            plt.bar(x + i * width, counts, width, label=scenario_name.replace('_', ' ').title())
        
        plt.xlabel('Asset Types')
        plt.ylabel('Count')
        plt.title('Asset Type Distribution Across Scenarios')
        plt.xticks(x + width, list(all_asset_types), rotation=45, ha='right')
        plt.legend()
        plt.tight_layout()
        plt.savefig(output_path / 'asset_type_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Security posture comparison
        plt.figure(figsize=(12, 8))
        
        security_metrics = ['internet_exposure_rate', 'endpoint_security_rate', 'firewall_active_rate']
        scenario_names = list(self.dataframes.keys())
        
        security_data = []
        for scenario_name, df in self.dataframes.items():
            security_data.append([
                df['internet_exposed'].mean(),
                df['endpoint_security_installed'].mean(),
                df['local_firewall_active'].mean()
            ])
        
        x = np.arange(len(security_metrics))
        width = 0.25
        
        for i, (scenario_name, metrics) in enumerate(zip(scenario_names, security_data)):
            plt.bar(x + i * width, metrics, width, label=scenario_name.replace('_', ' ').title())
        
        plt.xlabel('Security Metrics')
        plt.ylabel('Rate (0-1)')
        plt.title('Security Posture Comparison Across Scenarios')
        plt.xticks(x + width, ['Internet Exposure', 'Endpoint Security', 'Firewall Active'])
        plt.legend()
        plt.ylim(0, 1)
        plt.tight_layout()
        plt.savefig(output_path / 'security_posture_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. Vulnerability distribution
        plt.figure(figsize=(12, 8))
        
        software_counts = []
        labels = []
        for scenario_name, df in self.dataframes.items():
            counts = df['installed_software'].apply(len)
            software_counts.append(counts)
            labels.append(scenario_name.replace('_', ' ').title())
        
        plt.boxplot(software_counts)
        plt.xticks(range(1, len(labels) + 1), labels)
        plt.ylabel('Number of Software Packages per Asset')
        plt.title('Software Package Distribution Across Scenarios')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(output_path / 'software_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📊 Visualizations saved to {output_path}/")
    
    def vulnerability_analysis(self) -> Dict[str, Any]:
        """Analyze vulnerability patterns across scenarios."""
        print("\n📊 Analyzing vulnerability patterns...")
        
        vuln_stats = {}
        
        for scenario_name, df in self.findings_dataframes.items():
            if df.empty:
                continue
                
            scenario_stats = {
                'total_vulnerabilities': len(df),
                'severity_distribution': {},
                'cve_year_stats': {},
                'asset_coverage': {}
            }
            
            # Severity distribution
            if 'severity' in df.columns:
                severity_counts = df['severity'].value_counts()
                total = len(df)
                scenario_stats['severity_distribution'] = {
                    'counts': severity_counts.to_dict(),
                    'percentages': {k: round(v/total*100, 1) for k, v in severity_counts.items()}
                }
            
            # CVE year analysis
            if 'cve_id' in df.columns:
                # Extract year from CVE ID (format: CVE-YYYY-NNNNN)
                cve_years = df['cve_id'].str.extract(r'CVE-(\d{4})-').astype(int)
                if not cve_years.empty:
                    scenario_stats['cve_year_stats'] = {
                        'min_year': int(cve_years.min()),
                        'max_year': int(cve_years.max()),
                        'avg_year': round(float(cve_years.mean()), 1),
                        'recent_cves_2020_plus': int((cve_years >= 2020).sum()),
                        'recent_percentage': round(float((cve_years >= 2020).sum() / len(cve_years) * 100), 1)
                    }
            
            # Asset coverage
            if 'asset_uuid' in df.columns:
                unique_assets = df['asset_uuid'].nunique()
                avg_vulns_per_asset = round(len(df) / unique_assets, 1) if unique_assets > 0 else 0
                scenario_stats['asset_coverage'] = {
                    'assets_with_vulnerabilities': unique_assets,
                    'avg_vulnerabilities_per_asset': avg_vulns_per_asset
                }
            
            vuln_stats[scenario_name] = scenario_stats
        
        return vuln_stats
    
    def generate_report(self, output_file: str = "data/outputs/scenario_statistics/statistical_analysis_report.txt") -> None:
        """Generate comprehensive statistical analysis report."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("STATISTICAL ANALYSIS REPORT - SYNTHETIC VULNERABILITY DATASETS\n")
            f.write("=" * 80 + "\n\n")
            
            # Basic descriptive statistics
            f.write("1. DESCRIPTIVE STATISTICS\n")
            f.write("-" * 40 + "\n")
            
            basic_stats = self.basic_descriptive_stats()
            for scenario_name, stats in basic_stats.items():
                f.write(f"\n{scenario_name.upper().replace('_', ' ')} SCENARIO:\n")
                f.write(f"  Total Assets: {stats['total_assets']:,}\n")
                f.write(f"  Internet Exposure Rate: {stats['internet_exposure_rate']:.1%}\n")
                f.write(f"  Endpoint Security Rate: {stats['endpoint_security_rate']:.1%}\n")
                f.write(f"  Firewall Active Rate: {stats['firewall_active_rate']:.1%}\n")
                f.write(f"  Avg Open Ports per Asset: {stats['avg_open_ports']:.1f}\n")
                f.write(f"  Avg Software Packages per Asset: {stats['avg_software_per_asset']:.1f}\n")
                
                if 'cvss_stats' in stats:
                    cvss = stats['cvss_stats']
                    f.write(f"  CVSS Score Statistics:\n")
                    f.write(f"    Mean: {cvss['mean']:.2f}\n")
                    f.write(f"    Median: {cvss['median']:.2f}\n")
                    f.write(f"    Std Dev: {cvss['std']:.2f}\n")
                    f.write(f"    Range: {cvss['min']:.1f} - {cvss['max']:.1f}\n")
                
                f.write(f"\n  Top 5 Asset Types:\n")
                for asset_type, count in list(stats['asset_types'].items())[:5]:
                    f.write(f"    {asset_type}: {count} ({count/stats['total_assets']:.1%})\n")
            
            # Comparative analysis
            f.write("\n\n2. COMPARATIVE ANALYSIS\n")
            f.write("-" * 40 + "\n")
            
            comparison = self.comparative_analysis()
            
            f.write("\nSecurity Posture Comparison:\n")
            for scenario_name, metrics in comparison['security_posture'].items():
                f.write(f"\n{scenario_name.upper().replace('_', ' ')}:\n")
                f.write(f"  Internet Exposure: {metrics['internet_exposure_rate']:.1%}\n")
                f.write(f"  Endpoint Security: {metrics['endpoint_security_rate']:.1%}\n")
                f.write(f"  Firewall Active: {metrics['firewall_active_rate']:.1%}\n")
                f.write(f"  Avg Open Ports: {metrics['avg_open_ports']:.1f}\n")
                f.write(f"  Avg Software Packages: {metrics['avg_software_packages']:.1f}\n")
            
            # Statistical significance tests
            f.write("\n\n3. STATISTICAL SIGNIFICANCE TESTS\n")
            f.write("-" * 40 + "\n")
            
            test_results = self.statistical_significance_tests()
            
            for test_name, results in test_results.items():
                f.write(f"\n{test_name.upper().replace('_', ' ')}:\n")
                if 'chi2_statistic' in results:
                    f.write(f"  Chi-square statistic: {results['chi2_statistic']:.4f}\n")
                elif 'statistic' in results:
                    f.write(f"  Test statistic: {results['statistic']:.4f}\n")
                
                f.write(f"  P-value: {results['p_value']:.6f}\n")
                f.write(f"  Significant (α=0.05): {'Yes' if results['significant'] else 'No'}\n")
            
            # Vulnerability patterns
            f.write("\n\n4. VULNERABILITY PATTERN ANALYSIS\n")
            f.write("-" * 40 + "\n")
            
            vuln_analysis = self.vulnerability_analysis()
            
            for scenario_name in self.scenarios.keys():
                if scenario_name in vuln_analysis:
                    vuln_data = vuln_analysis[scenario_name]
                    f.write(f"\n{scenario_name.upper().replace('_', ' ')} VULNERABILITIES:\n")
                    f.write(f"  Total: {vuln_data['total_vulnerabilities']:,}\n")
                    
                    # Severity distribution
                    if 'severity_distribution' in vuln_data and vuln_data['severity_distribution']:
                        f.write(f"  Severity Distribution:\n")
                        severity_dist = vuln_data['severity_distribution']['counts']
                        percentages = vuln_data['severity_distribution']['percentages']
                        for severity, count in severity_dist.items():
                            percentage = percentages.get(severity, 0)
                            f.write(f"    {severity}: {count} ({percentage}%)\n")
                
                # Add vulnerability analysis data
                if scenario_name in vuln_analysis:
                    vuln_data = vuln_analysis[scenario_name]
                    if 'cve_year_stats' in vuln_data:
                        year_stats = vuln_data['cve_year_stats']
                        f.write(f"  CVE Year Statistics:\n")
                        f.write(f"    Range: {year_stats.get('min_year', 'N/A')} - {year_stats.get('max_year', 'N/A')}\n")
                        f.write(f"    Recent CVEs (2020+): {year_stats.get('recent_cves_2020_plus', 0)} ({year_stats.get('recent_percentage', 0)}%)\n")
                    
                    if 'asset_coverage' in vuln_data:
                        coverage = vuln_data['asset_coverage']
                        f.write(f"  Asset Coverage:\n")
                        f.write(f"    Assets with vulnerabilities: {coverage.get('assets_with_vulnerabilities', 0)}\n")
                        f.write(f"    Avg vulnerabilities per asset: {coverage.get('avg_vulnerabilities_per_asset', 0)}\n")
        
        print(f"📋 Statistical analysis report saved to {output_path}")

def run_comparative_analysis():
    """Run comparative analysis across three scenarios."""
    print("🔍 Starting Comparative Statistical Analysis of Synthetic Vulnerability Datasets")
    print("=" * 70)
    
    # Initialize analyzer
    analyzer = ScenarioStatistics()
    
    # Load scenario data
    print("\n📂 Loading scenario datasets...")
    analyzer.load_scenarios()
    
    if not analyzer.scenarios:
        print("❌ No scenario datasets found. Please generate datasets first.")
        return
    
    # Run analysis
    run_analysis(analyzer, "comparative")

def run_full_analysis():
    """Run full analysis across all scenarios plus baseline data."""
    print("🔍 Starting Full Statistical Analysis of Synthetic Vulnerability Datasets")
    print("=" * 70)
    
    # Initialize analyzer
    analyzer = ScenarioStatistics()
    
    # Load scenario data including baseline
    print("\n📂 Loading scenario datasets including baseline...")
    analyzer.load_scenarios_with_baseline()
    
    if not analyzer.scenarios:
        print("❌ No scenario datasets found. Please generate datasets first.")
        return
    
    # Run analysis
    run_analysis(analyzer, "full")

def run_analysis(analyzer, analysis_type):
    """Run the actual analysis steps."""
    # Generate basic statistics
    print("\n📊 Generating descriptive statistics...")
    basic_stats = analyzer.basic_descriptive_stats()
    
    # Perform comparative analysis
    print("🔄 Performing comparative analysis...")
    comparison = analyzer.comparative_analysis()
    
    # Run statistical significance tests
    print("🧪 Running statistical significance tests...")
    test_results = analyzer.statistical_significance_tests()
    
    # Analyze vulnerability data from findings files
    print("🔍 Analyzing vulnerability data...")
    vuln_stats = analyzer.vulnerability_analysis()
    
    # Generate visualizations
    print("📈 Generating visualizations...")
    analyzer.generate_visualizations()
    
    # Generate comprehensive report
    print("📋 Generating comprehensive report...")
    if analysis_type == "full":
        analyzer.generate_report("data/outputs/scenario_statistics/statistical_analysis_full_report.txt")
    else:
        analyzer.generate_report()
    
    print(f"\n✅ {analysis_type.title()} statistical analysis completed successfully!")
    print("\n📁 Output files:")
    if analysis_type == "full":
        print("   - data/outputs/scenario_statistics/statistical_analysis_full_report.txt")
    else:
        print("   - data/outputs/scenario_statistics/statistical_analysis_report.txt")
    print("   - data/outputs/scenario_statistics/asset_type_distribution.png")
    print("   - data/outputs/scenario_statistics/security_posture_comparison.png")
    print("   - data/outputs/scenario_statistics/software_distribution.png")

def main():
    """Main function to run statistical analysis."""
    parser = argparse.ArgumentParser(description='Statistical Analysis of Synthetic Vulnerability Datasets')
    parser.add_argument('--comparative', action='store_true', 
                       help='Run comparative analysis across all scenarios')
    parser.add_argument('--full', action='store_true', 
                       help='Run full analysis across all scenarios plus baseline data')
    
    args = parser.parse_args()
    
    if args.full:
        run_full_analysis()
    else:
        # Default: run comparative analysis
        run_comparative_analysis()

if __name__ == "__main__":
    main()