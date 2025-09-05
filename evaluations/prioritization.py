#!/usr/bin/env python3
"""
Sample Vulnerability Prioritization Analysis

This script implements vulnerability prioritization based on CVSS scores and asset criticality.
It follows the evaluation plan to rank vulnerabilities per asset and identify the top 10 riskiest assets.
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple
import statistics
from collections import defaultdict, Counter

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import load_config, setup_logging

class VulnerabilityPrioritizer:
    """Implements vulnerability prioritization and risk scoring algorithms."""
    
    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.logger = setup_logging('prioritization.log', 'PRIORITIZATION')
        
        # Risk scoring weights
        self.weights = {
            'cvss_weight': 0.4,
            'exposure_weight': 0.3,
            'criticality_weight': 0.3
        }
        
        # Asset criticality mapping
        self.asset_criticality = {
            'Database server': 10.0,
            'Webserver': 10.0,
            'Container': 9.5,
            'Server': 9.0,
            'Network device': 8.5,
            'Storage server': 8.0,
            'Desktop': 6.0,
            'Laptop': 5.5,
            'Mobile device': 5.0,
            'IoT device': 4.0
        }
        
        # Lifecycle stage risk multipliers
        self.lifecycle_multipliers = {
            'Production': 1.0,
            'Staging': 0.8,
            'Development': 0.6,
            'Testing': 0.5,
            'Maintenance': 0.9,
            'Backup': 0.7,
            'Decommissioned': 0.3
        }
        
    def load_data(self, assets_file: str, findings_file: str) -> Tuple[List[Dict], List[Dict]]:
        """Load assets and findings data from JSON files."""
        try:
            with open(assets_file, 'r', encoding='utf-8') as f:
                assets = json.load(f)
            self.logger.info(f"Loaded {len(assets)} assets from {assets_file}")
            
            with open(findings_file, 'r', encoding='utf-8') as f:
                findings = json.load(f)
            self.logger.info(f"Loaded {len(findings)} findings from {findings_file}")
            
            return assets, findings
            
        except FileNotFoundError as e:
            self.logger.error(f"File not found: {e}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON format: {e}")
            raise
    
    def calculate_asset_criticality(self, asset: Dict[str, Any]) -> float:
        """Calculate asset criticality score based on type and characteristics."""
        base_score = self.asset_criticality.get(asset.get('type', 'Unknown'), 5.0)
        
        # Apply lifecycle stage multiplier
        lifecycle = asset.get('lifecycle_stage', 'Production')
        multiplier = self.lifecycle_multipliers.get(lifecycle, 1.0)
        
        # Bonus for internet-exposed assets
        if asset.get('internet_exposed', False):
            multiplier += 0.1
        
        return min(base_score * multiplier, 10.0)
    
    def calculate_vulnerability_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate comprehensive vulnerability risk metrics for an asset."""
        if not vulnerabilities:
            return {
                'total_score': 0.0,
                'avg_cvss': 0.0,
                'max_cvss': 0.0,
                'vuln_count': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            }
        
        cvss_scores = [v.get('base_score', 0.0) for v in vulnerabilities]
        severity_counts = Counter(v.get('severity', 'Unknown') for v in vulnerabilities)
        
        # Calculate weighted risk score
        severity_weights = {'CRITICAL': 4.0, 'HIGH': 3.0, 'MEDIUM': 2.0, 'LOW': 1.0}
        weighted_score = sum(
            severity_weights.get(v.get('severity', 'LOW'), 1.0) * v.get('base_score', 0.0)
            for v in vulnerabilities
        )
        
        return {
            'total_score': weighted_score / len(vulnerabilities) if vulnerabilities else 0.0,
            'avg_cvss': statistics.mean(cvss_scores) if cvss_scores else 0.0,
            'max_cvss': max(cvss_scores) if cvss_scores else 0.0,
            'vuln_count': len(vulnerabilities),
            'critical_count': severity_counts.get('CRITICAL', 0),
            'high_count': severity_counts.get('HIGH', 0),
            'medium_count': severity_counts.get('MEDIUM', 0),
            'low_count': severity_counts.get('LOW', 0)
        }
    
    def calculate_composite_risk_score(self, asset: Dict[str, Any], vuln_metrics: Dict[str, float]) -> float:
        """Calculate composite risk score combining asset criticality and vulnerability metrics."""
        criticality_score = self.calculate_asset_criticality(asset)
        vulnerability_score = vuln_metrics['total_score']
        
        # Normalize scores to 0-10 scale
        normalized_criticality = min(criticality_score, 10.0)
        normalized_vulnerability = min(vulnerability_score, 20.0) / 2.0  # Scale down from 20 to 10
        
        # Calculate weighted composite score (max 30.0)
        composite_score = (
            normalized_criticality * self.weights['criticality_weight'] * 3 +
            normalized_vulnerability * self.weights['cvss_weight'] * 3 +
            (5.0 if asset.get('internet_exposed', False) else 2.0) * self.weights['exposure_weight'] * 3
        )
        
        return min(composite_score, 30.0)
    
    def group_vulnerabilities_by_asset(self, assets: List[Dict], findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by asset UUID."""
        asset_vulns = defaultdict(list)
        
        for finding in findings:
            asset_uuid = finding.get('asset_uuid')
            if asset_uuid:
                asset_vulns[asset_uuid].append(finding)
        
        return dict(asset_vulns)
    
    def prioritize_assets(self, assets: List[Dict], findings: List[Dict]) -> List[Dict[str, Any]]:
        """Prioritize assets based on vulnerability risk and criticality."""
        asset_vulns = self.group_vulnerabilities_by_asset(assets, findings)
        prioritized_assets = []
        
        for asset in assets:
            asset_uuid = asset['uuid']
            vulnerabilities = asset_vulns.get(asset_uuid, [])
            
            # Calculate vulnerability metrics
            vuln_metrics = self.calculate_vulnerability_risk_score(vulnerabilities)
            
            # Calculate scores
            criticality_score = self.calculate_asset_criticality(asset)
            composite_score = self.calculate_composite_risk_score(asset, vuln_metrics)
            
            prioritized_asset = {
                'asset_uuid': asset_uuid,
                'hostname': asset.get('hostname', 'Unknown'),
                'type': asset.get('type', 'Unknown'),
                'os_family': asset.get('os_family', 'Unknown'),
                'internet_exposed': asset.get('internet_exposed', False),
                'lifecycle_stage': asset.get('lifecycle_stage', 'Unknown'),
                'composite_risk_score': composite_score,
                'criticality_score': criticality_score,
                'vulnerability_metrics': vuln_metrics
            }
            
            prioritized_assets.append(prioritized_asset)
        
        # Sort by composite risk score (descending)
        prioritized_assets.sort(key=lambda x: x['composite_risk_score'], reverse=True)
        
        return prioritized_assets
    
    def generate_report(self, prioritized_assets: List[Dict], output_dir: str, scenario_name: str = ""):
        """Generate prioritization report and save top 10 riskiest assets."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Get top 10 riskiest assets
        top_10 = prioritized_assets[:10]
        
        # Save JSON output
        json_file = os.path.join(output_dir, 'top_10_riskiest_assets.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(top_10, f, indent=2, ensure_ascii=False)
        
        # Generate text report
        report_file = os.path.join(output_dir, 'vulnerability_prioritization_report.txt')
        with open(report_file, 'w', encoding='utf-8') as f:
            self._write_detailed_report(f, prioritized_assets, top_10, scenario_name)
        
        self.logger.info(f"Report generated: {report_file}")
        self.logger.info(f"Top 10 assets saved: {json_file}")
        
        return top_10
    
    def _write_detailed_report(self, f, all_assets: List[Dict], top_10: List[Dict], scenario_name: str):
        """Write detailed prioritization report."""
        f.write("=" * 80 + "\n")
        f.write("VULNERABILITY PRIORITIZATION ANALYSIS REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        if scenario_name:
            f.write(f"SCENARIO: {scenario_name.upper()}\n")
            f.write("-" * 40 + "\n")
        
        # Summary statistics
        total_assets = len(all_assets)
        assets_with_vulns = len([a for a in all_assets if a['vulnerability_metrics']['vuln_count'] > 0])
        total_vulns = sum(a['vulnerability_metrics']['vuln_count'] for a in all_assets)
        avg_vulns = total_vulns / total_assets if total_assets > 0 else 0
        
        f.write("SUMMARY STATISTICS:\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total Assets: {total_assets:,}\n")
        f.write(f"Assets with Vulnerabilities: {assets_with_vulns:,}\n")
        f.write(f"Total Vulnerabilities: {total_vulns:,}\n")
        f.write(f"Average Vulnerabilities per Asset: {avg_vulns:.1f}\n\n")
        
        f.write("TOP 10 RISKIEST ASSETS:\n")
        f.write("=" * 80 + "\n\n")
        
        for i, asset in enumerate(top_10, 1):
            f.write(f"{i}. {asset['hostname']} ({asset['asset_uuid']})\n")
            f.write("-" * 60 + "\n")
            f.write(f"Asset Type: {asset['type']}\n")
            f.write(f"Operating System: {asset['os_family']}\n")
            f.write(f"Internet Exposed: {asset['internet_exposed']}\n")
            f.write(f"Lifecycle Stage: {asset['lifecycle_stage']}\n\n")
            
            f.write("RISK SCORES:\n")
            f.write(f"  Composite Risk Score: {asset['composite_risk_score']:.2f}/30.0\n")
            f.write(f"  Asset Criticality: {asset['criticality_score']:.2f}/10.0\n")
            f.write(f"  Vulnerability Risk: {asset['vulnerability_metrics']['total_score']:.2f}/20.0\n\n")
            
            vm = asset['vulnerability_metrics']
            f.write("VULNERABILITY PROFILE:\n")
            f.write(f"  Total Vulnerabilities: {vm['vuln_count']}\n")
            f.write(f"  Average CVSS Score: {vm['avg_cvss']:.1f}\n")
            f.write(f"  Maximum CVSS Score: {vm['max_cvss']:.1f}\n")
            f.write(f"  Critical: {vm['critical_count']}\n")
            f.write(f"  High: {vm['high_count']}\n")
            f.write(f"  Medium: {vm['medium_count']}\n")
            f.write(f"  Low: {vm['low_count']}\n\n")

def run_prioritization_analysis(assets_file: str, findings_file: str, output_dir: str, scenario_name: str = ""):
    """Run complete prioritization analysis."""
    prioritizer = VulnerabilityPrioritizer()
    
    # Load data
    assets, findings = prioritizer.load_data(assets_file, findings_file)
    
    # Prioritize assets
    prioritized_assets = prioritizer.prioritize_assets(assets, findings)
    
    # Generate report
    top_10 = prioritizer.generate_report(prioritized_assets, output_dir, scenario_name)
    
    print(f"\n✅ Prioritization analysis complete!")
    print(f"📊 Analyzed {len(assets)} assets with {len(findings)} vulnerabilities")
    print(f"🎯 Top 10 riskiest assets identified")
    print(f"📁 Results saved to: {output_dir}")
    
    return prioritized_assets, top_10

def main():
    """Main function for command-line execution."""
    parser = argparse.ArgumentParser(description='Vulnerability Prioritization Analysis')
    parser.add_argument('--assets', required=True, help='Path to assets JSON file')
    parser.add_argument('--findings', required=True, help='Path to findings JSON file')
    parser.add_argument('--output', required=True, help='Output directory for results')
    parser.add_argument('--scenario', help='Scenario name for reporting')
    
    args = parser.parse_args()
    
    try:
        run_prioritization_analysis(
            args.assets,
            args.findings,
            args.output,
            args.scenario or ""
        )
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # Run analysis for all scenarios if executed directly
    base_dir = Path(__file__).parent.parent / 'data' / 'outputs'
    
    scenarios = {
        'baseline': ('assets.json', 'findings.json'),
        'enterprise': ('scenario_enterprise_assets.json', 'scenario_enterprise_findings.json'),
        'government': ('scenario_government_assets.json', 'scenario_government_findings.json'),
        'small_business': ('scenario_small_assets.json', 'scenario_small_findings.json')
    }
    
    print("🚀 Running Vulnerability Prioritization Analysis for all scenarios...\n")
    
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
            except Exception as e:
                print(f"❌ Error processing {scenario_name}: {e}")
        else:
            print(f"⚠️  Skipping {scenario_name}: Data files not found")
        
        print()
    
    print("🎉 All prioritization analyses complete!")