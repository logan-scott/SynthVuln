#!/usr/bin/env python3
"""
Business Intelligence Dashboard for SynthVuln Vulnerability Analysis

This script creates an interactive Streamlit dashboard to visualize
vulnerability data, risk metrics, and asset information.

Usage:
    streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import os
import sys
import warnings
warnings.filterwarnings('ignore')

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.util import load_config

# Page configuration
st.set_page_config(
    page_title="Vulnerability Analysis Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #1f77b4;
}
.high-risk {
    border-left-color: #d62728 !important;
}
.medium-risk {
    border-left-color: #ff7f0e !important;
}
.low-risk {
    border-left-color: #2ca02c !important;
}
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_data():
    """Load and cache vulnerability data"""
    try:
        # Load assets
        with open('data/outputs/scenario_enterprise_assets.json', 'r') as f:
            assets = json.load(f)
        
        # Load findings
        with open('data/outputs/scenario_enterprise_findings.json', 'r') as f:
            findings = json.load(f)
        
        # Load prioritization results if available
        try:
            with open('data/outputs/top_10_riskiest_assets.json', 'r') as f:
                top_risks = json.load(f)
        except FileNotFoundError:
            top_risks = []
        
        return assets, findings, top_risks
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return [], [], []

@st.cache_data
def prepare_dashboard_data(assets, findings):
    """Prepare data for dashboard visualizations"""
    # Convert to DataFrames
    assets_df = pd.DataFrame(assets)
    findings_df = pd.DataFrame(findings)
    
    if findings_df.empty:
        return assets_df, findings_df, pd.DataFrame(), assets_df
    
    # Merge assets with findings
    merged_df = findings_df.merge(
        assets_df[['uuid', 'type', 'os_family', 'location', 'internet_exposed', 'lifecycle_stage']], 
        left_on='asset_uuid', 
        right_on='uuid', 
        how='left'
    )
    
    # Calculate vulnerability metrics per asset
    base_metrics = findings_df.groupby('asset_uuid').agg({
        'base_score': ['count', 'mean', 'max']
    }).round(2)
    
    # Calculate severity counts separately
    severity_pivot = findings_df.pivot_table(
        index='asset_uuid',
        columns='severity',
        values='finding_id',
        aggfunc='count',
        fill_value=0
    )
    
    # Ensure all severity columns exist and rename to lowercase
    severity_columns = {}
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity in severity_pivot.columns:
            severity_columns[severity.lower()] = severity_pivot[severity]
        else:
            severity_columns[severity.lower()] = 0
    
    severity_counts = pd.DataFrame(severity_columns, index=severity_pivot.index)
    
    # Flatten base metrics column names
    base_metrics.columns = ['vuln_count', 'avg_cvss', 'max_cvss']
    
    # Combine metrics
    asset_metrics = base_metrics.join(severity_counts, how='outer').fillna(0)
    
    # Merge back with assets
    assets_with_metrics = assets_df.merge(
        asset_metrics, 
        left_on='uuid', 
        right_index=True, 
        how='left'
    ).fillna(0)
    
    return assets_df, findings_df, merged_df, assets_with_metrics

def create_overview_metrics(assets_df, findings_df, assets_with_metrics):
    """Create overview metrics cards"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Assets",
            value=len(assets_df),
            delta=None
        )
    
    with col2:
        total_vulns = len(findings_df)
        st.metric(
            label="Total Vulnerabilities",
            value=f"{total_vulns:,}",
            delta=None
        )
    
    with col3:
        assets_with_vulns = (assets_with_metrics['vuln_count'] > 0).sum()
        st.metric(
            label="Assets with Vulnerabilities",
            value=assets_with_vulns,
            delta=f"{(assets_with_vulns/len(assets_df)*100):.1f}%"
        )
    
    with col4:
        if not findings_df.empty:
            avg_cvss = findings_df['base_score'].mean()
            st.metric(
                label="Average CVSS Score",
                value=f"{avg_cvss:.1f}",
                delta=None
            )
        else:
            st.metric(label="Average CVSS Score", value="N/A")

def create_severity_distribution(findings_df):
    """Create severity distribution chart"""
    if findings_df.empty:
        st.warning("No vulnerability data available")
        return
    
    severity_counts = findings_df['severity'].value_counts()
    
    # Color mapping for severity levels
    colors = {
        'CRITICAL': '#d62728',
        'HIGH': '#ff7f0e', 
        'MEDIUM': '#ffbb78',
        'LOW': '#2ca02c'
    }
    
    fig = px.pie(
        values=severity_counts.values,
        names=severity_counts.index,
        title="Vulnerability Severity Distribution",
        color=severity_counts.index,
        color_discrete_map=colors
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(height=400)
    
    st.plotly_chart(fig, use_container_width=True)

def create_asset_type_analysis(assets_with_metrics):
    """Create asset type vulnerability analysis"""
    if assets_with_metrics.empty:
        st.warning("No asset data available")
        return
    
    # Group by asset type
    asset_type_stats = assets_with_metrics.groupby('type').agg({
        'vuln_count': ['count', 'sum', 'mean'],
        'avg_cvss': 'mean',
        'critical': 'sum'
    }).round(2)
    
    asset_type_stats.columns = ['asset_count', 'total_vulns', 'avg_vulns_per_asset', 'avg_cvss', 'critical_vulns']
    asset_type_stats = asset_type_stats.reset_index()
    
    # Create subplot
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            'Assets by Type', 
            'Vulnerabilities by Asset Type',
            'Average CVSS by Asset Type',
            'Critical Vulnerabilities by Asset Type'
        ),
        specs=[[{"type": "bar"}, {"type": "bar"}],
               [{"type": "bar"}, {"type": "bar"}]]
    )
    
    # Asset count by type
    fig.add_trace(
        go.Bar(x=asset_type_stats['type'], y=asset_type_stats['asset_count'], name='Asset Count'),
        row=1, col=1
    )
    
    # Total vulnerabilities by type
    fig.add_trace(
        go.Bar(x=asset_type_stats['type'], y=asset_type_stats['total_vulns'], name='Total Vulns'),
        row=1, col=2
    )
    
    # Average CVSS by type
    fig.add_trace(
        go.Bar(x=asset_type_stats['type'], y=asset_type_stats['avg_cvss'], name='Avg CVSS'),
        row=2, col=1
    )
    
    # Critical vulnerabilities by type
    fig.add_trace(
        go.Bar(x=asset_type_stats['type'], y=asset_type_stats['critical_vulns'], name='Critical Vulns'),
        row=2, col=2
    )
    
    fig.update_layout(height=600, showlegend=False, title_text="Asset Type Analysis")
    st.plotly_chart(fig, use_container_width=True)

def create_risk_heatmap(assets_with_metrics):
    """Create risk heatmap by location and asset type"""
    if assets_with_metrics.empty:
        st.warning("No asset data available")
        return
    
    # Create pivot table for heatmap
    heatmap_data = assets_with_metrics.pivot_table(
        values='avg_cvss',
        index='location',
        columns='type',
        aggfunc='mean',
        fill_value=0
    )
    
    fig = px.imshow(
        heatmap_data.values,
        x=heatmap_data.columns,
        y=heatmap_data.index,
        color_continuous_scale='Reds',
        title="Average CVSS Score Heatmap (Location vs Asset Type)"
    )
    
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

def create_timeline_analysis(findings_df):
    """Create timeline analysis (simulated dates)"""
    if findings_df.empty:
        st.warning("No vulnerability data available")
        return
    
    # Simulate discovery dates for demonstration
    np.random.seed(42)
    base_date = datetime.now() - timedelta(days=90)
    findings_with_dates = findings_df.copy()
    findings_with_dates['discovery_date'] = [
        base_date + timedelta(days=np.random.randint(0, 90)) 
        for _ in range(len(findings_df))
    ]
    
    # Group by date and severity
    daily_findings = findings_with_dates.groupby(
        [findings_with_dates['discovery_date'].dt.date, 'severity']
    ).size().reset_index(name='count')
    
    fig = px.line(
        daily_findings,
        x='discovery_date',
        y='count',
        color='severity',
        title="Vulnerability Discovery Timeline (Last 90 Days)",
        color_discrete_map={
            'CRITICAL': '#d62728',
            'HIGH': '#ff7f0e',
            'MEDIUM': '#ffbb78',
            'LOW': '#2ca02c'
        }
    )
    
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

def create_top_risks_table(top_risks):
    """Create top risks table"""
    if not top_risks:
        st.warning("No risk analysis data available")
        return
    
    if isinstance(top_risks, str):
        # Display text-based risk analysis report
        st.subheader("📊 Risk Analysis Report")
        st.text_area("Risk Analysis Report", top_risks, height=400)
        return
    
    st.subheader("🚨 Top 10 Riskiest Assets")
    
    # Convert to DataFrame for better display
    risks_df = pd.DataFrame(top_risks)
    
    # Format the display
    display_df = risks_df[[
        'hostname', 'type', 'os_family', 
        'composite_risk_score', 'vulnerability_count', 'critical_vulnerabilities'
    ]].copy()
    
    display_df.columns = [
        'Asset Name', 'Type', 'OS', 
        'Risk Score', 'Vulnerabilities', 'Critical'
    ]
    
    # Add risk level indicator
    def get_risk_level(score):
        if score >= 10:
            return "🔴 Critical"
        elif score >= 7:
            return "🟠 High"
        elif score >= 4:
            return "🟡 Medium"
        else:
            return "🟢 Low"
    
    display_df['Risk Level'] = [get_risk_level(score) for score in display_df['Risk Score']]
    
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True
    )

def create_filters_sidebar(assets_df, findings_df):
    """Create sidebar filters"""
    st.sidebar.header("🔍 Filters")
    
    # Asset type filter
    if not assets_df.empty:
        asset_types = ['All'] + sorted(assets_df['type'].unique().tolist())
        selected_asset_type = st.sidebar.selectbox(
            "Asset Type",
            asset_types
        )
    else:
        selected_asset_type = 'All'
    
    # Severity filter
    if not findings_df.empty:
        severities = ['All'] + sorted(findings_df['severity'].unique().tolist())
        selected_severity = st.sidebar.multiselect(
            "Severity Levels",
            severities[1:],  # Exclude 'All'
            default=severities[1:]  # Select all by default
        )
    else:
        selected_severity = []
    
    # CVSS score range
    if not findings_df.empty:
        min_cvss, max_cvss = st.sidebar.slider(
            "CVSS Score Range",
            min_value=0.0,
            max_value=10.0,
            value=(0.0, 10.0),
            step=0.1
        )
    else:
        min_cvss, max_cvss = 0.0, 10.0
    
    return selected_asset_type, selected_severity, (min_cvss, max_cvss)

def apply_filters(assets_df, findings_df, merged_df, asset_type, severities, cvss_range):
    """Apply filters to data"""
    filtered_findings = findings_df.copy()
    filtered_merged = merged_df.copy()
    
    # Apply severity filter
    if severities and not findings_df.empty:
        filtered_findings = filtered_findings[filtered_findings['severity'].isin(severities)]
        filtered_merged = filtered_merged[filtered_merged['severity'].isin(severities)]
    
    # Apply CVSS range filter
    if not findings_df.empty:
        filtered_findings = filtered_findings[
            (filtered_findings['base_score'] >= cvss_range[0]) & 
            (filtered_findings['base_score'] <= cvss_range[1])
        ]
        filtered_merged = filtered_merged[
            (filtered_merged['base_score'] >= cvss_range[0]) & 
            (filtered_merged['base_score'] <= cvss_range[1])
        ]
    
    # Apply asset type filter
    if asset_type != 'All' and not merged_df.empty:
        filtered_merged = filtered_merged[filtered_merged['type'] == asset_type]
        # Get asset UUIDs for this type
        asset_uuids = filtered_merged['asset_uuid'].unique()
        filtered_findings = filtered_findings[filtered_findings['asset_uuid'].isin(asset_uuids)]
    
    return filtered_findings, filtered_merged

def load_scenario_config(scenario_name):
    """
    Load scenario-specific configuration and merge with default config.
    
    Args:
        scenario_name: Name of the scenario (baseline, enterprise, government, small)
    
    Returns:
        dict: Merged configuration
    """
    # Load default configuration
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_config_path = os.path.join(base_dir, 'configs', 'generator_config.yaml')
    default_config = load_config(default_config_path, use_fallback=True)
    
    # Ensure default_config is not None
    if default_config is None:
        default_config = {}
    
    # For baseline scenario, return just the default configuration
    if scenario_name == 'baseline':
        return default_config
    
    # Load scenario-specific configuration
    scenario_config_path = os.path.join(base_dir, 'configs', f'scenario_{scenario_name}.yaml')
    scenario_config = load_config(scenario_config_path, use_fallback=True)
    
    # Ensure scenario_config is not None
    if scenario_config is None:
        scenario_config = {}
    
    # Merge configurations (scenario-specific overrides default)
    merged_config = {**default_config, **scenario_config}
    
    return merged_config

def load_scenario_data(scenario_name):
    """
    Load data for a specific scenario.
    
    Args:
        scenario_name: Name of the scenario to load (enterprise, government, small, baseline)
    
    Returns:
        tuple: (assets, findings, top_risks)
    """
    try:
        # Handle baseline scenario differently
        if scenario_name == 'baseline':
            # Load baseline assets
            assets_file = 'data/outputs/assets.json'
            with open(assets_file, 'r') as f:
                assets = json.load(f)
            
            # Load baseline findings
            findings_file = 'data/outputs/findings.json'
            with open(findings_file, 'r') as f:
                findings = json.load(f)
            
            # Load baseline risk analysis
            try:
                risks_file = 'data/outputs/prioritization_baseline_full/vulnerability_prioritization_report.txt'
                with open(risks_file, 'r') as f:
                    top_risks = f.read()
            except FileNotFoundError:
                try:
                    # Fallback to general prioritization report
                    risks_file = 'data/outputs/vulnerability_prioritization_report.txt'
                    with open(risks_file, 'r') as f:
                        top_risks = f.read()
                except FileNotFoundError:
                    top_risks = "Risk analysis not available for baseline scenario."
        else:
            # Load scenario-specific assets
            assets_file = f'data/outputs/scenario_{scenario_name}_assets.json'
            with open(assets_file, 'r') as f:
                assets = json.load(f)
            
            # Load scenario-specific findings
            findings_file = f'data/outputs/scenario_{scenario_name}_findings.json'
            with open(findings_file, 'r') as f:
                findings = json.load(f)
            
            # Load top risks if available
            try:
                # Try scenario-specific prioritization directory first
                risks_file = f'data/outputs/prioritization_{scenario_name}/vulnerability_prioritization_report.txt'
                with open(risks_file, 'r') as f:
                    top_risks = f.read()
            except FileNotFoundError:
                try:
                    # Try with scenario name variations
                    if scenario_name == 'small':
                        risks_file = f'data/outputs/prioritization_small_business_full/vulnerability_prioritization_report.txt'
                    else:
                        risks_file = f'data/outputs/prioritization_{scenario_name}_full/vulnerability_prioritization_report.txt'
                    with open(risks_file, 'r') as f:
                        top_risks = f.read()
                except FileNotFoundError:
                    try:
                        # Fallback to old naming convention
                        risks_file = f'data/outputs/vulnerability_prioritization_report_{scenario_name}.txt'
                        with open(risks_file, 'r') as f:
                            top_risks = f.read()
                    except FileNotFoundError:
                        top_risks = "Risk analysis not available for this scenario."
        
        return assets, findings, top_risks
    
    except FileNotFoundError as e:
        st.error(f"Data files not found for {scenario_name} scenario: {e}")
        return [], [], ""

def create_scenario_selector():
    """
    Create scenario selection interface in sidebar.
    
    Returns:
        str: Selected scenario name
    """
    st.sidebar.header("🎯 Scenario Selection")
    
    scenarios = {
        'baseline': '📊 Baseline Configuration',
        'enterprise': '🏢 Enterprise Environment',
        'government': '🏛️ Government Environment', 
        'small': '🏪 Small Business Environment'
    }
    
    selected_scenario = st.sidebar.selectbox(
        "Select Analysis Scenario:",
        options=list(scenarios.keys()),
        format_func=lambda x: scenarios[x],
        index=0
    )
    
    # Add scenario description
    scenario_descriptions = {
        'baseline': "Original baseline configuration from generator_config.yaml with default assets and findings.",
        'enterprise': "Large-scale corporate environment with complex infrastructure and high security requirements.",
        'government': "Government agency environment with strict compliance and security protocols.",
        'small': "Small business environment with limited resources and simplified infrastructure."
    }
    
    st.sidebar.info(f"**{scenarios[selected_scenario]}**\n\n{scenario_descriptions[selected_scenario]}")
    
    return selected_scenario

def create_comparative_view():
    """
    Create comparative analysis view across all scenarios.
    """
    st.header("📊 Comparative Analysis Across Scenarios")
    
    scenarios = ['baseline', 'enterprise', 'government', 'small']
    scenario_data = {}
    
    # Load data for all scenarios
    for scenario in scenarios:
        assets, findings, _ = load_scenario_data(scenario)
        if assets and findings:
            assets_df = pd.DataFrame(assets)
            findings_df = pd.DataFrame(findings)
            scenario_data[scenario] = {
                'assets': assets_df,
                'findings': findings_df,
                'asset_count': len(assets_df),
                'finding_count': len(findings_df)
            }
    
    if not scenario_data:
        st.error("No scenario data available for comparative analysis.")
        return
    
    # Create comparative metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("📈 Asset Counts")
        asset_counts = {scenario: data['asset_count'] for scenario, data in scenario_data.items()}
        fig = px.bar(
            x=list(asset_counts.keys()),
            y=list(asset_counts.values()),
            title="Assets by Scenario",
            labels={'x': 'Scenario', 'y': 'Asset Count'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🔍 Finding Counts")
        finding_counts = {scenario: data['finding_count'] for scenario, data in scenario_data.items()}
        fig = px.bar(
            x=list(finding_counts.keys()),
            y=list(finding_counts.values()),
            title="Findings by Scenario",
            labels={'x': 'Scenario', 'y': 'Finding Count'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col3:
        st.subheader("📊 Severity Distribution")
        severity_data = []
        for scenario, data in scenario_data.items():
            severity_counts = data['findings']['severity'].value_counts()
            for severity, count in severity_counts.items():
                severity_data.append({
                    'Scenario': scenario,
                    'Severity': severity,
                    'Count': count
                })
        
        if severity_data:
            severity_df = pd.DataFrame(severity_data)
            fig = px.bar(
                severity_df,
                x='Scenario',
                y='Count',
                color='Severity',
                title="Severity Distribution by Scenario",
                barmode='stack'
            )
            st.plotly_chart(fig, use_container_width=True)

def main():
    """Main dashboard function"""
    # Header
    st.title("🛡️ Vulnerability Analysis Dashboard")
    st.markdown("---")
    
    # Analysis mode selection
    analysis_mode = st.sidebar.radio(
        "📋 Analysis Mode:",
        ["Single Scenario", "Comparative Analysis"],
        index=0
    )
    
    if analysis_mode == "Comparative Analysis":
        create_comparative_view()
        return
    
    # Single scenario analysis
    selected_scenario = create_scenario_selector()
    
    # Load scenario configuration
    config = load_scenario_config(selected_scenario)
    st.sidebar.success(f"Configuration loaded: {len(config.get('asset_types', []))} asset types, {len(config.get('locations', []))} locations")
    
    # Load scenario data
    with st.spinner(f"Loading {selected_scenario} scenario data..."):
        assets, findings, top_risks = load_scenario_data(selected_scenario)
    
    if not assets:
        st.error(f"No data available for {selected_scenario} scenario. Please ensure the data files exist.")
        return
    
    # Display scenario info
    st.info(f"**Current Scenario:** {selected_scenario.title()} Environment")
    
    # Prepare data
    assets_df, findings_df, merged_df, assets_with_metrics = prepare_dashboard_data(assets, findings)
    
    # Sidebar filters
    selected_asset_type, selected_severities, cvss_range = create_filters_sidebar(assets_df, findings_df)
    
    # Apply filters
    filtered_findings, filtered_merged = apply_filters(
        assets_df, findings_df, merged_df, 
        selected_asset_type, selected_severities, cvss_range
    )
    
    # Overview metrics
    st.header("📊 Overview")
    create_overview_metrics(assets_df, filtered_findings, assets_with_metrics)
    
    st.markdown("---")
    
    # Main content in tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📈 Analytics", "🎯 Risk Analysis", "📋 Asset Details", "⚙️ System Info"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            create_severity_distribution(filtered_findings)
        
        with col2:
            create_timeline_analysis(filtered_findings)
        
        create_asset_type_analysis(assets_with_metrics)
        create_risk_heatmap(assets_with_metrics)
    
    with tab2:
        create_top_risks_table(top_risks)
        
        if not assets_with_metrics.empty:
            st.subheader("📊 Risk Distribution")
            
            # Risk score distribution
            risk_scores = assets_with_metrics['avg_cvss']
            fig = px.histogram(
                x=risk_scores,
                nbins=20,
                title="Risk Score Distribution",
                labels={'x': 'Average CVSS Score', 'y': 'Number of Assets'}
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        st.subheader("🖥️ Asset Inventory")
        
        if not assets_with_metrics.empty:
            # Asset summary table
            display_assets = assets_with_metrics[[
                'hostname', 'type', 'os_family', 'location',
                'internet_exposed', 'lifecycle_stage', 'vuln_count', 'avg_cvss'
            ]].copy()
            
            display_assets.columns = [
                'Asset Name', 'Type', 'Operating System', 'Location',
                'Internet Exposed', 'Lifecycle', 'Vulnerabilities', 'Avg CVSS'
            ]
            
            st.dataframe(
                display_assets,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No asset data available")
    
    with tab4:
        st.subheader("ℹ️ System Information")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.info(f"""
            **Data Summary:**
            - Assets: {len(assets_df):,}
            - Vulnerabilities: {len(findings_df):,}
            - Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """)
        
        with col2:
            if not findings_df.empty:
                detection_tools = findings_df['detection_tool'].value_counts()
                st.info(f"""
                **Detection Tools:**
                {chr(10).join([f'- {tool}: {count}' for tool, count in detection_tools.head().items()])}
                """)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666;'>"
        "🛡️ Vulnerability Analysis Dashboard | "
        f"Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}"
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()