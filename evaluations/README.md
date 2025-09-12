# SynthVuln Evaluations

This directory contains a comprehensive evaluation framework for the SynthVuln synthetic vulnerability dataset generator. The evaluation suite provides multiple analytical perspectives to assess dataset quality, realism, and utility for cybersecurity research and training.

## Overview

The evaluation framework consists of five main components:

1. **Statistical Analysis** (`scenario_statistics.py`) - Descriptive and inferential statistics
2. **Entropy Analysis** (`entropy.py`) - Data diversity and randomness assessment
3. **Risk Prioritization** (`prioritization.py`) - Vulnerability ranking and asset risk scoring
4. **Interactive Dashboard** (`dashboard.py`) - Real-time data visualization
5. **Machine Learning Analysis** (`ml_risk_prediction.ipynb`) - Predictive modeling and feature analysis

## Evaluation Scripts

### 1. Statistical Analysis (`scenario_statistics.py`)

**Purpose**: Performs comprehensive descriptive and inferential statistical analysis across different scenario datasets to validate the statistical properties and comparative characteristics of generated data.

**Methodology**:
- **Descriptive Statistics**: Asset count, type distributions, location distributions
- **Comparative Analysis**: Cross-scenario statistical comparisons
- **Significance Testing**: Chi-square tests for categorical distributions, Kruskal-Wallis tests for continuous variables
- **Vulnerability Pattern Analysis**: CVSS score distributions, severity classifications

**Key Features**:
- Multi-scenario comparison (small business, enterprise, government, baseline)
- Statistical significance testing with p-values
- Automated report generation with visualizations
- Support for both assets and findings analysis

**Usage**:
```bash
python evaluations/scenario_statistics.py
```

**Inputs**:
- `data/outputs/scenario_*_assets.json` - Asset data for each scenario
- `data/outputs/scenario_*_findings.json` - Vulnerability findings for each scenario
- `data/outputs/assets.json` - Baseline asset data
- `data/outputs/findings.json` - Baseline findings data

**Outputs**:
- `data/outputs/scenario_statistics/statistical_analysis_report.txt` - Comprehensive statistical report
- `data/outputs/scenario_statistics/asset_type_distribution.png` - Asset type distribution visualization
- `data/outputs/scenario_statistics/security_posture_comparison.png` - Security posture comparison chart
- `data/outputs/scenario_statistics/software_distribution.png` - Software package distribution visualization
- Console output with summary statistics

**Interpretation**:
- **Asset Distribution**: Validates scenario-specific asset type distributions
- **Statistical Significance**: P-values < 0.05 indicate significant differences between scenarios
- **Vulnerability Patterns**: Assesses CVSS score distributions and severity classifications

### 2. Entropy Analysis (`entropy.py`)

**Purpose**: Quantifies data diversity and randomness using Shannon entropy to evaluate the quality of categorical distributions across vulnerability scenarios.

**Methodology**:
- **Shannon Entropy Calculation**: H(X) = -Σ p(x) log₂ p(x) for categorical distributions
- **Normalized Entropy**: Scales entropy to [0,1] range for interpretability
- **Multi-dimensional Analysis**: Evaluates entropy across multiple categorical features
- **Comparative Assessment**: Cross-scenario entropy comparison

**Key Features**:
- Base-2 logarithm for bit-based entropy measurement
- Normalized entropy for standardized comparison
- Categorical feature analysis (asset types, locations, operating systems)
- Automated diversity level classification (Low/Medium/High)

**Usage**:
```bash
# Single scenario analysis
python evaluations/entropy.py --scenario enterprise

# Comparative analysis across all scenarios
python evaluations/entropy.py --comparative

# Full analysis with baseline
python evaluations/entropy.py --full
```

**Inputs**:
- Scenario configuration files (`configs/scenario_*.yaml`)
- Generated asset datasets (`data/outputs/scenario_*_assets.json`)
- Generated findings datasets (`data/outputs/scenario_*_findings.json`)

**Outputs**:
- `data/outputs/entropy_analysis_*.json` - Detailed entropy metrics
- `data/outputs/shannon_entropy_heatmap.png` - Shannon entropy heatmap visualization
- `data/outputs/normalized_entropy_heatmap.png` - Normalized entropy heatmap visualization
- `data/outputs/entropy_by_column.png` - Entropy comparison by column visualization
- `data/outputs/average_diversity_score.png` - Average diversity score by scenario
- `data/outputs/entropy_report_*.txt` - Human-readable analysis reports

**Interpretation**:
- **High Entropy (>0.8)**: Excellent diversity, realistic distribution
- **Medium Entropy (0.5-0.8)**: Good diversity with some concentration
- **Low Entropy (<0.5)**: Limited diversity, potential bias
- **Normalized Values**: Enable direct comparison across different categorical features

### 3. Risk Prioritization (`prioritization.py`)

**Purpose**: Implements a simple vulnerability prioritization algorithm based on CVSS scores and asset criticality to identify high-risk assets and validate risk assessment methodologies.

**Methodology**:
- **Composite Risk Scoring**: Combines CVSS scores, asset criticality, and exposure factors
- **Asset Criticality Mapping**: Type-based criticality scores (Database: 10.0, IoT: 4.0)
- **Lifecycle Risk Multipliers**: Production (1.0), Development (0.6), Decommissioned (0.3)
- **Multi-factor Risk Assessment**: Weighted combination of vulnerability and asset factors

**Risk Calculation Formula**:
```
Composite Risk = (CVSS_Weight × Avg_CVSS + Exposure_Weight × Exposure_Score + Criticality_Weight × Asset_Criticality)
Default Weights: CVSS (0.4), Exposure (0.3), Criticality (0.3)
```

**Key Features**:
- Configurable risk scoring weights
- Asset type-specific criticality scores
- Internet exposure risk amplification
- Top-10 riskiest assets identification
- Detailed vulnerability metrics per asset

**Usage**:
```bash
python evaluations/prioritization.py --scenario enterprise
```

**Inputs**:
- Asset datasets with type and lifecycle information
- Vulnerability findings with CVSS scores
- Configuration files for risk parameters

**Outputs**:
- `data/outputs/prioritization_*/top_10_riskiest_assets.json` - Top 10 riskiest assets data
- `data/outputs/prioritization_*/vulnerability_prioritization_report.txt` - Comprehensive risk report

**Interpretation**:
- **Composite Risk Score**: Range from 0-30, with >10.0 indicating high risk
- **Criticality Score**: Range from 0-10, based on asset type and characteristics
- **Vulnerability Risk**: Range from 0-20, weighted by severity and CVSS scores
- **Asset Rankings**: Prioritized list for remediation planning
- **Vulnerability Counts**: Critical, High, Medium, Low severity breakdown
- **CVSS Metrics**: Average and maximum CVSS scores per asset

### 4. Interactive Dashboard (`dashboard.py`)

**Purpose**: Provides real-time interactive visualization of vulnerability data, risk metrics, and asset information using Streamlit for exploratory data analysis.

**Methodology**:
- **Real-time Data Loading**: Dynamic loading of latest generated datasets
- **Interactive Filtering**: Multi-dimensional data exploration
- **Statistical Aggregation**: On-demand metric calculation
- **Responsive Visualization**: Plotly-based interactive charts

**Key Features**:
- Multi-scenario data visualization
- Asset and vulnerability overview metrics
- Severity distribution analysis
- Risk score distribution charts
- Asset type and location breakdowns
- Top riskiest assets display

**Usage**:
```bash
streamlit run evaluations/dashboard.py
```

**Inputs**:
- **Scenario-specific assets**: `data/outputs/scenario_{scenario}_assets.json` (enterprise, government, small)
- **Scenario-specific findings**: `data/outputs/scenario_{scenario}_findings.json` (enterprise, government, small)
- **Baseline assets**: `data/outputs/assets.json` (for baseline scenario)
- **Baseline findings**: `data/outputs/findings.json` (for baseline scenario)
- **Risk prioritization reports**: Multiple fallback paths including:
  - `data/outputs/prioritization_{scenario}/vulnerability_prioritization_report.txt`
  - `data/outputs/prioritization_{scenario}_full/vulnerability_prioritization_report.txt`
  - `data/outputs/vulnerability_prioritization_report_{scenario}.txt`

**Outputs**:
- Interactive web interface (default http://localhost:8501)
- Real-time charts and metrics
- Downloadable data tables

**Interpretation**:
- **Overview Metrics**: Total assets, vulnerabilities, coverage statistics
- **Severity Distribution**: Critical/High/Medium/Low vulnerability counts
- **Risk Analysis**: Asset risk score distributions and rankings
- **Interactive Exploration**: Drill-down capabilities for detailed analysis

### 5. Machine Learning Analysis (`ml_risk_prediction.ipynb`)

**Purpose**: Demonstrates machine learning approaches for vulnerability risk prediction and asset prioritization using SynthVuln-generated datasets for model training and validation.

**Methodology**:
- **Feature Engineering**: Asset characteristics, vulnerability metrics, security controls, privileged user counts
- **Model Training**: Linear Regression, Random Forest, Gradient Boosting (regression models)
- **Risk Scoring**: Composite risk score calculation with security control reduction factors
- **Performance Evaluation**: RMSE, MAE, R² metrics for regression analysis

**Key Features**:
- Enhanced feature set including security controls (endpoint security, firewall status)
- Vulnerability severity breakdown (critical, high, medium, low counts)
- Privileged user account analysis
- Multiple regression algorithms comparison
- Feature importance analysis using Random Forest
- Risk categorization (Low, Medium, High, Critical)

**Usage**:
- Set SCENARIO and file paths in notebook
- Run all cells in notebook

**Inputs (Set in notebook)**:
- `data/outputs/scenario_{scenario}_assets.json` - Asset data with security attributes
- `data/outputs/scenario_{scenario}_findings.json` - Vulnerability findings data
- Scenario configuration files (enterprise, government, small) or baseline configuration file

**Outputs (Set in notebook)**:
- `data/outputs/ml_risk_prediction_results_{scenario}.json` - Model performance, feature importance, top 10 riskiest assets
- Feature correlation heatmap visualization
- Risk score distribution plots
- Model performance comparison plots (actual vs predicted)
- Feature importance bar chart

**Interpretation**:
- **Model Performance**: RMSE, MAE, and R² scores for each algorithm
- **Feature Importance**: Vulnerability count and unique CVEs are top predictors
- **Risk Categories**: All assets categorized as Critical (risk score > 8)
- **Security Controls**: Endpoint security and firewall act as risk reduction factors

## Usage Examples

### Complete Evaluation Pipeline Example

```bash
# 1. Generate datasets (prerequisite)
python synthvuln.py --config configs/scenario_enterprise.yaml --count-assets 5000 --count-findings 20000
python synthvuln.py --config configs/scenario_government.yaml --count-assets 500 --count-findings 2000
python synthvuln.py --config configs/scenario_small.yaml --count-assets 50 --count-findings 150

# 2. Run statistical analysis
python evaluations/scenario_statistics.py

# 3. Perform entropy analysis
python evaluations/entropy.py --full

# 4. Execute risk prioritization
python evaluations/prioritization.py

# 5. Launch interactive dashboard
streamlit run evaluations/dashboard.py

# 6. Open ML analysis notebook
jupyter notebook evaluations/ml_risk_prediction.ipynb
```

### Custom Configuration

```python
# Custom risk weights for prioritization
from evaluations.prioritization import VulnerabilityPrioritizer

prioritizer = VulnerabilityPrioritizer()
prioritizer.weights = {
    'cvss_weight': 0.5,
    'exposure_weight': 0.3,
    'criticality_weight': 0.2
}
```