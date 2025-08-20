# SynthVuln Configurations

This directory contains configuration files that control the behavior of the SynthVuln synthetic vulnerability data generation system. Each configuration file serves a specific purpose in defining how synthetic assets and vulnerabilities are generated for different organizational scenarios.

## Overview

The SynthVuln system uses a combination of scenario-specific configurations and global generator settings to create realistic synthetic vulnerability datasets. The configuration files work together to:

- Define organizational scenarios with specific asset distributions and security postures
- Control the generation of synthetic assets with realistic characteristics
- Map Common Platform Enumerations (CPEs) to asset types for vulnerability matching
- Configure vulnerability detection patterns and severity distributions

## Configuration Files

### 1. Example Scenario Configuration Files

Three scenario-specific YAML files define different organizational contexts:

#### `scenario_small.yaml` - Small Organization Scenario

**Purpose**: Represents a small business or startup environment with limited IT infrastructure.

**Key Characteristics**:
- **Asset Count**: 50 total assets
- **OS Distribution**: Windows-heavy (85% Windows, 10% Linux, 5% macOS)
- **Cloud Adoption**: Minimal (5% cloud deployment)
- **Asset Diversity**: Low diversity with focus on end-user devices
- **Security Posture**: Basic security controls

**Primary Asset Types**:
- Desktop computers (40%)
- Laptops (30%)
- Servers (15%)
- Mobile devices (10%)
- Network infrastructure (5%)

**Network Configuration**:
- Simple internal network (192.168.1.0/24)
- Limited DMZ presence
- Basic firewall protection

**Use Cases**:
- Small business vulnerability assessments
- Startup security planning
- Basic penetration testing scenarios
- Educational demonstrations

#### `scenario_enterprise.yaml` - Large Enterprise Scenario

**Purpose**: Models a large corporation with complex, hybrid IT infrastructure.

**Key Characteristics**:
- **Asset Count**: 5,000 total assets
- **OS Distribution**: Balanced (50% Windows, 35% Linux, 10% macOS, 5% other)
- **Cloud Adoption**: High (60% hybrid cloud deployment)
- **Asset Diversity**: High diversity across all asset types
- **Security Posture**: Advanced security controls (85% detection rate)

**Primary Asset Types**:
- Servers and virtual machines (40%)
- End-user devices (35%)
- Cloud services (15%)
- Network infrastructure (10%)

**Network Configuration**:
- Multiple network segments (corporate, DMZ, data center)
- Complex cloud integration
- Advanced security appliances
- Comprehensive monitoring

**Use Cases**:
- Enterprise risk assessments
- Large-scale vulnerability management
- Complex penetration testing
- Security tool validation
- Compliance reporting

#### `scenario_government.yaml` - Government Agency Scenario

**Purpose**: Represents a government agency with strict compliance and security requirements.

**Key Characteristics**:
- **Asset Count**: 500 total assets
- **OS Distribution**: Windows-dominant (70% Windows, 25% Linux, 5% other)
- **Cloud Adoption**: Moderate (30% government cloud)
- **Asset Diversity**: Moderate with focus on secure systems
- **Security Posture**: High security emphasis with compliance focus

**Primary Asset Types**:
- Secure workstations (35%)
- Government servers (30%)
- Classified systems (20%)
- Network security appliances (15%)

**Network Configuration**:
- Segmented networks by classification level
- Enhanced security controls
- Compliance-focused monitoring
- Restricted internet access

**Use Cases**:
- Government security assessments
- Compliance validation (FISMA, FedRAMP)
- Classified system testing
- Security clearance scenarios

### 2. Baseline / Default Configuration File

#### `generator_config.yaml` - Core Generation Parameters

**Purpose**: Defines the comprehensive rules and parameters for generating synthetic assets and vulnerabilities across all scenarios. This file provides a broad baseline of the available features of SynthVuln and can be highly customized to meet specific requirements.

**Major Configuration Sections**:

##### Default Paths and Settings
```yaml
default_paths:
  asset_output: data/outputs/assets.json
  findings_output: data/outputs/findings.json
  nvd_data_dir: data/inputs/
  cpe_mapping_config: configs/cpe_mapping_config.json

random_seed: null  # Set to integer for reproducible results
```

##### Asset Type Definitions
Defines 24 comprehensive asset types covering enterprise environments:
- **End-user devices**: Desktop, Laptop, Mobile device, Workstation
- **Server infrastructure**: Server, Webserver, Database server, Application server
- **Virtualization**: Virtual machine, Container, Kubernetes cluster, Serverless
- **Network devices**: Firewall, Router, Switch, Load balancer
- **Services**: DNS server, DHCP server, Mail server, Identity server

##### Operating System Distributions
Comprehensive OS definitions across categories:
- **Windows**: 13 versions (Windows 11/10, Server 2025-2008)
- **Linux**: 25+ distributions (Ubuntu, RHEL, CentOS, SUSE, Debian)
- **macOS**: 8 versions (Tahoe 26 to Catalina 10.15)
- **Mobile**: iOS and Android versions
- **Specialized**: Virtualization, Container, Network, Embedded systems

##### Asset-to-OS Mapping
Defines realistic OS distribution weights by asset type:
```yaml
os_distribution_by_asset:
  Desktop:
    Windows: 75.0
    macOS: 15.0
    Linux: 10.0
  Server:
    Linux: 70.0
    Windows: 30.0
```

##### Network Configuration
Defines network segments and IP ranges:
- **Corporate networks**: 192.168.x.x, 10.0.x.x ranges
- **DMZ networks**: 172.16.x.x ranges
- **VPN networks**: 10.8.x.x, 10.9.x.x ranges
- **Data center**: 10.10.x.x, 10.20.x.x, 10.30.x.x ranges

##### Security Features
Configures security control distributions:
```yaml
security_features:
  endpoint_security:
    default_probability: 0.8  # 80% coverage
    applicable_asset_types: [Desktop, Laptop, Server, ...]
  local_firewall:
    default_probability: 0.7  # 70% coverage
```

##### Internet Exposure Configuration
Defines realistic internet exposure probabilities:
```yaml
asset_internet_exposure_base:
  Webserver: 0.8      # 80% internet-facing
  VPN server: 0.85    # 85% internet-accessible
  Desktop: 0.05       # 5% exposed (remote access only)
  Database server: 0.05  # 5% directly exposed
```

##### Vulnerability Generation Settings
```yaml
findings_config:
  detection_tools: [Nessus, Qualys, OpenVAS, Nexpose, ...]
  severity_weights:
    CRITICAL: 5    # 5% critical vulnerabilities
    HIGH: 15       # 15% high severity
    MEDIUM: 35     # 35% medium severity
    LOW: 45        # 45% low severity
  
  recent_bias:
    enabled: true
    cutoff_years: 2
    multiplier: 3.0  # 3x weight for recent vulnerabilities
  
  vulnerability_counts:
    min: 1
    max: 8
  
  detection_probability: 0.7      # 70% detection rate
  false_positive_rate: 0.1        # 10% false positives
```

##### CPE (Common Platform Enumeration) Configuration
```yaml
cpe_config:
  enabled: true
  use_cpe_pools: true
  min_confidence_threshold: 0.15
  prefer_versioned_cpes: true
  
  cpe_based_asset_generation:
    enabled: true
    max_cpes_per_asset_type: 50
    version_distribution:
      latest: 0.3   # 30% latest versions
      recent: 0.4   # 40% recent versions
      older: 0.3    # 30% older versions
```

### 3. CPE Mapping Configuration File

#### `cpe_mapping_config.json` - CPE Database and Mapping

**Purpose**: Contains a comprehensive database of Common Platform Enumerations (CPEs) with enhanced metadata for realistic asset generation and vulnerability matching.

**Structure**:
```json
{
  "metadata": {
    "generated_at": "2025-01-01T20:20:20.111111",
    "nvd_source": "data/inputs/nvd_cpes.json",
    "total_cpes": 1445000,
    "processed_cpes": 1445000,
    "excluded_cpes": 50000,
    "confidence_threshold": 0.15
  },
  "cpe_index": {
    "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*": {
      "vendor": "vendor_name",
      "product": "product_name",
      "version": "version_string",
      "os_families": ["linux", "windows"],
      "system_types": ["server", "workstation"],
      "tags": ["database", "webserver"],
      "confidence": 0.85,
      "canonical_tokens": ["normalized", "search", "terms"]
    }
  },
  "cpe_pools": {
    "Server": ["cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", ...],
    "Desktop": ["cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*", ...]
  }
}
```

**Key Features**:
- **1.4+ million CPE entries** from the National Vulnerability Database
- **Enhanced metadata** including OS families, system types, and confidence scores
- **Canonical tokens** for improved search and matching
- **Pre-organized pools** by asset type for efficient generation
- **Confidence scoring** (0.15-1.0) based on keyword matching and metadata quality

**CPE Entry Attributes**:
- `vendor`: Software/hardware vendor name
- `product`: Product or software name
- `version`: Specific version string
- `os_families`: Compatible operating system families
- `system_types`: Applicable system types (server, workstation, network, mobile)
- `tags`: Descriptive tags (database, webserver, security, etc.)
- `confidence`: Quality score for CPE classification
- `canonical_tokens`: Normalized search terms for matching

**Usage in Asset Generation**:
1. **Asset Type Mapping**: CPEs are pre-filtered into pools by asset type
2. **Version Distribution**: Realistic version distributions (30% latest, 40% recent, 30% older)
3. **Vulnerability Matching**: CPEs enable accurate vulnerability-to-asset mapping
4. **Software Installation**: Realistic software installation patterns based on asset type

## Configuration Usage Examples

### Custom Scenario Creation

```yaml
# custom_scenario.yaml
name: "Custom Healthcare Scenario"
description: "Healthcare organization with HIPAA compliance focus"

asset_count: 1000

asset_type_weights:
  Desktop: 30.0
  Laptop: 25.0
  Server: 20.0
  Medical device: 15.0  # Custom asset type
  Mobile device: 10.0

os_distribution:
  Windows: 60.0
  Linux: 30.0
  Embedded: 10.0  # Medical devices

security_controls:
  endpoint_security_probability: 0.95  # High security requirement
  encryption_probability: 0.9          # HIPAA compliance
  access_control_probability: 0.95     # Strict access controls

network_segmentation:
  patient_network: "10.1.0.0/24"
  clinical_network: "10.2.0.0/24"
  administrative_network: "10.3.0.0/24"
  guest_network: "192.168.100.0/24"

compliance_requirements: # Not originally included but SynthVuln can be expanded to include compliance-based logic
  - "HIPAA"
  - "HITECH"
  - "SOX"
```

## Best Practices

### Scenario Configuration

1. **Asset Count Scaling**: Start with smaller counts for testing, scale up for production
2. **Realistic Distributions**: Base OS and asset type distributions on actual or desired organizational data
3. **Network Segmentation**: Define network segments that reflect real security boundaries
4. **Security Controls**: Align security control probabilities with organizational maturity

### Generator Configuration

1. **Reproducibility**: Set `random_seed` for consistent results across runs
2. **Performance Tuning**: Adjust batch sizes and cache settings for large datasets
3. **CPE Filtering**: Tune confidence thresholds to balance accuracy and coverage
4. **Vulnerability Bias**: Configure recent bias to reflect current threat landscape

### CPE Mapping

1. **Regular Updates**: Refresh CPE database
2. **Confidence Tuning**: Adjust confidence thresholds based on accuracy requirements
3. **Custom Pools**: Create custom CPE pools for specialized environments
4. **Version Management**: Balance between latest and legacy versions based on real-world practices


## Troubleshooting

### Common Issues

1. **Performance Issues**: Large asset and findings counts may require longer runtime
   - Solution: Tune performance settings or *patience*

2. **Unrealistic Distributions**: Generated data doesn't match expected patterns
   - Solution: Review and adjust probability, mappings, and more in the configuration