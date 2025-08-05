"""
NVD (National Vulnerability Database) integration

This module provides integration with the NVD API to fetch vulnerability data.
"""

import json
import sys
import os
import csv
import time
from typing import List

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from utils import load_secrets, send_request, setup_logging

# Constants
LOG_PREFIX = "NVD INTEGRATION: "
NVD_BASE_DIR = os.path.join(os.path.dirname(__file__), '..', 'data/inputs')
NVD_JSON_FILE = os.path.join(NVD_BASE_DIR, 'nvd_vulnerabilities.json')
NVD_CSV_FILE = os.path.join(NVD_BASE_DIR, 'nvd_vulnerabilities.csv')
NVD_SQL_FILE = os.path.join(NVD_BASE_DIR, 'nvd_vulnerabilities.sql')
logger = setup_logging('nvd_integration.log')


def collect(key: str) -> List:
    """
    Collect vulnerability data from NVD API.

    Args:
        key: NVD API key.

    Returns:
        List of vulnerability data.
    """
    start_index = 0
    results_per_page = 1000
    total_results = 1
    vulnerabilities = []

    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    headers = {
        'apiKey': key,
        'Accept': 'application/json'
    }
    
    while start_index < total_results:
        params = {
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }
        
        try:
            logger.info(f"{LOG_PREFIX}Requesting vulnerabilities {start_index} to {start_index + params['resultsPerPage']}...")
            response = send_request(url, params, headers, method='GET')
            
            if 'vulnerabilities' in response:
                batch_vulns = response['vulnerabilities']
                vulnerabilities.extend(batch_vulns)
                logger.info(f"{LOG_PREFIX}Retrieved {len(batch_vulns)} vulnerabilities (total: {len(vulnerabilities)})")
                
                # Update total_results from first response, but cap at max_results
                if start_index == 0 and 'totalResults' in response:
                    total_results = response['totalResults']
                    logger.info(f"{LOG_PREFIX}NVD API reports {total_results} total vulnerabilities")
            else:
                logger.warning(f"{LOG_PREFIX}Warning: No 'vulnerabilities' field in response: {response}")
                break
                
            start_index += params['resultsPerPage']
            
            # Respect rate limits
            time.sleep(0.1)
            
        except Exception as e:
            logger.error(f"{LOG_PREFIX}Error collecting vulnerabilities at index {start_index}: {e}")
            break
    
    logger.info(f"{LOG_PREFIX}Collection completed: {len(vulnerabilities)} vulnerabilities retrieved")
    return vulnerabilities

def process(vulnerabilities: List) -> List | None:
    """
    Process NVD vulnerabilities into a consistent format.
    
    Args:
        vulnerabilities: List of vulnerability data.
    
    Returns:
        List of processed vulnerability data.
    """
    try:
        # Process vulnerabilities into the expected format
        processed_vulns = []
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', 'UNKNOWN')
            vuln_status = cve_data.get('vulnStatus', 'UNKNOWN')
            
            # Skip rejected
            if vuln_status == 'REJECTED':
                logger.info(f"{LOG_PREFIX}Skipping rejected vulnerability: {cve_id}")
                continue
            
            # Extract CVSS metrics
            metrics = cve_data.get('metrics', {})
            base_score = 0.0
            severity = 'UNKNOWN'
            
            # Try CVSS v3.1 first
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                attack_complexity = cvss_data.get('attackComplexity', 'UNKNOWN')
                privileges_required = cvss_data.get('privilegesRequired', 'UNKNOWN')
                user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
                confidentiality_impact = cvss_data.get('confidentialityImpact', 'UNKNOWN')
                integrity_impact = cvss_data.get('integrityImpact', 'UNKNOWN')
                availability_impact = cvss_data.get('availabilityImpact', 'UNKNOWN')
            # Try CVSS v3.0
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                attack_complexity = cvss_data.get('attackComplexity', 'UNKNOWN')
                privileges_required = cvss_data.get('privilegesRequired', 'UNKNOWN')
                user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
                confidentiality_impact = cvss_data.get('confidentialityImpact', 'UNKNOWN')
                integrity_impact = cvss_data.get('integrityImpact', 'UNKNOWN')
                availability_impact = cvss_data.get('availabilityImpact', 'UNKNOWN')
            # Fallback to CVSS v2.0
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                # Derive severity from score for v2
                if base_score >= 9.0:
                    severity = 'CRITICAL'
                elif base_score >= 7.0:
                    severity = 'HIGH'
                elif base_score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                attack_vector = cvss_data.get('accessVector', 'UNKNOWN')
                attack_complexity = cvss_data.get('accessComplexity', 'UNKNOWN')
                privileges_required = cvss_data.get('privilegesRequired', 'UNKNOWN')
                user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
                confidentiality_impact = cvss_data.get('confidentialityImpact', 'UNKNOWN')
                integrity_impact = cvss_data.get('integrityImpact', 'UNKNOWN')
                availability_impact = cvss_data.get('availabilityImpact', 'UNKNOWN')
            
            # Extract description
            description = ''
            descriptions = cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract year from CVE ID
            year = 0
            if cve_id.startswith('CVE-'):
                try:
                    year = int(cve_id.split('-')[1])
                except (IndexError, ValueError):
                    year = 0
            
            processed_vulns.append({
                'id': cve_id,
                'severity': severity,
                'base_score': base_score,
                'description': description,
                'year': year,
                'attack_vector': attack_vector,
                'attack_complexity': attack_complexity,
                'privileges_required': privileges_required,
                'user_interaction': user_interaction,
                'confidentiality_impact': confidentiality_impact,
                'integrity_impact': integrity_impact,
                'availability_impact': availability_impact,
            })
    except Exception as e:
        logger.error(f"{LOG_PREFIX}Error processing vulnerabilities: {e}")
        return None
    else:
        logger.info(f"{LOG_PREFIX}Processing completed: {len(processed_vulns)} vulnerabilities processed")
        return processed_vulns


def save(processed_vulns: list) -> bool:
    """
    Save vulnerabilities to a JSON file, SQL file, and CSV file in data/inputs.

    Args:
        processed_vulns: List of processed vulnerability data.

    Returns:
        True if save is successful, False otherwise.
    """
    try:
        # Save as JSON
        json_file = os.path.join(NVD_BASE_DIR, 'nvd_vulnerabilities.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(processed_vulns, f, indent=2, ensure_ascii=False)
        
        # Save as CSV
        csv_file = os.path.join(NVD_BASE_DIR, 'nvd_vulnerabilities.csv')
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            if processed_vulns:
                writer = csv.DictWriter(f, fieldnames=[
                    'id',
                    'severity',
                    'base_score',
                    'description',
                    'year',
                    'attack_vector',
                    'attack_complexity',
                    'privileges_required',
                    'user_interaction',
                    'confidentiality_impact',
                    'integrity_impact',
                    'availability_impact',
                ])
                writer.writeheader()
                writer.writerows(processed_vulns)
        
        # Save as SQL
        sql_file = os.path.join(NVD_BASE_DIR, 'nvd_vulnerabilities.sql')
        with open(sql_file, 'w', encoding='utf-8') as f:
            f.write("-- NVD Vulnerabilities table\n")
            f.write("CREATE TABLE IF NOT EXISTS nvd_vulnerabilities (\n")
            f.write("    id VARCHAR(20) PRIMARY KEY,\n")
            f.write("    severity VARCHAR(20),\n")
            f.write("    base_score DECIMAL(3,1),\n")
            f.write("    description TEXT,\n")
            f.write("    year INTEGER,\n")
            f.write("    attack_vector VARCHAR(20),\n")
            f.write("    attack_complexity VARCHAR(20),\n")
            f.write("    privileges_required VARCHAR(20),\n")
            f.write("    confidentiality_impact VARCHAR(20),\n")
            f.write("    user_interaction VARCHAR(20),\n")
            f.write("    integrity_impact VARCHAR(20),\n")
            f.write("    availability_impact VARCHAR(20)\n")
            f.write(");\n\n")
            
            f.write("-- Vulnerabilities data\n")
            for vuln in processed_vulns:
                description = vuln['description'].replace("'", "''")
                f.write(f"INSERT INTO nvd_vulnerabilities VALUES (\n")
                f.write(f"    '{vuln['id']}',\n")
                f.write(f"    '{vuln['severity']}',\n")
                f.write(f"    {vuln['base_score']},\n")
                f.write(f"    '{description}',\n")
                f.write(f"    {vuln['year']},\n")    
                f.write(f"    '{vuln['attack_vector']}',\n")
                f.write(f"    '{vuln['attack_complexity']}',\n")
                f.write(f"    '{vuln['privileges_required']}',\n")
                f.write(f"    '{vuln['user_interaction']}',\n")
                f.write(f"    '{vuln['confidentiality_impact']}',\n")
                f.write(f"    '{vuln['integrity_impact']}',\n")
                f.write(f"    '{vuln['availability_impact']}'\n")
                f.write(");\n")
        
        logger.info(f"{LOG_PREFIX}Successfully saved {len(processed_vulns)} vulnerabilities to:")
        logger.info(f"  JSON: {json_file}")
        logger.info(f"  CSV: {csv_file}")
        logger.info(f"  SQL: {sql_file}")
        
        return True
        
    except Exception as e:
        logger.error(f"{LOG_PREFIX}Error saving vulnerabilities: {e}")
        return False

def main():
    """NVD Integration main function."""
    try:
        # Load NVD API key
        secrets = load_secrets()
        if 'nvd_key' not in secrets:
            logger.error(f"{LOG_PREFIX}Error: 'nvd_key' not found in secrets. Please add your NVD API key to SYNTHVULN_SECRETS environment variable.")
            logger.info(f"{LOG_PREFIX}Format: {{'nvd_key': '1234-5678-9012-3456-7890-1234-5678-9012'}}")
            return
        nvd_key = secrets['nvd_key']
        
        # Collect and process from API
        vulnerabilities = collect(nvd_key)
        processed_vulns = process(vulnerabilities)

        # Save to formats
        if processed_vulns:
            success = save(processed_vulns)
            if success:
                logger.info(f"{LOG_PREFIX}NVD integration completed successfully!")
            else:
                logger.error(f"{LOG_PREFIX}Error saving vulnerabilities.")
        else:
            logger.error(f"{LOG_PREFIX}Error processing vulnerabilities.")
            
    except KeyError as e:
        logger.error(f"{LOG_PREFIX}Missing required key in secrets: {e}")
        logger.info(f"{LOG_PREFIX}Please ensure 'nvd_key' is defined in your SYNTHVULN_SECRETS environment variable.")
    except Exception as e:
        logger.error(f"{LOG_PREFIX}Error in NVD integration: {e}")


if __name__ == '__main__':
    main()