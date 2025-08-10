"""NVD (National Vulnerability Database) integration

This module provides integration with the NVD API to fetch vulnerability data and CPE (Common Platform Enumeration) data.
The module can collect, process, and save both vulnerabilities and CPEs in JSON, CSV, and SQL formats.
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
CPE_JSON_FILE = os.path.join(NVD_BASE_DIR, 'nvd_cpes.json')
CPE_CSV_FILE = os.path.join(NVD_BASE_DIR, 'nvd_cpes.csv')
CPE_SQL_FILE = os.path.join(NVD_BASE_DIR, 'nvd_cpes.sql')
logger = setup_logging('nvd_integration.log')


def collect(key: str, url: str, data_type: str = 'vulnerabilities') -> List:
    """
    Collect data from NVD API (vulnerabilities or CPEs).

    Args:
        key: NVD API key.
        url: API endpoint URL.
        data_type: Type of data to collect ('vulnerabilities' or 'products').

    Returns:
        List of collected data.
    """
    start_index = 0
    results_per_page = 1
    total_results = 1
    collected_data = []

    headers = {
        'apiKey': key,
        'Accept': 'application/json'
    }
    
    results_per_page = 2000 if data_type == 'vulnerabilities' else 10000
    response_field = 'vulnerabilities' if data_type == 'vulnerabilities' else 'products'
    data_name = 'vulnerabilities' if data_type == 'vulnerabilities' else 'CPEs'
    
    while start_index < total_results:
        params = {
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }
        
        try:
            logger.info(f"{LOG_PREFIX}Requesting {data_name} {start_index} to {start_index + params['resultsPerPage']}...")
            response = send_request(url, params, headers, method='GET')
            
            if response_field in response:
                batch_data = response[response_field]
                collected_data.extend(batch_data)
                logger.info(f"{LOG_PREFIX}Retrieved {len(batch_data)} {data_name} (total: {len(collected_data)})")
                
                # Update total_results from first response
                if start_index == 0 and 'totalResults' in response:
                    total_results = response['totalResults']
                    logger.info(f"{LOG_PREFIX}NVD API reports {total_results} total {data_name}")
            else:
                logger.warning(f"{LOG_PREFIX}Warning: No '{response_field}' field in response: {response}")
                break
                
            start_index += params['resultsPerPage']
            
            # Respect rate limits
            time.sleep(0.1)
            
        except Exception as e:
            logger.error(f"{LOG_PREFIX}Error collecting {data_name} at index {start_index}: {e}")
            break
    
    logger.info(f"{LOG_PREFIX}Collection completed: {len(collected_data)} {data_name} retrieved")
    return collected_data

def process(data: List, data_type: str = 'vulnerabilities') -> List | None:
    """
    Process NVD data (vulnerabilities or CPEs) into a consistent format.
    
    Args:
        data: List of data from NVD API.
        data_type: Type of data to process ('vulnerabilities' or 'products').
    
    Returns:
        List of processed data.
    """
    if data_type == 'vulnerabilities':
        return _process_vulnerabilities(data)
    elif data_type == 'products':
        return _process_cpes(data)
    else:
        logger.error(f"{LOG_PREFIX}Unknown data type: {data_type}")
        return None


def _process_vulnerabilities(vulnerabilities: List) -> List | None:
    """
    Process NVD vulnerabilities into a consistent format.
    
    Args:
        vulnerabilities: List of vulnerability data.
    
    Returns:
        List of processed vulnerability data.
    """
    try:
        # Process vulnerabilities into the expected format
        processed = []
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', 'UNKNOWN')

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
            
            # Extract CPE information from configurations
            cpe_matches = []
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_match_list = node.get('cpeMatch', [])
                    for cpe_match in cpe_match_list:
                        cpe_info = {
                            'criteria': cpe_match.get('criteria', ''),
                            'vulnerable': cpe_match.get('vulnerable', False),
                            'match_criteria_id': cpe_match.get('matchCriteriaId', ''),
                            'version_start_including': cpe_match.get('versionStartIncluding', ''),
                            'version_end_including': cpe_match.get('versionEndIncluding', ''),
                            'version_start_excluding': cpe_match.get('versionStartExcluding', ''),
                            'version_end_excluding': cpe_match.get('versionEndExcluding', '')
                        }
                        # Only add non-empty CPE criteria
                        if cpe_info['criteria']:
                            cpe_matches.append(cpe_info)
            
            processed.append({
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
                'cpe_matches': cpe_matches,
            })
    except Exception as e:
        logger.error(f"{LOG_PREFIX}Error processing vulnerabilities: {e}")
        return None
    else:
        logger.info(f"{LOG_PREFIX}Processing completed: {len(processed)} vulnerabilities processed")
        return processed


def _process_cpes(cpes: List) -> List | None:
    """
    Process NVD CPEs into a consistent format.
    
    Args:
        cpes: List of CPE data from NVD API.
    
    Returns:
        List of processed CPE data.
    """
    try:
        processed = []
        for cpe_item in cpes:
            cpe_data = cpe_item.get('cpe', {})
            cpe_name = cpe_data.get('cpeName', '')
            
            if not cpe_name:
                continue
                
            # Parse CPE name (format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other)
            cpe_parts = cpe_name.split(':')
            if len(cpe_parts) < 6:
                continue
                
            part = cpe_parts[2] if len(cpe_parts) > 2 else ''
            vendor = cpe_parts[3] if len(cpe_parts) > 3 else ''
            product = cpe_parts[4] if len(cpe_parts) > 4 else ''
            version = cpe_parts[5] if len(cpe_parts) > 5 else ''
            update = cpe_parts[6] if len(cpe_parts) > 6 else ''
            edition = cpe_parts[7] if len(cpe_parts) > 7 else ''
            language = cpe_parts[8] if len(cpe_parts) > 8 else ''
            sw_edition = cpe_parts[9] if len(cpe_parts) > 9 else ''
            target_sw = cpe_parts[10] if len(cpe_parts) > 10 else ''
            target_hw = cpe_parts[11] if len(cpe_parts) > 11 else ''
            other = cpe_parts[12] if len(cpe_parts) > 12 else ''
            
            # Extract titles and references
            titles = cpe_data.get('titles', [])
            title = ''
            for title_item in titles:
                if title_item.get('lang') == 'en':
                    title = title_item.get('title', '')
                    break
            
            # Extract references
            refs = cpe_data.get('refs', [])
            references = [ref.get('ref', '') for ref in refs if ref.get('ref')]
            
            # Determine last modified date
            last_modified = cpe_data.get('lastModified', '')
            created = cpe_data.get('created', '')
            
            processed.append({
                'cpe_name': cpe_name,
                'part': part,
                'vendor': vendor,
                'product': product,
                'version': version,
                'update': update,
                'edition': edition,
                'language': language,
                'sw_edition': sw_edition,
                'target_sw': target_sw,
                'target_hw': target_hw,
                'other': other,
                'title': title,
                'references': '|'.join(references),
                'last_modified': last_modified,
                'created': created
            })
            
    except Exception as e:
        logger.error(f"{LOG_PREFIX}Error processing CPEs: {e}")
        return None
    else:
        logger.info(f"{LOG_PREFIX}Processing completed: {len(processed)} CPEs processed")
        return processed


def save_cpes(processed: list) -> bool:
    """
    Save CPEs to JSON, CSV, and SQL files in data/inputs.

    Args:
        processed: List of processed CPE data.

    Returns:
        True if save is successful, False otherwise.
    """
    try:
        # Save as JSON
        with open(CPE_JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump(processed, f, indent=2, ensure_ascii=False)
        
        # Save as CSV
        with open(CPE_CSV_FILE, 'w', newline='', encoding='utf-8') as f:
            if processed:
                writer = csv.DictWriter(f, fieldnames=[
                    'cpe_name',
                    'part',
                    'vendor',
                    'product',
                    'version',
                    'update',
                    'edition',
                    'language',
                    'sw_edition',
                    'target_sw',
                    'target_hw',
                    'other',
                    'title',
                    'references',
                    'last_modified',
                    'created'
                ])
                writer.writeheader()
                writer.writerows(processed)
        
        # Save as SQL
        with open(CPE_SQL_FILE, 'w', encoding='utf-8') as f:
            f.write("-- NVD CPEs table\n")
            f.write("CREATE TABLE IF NOT EXISTS nvd_cpes (\n")
            f.write("    cpe_name VARCHAR(500) PRIMARY KEY,\n")
            f.write("    part VARCHAR(10),\n")
            f.write("    vendor VARCHAR(100),\n")
            f.write("    product VARCHAR(100),\n")
            f.write("    version VARCHAR(100),\n")
            f.write("    update_field VARCHAR(100),\n")
            f.write("    edition VARCHAR(100),\n")
            f.write("    language VARCHAR(20),\n")
            f.write("    sw_edition VARCHAR(100),\n")
            f.write("    target_sw VARCHAR(100),\n")
            f.write("    target_hw VARCHAR(100),\n")
            f.write("    other_field VARCHAR(100),\n")
            f.write("    title TEXT,\n")
            f.write("    references TEXT,\n")
            f.write("    last_modified VARCHAR(30),\n")
            f.write("    created VARCHAR(30)\n")
            f.write(");\n\n")
            
            f.write("-- CPEs data\n")
            for cpe in processed:
                title = cpe['title'].replace("'", "''")
                references = cpe['references'].replace("'", "''")
                f.write(f"INSERT INTO nvd_cpes VALUES (\n")
                f.write(f"    '{cpe['cpe_name']}',\n")
                f.write(f"    '{cpe['part']}',\n")
                f.write(f"    '{cpe['vendor']}',\n")
                f.write(f"    '{cpe['product']}',\n")
                f.write(f"    '{cpe['version']}',\n")
                f.write(f"    '{cpe['update']}',\n")
                f.write(f"    '{cpe['edition']}',\n")
                f.write(f"    '{cpe['language']}',\n")
                f.write(f"    '{cpe['sw_edition']}',\n")
                f.write(f"    '{cpe['target_sw']}',\n")
                f.write(f"    '{cpe['target_hw']}',\n")
                f.write(f"    '{cpe['other']}',\n")
                f.write(f"    '{title}',\n")
                f.write(f"    '{references}',\n")
                f.write(f"    '{cpe['last_modified']}',\n")
                f.write(f"    '{cpe['created']}'\n")
                f.write(");\n")
        
        logger.info(f"{LOG_PREFIX}Successfully saved {len(processed)} CPEs to:")
        logger.info(f"  JSON: {CPE_JSON_FILE}")
        logger.info(f"  CSV: {CPE_CSV_FILE}")
        logger.info(f"  SQL: {CPE_SQL_FILE}")
        
        return True
        
    except Exception as e:
        logger.error(f"{LOG_PREFIX}Error saving CPEs: {e}")
        return False


def save(processed: list) -> bool:
    """
    Save vulnerabilities to a JSON file, SQL file, and CSV file in data/inputs.

    Args:
        processed: List of processed vulnerability data.

    Returns:
        True if save is successful, False otherwise.
    """
    try:
        # Save as JSON
        json_file = os.path.join(NVD_BASE_DIR, 'nvd_vulnerabilities.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(processed, f, indent=2, ensure_ascii=False)
        
        # Save as CSV
        csv_file = os.path.join(NVD_BASE_DIR, 'nvd_vulnerabilities.csv')
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            if processed:
                csv_data = []
                for vuln in processed:
                    csv_row = vuln.copy()
                    csv_row['cpe_matches'] = json.dumps(csv_row['cpe_matches'])
                    csv_data.append(csv_row)
                
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
                    'cpe_matches',
                ])
                writer.writeheader()
                writer.writerows(csv_data)
        
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
            
            f.write("-- CVE CPE Matches table\n")
            f.write("CREATE TABLE IF NOT EXISTS cve_cpe_matches (\n")
            f.write("    id INTEGER PRIMARY KEY AUTOINCREMENT,\n")
            f.write("    cve_id VARCHAR(20),\n")
            f.write("    criteria VARCHAR(500),\n")
            f.write("    vulnerable BOOLEAN,\n")
            f.write("    match_criteria_id VARCHAR(50),\n")
            f.write("    version_start_including VARCHAR(50),\n")
            f.write("    version_end_including VARCHAR(50),\n")
            f.write("    version_start_excluding VARCHAR(50),\n")
            f.write("    version_end_excluding VARCHAR(50),\n")
            f.write("    FOREIGN KEY (cve_id) REFERENCES nvd_vulnerabilities(id)\n")
            f.write(");\n\n")
            
            f.write("-- Vulnerabilities data\n")
            for vuln in processed:
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
                
                # Insert CPE matches
                for cpe_match in vuln['cpe_matches']:
                    criteria = cpe_match['criteria'].replace("'", "''")
                    f.write(f"INSERT INTO cve_cpe_matches (cve_id, criteria, vulnerable, match_criteria_id, version_start_including, version_end_including, version_start_excluding, version_end_excluding) VALUES (\n")
                    f.write(f"    '{vuln['id']}',\n")
                    f.write(f"    '{criteria}',\n")
                    f.write(f"    {1 if cpe_match['vulnerable'] else 0},\n")
                    f.write(f"    '{cpe_match['match_criteria_id']}',\n")
                    f.write(f"    '{cpe_match['version_start_including']}',\n")
                    f.write(f"    '{cpe_match['version_end_including']}',\n")
                    f.write(f"    '{cpe_match['version_start_excluding']}',\n")
                    f.write(f"    '{cpe_match['version_end_excluding']}'\n")
                    f.write(");\n")
        
        logger.info(f"{LOG_PREFIX}Successfully saved {len(processed)} vulnerabilities to:")
        logger.info(f"  JSON: {json_file}")
        logger.info(f"  CSV: {csv_file}")
        logger.info(f"  SQL: {sql_file}")
        
        return True
        
    except Exception as e:
        logger.error(f"{LOG_PREFIX}Error saving vulnerabilities: {e}")
        return False

def main(collection_type='both'):
    """NVD Integration main function.
    
    Args:
        collection_type (str): Type of data to collect - 'cves', 'cpes', or 'both'
    """
    try:
        # Load NVD API key
        secrets = load_secrets()
        if 'nvd_key' not in secrets:
            logger.error(f"{LOG_PREFIX}Error: 'nvd_key' not found in secrets. Please add your NVD API key to SYNTHVULN_SECRETS environment variable.")
            logger.info(f"{LOG_PREFIX}Format: {{'nvd_key': '1234-5678-9012-3456-7890-1234-5678-9012'}}")
            return
        nvd_key = secrets['nvd_key']

        all_collections = {
            "vulnerabilities" : {
                'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected',
                'data_type': 'vulnerabilities'
            },
            "products" : {
                'url': 'https://services.nvd.nist.gov/rest/json/cpes/2.0',
                'data_type': 'products'
            }
        }
        
        # Filter collections based on collection_type
        collections = {}
        if collection_type in ['cves', 'both']:
            collections['vulnerabilities'] = all_collections['vulnerabilities']
        if collection_type in ['cpes', 'both']:
            collections['products'] = all_collections['products']
        
        if not collections:
            logger.error(f"{LOG_PREFIX}Invalid collection_type: {collection_type}. Must be 'cves', 'cpes', or 'both'.")
            return
        
        # Collect and process from API
        for collection_name, collection_info in collections.items():
            logger.info(f"{LOG_PREFIX}Starting collection of {collection_name}...")
            
            # Collect data
            results = collect(nvd_key, collection_info['url'], collection_info['data_type'])
            
            # Process data based on type
            processed = process(results, collection_info['data_type'])
            save_func = save if collection_name == 'vulnerabilities' else save_cpes

            # Save to formats
            if processed:
                success = save_func(processed)
                if success:
                    logger.info(f"{LOG_PREFIX}{collection_name.capitalize()} integration completed successfully!")
                else:
                    logger.error(f"{LOG_PREFIX}Error saving {collection_name}.")
            else:
                logger.error(f"{LOG_PREFIX}Error processing {collection_name}.")
            
    except KeyError as e:
        logger.error(f"{LOG_PREFIX}Missing required key in secrets: {e}")
        logger.info(f"{LOG_PREFIX}Please ensure 'nvd_key' is defined in your SYNTHVULN_SECRETS environment variable.")
    except Exception as e:
        logger.error(f"{LOG_PREFIX}Error in NVD integration: {e}")


if __name__ == '__main__':
    main()
