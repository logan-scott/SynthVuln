import json
from typing import List, Dict, Any
from datetime import datetime

class FindingsValidator:
    def __init__(self, findings_file: str = 'data/raw/findings.json',
                 asset_file: str = 'data/raw/asset_metadata.json'):
        self.findings_file = findings_file
        self.asset_file = asset_file
        self.findings = self._load_findings()
        self.assets = self._load_assets()
        self.asset_uuids = set(asset['uuid'] for asset in self.assets)

    def _load_findings(self) -> List[Dict[str, Any]]:
        try:
            with open(self.findings_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading findings: {e}")
            return []

    def _load_assets(self) -> List[Dict[str, Any]]:
        try:
            with open(self.asset_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading assets: {e}")
            return []

    def _is_valid_uuid(self, uuid_str: str) -> bool:
        try:
            # Basic UUID format check
            return len(uuid_str) == 36 and uuid_str.count('-') == 4
        except:
            return False

    def _is_valid_timestamp(self, timestamp_str: str) -> bool:
        try:
            datetime.fromisoformat(timestamp_str)
            return True
        except:
            return False

    def _is_valid_severity(self, severity: str) -> bool:
        return severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def _is_valid_base_score(self, score: float) -> bool:
        return 0.0 <= score <= 10.0

    def validate_finding(self, finding: Dict[str, Any]) -> List[str]:
        errors = []

        # Required fields
        required_fields = [
            "finding_id", "asset_uuid", "timestamp", "detection_tool",
            "cve_id", "severity", "base_score", "is_false_positive"
        ]
        
        for field in required_fields:
            if field not in finding:
                errors.append(f"Missing required field: {field}")

        if not errors:  # Only proceed with validation if all required fields exist
            # Validate finding_id (UUID format)
            if not self._is_valid_uuid(finding["finding_id"]):
                errors.append(f"Invalid finding_id format: {finding['finding_id']}")

            # Validate asset_uuid exists in assets
            if finding["asset_uuid"] not in self.asset_uuids:
                errors.append(f"Asset UUID not found: {finding['asset_uuid']}")

            # Validate timestamp format
            if not self._is_valid_timestamp(finding["timestamp"]):
                errors.append(f"Invalid timestamp format: {finding['timestamp']}")

            # Validate CVE ID format
            if not finding["cve_id"].startswith("CVE-"):
                errors.append(f"Invalid CVE ID format: {finding['cve_id']}")

            # Validate severity
            if not self._is_valid_severity(finding["severity"]):
                errors.append(f"Invalid severity value: {finding['severity']}")

            # Validate base score
            if not self._is_valid_base_score(finding["base_score"]):
                errors.append(f"Invalid base score: {finding['base_score']}")

            # Validate is_false_positive is boolean
            if not isinstance(finding["is_false_positive"], bool):
                errors.append("is_false_positive must be a boolean value")

        return errors

    def validate_all(self) -> Dict[str, Any]:
        if not self.findings:
            return {"status": "error", "message": "No findings to validate"}

        all_errors = {}
        for i, finding in enumerate(self.findings):
            errors = self.validate_finding(finding)
            if errors:
                all_errors[f"finding_{i}"] = errors

        if all_errors:
            return {
                "status": "error",
                "message": "Validation failed",
                "errors": all_errors
            }
        else:
            return {
                "status": "success",
                "message": f"All {len(self.findings)} findings are valid"
            }

def main():
    validator = FindingsValidator()
    result = validator.validate_all()
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()