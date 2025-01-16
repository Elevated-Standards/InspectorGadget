import os
import json
import logging
from typing import Dict, Any

# Configure logging
logger = logging.getLogger(__name__)

def get_service_findings(service_type: str, resource_arn: str = None) -> str:
    """
    Generate filter criteria for AWS Inspector findings.
    
    Args:
        service_type (str): Type of AWS service to filter findings for
        resource_arn (str, optional): Specific resource ARN to filter by
        
    Returns:
        str: JSON string containing the filter criteria
    """
    base_criteria = {
        "resourceType": [{
            "comparison": "EQUALS", 
            "value": service_type
        }]
    }
    if resource_arn:
        base_criteria["resourceArn"] = [{
            "comparison": "EQUALS",
            "value": resource_arn
        }]
    
    return json.dumps(base_criteria)

def save_findings(file_path: str, findings: Dict[str, Any]) -> None:
    """
    Save findings to a JSON file.
    
    Args:
        file_path (str): Path where findings should be saved
        findings (Dict[str, Any]): Findings data to save
        
    Raises:
        Exception: If there's an error creating directory or saving file
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as output_file:
            json.dump(findings, output_file, indent=2)
        logger.info(f"Findings saved to {file_path}")
    except Exception as e:
        logger.error(f"Failed to save findings to {file_path}: {e}")