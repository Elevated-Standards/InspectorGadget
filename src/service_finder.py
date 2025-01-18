import os
import json
import datetime
import sys
import logging
import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)

def get_service_findings(service_type: str, resource_arn: Optional[str] = None) -> str:
    """
    This function creates a JSON string that represents the filter criteria for AWS Inspector findings based on the provided service type and optional resource ARN.
    
    Args:
        service_type (str): The type of AWS service to filter findings for.
        resource_arn (Optional[str], optional): The specific resource ARN to filter by. Defaults to None.
        
    Returns:
        str: A JSON string containing the filter criteria.
        
    Raises:
        TypeError: If `service_type` is not a string or `resource_arn` is not a string or None.
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
