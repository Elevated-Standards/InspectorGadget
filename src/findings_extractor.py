import os
import json
import datetime
import sys
import logging
import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

def extract_basic_info(finding: Dict[str, Any], aws_service: str) -> Dict[str, Any]:
    """
    Extracts basic information from a finding.

    Args:
        finding (Dict[str, Any]): The finding dictionary.
        aws_service (str): The name of the AWS service.

    Returns:
        Dict[str, Any]: A dictionary containing basic information about the finding.
    """
    return {
        "AWS Service": aws_service,
        "findingArn": finding.get("findingArn"),
        "firstObservedAt": finding.get("firstObservedAt"),
        "lastObservedAt": finding.get("lastObservedAt"),
        "status": finding.get("status"),
        "type": finding.get("type"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "description": finding.get("description")
    }

def extract_service_specific_info(finding: Dict[str, Any], aws_service: str) -> Dict[str, Any]:
    """
    Extracts service-specific information from a finding.

    Args:
        finding (Dict[str, Any]): The finding dictionary.
        aws_service (str): The name of the AWS service.

    Returns:
        Dict[str, Any]: A dictionary containing service-specific information about the finding.
    """
    return {
        "codeVulnerabilityDetails": finding.get("codeVulnerabilityDetails") if aws_service == "Lambda" else None,
        "awsLambdaFunction": finding.get("resources", [{}])[0].get("details", {}).get("awsLambdaFunction") if aws_service == "Lambda" else None,
        "awsEc2Instance": finding.get("resources", [{}])[0].get("details", {}).get("awsEc2Instance") if aws_service == "EC2" else None,
        "awsEcrContainerImage": finding.get("resources", [{}])[0].get("details", {}).get("awsEcrContainerImage") if aws_service in ["EKS", "ECR"] else None,
    }

def extract_vulnerability_details(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts vulnerability details from a finding.

    Args:
        finding (Dict[str, Any]): The finding dictionary.

    Returns:
        Dict[str, Any]: A dictionary containing vulnerability details about the finding.
    """
    return {
        "epss": finding.get("epss", {}).get("score"),
        "fixAvailable": finding.get("fixAvailable"),
        "inspectorScoreDetails": finding.get("inspectorScoreDetails"),
        "cvss2": finding.get("packageVulnerabilityDetails", {}).get("cvss", [{}])[0].get("cvss2"),
        "cvss3": finding.get("packageVulnerabilityDetails", {}).get("cvss", [{}])[0].get("cvss3"),
        "atigData": finding.get("atigData")
    }

def extract_vendor_info(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts vendor information from a finding.

    Args:
        finding (Dict[str, Any]): The finding dictionary.

    Returns:
        Dict[str, Any]: A dictionary containing vendor information about the finding.
    """
    vuln_details = finding.get("packageVulnerabilityDetails", {})
    return {
        "referenceUrls": vuln_details.get("referenceUrls"),
        "source": vuln_details.get("source"),
        "sourceUrl": vuln_details.get("sourceUrl"),
        "vendorSeverity": vuln_details.get("vendorSeverity"),
        "vendorCreatedAt": vuln_details.get("vendorCreatedAt"),
        "vendorUpdatedAt": vuln_details.get("vendorUpdatedAt"),
        "relatedVulnerabilities": vuln_details.get("relatedVulnerabilities"),
        "vulnerablePackages": vuln_details.get("vulnerablePackages")
    }

def extract_findings(findings: Optional[Dict[str, Any]], aws_service: str) -> List[Dict[str, Any]]:
    """
    Extracts and processes findings for a given AWS service.

    Args:
        findings (Optional[Dict[str, Any]]): A dictionary containing findings or None.
        aws_service (str): The name of the AWS service for which findings are being processed.

    Returns:
        List[Dict[str, Any]]: A list of processed findings dictionaries. If no findings are provided or an error occurs, an empty list is returned.

    The function performs the following steps:
    1. Checks if findings are None or not a list, logs appropriate warnings or errors, and returns an empty list.
    2. Iterates over each finding in the findings list.
    3. Validates that each finding is a dictionary, logs a warning if not, and skips invalid entries.
    4. Extracts and combines basic information, service-specific information, vulnerability details, and vendor information from each finding.
    5. Extracts additional details such as network reachability, remediation text and URL, resources, creation, and update timestamps.
    6. Appends the processed finding to the extracted_findings list.
    7. Logs any exceptions that occur during processing and continues with the next finding.

    Raises:
        None: Any exceptions during processing are caught and logged.
    """
    if findings is None or aws_service not in findings:
        logger.warning(f"No findings returned for {aws_service}")
        return []
        
    findings_list = findings.get(aws_service, [])
    if not isinstance(findings_list, list):
        logger.error(f"Findings for {aws_service} is not a list: {type(findings_list)}")
        return []

    extracted_findings: List[Dict[str, Any]] = []
    for f in findings_list:
        try:
            if not isinstance(f, dict):
                logger.warning(f"Invalid finding structure for {aws_service}: {type(f)}")
                continue
                
            finding: Dict[str, Any] = {
                **extract_basic_info(f, aws_service),
                **extract_service_specific_info(f, aws_service),
                **extract_vulnerability_details(f),
                **extract_vendor_info(f),
                "networkReachabilityDetails": f.get("networkReachabilityDetails"),
                "remediation": f.get("remediation", {}).get("recommendation", {}).get("text"),
                "remediationUrl": f.get("remediation", {}).get("recommendation", {}).get("Url"),
                "resources": f.get("resources", []),
                "createdAt": f.get("createdAt"),
                "updatedAt": f.get("updatedAt")
            }
            extracted_findings.append(finding)
        except Exception as e:
            logger.error(f"Error processing finding for {aws_service}: {str(e)}")
            continue
            
    return extracted_findings