import os
import datetime
import boto3
import sys
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from src.base_inspector import BaseInspector
from src.findings_extractor import extract_findings
from utils.aws_cli import run_aws_cli

class Ec2Inspector(BaseInspector):
    """
    Ec2Inspector is a class that inspects EC2 instances for findings using AWS CLI and boto3.

    Methods
    -------
    get_findings():
        Retrieves findings for EC2 instances if the inspector is enabled.

    _extract_instance_ids(result):
        Extracts instance IDs from the AWS CLI describe-instances command result.

    _get_instances_findings(instances):
        Retrieves findings for a list of EC2 instances.

    _get_instance_findings(instance_id, account_id, region):
        Retrieves findings for a specific EC2 instance using AWS Inspector2.
    """

    def get_findings(self) -> List[Dict[str, Any]]:
    
        def _extract_instance_ids(self, result: Dict[str, Any]) -> List[str]:
            """
            Extracts instance IDs from the AWS CLI describe-instances command result.
    
            Parameters
            ----------
            result : Dict[str, Any]
                The result from the AWS CLI describe-instances command.
    
            Returns
            -------
            List[str]
                A list of instance IDs extracted from the result.
    
            Raises
            ------
            None
            """
            pass
    
        def _get_instances_findings(self, instances: List[str]) -> List[Dict[str, Any]]:
            """
            Retrieves findings for a list of EC2 instances.
    
            Parameters
            ----------
            instances : List[str]
                A list of EC2 instance IDs.
    
            Returns
            -------
            List[Dict[str, Any]]
                A list of dictionaries containing findings for the specified EC2 instances.
    
            Raises
            ------
            None
            """
            pass
    
        def _get_instance_findings(self, instance_id: str, account_id: str, region: str) -> List[Dict[str, Any]]:
            """
            Retrieves findings for a specific EC2 instance using AWS Inspector2.
    
            Parameters
            ----------
            instance_id : str
                The ID of the EC2 instance.
            account_id : str
                The AWS account ID.
            region : str
                The AWS region.
    
            Returns
            -------
            List[Dict[str, Any]]
                A list of dictionaries containing findings for the specified EC2 instance.
    
            Raises
            ------
            None
            """
            pass
    """
    Ec2Inspector is a class that inspects EC2 instances for findings using AWS CLI and boto3.

    Methods
    -------
    get_findings():
        Retrieves findings for EC2 instances if the inspector is enabled.

    _extract_instance_ids(result):
        Extracts instance IDs from the AWS CLI describe-instances command result.

    _get_instances_findings(instances):
        Retrieves findings for a list of EC2 instances.

    _get_instance_findings(instance_id, account_id, region):
        Retrieves findings for a specific EC2 instance using AWS Inspector2.
    """
    def get_findings(self) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []
        command = "aws ec2 describe-instances"
        result = run_aws_cli(command)
        instances = self._extract_instance_ids(result)
        return self._get_instances_findings(instances)

    def _extract_instance_ids(self, result: Dict[str, Any]) -> List[str]:
        instances = []
        for reservation in result.get("Reservations", []) if result else []:
            if "Instances" in reservation:
                instances.extend([instance["InstanceId"] for instance in reservation["Instances"]])
        return instances

    def _get_instances_findings(self, instances: List[str]) -> List[Dict[str, Any]]:
        findings = []
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        region = os.environ.get('AWS_REGION', 'us-east-1')
        for instance_id in instances:
            findings.extend(self._get_instance_findings(instance_id, account_id, region))
        return findings

    def _get_instance_findings(self, instance_id: str, account_id: str, region: str) -> List[Dict[str, Any]]:
        command = (
            "aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"Ec2Instance\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}\"}}]}}'"
        )
        out = run_aws_cli(command)
        return extract_findings(out.get("findings", []), "EC2") if out else []
