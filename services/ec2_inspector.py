import os
import datetime
import boto3
import sys
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
    def get_findings(self):
        if not self.enabled:
            return []
        command = "aws ec2 describe-instances"
        result = run_aws_cli(command)
        instances = self._extract_instance_ids(result)
        return self._get_instances_findings(instances)

    def _extract_instance_ids(self, result):
        instances = []
        for reservation in result.get("Reservations", []) if result else []:
            if "Instances" in reservation:
                instances.extend([instance["InstanceId"] for instance in reservation["Instances"]])
        return instances

    def _get_instances_findings(self, instances):
        findings = []
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        region = os.environ.get('AWS_REGION', 'us-east-1')
        for instance_id in instances:
            findings.extend(self._get_instance_findings(instance_id, account_id, region))
        return findings

    def _get_instance_findings(self, instance_id, account_id, region):
        command = (
            "aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"Ec2Instance\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}\"}}]}}'"
        )
        out = run_aws_cli(command)
        return extract_findings(out.get("findings", []), "EC2") if out else []
