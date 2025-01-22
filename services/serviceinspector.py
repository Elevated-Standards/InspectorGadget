import os
import datetime
import boto3
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
from src.base_inspector import BaseInspector
from src.findings_extractor import extract_findings
from utils.aws_cli import run_aws_cli

class ServiceInspector(BaseInspector):
    """
    ServiceInspector is a class that inspects various AWS resources (EKS, Lambda, EC2, ECR, RDS) for findings using AWS CLI and boto3.

    Methods
    -------
    get_findings():
        Retrieves findings for all enabled AWS resources.
    """

    def __init__(self, client: boto3.client, repositories: Optional[List[str]] = None, enabled: bool = True):
        super().__init__(client, enabled)
        self.repositories = repositories

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Retrieves findings for all enabled AWS resources.

        Returns
        -------
        List[Dict[str, Any]]
            A list of findings for all enabled AWS resources.
        """
        findings = []
        findings.extend(self.get_lambda_findings())
        findings.extend(self.get_eks_findings())
        findings.extend(self.get_ec2_findings())
        findings.extend(self.get_rds_findings())
        findings.extend(self.get_ecr_findings())
        return findings

    def get_lambda_findings(self) -> List[Dict[str, Any]]:
        command = "aws lambda list-functions"
        result = run_aws_cli(command, "Lambda")
        functions = [func["FunctionArn"] for func in result.get("Functions", [])] if result else []
        findings = []
        for function_arn in functions:
            findings.extend(self.get_findings_for_function(function_arn))
        return findings

    def get_findings_for_function(self, function_arn: str) -> List[Dict[str, Any]]:
        command = (
            f"aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"LambdaFunction\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"{function_arn}\"}}]}}'"
        )
        out = run_aws_cli(command, "Lambda")
        return extract_findings(out.get("findings", []), "Lambda") if out else []

    def get_eks_findings(self) -> List[Dict[str, Any]]:
        command = "aws eks list-clusters"
        result = run_aws_cli(command, "EKS")
        clusters = result.get("clusters", []) if result else []
        findings = []
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        for cluster_name in clusters:
            findings.extend(self.get_cluster_findings(cluster_name, account_id))
        return findings

    def get_cluster_findings(self, cluster_name: str, account_id: str) -> List[Dict[str, Any]]:
        command = (
            "aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"EksCluster\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"arn:aws:eks:{os.environ.get('AWS_REGION', 'us-east-1')}:{account_id}:cluster/{cluster_name}\"}}]}}'"
        )
        out = run_aws_cli(command, "EKS")
        return extract_findings(out.get("findings", []), "EKS") if out else []

    def get_ec2_findings(self) -> List[Dict[str, Any]]:
        command = "aws ec2 describe-instances"
        result = run_aws_cli(command, "EC2")
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
        out = run_aws_cli(command, "EC2")
        return extract_findings(out.get("findings", []), "EC2") if out else []

    def get_rds_findings(self) -> List[Dict[str, Any]]:
        command = "aws rds describe-db-instances"
        result = run_aws_cli(command, "RDS")
        instances = [db["DBInstanceIdentifier"] for db in result.get("DBInstances", [])] if result else []
        findings = []
        for db_instance_id in instances:
            findings.extend(self._get_db_findings(db_instance_id))
        return findings

    def _get_db_findings(self, db_instance_id: str) -> List[Dict[str, Any]]:
        command = (
            "aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"RdsInstance\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"{db_instance_id}\"}}]}}'"
        )
        out = run_aws_cli(command, "RDS")
        return extract_findings(out.get("findings", []), "RDS") if out else []

    def get_ecr_findings(self) -> List[Dict[str, Any]]:
        if not self.repositories:
            return []
        findings = []
        for repository_name in self.repositories:
            findings.extend(self._get_repo_findings(repository_name))
        return findings

    def _get_repo_findings(self, repository_name: str) -> List[Dict[str, Any]]:
        command = (
            f"aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"EcrRepository\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"{repository_name}\"}}]}}'"
        )
        out = run_aws_cli(command, "ECR")
        return extract_findings(out.get("findings", []), "ECR") if out else []