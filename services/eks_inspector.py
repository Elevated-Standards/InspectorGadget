import os
import datetime
import boto3
import sys
from typing import List
from botocore.exceptions import ClientError
from src.base_inspector import BaseInspector
from src.findings_extractor import extract_findings
from utils.aws_cli import run_aws_cli

class EksInspector(BaseInspector):
    def get_findings(self) -> List[dict]:
        """
        Retrieves findings for EKS clusters.

        This method checks if the service is enabled. If not, it returns an empty list.
        It then lists all EKS clusters using the AWS CLI and retrieves findings for each cluster.

        Returns:
            list: A list of findings for all EKS clusters.

        Raises:
            Exception: If there is an error in retrieving the account ID or cluster findings.
        """
        if not self.enabled:
            return []
        command = "aws eks list-clusters"
        result = run_aws_cli(command)
        clusters = result.get("clusters", []) if result else []
        findings = []
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        for cluster_name in clusters:
            findings.extend(self._get_cluster_findings(cluster_name, account_id))
        return findings

    def _get_cluster_findings(self, cluster_name: str, account_id: str) -> List[dict]:
        """
        Retrieves findings for a specified EKS cluster using AWS Inspector.

        Args:
            cluster_name (str): The name of the EKS cluster.
            account_id (str): The AWS account ID.

        Returns:
            list: A list of findings related to the specified EKS cluster.
        """
        command = (
            "aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"EksCluster\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"arn:aws:eks:{os.environ.get('AWS_REGION', 'us-east-1')}:{account_id}:cluster/{cluster_name}\"}}]}}'"
        )
        out = run_aws_cli(command)
        return extract_findings(out.get("findings", []), "EKS") if out else []
