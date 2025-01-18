import os
import datetime
import boto3
import sys
from botocore.exceptions import ClientError
from src.base_inspector import BaseInspector
from src.findings_extractor import extract_findings
from utils.aws_cli import run_aws_cli
from typing import List, Optional

class EcrInspector(BaseInspector):
    """
    EcrInspector is a class that inspects Amazon ECR repositories for findings using AWS Inspector.

    Attributes:
        client (boto3.client): The boto3 client used to interact with AWS services.
        repositories (list): A list of ECR repository names to inspect.

    Methods:
        get_findings():
            Retrieves findings for the specified ECR repositories.
            Returns a list of findings.

        _get_repo_findings(repository_name):
            Retrieves findings for a specific ECR repository.
            Args:
                repository_name (str): The name of the ECR repository.
            Returns a list of findings for the specified repository.
    """
    def __init__(self, client: boto3.client, repositories: Optional[List[str]] = None) -> None:
        super().__init__(client)
        self.repositories = repositories

    def get_findings(self) -> List[dict]:
        if not self.enabled or not self.repositories:
            return []
        findings = []
        for repository_name in self.repositories:
            findings.extend(self._get_repo_findings(repository_name))
        return findings

    def _get_repo_findings(self, repository_name: str) -> List[dict]:
        command = (
            f"aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"EcrRepository\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"{repository_name}\"}}]}}'"
        )
        out = run_aws_cli(command)
        return extract_findings(out.get("findings", []), "ECR Repository") if out else []
