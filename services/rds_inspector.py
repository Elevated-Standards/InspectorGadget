import os
import datetime
import boto3
import sys
from typing import List, Dict
from botocore.exceptions import ClientError
from src.base_inspector import BaseInspector
from src.findings_extractor import extract_findings
from utils.aws_cli import run_aws_cli

class RdsInspector(BaseInspector):
    def get_findings(self) -> List[Dict]:
        """
        Retrieves findings for all RDS instances if the service is enabled.

        This method executes the AWS CLI command to describe RDS instances and
        collects the findings for each instance by calling the internal method
        `_get_db_findings`.

        Returns:
            list: A list of findings for all RDS instances. If the service is
            not enabled, an empty list is returned.
        """
        if not self.enabled:
            return []
        command = "aws rds describe-db-instances"
        result = run_aws_cli(command)
        instances = [db["DBInstanceIdentifier"] for db in result.get("DBInstances", [])] if result else []
        findings = []
        for db_instance_id in instances:
            findings.extend(self._get_db_findings(db_instance_id))
        return findings

    def _get_db_findings(self, db_instance_id: str) -> List[Dict]:
        """
        Retrieves security findings for a specified RDS instance.

        Args:
            db_instance_id (str): The ARN of the RDS instance to retrieve findings for.

        Returns:
            list: A list of findings related to the specified RDS instance. Each finding is a dictionary containing details about the security issue.
        """
        command = (
            "aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"RdsInstance\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"{db_instance_id}\"}}]}}'"
        )
        out = run_aws_cli(command)
        return extract_findings(out.get("findings", []), "RDS") if out else []
