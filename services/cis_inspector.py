import os
import datetime
import boto3
import sys
from botocore.exceptions import ClientError
from src.services.base_inspector import BaseInspector
from src.findings.findings_extractor import extract_findings
from utils.aws_cli import run_aws_cli

class CisInspector(BaseInspector):
    """
    CisInspector is a subclass of BaseInspector that retrieves findings related to CIS benchmarks.

    Methods:
        get_findings():
            Retrieves findings from AWS Inspector2 service filtered by CIS benchmark resource type.
            Returns a list of findings if the inspector is enabled, otherwise returns an empty list.
    """
    def get_findings(self):
        if not self.enabled:
            return []
        command = (
            "aws inspector2 list-findings "
            "--filter-criteria '{\"resourceType\":[{\"comparison\":\"EQUALS\",\"value\":\"CisBenchmark\"}]}'"
        )
        result = run_aws_cli(command)
        return extract_findings(result.get("findings", []), "CIS") if result else []
