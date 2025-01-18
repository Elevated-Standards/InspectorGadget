import os
import datetime
import boto3
import sys
from typing import List, Dict
from botocore.exceptions import ClientError
from src.base_inspector import BaseInspector
from src.findings_extractor import extract_findings
from utils.aws_cli import run_aws_cli


class LambdaInspector(BaseInspector):
    def get_findings(self) -> List[Dict]:
        """
        Retrieves a list of findings for all AWS Lambda functions.

        This method executes the AWS CLI command to list all Lambda functions,
        extracts their ARNs (Amazon Resource Names), and then gathers findings
        for each function by calling `get_findings_for_function`.

        Returns:
            list: A list of findings for all Lambda functions.
        """
        command = "aws lambda list-functions"
        result = run_aws_cli(command)
        functions = [func["FunctionArn"] for func in result.get("Functions", [])] if result else []
        findings = []
        for function_arn in functions:
            findings.extend(self.get_findings_for_function(function_arn))
        return findings

    def get_findings_for_function(self, function_arn: str) -> List[Dict]:
        """
        Retrieves security findings for a specified AWS Lambda function.

        This method uses the AWS CLI to list findings from AWS Inspector2 for the given Lambda function ARN.
        It filters the findings to only include those related to the specified Lambda function.

        Args:
            function_arn (str): The Amazon Resource Name (ARN) of the Lambda function to retrieve findings for.

        Returns:
            list: A list of findings related to the specified Lambda function. Each finding is represented as a dictionary.
              If no findings are found, an empty list is returned.
        """
        command = (
            f"aws inspector2 list-findings "
            f"--filter-criteria '{{\"resourceType\":[{{\"comparison\":\"EQUALS\",\"value\":\"LambdaFunction\"}}], "
            f"\"resourceArn\":[{{\"comparison\":\"EQUALS\",\"value\":\"{function_arn}\"}}]}}'"
        )
        out = run_aws_cli(command)
        if out:
            return extract_findings(out.get("findings", []), "Lambda")
        return []
