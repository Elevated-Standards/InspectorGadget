import os
import json
import datetime
import sys
import logging
import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector import FindingsCollector
from utils.aws_cli import run_aws_cli

logger = logging.getLogger(__name__)

class Inspector:
    """
    A class to initialize and run various AWS service inspectors.

    Parameters:
        enable_lambda (bool): Flag to enable Lambda inspector. Default is True.
        enable_eks (bool): Flag to enable EKS inspector. Default is True.
        enable_ec2 (bool): Flag to enable EC2 inspector. Default is True.
        enable_rds (bool): Flag to enable RDS inspector. Default is True.
        enable_ecr_repos (bool): Flag to enable ECR inspector. Default is False.
        enable_cis (bool): Flag to enable CIS inspector. Default is True.
        repositories_to_scan (Optional[List[str]]): List of ECR repositories to scan. Default is None.

    Raises:
        boto3.exceptions.Boto3Error: If there is an error initializing the boto3 client.
        FindingsCollectorError: If there is an error collecting or saving findings.

    Methods:
        __init__(enable_lambda=True, enable_eks=True, enable_ec2=True, enable_rds=True, 
                 enable_ecr_repos=False, enable_cis=True, repositories_to_scan=None):
            Initializes the Inspector with the specified services enabled or disabled.
        run():
            Executes the enabled inspectors and collects their findings.
    """
    def __init__(self, enable_lambda: bool = True, enable_eks: bool = True, enable_ec2: bool = True, 
                 enable_rds: bool = True, enable_ecr_repos: bool = False, 
                 enable_cis: bool = True, repositories_to_scan: Optional[List[str]] = None) -> None:
        logger.info("Initializing Inspector")
        self.client = boto3.client('inspector2')
        self.collector = FindingsCollector()
        
        # Initialize service inspectors
        if enable_lambda:
            from services.lambda_inspector import LambdaInspector
            self.lambda_inspector = LambdaInspector(self.client)
        else:
            self.lambda_inspector = None

        if enable_eks:
            from services.eks_inspector import EksInspector
            self.eks_inspector = EksInspector(self.client)
        else:
            self.eks_inspector = None

        if enable_ec2:
            from services.ec2_inspector import Ec2Inspector
            self.ec2_inspector = Ec2Inspector(self.client)
        else:
            self.ec2_inspector = None

        if enable_rds:
            from services.rds_inspector import RdsInspector
            self.rds_inspector = RdsInspector(self.client)
        else:
            self.rds_inspector = None

        if enable_ecr_repos:
            from services.ecr_inspector import EcrInspector
            self.ecr_inspector = EcrInspector(self.client, repositories_to_scan)
        else:
            self.ecr_inspector = None

        if enable_cis:
            from services.cis_inspector import CisInspector
            self.cis_inspector = CisInspector(self.client)
        else:
            self.cis_inspector = None

    def run(self) -> None:
        """
        Executes the enabled inspectors and collects their findings.
        """
        logger.info("Inspector execution started")
        
        combined_findings = []

        if self.lambda_inspector:
            lambda_findings = run_aws_cli("aws lambda list-functions --region us-east-1 --output json", "Lambda")
            combined_findings.extend(extract_findings(lambda_findings, "Lambda"))
        if self.eks_inspector:
            eks_findings = run_aws_cli("aws eks list-clusters --region us-east-1 --output json", "EKS")
            combined_findings.extend(extract_findings(eks_findings, "EKS"))
        if self.ec2_inspector:
            ec2_findings = run_aws_cli("aws ec2 describe-instances --region us-east-1 --output json", "EC2")
            combined_findings.extend(extract_findings(ec2_findings, "EC2"))
        if self.rds_inspector:
            rds_findings = run_aws_cli("aws rds describe-db-instances --region us-east-1 --output json", "RDS")
            combined_findings.extend(extract_findings(rds_findings, "RDS"))
        if self.ecr_inspector:
            ecr_findings = run_aws_cli("aws ecr describe-repositories --region us-east-1 --output json", "ECR")
            combined_findings.extend(extract_findings(ecr_findings, "ECR"))
        if self.cis_inspector:
            cis_findings = run_aws_cli("aws inspector2 list-findings --filter-criteria '{\"resourceType\":[{\"comparison\":\"EQUALS\",\"value\":\"CisBenchmark\"}]}' --region us-east-1 --output json", "CIS")
            combined_findings.extend(extract_findings(cis_findings, "CIS"))

        self.collector.add_findings(combined_findings)
        self.collector.save_findings()
        logger.info("Inspector execution completed")

def main():
    inspector = Inspector()
    inspector.run()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()