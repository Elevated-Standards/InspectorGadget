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
from findings_extractor import extract_findings
from services.serviceinspector import ServiceInspector

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
        
        # Initialize service inspector
        self.service_inspector = ServiceInspector(self.client, repositories_to_scan, enabled=True)

    def run(self) -> None:
        """
        Executes the enabled inspectors and collects their findings.
        """
        logger.info("Inspector execution started")
        
        combined_findings = self.service_inspector.get_findings()

        self.collector.add_findings(combined_findings)
        self.collector.save_findings()
        logger.info("Inspector execution completed")

def main():
    inspector = Inspector()
    inspector.run()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()