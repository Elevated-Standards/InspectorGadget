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
from services import (
    LambdaInspector,
    EksInspector,
    Ec2Inspector,
    RdsInspector,
    EcrInspector,
    CisInspector,
)

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
        self.lambda_inspector = LambdaInspector(self.client) if enable_lambda else None
        self.eks_inspector = EksInspector(self.client) if enable_eks else None
        self.ec2_inspector = Ec2Inspector(self.client) if enable_ec2 else None
        self.rds_inspector = RdsInspector(self.client) if enable_rds else None
        self.ecr_inspector = EcrInspector(self.client, repositories_to_scan) if enable_ecr_repos else None
        self.cis_inspector = CisInspector(self.client) if enable_cis else None

    def run(self) -> None:
        """
        Executes the enabled inspectors and collects their findings.
        """
        logger.info("Inspector execution started")
        
        if self.lambda_inspector:
            self.collector.add_findings(self.lambda_inspector.get_findings())
        if self.eks_inspector:
            self.collector.add_findings(self.eks_inspector.get_findings())
        if self.ec2_inspector:
            self.collector.add_findings(self.ec2_inspector.get_findings())
        if self.rds_inspector:
            self.collector.add_findings(self.rds_inspector.get_findings())
        if self.ecr_inspector:
            self.collector.add_findings(self.ecr_inspector.get_findings())
        if self.cis_inspector:
            self.collector.add_cis_findings(self.cis_inspector.get_findings())

        self.collector.save_findings()
        logger.info("Inspector execution completed")
