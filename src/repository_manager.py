import os
import json
import datetime import datetime
import sys
import logging
import boto3
from botocore.exceptions import ClientError
from typing import List, Tuple, Optional

# Configure logging
logger = logging.getLogger(__name__)

def load_repositories() -> List[str]:
    """Load repositories from a configuration file."""
    config_path = "config/repositories.json"
    if not os.path.exists(config_path):
        logger.warning(f"Config file {config_path} does not exist.")
        return []
    try:
        with open(config_path, "r") as config_file:
            repositories = json.load(config_file)
            return repositories.get("repositories", [])
    except Exception as e:
        logger.error(f"Error loading repositories from {config_path}: {e}")
        return []

def parse_repository_arn(repo_arn: str) -> Tuple[str, str]:
    """Parse repository ARN into account ID and repository name."""
    try:
        parts = repo_arn.split('/')
        account_id = parts[0].split(':')[4]
        repo_name = parts[-1]
        return account_id, repo_name
    except (IndexError, ValueError) as e:
        logger.error(f"Invalid repository ARN format: {repo_arn}")
        raise ValueError(f"Invalid repository ARN: {repo_arn}") from e

def validate_repository(ecr_client, account_id: str, repo_name: str) -> bool:
    """Validate if repository exists in ECR."""
    try:
        ecr_client.describe_repositories(
            registryId=account_id,
            repositoryNames=[repo_name]
        )
        return True
    except ecr_client.exceptions.RepositoryNotFoundException:
        logger.warning(f"Repository {repo_name} not found in account {account_id}")
        return False
    except Exception as e:
        logger.error(f"Error validating repository {repo_name}: {e}")
        return False

def get_latest_digest(repo_arn: str) -> Optional[str]:
    """
    Get the latest image digest for a given ECR repository.
    Args:
        repo_arn (str): The Amazon Resource Name (ARN) of the ECR repository.
    Returns:
        Optional[str]: The latest image digest if found, otherwise None.
    Raises:
        Exception: If there is an error in retrieving the image digest.
    """
    """Get latest image digest for repository."""
    try:
        account_id, repo_name = parse_repository_arn(repo_arn)
        ecr_client = boto3.client('ecr')
        
        if not validate_repository(ecr_client, account_id, repo_name):
            return None
            
        response = ecr_client.describe_images(
            registryId=account_id,
            repositoryName=repo_name,
            filter={'tagStatus': 'TAGGED'},
            maxResults=1,
            orderBy='TIMESTAMP',
            sort='DESC'
        )
        
        if not response.get('imageDetails'):
            logger.info(f"No tagged images found in {repo_name}")
            return None
            
        return response['imageDetails'][0].get('imageDigest')
        
    except Exception as e:
        logger.error(f"Error getting latest digest for {repo_name}: {e}")
        return None
