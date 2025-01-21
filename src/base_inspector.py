import os
import datetime
import sys
import logging
import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class BaseInspector:
    """
    A base class for inspecting resources and retrieving findings.
    
    Attributes:
        client: The client used to interact with the findings service.
        enabled: A flag indicating whether the inspector is enabled.
    """
    
    def __init__(self, client, enabled: bool = True):
        """
        Initializes the BaseInspector with a client and enabled flag.
        
        Args:
            client: The client used to interact with the findings service.
            enabled (bool): A flag indicating whether the inspector is enabled.
        """
        self.client = client
        self.enabled = enabled

    def get_findings_for_resource(self, resource_id: str, resource_type: str) -> List[Dict[str, Any]]:
        """
        Retrieves findings for a specified resource.
        
        Args:
            resource_id (str): The ID of the resource to retrieve findings for.
            resource_type (str): The type of the resource to retrieve findings for.
        
        Returns:
            List[Dict[str, Any]]: A list of findings for the specified resource.
        
        Raises:
            Exception: If there is an error retrieving the findings.
        """
        try:
            filter_criteria = {
                'resourceId': [{'comparison': 'EQUALS', 'value': resource_id}],
                'resourceType': [{'comparison': 'EQUALS', 'value': resource_type}]
            }
            
            response = self.client.list_findings(
                filterCriteria=filter_criteria,
                maxResults=100
            )
            return response.get('findings', [])
        except Exception as e:
            logger.error(f"Error getting findings for resource {resource_id}: {e}")
            return []