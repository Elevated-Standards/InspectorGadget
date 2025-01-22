import os
import json
import logging
import subprocess
from typing import Optional, Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential

# Configure logging
logger = logging.getLogger(__name__)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def run_aws_cli(command: str, service: str) -> Optional[Dict[str, Any]]:
    """
    Execute an AWS CLI command with retries and error handling.
    
    Args:
        command (str): AWS CLI command to execute
        service (str): The AWS service being queried
        
    Returns:
        Optional[Dict[str, Any]]: Parsed JSON output from the command or an empty list if an error occurs
        
    Raises:
        subprocess.TimeoutExpired: If command execution times out
        json.JSONDecodeError: If command output is not valid JSON
        Exception: For other unexpected errors
    """
    try:
        if "--region" not in command:
            command += f" --region {os.environ.get('AWS_REGION', 'us-east-1')}"
        if "--output" not in command:
            command += " --output json"
        logger.info(f"Executing command: {command}")
        
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, timeout=300, text=True)
        
        # Log the raw output for debugging
        logger.debug(f"Raw stdout: {result.stdout[:500]}...")
        logger.debug(f"Raw stderr: {result.stderr[:500]}...")
        
        if result.returncode != 0:
            logger.error(f"Command failed with exit code {result.returncode}")
            logger.error(f"stderr: {result.stderr}")
            return {service: []}

        if not result.stdout or result.stdout.isspace():
            logger.error("Command returned empty output")
            return {service: []}

        try:
            output = json.loads(result.stdout)
            if not output:
                logger.warning(f"No data found for {service}")
                return {service: []}
            logger.info(f"Successfully parsed JSON output with {len(str(output))} characters")
            return {service: output}
        except json.JSONDecodeError as je:
            logger.error(f"JSON parse error: {je}")
            logger.error(f"Failed JSON string: {result.stdout[:200]}...")
            return {service: []}
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error: {e.stderr}")
        return {service: []}
    except FileNotFoundError:
        logger.error("AWS CLI not found. Please install the AWS CLI and ensure it is in your PATH.")
        return {service: []}
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after 300 seconds: {command}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error running command: {str(e)}", exc_info=True)
        raise