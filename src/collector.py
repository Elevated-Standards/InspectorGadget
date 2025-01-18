import os
import json
import datetime
import sys
import logging
import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Any

class FindingsCollector:
    add_findings(findings: List[Dict[str, Any]]) -> None:
        Parameters:
        findings : List[Dict[str, Any]]
            A list of dictionaries containing general findings.
    add_cis_findings(findings: List[Dict[str, Any]]) -> None:
        Parameters:
        findings : List[Dict[str, Any]]
            A list of dictionaries containing CIS findings.
    save_findings() -> None:
        Raises:
        -------
        OSError:
            If there is an issue creating directories or writing to files.
    _save_general_findings(current_date: datetime.datetime) -> None:
        Parameters:
        current_date : datetime.datetime
            The current date and time used for generating the filename.
    _save_cis_findings(current_date: datetime.datetime) -> None:
        Parameters:
        current_date : datetime.datetime
            The current date and time used for generating the filename.
        Parameters:
        date : datetime.datetime
            The current date and time used for generating the path.
        type_suffix : str
            The suffix indicating the type of findings (e.g., "inspector" or "cis").
        Returns:
        str
            The generated output file path.
    _save_to_file(path: str, data: Any) -> None:
        Parameters:
        path : str
            The file path where the data will be saved.
        data : Any
            The data to be saved to the file.
        Raises:
        -------
        OSError:
            If there is an issue creating directories or writing to the file.
    """
    A class to collect and save findings and CIS findings.

    Attributes:
    -----------
    findings : list
        A list to store general findings.
    cis_findings : list
        A list to store CIS findings.

    Methods:
    --------
    add_findings(findings: List[Dict[str, Any]]):
        Adds a list of general findings to the findings attribute.
    
    add_cis_findings(findings: List[Dict[str, Any]]):
        Adds a list of CIS findings to the cis_findings attribute.
    
    save_findings():
        Saves both general findings and CIS findings to their respective files.
    
    _save_general_findings(current_date: datetime.datetime):
        Saves general findings to a file with a timestamped filename.
    
    _save_cis_findings(current_date: datetime.datetime):
        Saves CIS findings to a file with a timestamped filename.
    
    _get_output_path(date: datetime.datetime, type_suffix: str) -> str:
        Generates the output file path based on the current date and type suffix.
    
    _save_to_file(path: str, data: Any):
        Saves the given data to a file at the specified path.
    """
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.cis_findings: List[Dict[str, Any]] = []

    def add_findings(self, findings: List[Dict[str, Any]]) -> None:
        self.findings.extend(findings)

    def add_cis_findings(self, findings: List[Dict[str, Any]]) -> None:
        self.cis_findings.extend(findings)

    def save_findings(self) -> None:
        current_date = datetime.datetime.now()
        self._save_general_findings(current_date)
        self._save_cis_findings(current_date)

    def _save_general_findings(self, current_date: datetime.datetime) -> None:
        output_path = self._get_output_path(current_date, "inspector")
        self._save_to_file(output_path, self.findings)

    def _save_cis_findings(self, current_date: datetime.datetime) -> None:
        output_path = self._get_output_path(current_date, "cis")
        self._save_to_file(output_path, self.cis_findings)

    def _get_output_path(self, date: datetime.datetime, type_suffix: str) -> str:
        return (
            f"output/{date.year}/{date.month:02}/{type_suffix}/"
            f"{date.year}-{date.month:02}-{date.day:02}_"
            f"{date.hour:02}{date.minute:02}{date.second:02}.json"
        )

    def _save_to_file(self, path: str, data: Any) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
