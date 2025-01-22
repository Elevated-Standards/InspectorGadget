import os
import json
import datetime
from typing import List, Dict, Any


class FindingsCollector:
    """
    A class to collect and save general findings and CIS findings.

    Attributes:
    -----------
    findings : List[Dict[str, Any]]
        A list to store general findings.
    cis_findings : List[Dict[str, Any]]
        A list to store CIS findings.

    Methods:
    --------
    add_findings(findings: List[Dict[str, Any]]) -> None:
        Adds a list of general findings to the findings attribute.
    
    add_cis_findings(findings: List[Dict[str, Any]]) -> None:
        Adds a list of CIS findings to the cis_findings attribute.
    
    save_findings() -> None:
        Saves both general findings and CIS findings to their respective files.
    
    _save_general_findings(current_date: datetime.datetime) -> None:
        Saves general findings to a file with a timestamped filename.
    
    _save_cis_findings(current_date: datetime.datetime) -> None:
        Saves CIS findings to a file with a timestamped filename.
    
    _get_output_path(date: datetime.datetime, type_suffix: str) -> str:
        Generates the output file path based on the current date and type suffix.
    
    _save_to_file(path: str, data: Any) -> None:
        Saves the given data to a file at the specified path.
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.cis_findings: List[Dict[str, Any]] = []

    def add_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Adds a list of general findings to the findings attribute.

        Parameters:
        -----------
        findings : List[Dict[str, Any]]
            A list of dictionaries containing general findings.
        """
        self.findings.extend(findings)

    def add_cis_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Adds a list of CIS findings to the cis_findings attribute.

        Parameters:
        -----------
        findings : List[Dict[str, Any]]
            A list of dictionaries containing CIS findings.
        """
        self.cis_findings.extend(findings)

    def save_findings(self) -> None:
        """
        Saves both general findings and CIS findings to their respective files.

        Raises:
        -------
        OSError:
            If there is an issue creating directories or writing to files.
        """
        current_date = datetime.datetime.now()
        self._save_general_findings(current_date)
        self._save_cis_findings(current_date)

    def _save_general_findings(self, current_date: datetime.datetime) -> None:
        """
        Saves general findings to a file with a timestamped filename.

        Parameters:
        -----------
        current_date : datetime.datetime
            The current date and time used for generating the filename.
        """
        output_path = self._get_output_path(current_date, "inspector")
        self._save_to_file(output_path, self.findings)

    def _save_cis_findings(self, current_date: datetime.datetime) -> None:
        """
        Saves CIS findings to a file with a timestamped filename.

        Parameters:
        -----------
        current_date : datetime.datetime
            The current date and time used for generating the filename.
        """
        output_path = self._get_output_path(current_date, "cis")
        self._save_to_file(output_path, self.cis_findings)

    def _get_output_path(self, date: datetime.datetime, type_suffix: str) -> str:
        """
        Generates the output file path based on the current date and type suffix.

        Parameters:
        -----------
        date : datetime.datetime
            The current date and time used for generating the path.
        type_suffix : str
            The suffix indicating the type of findings (e.g., "inspector" or "cis").

        Returns:
        --------
        str
            The generated output file path.
        """
        return (
            f"output/{date.year}/{date.month:02}/{type_suffix}/"
            f"{date.year}-{date.month:02}-{date.day:02}_"
            f"{date.hour:02}{date.minute:02}{date.second:02}.json"
        )

    def _save_to_file(self, output_path: str, data: List[Dict[str, Any]]) -> None:
        """
        Saves the given data to a file at the specified path.

        Parameters:
        -----------
        output_path : str
            The file path where the data will be saved.
        data : Any
            The data to be saved to the file.

        Raises:
        -------
        OSError:
            If there is an issue creating directories or writing to the file.
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)