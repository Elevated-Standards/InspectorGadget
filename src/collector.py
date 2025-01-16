from typing import List, Dict, Any
from datetime import datetime
import os
import json

class FindingsCollector:
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
    
    _save_general_findings(current_date):
        Saves general findings to a file with a timestamped filename.
    
    _save_cis_findings(current_date):
        Saves CIS findings to a file with a timestamped filename.
    
    _get_output_path(date, type_suffix):
        Generates the output file path based on the current date and type suffix.
    
    _save_to_file(path, data):
        Saves the given data to a file at the specified path.
    """
    def __init__(self):
        self.findings = []
        self.cis_findings = []

    def add_findings(self, findings: List[Dict[str, Any]]):
        self.findings.extend(findings)

    def add_cis_findings(self, findings: List[Dict[str, Any]]):
        self.cis_findings.extend(findings)

    def save_findings(self):
        current_date = datetime.now()
        self._save_general_findings(current_date)
        self._save_cis_findings(current_date)

    def _save_general_findings(self, current_date):
        output_path = self._get_output_path(current_date, "inspector")
        self._save_to_file(output_path, self.findings)

    def _save_cis_findings(self, current_date):
        output_path = self._get_output_path(current_date, "cis")
        self._save_to_file(output_path, self.cis_findings)


    def _get_output_path(self, date, type_suffix):
        return (
            f"output/{date.year}/{date.month:02}/{type_suffix}/"
            f"{date.year}-{date.month:02}-{date.day:02}_"
            f"{date.hour:02}{date.minute:02}{date.second:02}.json"
        )

    def _save_to_file(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)