import unittest
from unittest.mock import patch, MagicMock
from src.inspector import Inspector

class TestInspector(unittest.TestCase):

    @patch('findings.inspector.boto3.client')
    @patch('findings.inspector.FindingsCollector')
    @patch('findings.inspector.LambdaInspector')
    @patch('findings.inspector.EksInspector')
    @patch('findings.inspector.Ec2Inspector')
    @patch('findings.inspector.RdsInspector')
    @patch('findings.inspector.EcrInspector')
    @patch('findings.inspector.CisInspector')
    def test_inspector_initialization(self, MockCisInspector, MockEcrInspector, MockRdsInspector, 
                                      MockEc2Inspector, MockEksInspector, MockLambdaInspector, 
                                      MockFindingsCollector, MockBotoClient):
        # Mock the boto3 client and FindingsCollector
        mock_client = MockBotoClient.return_value
        mock_collector = MockFindingsCollector.return_value

        # Initialize the Inspector
        inspector = Inspector()

        # Assertions to check if the inspectors are initialized
        self.assertIsNotNone(inspector.lambda_inspector)
        self.assertIsNotNone(inspector.eks_inspector)
        self.assertIsNotNone(inspector.ec2_inspector)
        self.assertIsNotNone(inspector.rds_inspector)
        self.assertIsNone(inspector.ecr_inspector)
        self.assertIsNotNone(inspector.cis_inspector)

        # Check if boto3 client and FindingsCollector were called
        MockBotoClient.assert_called_once_with('inspector2')
        MockFindingsCollector.assert_called_once()

    @patch('findings.inspector.boto3.client')
    @patch('findings.inspector.FindingsCollector')
    @patch('findings.inspector.LambdaInspector')
    @patch('findings.inspector.EksInspector')
    @patch('findings.inspector.Ec2Inspector')
    @patch('findings.inspector.RdsInspector')
    @patch('findings.inspector.EcrInspector')
    @patch('findings.inspector.CisInspector')
    def test_inspector_run(self, MockCisInspector, MockEcrInspector, MockRdsInspector, 
                           MockEc2Inspector, MockEksInspector, MockLambdaInspector, 
                           MockFindingsCollector, MockBotoClient):
        # Mock the boto3 client and FindingsCollector
        mock_client = MockBotoClient.return_value
        mock_collector = MockFindingsCollector.return_value

        # Mock the inspectors
        mock_lambda_inspector = MockLambdaInspector.return_value
        mock_eks_inspector = MockEksInspector.return_value
        mock_ec2_inspector = MockEc2Inspector.return_value
        mock_rds_inspector = MockRdsInspector.return_value
        mock_cis_inspector = MockCisInspector.return_value

        # Mock the get_findings method for each inspector
        mock_lambda_inspector.get_findings.return_value = ['lambda_finding']
        mock_eks_inspector.get_findings.return_value = ['eks_finding']
        mock_ec2_inspector.get_findings.return_value = ['ec2_finding']
        mock_rds_inspector.get_findings.return_value = ['rds_finding']
        mock_cis_inspector.get_findings.return_value = ['cis_finding']

        # Initialize the Inspector
        inspector = Inspector()

        # Run the inspector
        inspector.run()

        # Assertions to check if the get_findings methods were called
        mock_lambda_inspector.get_findings.assert_called_once()
        mock_eks_inspector.get_findings.assert_called_once()
        mock_ec2_inspector.get_findings.assert_called_once()
        mock_rds_inspector.get_findings.assert_called_once()
        mock_cis_inspector.get_findings.assert_called_once()

        # Assertions to check if the findings were added to the collector
        mock_collector.add_findings.assert_any_call(['lambda_finding'])
        mock_collector.add_findings.assert_any_call(['eks_finding'])
        mock_collector.add_findings.assert_any_call(['ec2_finding'])
        mock_collector.add_findings.assert_any_call(['rds_finding'])
        mock_collector.add_cis_findings.assert_called_once_with(['cis_finding'])

        # Check if save_findings was called
        mock_collector.save_findings.assert_called_once()

if __name__ == '__main__':
    unittest.main()