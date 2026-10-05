from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from unittest.mock import patch, MagicMock

from .models import ScanResult, Vulnerability
from .views import perform_scan, scan_ports, check_security_headers


class ScanResultModelTest(TestCase):
    """Tests for the ScanResult model."""
    
    def setUp(self):
        self.scan = ScanResult.objects.create(
            target='https://example.com',
            scan_type='url',
            status='completed',
            risk_level='low'
        )
    
    def test_scan_creation(self):
        """Test scan result creation."""
        self.assertEqual(self.scan.target, 'https://example.com')
        self.assertEqual(self.scan.scan_type, 'url')
        self.assertEqual(self.scan.status, 'completed')
    
    def test_scan_str(self):
        """Test string representation."""
        self.assertIn('example.com', str(self.scan))
        self.assertIn('completed', str(self.scan))
    
    def test_duration_property(self):
        """Test duration calculation."""
        self.scan.completed_at = self.scan.created_at + timezone.timedelta(seconds=30)
        self.scan.save()
        self.assertEqual(self.scan.duration, 30.0)
    
    def test_duration_none_when_not_completed(self):
        """Test duration returns None when not completed."""
        self.scan.completed_at = None
        self.assertIsNone(self.scan.duration)


class VulnerabilityModelTest(TestCase):
    """Tests for the Vulnerability model."""
    
    def setUp(self):
        self.scan = ScanResult.objects.create(
            target='https://example.com',
            scan_type='url',
            status='completed'
        )
        self.vuln = Vulnerability.objects.create(
            scan_result=self.scan,
            name='Test Vulnerability',
            description='Test description',
            severity='high',
            recommendation='Fix it'
        )
    
    def test_vulnerability_creation(self):
        """Test vulnerability creation."""
        self.assertEqual(self.vuln.name, 'Test Vulnerability')
        self.assertEqual(self.vuln.severity, 'high')
        self.assertEqual(self.vuln.scan_result, self.scan)
    
    def test_vulnerability_str(self):
        """Test string representation."""
        self.assertIn('Test Vulnerability', str(self.vuln))
        self.assertIn('High', str(self.vuln))


class ViewsTest(TestCase):
    """Tests for the views."""
    
    def setUp(self):
        self.client = Client()
        self.scan = ScanResult.objects.create(
            target='https://example.com',
            scan_type='url',
            status='completed',
            risk_level='low'
        )
    
    def test_index_view(self):
        """Test index page loads."""
        response = self.client.get(reverse('scanner:index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'scanner/index.html')
    
    def test_start_scan_missing_target(self):
        """Test start scan with missing target."""
        response = self.client.post(
            reverse('scanner:start_scan'),
            data='{"scan_type": "url"}',
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())
    
    def test_start_scan_invalid_json(self):
        """Test start scan with invalid JSON."""
        response = self.client.post(
            reverse('scanner:start_scan'),
            data='invalid json',
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
    
    def test_scan_detail_view(self):
        """Test scan detail page loads."""
        response = self.client.get(
            reverse('scanner:scan_detail', args=[self.scan.id])
        )
        self.assertEqual(response.status_code, 200)
    
    def test_scan_detail_not_found(self):
        """Test scan detail with non-existent ID."""
        response = self.client.get(
            reverse('scanner:scan_detail', args=[99999])
        )
        self.assertEqual(response.status_code, 404)
    
    def test_scan_history_view(self):
        """Test scan history page loads."""
        response = self.client.get(reverse('scanner:history'))
        self.assertEqual(response.status_code, 200)
    
    def test_api_scan_status(self):
        """Test API scan status endpoint."""
        response = self.client.get(
            reverse('scanner:api_scan_status', args=[self.scan.id])
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['id'], self.scan.id)
        self.assertEqual(data['status'], 'completed')
    
    def test_delete_scan(self):
        """Test deleting a scan."""
        response = self.client.delete(
            reverse('scanner:delete_scan', args=[self.scan.id])
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(ScanResult.objects.filter(id=self.scan.id).exists())


class ScanFunctionsTest(TestCase):
    """Tests for scan utility functions."""
    
    def test_perform_scan_url(self):
        """Test perform_scan with URL type."""
        results = perform_scan('https://example.com', 'url')
        self.assertEqual(results['target'], 'https://example.com')
        self.assertEqual(results['scan_type'], 'url')
        self.assertIn('vulnerabilities', results)
        self.assertIn('risk_level', results)
    
    def test_check_security_headers(self):
        """Test security headers check."""
        headers = check_security_headers('https://example.com')
        self.assertIsInstance(headers, dict)
        self.assertIn('X-Content-Type-Options', headers)
        self.assertIn('Strict-Transport-Security', headers)
    
    @patch('socket.create_connection')
    def test_scan_ports(self, mock_conn):
        """Test port scanning."""
        # Mock successful connection
        mock_conn.return_value.__enter__ = MagicMock()
        mock_conn.return_value.__exit__ = MagicMock()
        
        results = {'details': {}, 'vulnerabilities': []}
        results = scan_ports('127.0.0.1', results, ports=[80, 443])
        
        self.assertIn('port_scan', results['details'])
        self.assertIn('open_ports', results['details']['port_scan'])
    
    def test_perform_scan_invalid_target(self):
        """Test perform_scan with invalid target."""
        results = perform_scan('invalid-target-xyz', 'url')
        self.assertIn('vulnerabilities', results)