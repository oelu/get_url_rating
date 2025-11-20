#!/usr/bin/env python3
"""
Unit tests for get_url_rating.py

Tests only functions that can be executed locally without external API calls.
"""

import unittest
import sys
from io import StringIO
from get_url_rating import display_virustotal_result, display_urlhaus_result


class TestDisplayVirusTotalResult(unittest.TestCase):
    """Test cases for display_virustotal_result function"""

    def setUp(self):
        """Set up test fixtures"""
        self.held_stdout = StringIO()
        sys.stdout = self.held_stdout

    def tearDown(self):
        """Clean up after tests"""
        sys.stdout = sys.__stdout__

    def test_display_clean_result(self):
        """Test display of clean URL result"""
        url = "https://example.com"
        result = {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 75,
            "undetected": 10,
            "total": 85
        }

        display_virustotal_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[CLEAN]", output)
        self.assertIn(url, output)
        self.assertIn("Malicious: 0/85", output)
        self.assertIn("Suspicious: 0/85", output)
        self.assertIn("Harmless: 75/85", output)

    def test_display_malicious_result(self):
        """Test display of malicious URL result"""
        url = "https://malicious.example"
        result = {
            "status": "success",
            "malicious": 45,
            "suspicious": 5,
            "harmless": 20,
            "undetected": 15,
            "total": 85
        }

        display_virustotal_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[MALICIOUS]", output)
        self.assertIn(url, output)
        self.assertIn("Malicious: 45/85", output)

    def test_display_suspicious_result(self):
        """Test display of suspicious URL result (no malicious, but some suspicious)"""
        url = "https://suspicious.example"
        result = {
            "status": "success",
            "malicious": 0,
            "suspicious": 3,
            "harmless": 70,
            "undetected": 12,
            "total": 85
        }

        display_virustotal_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[SUSPICIOUS]", output)
        self.assertIn(url, output)
        self.assertIn("Suspicious: 3/85", output)

    def test_display_submitted_result(self):
        """Test display of newly submitted URL"""
        url = "https://new.example"
        result = {
            "status": "submitted",
            "message": "URL submitted for scanning. Check later for results."
        }

        display_virustotal_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[SUBMITTED]", output)
        self.assertIn(url, output)
        self.assertIn("URL submitted for scanning", output)

    def test_display_error_result(self):
        """Test display of error result"""
        url = "https://error.example"
        result = {
            "status": "error",
            "message": "API error: 403"
        }

        display_virustotal_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[ERROR]", output)
        self.assertIn(url, output)
        self.assertIn("API error: 403", output)


class TestDisplayURLhausResult(unittest.TestCase):
    """Test cases for display_urlhaus_result function"""

    def setUp(self):
        """Set up test fixtures"""
        self.held_stdout = StringIO()
        sys.stdout = self.held_stdout

    def tearDown(self):
        """Clean up after tests"""
        sys.stdout = sys.__stdout__

    def test_display_clean_result(self):
        """Test display of clean URL (not found in URLhaus)"""
        url = "https://example.com"
        result = {
            "status": "not_found",
            "message": "URL not found in URLhaus database"
        }

        display_urlhaus_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[CLEAN]", output)
        self.assertIn(url, output)
        self.assertIn("not found in URLhaus database", output)

    def test_display_malicious_online_result(self):
        """Test display of malicious online URL"""
        url = "https://malicious.example/malware.exe"
        result = {
            "status": "found",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe", "trojan", "AsyncRAT"],
            "date_added": "2024-01-15 10:30:00",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/"
        }

        display_urlhaus_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[MALICIOUS - ONLINE]", output)
        self.assertIn(url, output)
        self.assertIn("Threat: malware_download", output)
        self.assertIn("Tags: exe, trojan, AsyncRAT", output)
        self.assertIn("Date Added: 2024-01-15 10:30:00", output)
        self.assertIn("Reference: https://urlhaus.abuse.ch/url/12345/", output)

    def test_display_malicious_offline_result(self):
        """Test display of malicious offline URL"""
        url = "https://old-malware.example/payload.zip"
        result = {
            "status": "found",
            "url_status": "offline",
            "threat": "malware_download",
            "tags": ["zip", "emotet"],
            "date_added": "2024-01-10 08:15:00",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/12346/"
        }

        display_urlhaus_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[MALICIOUS - OFFLINE]", output)
        self.assertIn(url, output)
        self.assertIn("Threat: malware_download", output)
        self.assertIn("Tags: zip, emotet", output)

    def test_display_malicious_with_empty_tags(self):
        """Test display of malicious URL with no tags"""
        url = "https://malicious.example"
        result = {
            "status": "found",
            "url_status": "online",
            "threat": "phishing",
            "tags": [],
            "date_added": "2024-01-20 12:00:00",
            "urlhaus_reference": ""
        }

        display_urlhaus_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[MALICIOUS - ONLINE]", output)
        self.assertIn("Threat: phishing", output)
        # Should not show Tags line when empty
        self.assertNotIn("Tags:", output)

    def test_display_error_result(self):
        """Test display of error result"""
        url = "https://error.example"
        result = {
            "status": "error",
            "message": "API error: 401"
        }

        display_urlhaus_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[ERROR]", output)
        self.assertIn(url, output)
        self.assertIn("API error: 401", output)

    def test_display_unknown_status(self):
        """Test display of URL with unknown status"""
        url = "https://unknown.example"
        result = {
            "status": "found",
            "url_status": "unknown",
            "threat": "unknown",
            "tags": [],
            "date_added": None,
            "urlhaus_reference": ""
        }

        display_urlhaus_result(url, result)
        output = self.held_stdout.getvalue()

        self.assertIn("[MALICIOUS - UNKNOWN]", output)
        self.assertIn("Threat: unknown", output)


if __name__ == "__main__":
    unittest.main()
