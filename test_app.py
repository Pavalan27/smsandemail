"""
PhishShift Backend Test Suite
Covers:
- /api/health endpoint status
- /api/scan with valid messages (phishing, spam, legitimate)
- /api/scan with empty or whitespace message (400 validation)
- /api/scan with oversized message (400 validation)
- /api/scan with invalid JSON payload (400 validation)
- /api/scan URL forensics extraction and indicators
- Missing model graceful 503 behavior
"""

import unittest
import json
import app as phishshift_app


class PhishShiftTestCase(unittest.TestCase):
    def setUp(self):
        phishshift_app.app.config['TESTING'] = True
        self.client = phishshift_app.app.test_client()

    def test_health_endpoint(self):
        """Test that /api/health returns 200 with service information."""
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("status", data)
        self.assertIn("model_loaded", data)
        self.assertIn("service", data)
        self.assertTrue(data["model_loaded"])

    def test_index_page(self):
        """Test that GET / returns 200 and loads HTML template."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PhishShift", response.data)
        self.assertIn(b"Message Threat Scanner", response.data)

    def test_scan_phishing_message(self):
        """Test scan on a clear phishing SMS containing urgency, credentials, and suspicious URL."""
        payload = {
            "message": "URGENT: Your Wells Fargo account has been locked due to suspicious activity. Verify immediately at http://192.168.1.1/login-wf"
        }
        response = self.client.post(
            '/api/scan',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["prediction"], "phishing")
        self.assertEqual(data["label"], "Phishing")
        self.assertIn(data["risk_level"], ["Medium", "High"])
        self.assertGreaterEqual(data["risk_score"], 60)
        self.assertIsNotNone(data["confidence"])
        self.assertIn("probabilities", data)
        self.assertIn("phishing", data["probabilities"])

        # Check URL forensics
        self.assertGreater(len(data["urls"]), 0)
        url_entry = data["urls"][0]
        self.assertIn("192.168.1.1", url_entry["display_host"])
        self.assertEqual(url_entry["risk_level"], "High")

        # Check indicators
        self.assertGreater(len(data["indicators"]), 0)
        ind_types = [i["type"] for i in data["indicators"]]
        self.assertTrue(any(t in ind_types for t in ["urgency", "credential_harvesting", "account_threat"]))

    def test_scan_spam_message(self):
        """Test scan on an unsolicited marketing prize message."""
        payload = {
            "message": "Congratulations! You have been selected as a winner of a $1000 Walmart gift card. Call 1800-FREE now to claim your prize."
        }
        response = self.client.post(
            '/api/scan',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertIn(data["prediction"], ["spam", "phishing"])
        self.assertIn("probabilities", data)
        self.assertGreater(len(data["indicators"]), 0)

    def test_scan_legitimate_message(self):
        """Test scan on normal conversational SMS text."""
        payload = {
            "message": "Hey Sarah, are we still meeting for lunch tomorrow at 12:30 PM at the cafe downtown?"
        }
        response = self.client.post(
            '/api/scan',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["prediction"], "legitimate")
        self.assertEqual(data["label"], "Legitimate")
        self.assertEqual(data["risk_level"], "Low")
        self.assertLess(data["risk_score"], 45)

    def test_scan_empty_message(self):
        """Test that empty messages return 400 with descriptive error."""
        payload = {"message": ""}
        response = self.client.post(
            '/api/scan',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])
        self.assertIn("empty", data["error"].lower())

    def test_scan_whitespace_only(self):
        """Test that whitespace-only messages return 400."""
        payload = {"message": "   \n\t  "}
        response = self.client.post(
            '/api/scan',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])

    def test_scan_oversized_message(self):
        """Test that messages exceeding 10,000 characters return 400."""
        payload = {"message": "A" * 10001}
        response = self.client.post(
            '/api/scan',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])
        self.assertIn("exceeds", data["error"].lower())

    def test_scan_invalid_json(self):
        """Test that non-JSON requests return 400."""
        response = self.client.post(
            '/api/scan',
            data="not-a-json-string",
            content_type='text/plain'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])

    def test_scan_missing_message_key(self):
        """Test that JSON without 'message' key returns 400."""
        payload = {"other_key": "some text"}
        response = self.client.post(
            '/api/scan',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])

    def test_model_unloaded_graceful_error(self):
        """Test that if the model is unavailable, /api/scan returns 503 error."""
        # Temporarily detach MODEL
        original_model = phishshift_app.MODEL
        try:
            phishshift_app.MODEL = None
            response = self.client.post(
                '/api/scan',
                data=json.dumps({"message": "Hello world"}),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 503)
            data = json.loads(response.data)
            self.assertFalse(data["success"])
            self.assertIn("phishshift_3class.joblib", data["error"])
        finally:
            phishshift_app.MODEL = original_model


if __name__ == '__main__':
    unittest.main()
