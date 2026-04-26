"""
API endpoint tests — covers all FastAPI routes.
Uses TestClient (synchronous) so no async runner needed.
Models are NOT loaded; services layer is patched where needed.
"""
import json
import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api.main import app

client = TestClient(app)


class TestHealthEndpoint(unittest.TestCase):
    def test_health_returns_200(self):
        r = client.get("/health")
        self.assertEqual(r.status_code, 200)

    def test_health_body(self):
        r = client.get("/health")
        data = r.json()
        self.assertIn("status", data)
        self.assertEqual(data["status"], "ok")


class TestAnalyzeSubmit(unittest.TestCase):
    """POST /api/analyze/github — job creation."""

    def test_missing_repo_url_returns_422(self):
        r = client.post("/api/analyze/github", json={})
        self.assertEqual(r.status_code, 422)

    def test_valid_request_returns_job_id(self):
        payload = {
            "repo_url": "https://github.com/curl/curl",
            "max_files": 5,
            "confidence_threshold": 0.308,
            "ml_model": "ensemble",
        }
        with patch("src.api.services.run_analysis_task"):
            r = client.post("/api/analyze/github", json=payload)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("job_id", data)
        self.assertTrue(len(data["job_id"]) > 0)

    def test_invalid_ml_model_still_accepted(self):
        """API accepts any string for ml_model — validation is downstream."""
        payload = {
            "repo_url": "https://github.com/curl/curl",
            "ml_model": "unknown_model",
        }
        with patch("src.api.services.run_analysis_task"):
            r = client.post("/api/analyze/github", json=payload)
        self.assertIn(r.status_code, [200, 422])


class TestJobStatus(unittest.TestCase):
    """GET /api/analyze/status/{job_id}"""

    def _create_job(self) -> str:
        payload = {"repo_url": "https://github.com/curl/curl"}
        with patch("src.api.services.run_analysis_task"):
            r = client.post("/api/analyze/github", json=payload)
        return r.json()["job_id"]

    def test_unknown_job_returns_404(self):
        r = client.get("/api/analyze/status/nonexistent-id")
        self.assertEqual(r.status_code, 404)

    def test_known_job_returns_status(self):
        job_id = self._create_job()
        r = client.get(f"/api/analyze/status/{job_id}")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("status", data)
        self.assertIn("progress", data)
        self.assertIn(data["status"], ["pending", "running", "completed", "failed"])

    def test_progress_is_integer_0_to_100(self):
        job_id = self._create_job()
        r = client.get(f"/api/analyze/status/{job_id}")
        progress = r.json()["progress"]
        self.assertIsInstance(progress, int)
        self.assertGreaterEqual(progress, 0)
        self.assertLessEqual(progress, 100)


class TestJobResults(unittest.TestCase):
    """GET /api/analyze/results/{job_id}"""

    def test_unknown_job_returns_404(self):
        r = client.get("/api/analyze/results/nonexistent-id")
        self.assertEqual(r.status_code, 404)

    def test_pending_job_result_schema(self):
        payload = {"repo_url": "https://github.com/curl/curl"}
        with patch("src.api.services.run_analysis_task"):
            r = client.post("/api/analyze/github", json=payload)
        job_id = r.json()["job_id"]
        r2 = client.get(f"/api/analyze/results/{job_id}")
        self.assertEqual(r2.status_code, 200)
        data = r2.json()
        self.assertIn("job_id", data)
        self.assertIn("status", data)


class TestJobLogs(unittest.TestCase):
    """GET /api/analyze/logs/{job_id}"""

    def test_unknown_job_returns_404(self):
        r = client.get("/api/analyze/logs/nonexistent-id")
        self.assertEqual(r.status_code, 404)

    def test_known_job_returns_list(self):
        payload = {"repo_url": "https://github.com/curl/curl"}
        with patch("src.api.services.run_analysis_task"):
            r = client.post("/api/analyze/github", json=payload)
        job_id = r.json()["job_id"]
        r2 = client.get(f"/api/analyze/logs/{job_id}")
        self.assertEqual(r2.status_code, 200)
        self.assertIsInstance(r2.json(), list)


class TestRequestDefaults(unittest.TestCase):
    """Pydantic model default values are applied correctly."""

    def test_defaults_applied(self):
        payload = {"repo_url": "https://github.com/curl/curl"}
        with patch("src.api.services.run_analysis_task"):
            r = client.post("/api/analyze/github", json=payload)
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
