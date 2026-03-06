import os
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from tools.security.secrets import scan_secrets
from tools.security.deps import check_dependencies
from tools.network.ssl_checker import check_ssl_certificate
from tools.network.headers import check_http_headers
from tools.network.port_scanner import port_scan


class TestScanSecrets(unittest.TestCase):
    def _make_temp(self, content: str, suffix: str = ".env") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        return path

    def test_detects_aws_access_key(self) -> None:
        path = self._make_temp("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        try:
            findings = scan_secrets(path)
            self.assertTrue(len(findings) >= 1)
            self.assertEqual(findings[0]["line"], 1)
            self.assertEqual(findings[0]["pattern"], "AWS Access Key")
            self.assertIn("REDACTED", findings[0]["match"])
        finally:
            os.unlink(path)

    def test_detects_private_key(self) -> None:
        path = self._make_temp(
            "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n",
            suffix=".pem",
        )
        try:
            findings = scan_secrets(path)
            self.assertTrue(len(findings) >= 1)
            self.assertEqual(findings[0]["pattern"], "Private Key")
        finally:
            os.unlink(path)

    def test_returns_empty_for_clean_file(self) -> None:
        path = self._make_temp("This is a clean file with no secrets.\n", suffix=".txt")
        try:
            findings = scan_secrets(path)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_raises_on_missing_path(self) -> None:
        with self.assertRaises(RuntimeError):
            scan_secrets("/nonexistent/path/file.txt")


class TestCheckDependencies(unittest.TestCase):
    @patch("tools.security.deps.requests.post")
    def test_parses_requirements_txt(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": []}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        tmpdir = tempfile.mkdtemp()
        filepath = os.path.join(tmpdir, "requirements.txt")
        with open(filepath, "w") as fh:
            fh.write("flask==2.3.0\nrequests>=2.28.0\n")

        try:
            results = check_dependencies(filepath)
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["package"], "flask")
            self.assertEqual(results[0]["version"], "2.3.0")
        finally:
            os.unlink(filepath)
            os.rmdir(tmpdir)

    def test_raises_on_unsupported_file(self) -> None:
        tmpdir = tempfile.mkdtemp()
        filepath = os.path.join(tmpdir, "pyproject.toml")
        with open(filepath, "w") as fh:
            fh.write("[project]\n")

        try:
            with self.assertRaises(RuntimeError):
                check_dependencies(filepath)
        finally:
            os.unlink(filepath)
            os.rmdir(tmpdir)


class TestCheckSSLCertificate(unittest.TestCase):
    @patch("tools.network.ssl_checker.socket.create_connection")
    @patch("tools.network.ssl_checker.ssl.create_default_context")
    def test_returns_cert_info(self, mock_ssl_ctx: MagicMock, mock_conn: MagicMock) -> None:
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "serialNumber": "ABC123",
            "version": 3,
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ssl_ctx.return_value = mock_ctx

        result = check_ssl_certificate("example.com")
        self.assertEqual(result["hostname"], "example.com")
        self.assertFalse(result["expired"])
        self.assertIn("commonName=example.com", result["subject"])

    @patch("tools.network.ssl_checker.socket.create_connection", side_effect=OSError("refused"))
    def test_raises_on_connection_failure(self, _mock: MagicMock) -> None:
        with self.assertRaises(RuntimeError):
            check_ssl_certificate("nonexistent.invalid")


class TestCheckHTTPHeaders(unittest.TestCase):
    @patch("tools.network.headers.requests.head")
    def test_scores_headers(self, mock_head: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
            "Cache-Control": "no-store",
        }
        mock_head.return_value = mock_resp

        result = check_http_headers("https://example.com")
        self.assertEqual(result["status_code"], 200)
        self.assertGreater(result["score"], 80)
        self.assertIn(result["grade"], ("A", "B"))

    @patch("tools.network.headers.requests.head", side_effect=Exception("timeout"))
    def test_raises_on_failure(self, _mock: MagicMock) -> None:
        with self.assertRaises(Exception):
            check_http_headers("https://unreachable.example.com")


class TestPortScan(unittest.TestCase):
    @patch("tools.network.port_scanner.socket.create_connection")
    @patch("tools.network.port_scanner.socket.gethostbyname", return_value="127.0.0.1")
    def test_reports_open_ports(self, _mock_dns: MagicMock, mock_conn: MagicMock) -> None:
        mock_conn.return_value.__enter__ = MagicMock()
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        results = port_scan("localhost", "80,443")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["port"], 80)
        self.assertEqual(results[0]["status"], "open")

    @patch("tools.network.port_scanner.socket.gethostbyname", side_effect=socket.gaierror("cannot resolve"))
    def test_raises_on_dns_failure(self, _mock: MagicMock) -> None:
        with self.assertRaises(RuntimeError):
            port_scan("nonexistent.invalid")


if __name__ == "__main__":
    unittest.main()
