import socket
import whois
from typing import Optional
from .base import SecurityTool, SecurityToolResult


class NetworkAnalyzer(SecurityTool):
    """Class for network-related security operations"""

    def __init__(self):
        super().__init__()
        self._cache = {}  # Simple cache for results

    def execute(self, operation: str, target: str, **kwargs) -> SecurityToolResult:
        """Execute network analysis operations"""
        operations = {
            'nslookup': self._nslookup,
            'whois': self._whois,
            # Add more network operations here
        }

        if operation not in operations:
            return SecurityToolResult(False, None, f"Unsupported operation: {operation}")

        try:
            result = operations[operation](target, **kwargs)
            return SecurityToolResult(True, result)
        except Exception as e:
            self.logger.error(f"Error in {operation}: {str(e)}")
            return SecurityToolResult(False, None, str(e))

    def _nslookup(self, domain: str) -> Optional[str]:
        """Perform DNS lookup"""
        cache_key = f"nslookup_{domain}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            ip_address = socket.gethostbyname(domain)
            self._cache[cache_key] = ip_address
            self.log_operation("nslookup", {"domain": domain, "ip": ip_address})
            return ip_address
        except socket.gaierror as e:
            raise Exception(f"DNS lookup failed for {domain}: {str(e)}")

    def _whois(self, host: str) -> dict:
        """Perform WHOIS lookup"""
        cache_key = f"whois_{host}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            whois_info = whois.whois(host)
            self._cache[cache_key] = whois_info
            self.log_operation("whois", {"host": host})
            return whois_info
        except Exception as e:
            raise Exception(f"WHOIS lookup failed for {host}: {str(e)}")