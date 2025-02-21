import os
import json
from typing import Optional

from dotenv import load_dotenv
from pycrtsh import Crtsh
from .base import SecurityTool, SecurityToolResult


class CrtshAnalyzer(SecurityTool):
    """Class for interacting with crt.sh API to gather certificate information about a domain."""

    def __init__(self):
        """
        Initializes the CrtshAnalyzer instance.

        Attributes:
            _crtsh (Crtsh): The Crtsh API client.
            _cache (dict): A dictionary to cache the results of previous queries to improve performance.
        """
        super().__init__()

        # Завантажуємо змінні середовища з .env файлу
        load_dotenv()

        # Ініціалізація Crtsh API клієнта
        self._crtsh = Crtsh()
        self._cache = {}  # Simple cache to store results of previous queries

    def execute(self, operation: str, target: str, **kwargs) -> SecurityToolResult:
        """
        Executes an operation using the Crtsh API.

        Args:
            operation (str): The operation to perform, in this case, 'cert_query'.
            target (str): The target domain for the operation.
            **kwargs: Additional arguments for specific operations.

        Returns:
            SecurityToolResult: The result of the operation, either successful with data or failed with an error message.
        """
        operations = {
            'cert_query': self._cert_query,
        }

        if operation not in operations:
            return SecurityToolResult(False, None, f"Unsupported operation: {operation}")

        try:
            result = operations[operation](target, **kwargs)
            return SecurityToolResult(True, result)
        except Exception as e:
            self.logger.error(f"Error in {operation}: {str(e)}")
            return SecurityToolResult(False, None, str(e))

    def _cert_query(self, host: str) -> Optional[dict]:
        """
        Perform a crt.sh certificate lookup for the target domain.

        Args:
            host (str): The domain to search for certificates.

        Returns:
            Optional[dict]: A dictionary containing the certificates information for the given domain.

        Raises:
            Exception: If the Crtsh API query fails for the given domain.
        """
        cache_key = f"crtsh_{host}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            certs = self._crtsh.search(host)

            # Caching the result
            self._cache[cache_key] = certs

            # Log operation
            self.log_operation("crtsh", {"host": host, "certificates": json.dumps(certs, indent=4, default=str)})

            return certs
        except Exception as e:
            raise Exception(f"Crtsh query failed for {host}: {str(e)}")
