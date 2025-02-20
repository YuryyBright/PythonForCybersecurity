import os
from typing import Optional
import json

from dotenv import load_dotenv
from shodan import Shodan
from .base import SecurityTool, SecurityToolResult


class ShodanAnalyzer(SecurityTool):
    """Class for interacting with Shodan API to gather details about a target system."""

    def __init__(self):
        """
        Initializes the ShodanAnalyzer instance.

        Attributes:
            _api (Shodan): The Shodan API client.
            _cache (dict): A dictionary to cache the results of previous queries to improve performance.
        """
        super().__init__()

        # Завантажуємо змінні середовища з .env файлу
        load_dotenv()

        # Отримуємо API-ключ із середовища
        api_key = os.getenv('SHODAN_API_KEY')
        if api_key is None:
            raise ValueError("Shodan API key is missing in environment variables.")
        self._api = Shodan(api_key)
        self._cache = {}  # Simple cache to store results of previous queries

    def execute(self, operation: str, target: str, **kwargs) -> SecurityToolResult:
        """
        Executes an operation using the Shodan API.

        Args:
            operation (str): The operation to perform, in this case, 'host'.
            target (str): The target (IP address) for the operation.
            **kwargs: Additional arguments for specific operations.

        Returns:
            SecurityToolResult: The result of the operation, either successful with data or failed with an error message.
        """
        operations = {
            'get_host_details': self._get_host_details,
        }

        if operation not in operations:
            return SecurityToolResult(False, None, f"Unsupported operation: {operation}")

        try:
            result = operations[operation](target, **kwargs)
            return SecurityToolResult(True, result)
        except Exception as e:
            self.logger.error(f"Error in {operation}: {str(e)}")
            return SecurityToolResult(False, None, str(e))

    def _get_host_details(self, host: str) -> Optional[dict]:
        """
        Fetches detailed information about the target IP address from Shodan.

        Args:
            ip_address (str): The IP address to retrieve details for.

        Returns:
            Optional[dict]: The Shodan information for the given IP address.

        Raises:
            Exception: If the Shodan API query fails for the given IP address.
        """
        cache_key = f"shodan_{host}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            ipinfo = self._api.host(host)

            self._cache[cache_key] = ipinfo
            self.log_operation("shodan", {"ip": host, "info": json.dumps(ipinfo, indent=4)})
            return ipinfo
        except Exception as e:
            raise Exception(f"Shodan query failed for {host}: {str(e)}")

