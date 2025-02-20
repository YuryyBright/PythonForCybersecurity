import os
import json
from typing import Optional
from dotenv import load_dotenv
import ipinfo

from .base import SecurityTool, SecurityToolResult

class IpinfoAnalyzer(SecurityTool):
    """Class for interacting with IPInfo API to gather details about a target IP address."""

    def __init__(self):
        """
        Initializes the IpinfoAnalyzer instance.

        Attributes:
            _handler (ipinfo.Handler): The IPInfo API client.
            _cache (dict): A dictionary to cache the results of previous queries to improve performance.
        """
        super().__init__()

        # Завантажуємо змінні середовища з .env файлу
        load_dotenv()

        # Отримуємо Access Token із середовища
        access_token = os.getenv('IPINFO_ACCESS_TOKEN')
        if access_token is None:
            raise ValueError("IPInfo Access Token is missing in environment variables.")
        self._handler = ipinfo.getHandler(access_token)
        self._cache = {}  # Simple cache to store results of previous queries

    def execute(self, operation: str, target: str, **kwargs) -> SecurityToolResult:
        """
        Executes an operation using the IPInfo API.

        Args:
            operation (str): The operation to perform, in this case, 'get_host_details'.
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
        Fetches detailed information about the target IP address from IPInfo.

        Args:
            host (str): The IP address to retrieve details for.

        Returns:
            Optional[dict]: The IPInfo information for the given IP address.

        Raises:
            Exception: If the IPInfo API query fails for the given IP address.
        """
        cache_key = f"ipinfo_{host}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            ipinfo_details = self._handler.getDetails(host)
            # Convert to JSON-like structure for easier parsing
            json_data = json.loads(json.dumps(ipinfo_details.all, indent=4))

            details = {
                'city': json_data.get('city'),
                'country': json_data.get('country'),
                'timezone': json_data.get('timezone'),
            }

            self._cache[cache_key] = details
            self.log_operation("ipinfo", {"ip": host, "info": json.dumps(details, indent=4)})
            return details
        except Exception as e:
            raise Exception(f"IPInfo query failed for {host}: {str(e)}")
