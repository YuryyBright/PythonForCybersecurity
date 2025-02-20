import os
from typing import Optional
import json

from dotenv import load_dotenv
from censys.search import CensysHosts
from .base import SecurityTool, SecurityToolResult

class CensysAnalyzer(SecurityTool):
    """Class for interacting with Censys API to gather details about a target system."""

    def __init__(self):
        """
        Initializes the CensysAnalyzer instance.

        Attributes:
            _api (CensysHosts): The Censys API client.
            _cache (dict): A dictionary to cache the results of previous queries to improve performance.
        """
        super().__init__()

        # Load environment variables from .env file
        load_dotenv()

        # Retrieve the API key from environment variables (if required by Censys)
        api_key = os.getenv('CENSYS_API_KEY')
        if api_key is None:
            raise ValueError("Censys API key is missing in environment variables.")
        self._api = CensysHosts()
        self._cache = {}  # Simple cache to store results of previous queries

    def execute(self, operation: str, target: str, **kwargs) -> SecurityToolResult:
        """
        Executes an operation using the Censys API.

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
        Fetches detailed information about the target IP address from Censys.

        Args:
            host (str): The IP address to retrieve details for.

        Returns:
            Optional[dict]: The Censys information for the given IP address.

        Raises:
            Exception: If the Censys API query fails for the given IP address.
        """
        cache_key = f"censys_{host}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            ipinfo = self._api.view(host)

            self._cache[cache_key] = ipinfo
            self.log_operation("censys", {"ip": host, "info": json.dumps(ipinfo, indent=4)})

            # Print specific details of the host like services, ports, and banners
            if 'services' in ipinfo:
                for service in ipinfo['services']:
                    if 'service_name' in service and 'port' in service and 'banner' in service:
                        print(f"[services][{service.get('port')}][service_name]: {service.get('service_name')}")
                        print(f"[services][{service.get('port')}][port]: {service.get('port')}")
                        print(f"[services][{service.get('port')}][banner]: {service.get('banner')}")
            return ipinfo
        except Exception as e:
            raise Exception(f"Censys query failed for {host}: {str(e)}")


