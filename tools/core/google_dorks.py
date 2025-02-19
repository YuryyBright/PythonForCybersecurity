from typing import Optional

from googlesearch import search

from pagodo.pagodo import Pagodo
from .base import SecurityTool, SecurityToolResult

class GoogleDorks(SecurityTool):
    """Class for processing Google Dorks using Pagodo to get vulnerabilities/exploit information."""

    def __init__(self):
        """
        Initializes the GoogleDorks instance.
        """
        super().__init__()

    def execute(self, operation: str, domain: str, **kwargs) -> SecurityToolResult:
        """
        Executes the Google Dorks operation to process dorks using Pagodo.

        Args:
            operation (str): The operation to be performed, should be 'process_dorks'.
            google_dorks_file (str): Path to the file containing the Google Dorks.
            domain (str): The domain to perform the dork search on.
            **kwargs: Additional arguments for operation.

        Returns:
            SecurityToolResult: The result of the dork processing operation, either successful with data or failed with an error message.
        """
        operations = {
            'process_dorks': self._process_dorks,
            'process_search': self._perform_google_search,
        }

        if operation not in operations:
            return SecurityToolResult(False, None, f"Unsupported operation: {operation}")

        try:
            result = operations[operation](domain, **kwargs)
            return SecurityToolResult(True, result)
        except Exception as e:
            self.logger.error(f"Error in {operation}: {str(e)}")
            return SecurityToolResult(False, None, str(e))

    def _perform_google_search(self, host, **kwargs):
        """
        Perform google search using the host and query string.

        Args:
            host (string): Target system
            query_string (String): Query string
        """
        result = []
        for query in search(host + " " + kwargs['query_string'], stop=5):
            result.append(query)
        return result
    def _process_dorks(self, domain: str, **kwargs) -> str:
        """
        Processes Google Dorks using Pagodo to get vulnerabilities/exploit information.

        Args:
            google_dorks_file (str): Path to the file containing the Google Dorks.
            domain (str): The domain for which dorks will be processed.

        Returns:
            str: Formatted string with dorks and their associated URLs.
        """
        pg = Pagodo(
            google_dorks_file='dorks.txt',
            domain=domain,
            max_search_result_urls_to_return_per_dork=3,
            save_pagodo_results_to_json_file=True,
            minimum_delay_between_dork_searches_in_seconds=10,
            maximum_delay_between_dork_searches_in_seconds=15,
            save_urls_to_file=True,
            verbosity=4
        )

        pagodo_results_dict = pg.go()

        result = ""
        for key, value in pagodo_results_dict["dorks"].items():
            result += f"dork: {key}\n"
            for url in value["urls"]:
                result += f"{url}\n"

        return result
