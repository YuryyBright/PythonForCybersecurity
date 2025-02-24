import os
from typing import Optional
import json
from icmplib import traceroute
from dotenv import load_dotenv
from psutil import net_connections
from .base import SecurityTool, SecurityToolResult


class ActiveReconnaissance(SecurityTool):
    """Class for performing active reconnaissance using Shodan API to gather details about a target system."""

    def __init__(self):
        """
        Initializes the ActiveReconnaissance instance.

        Attributes:
            _api (Shodan): The Shodan API client.
            _cache (dict): A dictionary to cache the results of previous queries to improve performance.
        """
        super().__init__()

        # Завантажуємо змінні середовища з .env файлу
        load_dotenv()

        # # Отримуємо API-ключ із середовища
        # api_key = os.getenv('SHODAN_API_KEY')
        # if api_key is None:
        #     raise ValueError("Shodan API key is missing in environment variables.")
        # self._api = Shodan(api_key)
        self._cache = {}  # Simple cache to store results of previous queries

    def execute(self, operation: str, target: str, **kwargs) -> SecurityToolResult:
        """
        Executes an operation using the Shodan API.

        Args:
            operation (str): The operation to perform, in this case, 'host' or similar.
            target (str): The target (IP address) for the operation.
            **kwargs: Additional arguments for specific operations.

        Returns:
            SecurityToolResult: The result of the operation, either successful with data or failed with an error message.
        """
        operations = {
            'print_net_connections': self._print_net_connections,
            'check_traceroute': self._check_traceroute,
        }

        if operation not in operations:
            return SecurityToolResult(False, None, f"Unsupported operation: {operation}")

        try:

            # If the operation requires a target, pass it, otherwise call without target
            if operation == 'print_net_connections':
                result = operations[operation]()  # This method does not need target
            else:
                result = operations[operation](target, **kwargs)  # Other operations might need target
            return SecurityToolResult(True, result)
        except Exception as e:
            self.logger.error(f"Error in {operation}: {str(e)}")
            return SecurityToolResult(False, None, str(e))

    def _print_net_connections(self) -> str:
        """
        Retrieve and return the current TCP and UDP network connections as a string.

        This method retrieves all active TCP and UDP network connections using
        the `net_connections` function. It returns a formatted string containing
        both the TCP and UDP connections.

        Args:
            None

        Returns:
            str: A formatted string containing the TCP and UDP network connections.

        Raises:
            Exception: If there is an error retrieving the network connections.
        """

        cache_key = f"net_connections_"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            tcp_connections = net_connections(kind='tcp')
            udp_connections = net_connections(kind='udp')


            result = f"TCP connections:\n{tcp_connections}\n\nUDP connections:\n{udp_connections}"
            self.log_operation("net_connections", {"TCP": tcp_connections, "UDP": udp_connections})
            self._cache[cache_key] = result
            return result
        except Exception as e:
            raise Exception(f"Failed to retrieve network connections: {str(e)}")

    def _check_traceroute(self, host: str) -> str:
        """
        Retrieve the traceroute information to the specified host as a formatted string.

        This method performs a traceroute to the given host and returns a formatted string with the hops details,
        including the TTL, address, round-trip time, and packets sent.

        Args:
            host (str): The target host for the traceroute.

        Returns:
            str: A formatted string containing the traceroute hops details.

        Raises:
            Exception: If there is an error retrieving the traceroute information.
        """
        cache_key = f"traceroute_{host}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            print('Checking hops for the host...')
            hops = traceroute(host, max_hops=20)  # Perform traceroute
            print('All Hops:\n', hops, '\n')

            result = "Distance/TTL \tAddress \tAverage round-trip time  \tPackets Sent\n"
            last_distance = 0

            for hop in hops:
                if last_distance + 1 != hop.distance:
                    result += 'No response from gateway\n'

                # Append hop details to result
                result += f'{hop.distance:<15} {hop.address:<15} {hop.avg_rtt} ms \t\t\t{hop.packets_sent:<5}\n'

                last_distance = hop.distance

            # Log operation and cache the result
            self.log_operation("traceroute", {"host": host, "hops": hops})
            self._cache[cache_key] = result
            return result
        except Exception as e:
            raise Exception(f"Failed to retrieve traceroute for {host}: {str(e)}")