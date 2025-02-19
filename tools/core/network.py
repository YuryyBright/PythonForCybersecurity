from typing import Optional
import socket
import whois
import pydig as pd
from nslookup import Nslookup
from .base import SecurityTool, SecurityToolResult


class NetworkAnalyzer(SecurityTool):
    """Class for performing network-related security operations like DNS lookups, WHOIS queries, and DIG queries."""

    def __init__(self):
        """
        Initializes the NetworkAnalyzer instance with an empty cache.

        Attributes:
            _cache (dict): A dictionary to cache the results of queries to improve performance.
        """
        super().__init__()
        self._cache = {}  # Simple cache to store results of previous queries

    def execute(self, operation: str, target: str, **kwargs) -> SecurityToolResult:
        """
        Executes a network analysis operation based on the given operation type.

        Args:
            operation (str): The operation to be performed, such as 'nslookup', 'whois', or 'dig'.
            target (str): The target (domain/host) for the operation.
            **kwargs: Additional arguments for specific operations (e.g., record type for dig queries).

        Returns:
            SecurityToolResult: The result of the operation, either successful with data or failed with an error message.
        """
        operations = {
            'nslookup': self._nslookup,
            'whois': self._whois,
            'dig': self._dig_info,  # Adding 'dig' operation
            'nslookup2': self._nslookup2,
            'reverse_lookup': self._reverse_lookup,
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
        """
        Performs a DNS lookup for the given domain and returns the corresponding IP address.

        Args:
            domain (str): The domain for which the DNS lookup is performed.

        Returns:
            Optional[str]: The IP address of the domain, or None if the domain lookup fails.

        Raises:
            Exception: If DNS lookup fails for the given domain.
        """
        cache_key = f"nslookup_{domain}"

        # Check cache first to avoid redundant queries
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
        """
        Performs a WHOIS lookup for the given host.

        Args:
            host (str): The host for which the WHOIS lookup is performed.

        Returns:
            dict: The WHOIS information of the host.

        Raises:
            Exception: If WHOIS lookup fails for the given host.
        """
        cache_key = f"whois_{host}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            whois_info = whois.whois(host)
            self._cache[cache_key] = whois_info
            self.log_operation("whois", {"host": host})
            return whois_info
        except Exception as e:
            raise Exception(f"WHOIS lookup failed for {host}: {str(e)}")

    def _dig_info(self, host, **kwargs):
        """
        Performs a DIG DNS query for the given host and record type, and returns the results.

        Args:
            host (str): The domain/host to query.
            record_type (str): The type of DNS record to query (e.g., 'A', 'NS').

        Returns:
            str: The results of the DIG query.

        Raises:
            Exception: If the DIG query fails.
        """
        record_type = kwargs['type']

        cache_key = f"dig_{host}_{record_type}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            print(f"Using cached DIG info for {host} with type {record_type}")
            return self._cache[cache_key]

        try:
            dig_info = pd.query(host, record_type)  # Assuming pd.query retrieves the DIG info

            # Cache the result
            self._cache[cache_key] = dig_info

            # Return the DIG query result
            return dig_info
        except Exception as e:
            raise Exception(f"DIG query failed for {host} with type {record_type}: {str(e)}")

    def _nslookup2(self, domain: str):
        """
        Performs a DNS lookup for a given domain using Google's DNS servers.

        Args:
            domain (str): The domain to look up.

        Returns:
            tuple: The full DNS response and the answer to the lookup.

        Raises:
            Exception: If DNS lookup fails.
        """
        cache_key = f"nslookup_{domain}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            print(f"Using cached NSLookup result for {domain}")
            return self._cache[cache_key]

        try:
            # Using Google's DNS server (8.8.8.8) for DNS lookup
            dns_query = Nslookup(dns_servers=["8.8.8.8"])
            dns_record = dns_query.dns_lookup(domain)

            # Cache the result
            self._cache[cache_key] = dns_record.answer

            # Log the operation
            self.log_operation("nslookup", {"domain": domain, "answer": dns_record.answer})
            # Return full DNS response and the answer
            return dns_record.response_full, dns_record.answer
        except Exception as e:
            raise Exception(f"NSLookup failed for {domain}: {str(e)}")

    def _reverse_lookup(self, ip_address: str) -> Optional[str]:
        """
        Perform a reverse DNS lookup for a given IP address to get the associated domain name (PTR record).

        Args:
            ip_address (str): The IP address for which to perform the reverse lookup.

        Returns:
            Optional[str]: The domain name associated with the IP address or None if no PTR record is found.

        Raises:
            Exception: If the reverse lookup fails.
        """
        cache_key = f"reverse_lookup_{ip_address}"

        # Check cache first to avoid redundant queries
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            domain_name = socket.gethostbyaddr(ip_address)[0]  # Reverse lookup using socket.gethostbyaddr
            self._cache[cache_key] = domain_name
            self.log_operation("reverse_lookup", {"ip": ip_address, "domain": domain_name})
            return domain_name
        except socket.herror as e:
            raise Exception(f"Reverse lookup failed for {ip_address}: {str(e)}")