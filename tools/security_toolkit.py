# security_toolkit.py
import logging
from typing import Dict, Any
from core.network import NetworkAnalyzer
from core.forensics import ForensicsAnalyzer
from tools.core.base import SecurityToolResult
from tools.core.censys import CensysAnalyzer
from tools.core.crt_info import CrtshAnalyzer
from tools.core.google_dorks import GoogleDorks
from tools.core.ipinfo import IpinfoAnalyzer
from tools.core.shodan import ShodanAnalyzer


class SecurityToolkit:
    """Main interface for the security toolkit"""

    def __init__(self):
        self._tools = {
            'network': NetworkAnalyzer(),
            'forensics': ForensicsAnalyzer(),
            'google_dorks': GoogleDorks(),  # Adding Google Dorks tool to the toolkit
            'shodan': ShodanAnalyzer(),
            # 'censys': CensysAnalyzer(),
            'ipinfo': IpinfoAnalyzer(),
            'crt_info': CrtshAnalyzer(),
        }

    def execute_tool(self,
                     tool_type: str,
                     operation: str,
                     target: Any,
                     **kwargs) -> SecurityToolResult:
        """
        Execute a security tool operation

        Args:
            tool_type: Type of security tool ('network', 'forensics', etc.)
            operation: Specific operation to perform
            target: Target for the operation
            **kwargs: Additional arguments for the operation

        Returns:
            SecurityToolResult object containing the operation result
        """
        if tool_type not in self._tools:
            return SecurityToolResult(False, None, f"Unsupported tool type: {tool_type}")



        return self._tools[tool_type].execute(operation, target, **kwargs)


# Example usage
def main():
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create toolkit instance
    toolkit = SecurityToolkit()

    # # Example network analysis - NSLookup
    # result = toolkit.execute_tool('network', 'nslookup', 'www.president.gospmr.org')
    # print(f"NSLookup result: {result}")
    # #
    # # Example network analysis - WHOIS
    # result = toolkit.execute_tool('network', 'whois', 'www.president.gospmr.org')
    # print(f"WHOIS result: {result}")

    # # Perform a DIG query for A record
    # result = toolkit.execute_tool('network', 'dig', 'www.president.gospmr.org', type="A")
    # print(f"DIG A record result: {result}")
    # #
    # # Perform a DIG query for NS record
    # result = toolkit.execute_tool('network', 'dig', 'www.president.gospmr.org', type="A")
    # print(f"DIG NS record result: {result}")
    # # Perform a DIG query for NS record
    # result = toolkit.execute_tool('network', 'dig', 'www.president.gospmr.org', type="NS")
    # print(f"DIG NS record result: {result}")

    # Perform a Reverse DNS Lookup (reverse lookup)
    # result = toolkit.execute_tool('network', 'reverse_lookup', '217.19.216.168')  # Example with Google's DNS IP
    # print(f"Reverse lookup result for 217.19.216.168: {result}")
    #
    # # Example network analysis - NSLookup
    # result = toolkit.execute_tool('network', 'nslookup', 'www.president.gospmr.org')
    # print(f"NSLookup result: {result}")
    # Create toolkit instance
    # toolkit = SecurityToolkit()
    #
    # Example Google Dorks processing
    # result = toolkit.execute_tool('google_dorks', 'process_dorks','www.president.gospmr.org')
    # print(f"Google Dorks result: {result}")

    # result = toolkit.execute_tool('google_dorks', 'process_search', 'www.president.gospmr.org', query_string='inurl:"/admin/login"')
    # print(f"Google search result: {result}")

    # result = toolkit.execute_tool('shodan', 'get_host_details', '217.19.216.168')
    # print(f"Shodan search result: {result}")

    # result = toolkit.execute_tool('censys', 'get_host_details', '217.19.216.168')
    # print(f"Shodan search result: {result}")

    result = toolkit.execute_tool('crt_info', 'cert_query', 'abc.xyz')

if __name__ == '__main__':
    main()