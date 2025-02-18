# security_toolkit.py
import logging
from typing import Dict, Any
from core.network import NetworkAnalyzer
from core.forensics import ForensicsAnalyzer
from tools.core.base import SecurityToolResult


class SecurityToolkit:
    """Main interface for the security toolkit"""

    def __init__(self):
        self._tools = {
            'network': NetworkAnalyzer(),
            'forensics': ForensicsAnalyzer(),
            # Add more tools here
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

    # Example network analysis
    result = toolkit.execute_tool('network', 'nslookup', 'www.president.gospmr.org')
    print(f"NSLookup result: {result}")

    result = toolkit.execute_tool('network', 'whois', 'www.president.gospmr.org')
    print(f"WHOIS result: {result}")


if __name__ == "__main__":
    main()