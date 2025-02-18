# core/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import logging


class SecurityToolResult:
    """Base class for tool operation results"""

    def __init__(self, success: bool, data: Any, error: Optional[str] = None):
        self.success = success
        self.data = data
        self.error = error

    def __str__(self) -> str:
        if self.success:
            return f"Success: {self.data}"
        return f"Error: {self.error}"


class SecurityTool(ABC):
    """Base abstract class for all security tools"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def execute(self, *args, **kwargs) -> SecurityToolResult:
        """Execute the security tool operation"""
        pass

    def log_operation(self, operation: str, details: Dict[str, Any]):
        """Log security tool operations"""
        self.logger.info(f"{operation}: {details}")