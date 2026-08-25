from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from app.schemas.event import SecurityEventCreate


class BaseLogParser(ABC):
    """Abstract base class for all log parsers."""

    @abstractmethod
    def can_parse(self, raw_log: str, source_type: Optional[str] = None) -> bool:
        """Determine if this parser can handle the provided raw log format."""
        pass

    @abstractmethod
    def parse(self, raw_log: str) -> SecurityEventCreate:
        """Parse raw string log into unified SecurityEventCreate schema."""
        pass
