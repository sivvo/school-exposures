"""Output writer modules."""
from .ndjson import NDJSONWriter
from .splunk_hec import SplunkHECWriter

__all__ = ["NDJSONWriter", "SplunkHECWriter"]
