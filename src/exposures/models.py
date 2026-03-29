from enum import Enum
from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel
import uuid


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"
    ERROR = "error"


class CheckCategory(str, Enum):
    HTTP_HEADERS = "http_headers"
    TLS = "tls"
    DNS = "dns"
    EMAIL_SECURITY = "email_security"
    COMPONENTS = "components"
    NETWORK_EXPOSURE = "network_exposure"
    INSECURE_SERVICES = "insecure_services"
    CLOUD_STORAGE = "cloud_storage"
    DOMAIN_EXPIRY = "domain_expiry"
    REPUTATION = "reputation"


class Finding(BaseModel):
    runkey: str
    url: str
    business_unit: str
    check_category: CheckCategory
    check_name: str
    status: Status
    severity: Severity
    detail: str
    evidence: dict[str, Any] = {}
    timestamp: datetime | None = None

    def model_post_init(self, __context: Any) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

    def to_splunk_event(self) -> dict:
        data = self.model_dump(mode="json")
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return {
            "time": self.timestamp.timestamp() if self.timestamp else datetime.now(timezone.utc).timestamp(),
            "sourcetype": "cyber_exposure:finding",
            "event": data,
        }


class ScanTarget(BaseModel):
    url: str
    original_url: str
    business_unit: str
    domain: str  # registered domain via tldextract
    ip_addresses: list[str] = []


class RunSummary(BaseModel):
    runkey: str
    started_at: datetime
    completed_at: datetime | None = None
    total_targets: int
    completed_targets: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = {}
    findings_by_category: dict[str, int] = {}
    errors: list[str] = []

    def to_splunk_event(self) -> dict:
        data = self.model_dump(mode="json")
        return {
            "time": self.started_at.timestamp(),
            "sourcetype": "cyber_exposure:run_summary",
            "event": data,
        }
