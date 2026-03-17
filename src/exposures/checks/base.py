"""Abstract base class for all security checks."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import CheckCategory, Finding, ScanTarget, Severity, Status


class BaseCheck(ABC):
    """Every check module must subclass this and implement `run`."""

    name: str
    category: CheckCategory

    @abstractmethod
    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        """Execute the check against *target* and return a list of findings.

        Implementations MUST catch all exceptions internally and return an
        ERROR finding rather than letting exceptions propagate.
        """
        ...

    def make_finding(
        self,
        target: ScanTarget,
        runkey: str,
        check_name: str,
        status: Status,
        severity: Severity,
        detail: str,
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        """Convenience factory that stamps runkey/url/business_unit automatically."""
        return Finding(
            runkey=runkey,
            url=target.url,
            business_unit=target.business_unit,
            check_category=self.category,
            check_name=check_name,
            status=status,
            severity=severity,
            detail=detail,
            evidence=evidence or {},
        )

    def make_error(
        self,
        target: ScanTarget,
        runkey: str,
        check_name: str,
        exc: Exception,
    ) -> Finding:
        """Return a standardised ERROR finding when an unexpected exception occurs."""
        return self.make_finding(
            target=target,
            runkey=runkey,
            check_name=check_name,
            status=Status.ERROR,
            severity=Severity.INFO,
            detail=f"Check failed with exception: {type(exc).__name__}: {exc}",
            evidence={"exception_type": type(exc).__name__, "exception_msg": str(exc)},
        )
