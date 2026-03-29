"""Configuration management 
settings.yaml
env variables will override specific fields if present
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml

class RunConfig(BaseModel):
    dry_run: bool = False
    resume_runkey: str = ""

class InputConfig(BaseModel):
    csv_path: str = "./config/urls.csv"

class OutputConfig(BaseModel):
    send_to_splunk: bool = True
    log_locally: bool = True
    local_output_dir: str = "./output"

class ConcurrencyConfig(BaseModel):
    http_workers: int = 200
    dns_workers: int = 500
    tls_workers: int = 50
    censys_qps: int = 10
    request_timeout_s: int = 15
    connect_timeout_s: int = 5


class HttpHeadersCheckConfig(BaseModel):
    follow_redirects: bool = True
    max_redirects: int = 10
    #TODO the user_agent is hard coded in multiple places - make this reference a consistent static variable
    user_agent: str = "DfE-CyberExposureScanner/1.0"

class TLSCheckConfig(BaseModel):
    warn_expiry_days: int = 30
    critical_expiry_days: int = 7


class ComponentsCheckConfig(BaseModel):
    check_well_known_paths: bool = True
    parse_html: bool = False
    nvd_api_key: str = ""
    nvd_feed_cache_path: str = "./cache/nvd_feed.json.gz"
    nvd_feed_max_age_days: int = 1


class EmailSecurityCheckConfig(BaseModel):
    check_spf: bool = True
    check_dmarc: bool = True


class CertTransparencyCheckConfig(BaseModel):
    lookback_days: int = 90
    flag_unexpected_issuers: bool = True


class OpenRedirectCheckConfig(BaseModel):
    pass  # no config currently needed beyond the shared concurrency settings


class SafeBrowsingCheckConfig(BaseModel):
    api_key: str = ""


class ChecksConfig(BaseModel):
    enabled: list[str] = [
        "http_headers",
        "tls",
        "dns_records",
        "email_security",
        "components",
        "censys_ports",
        "insecure_services",
        "open_redirect",
        "cert_transparency",
        "cloud_storage",
        "domain_expiry",
        "safe_browsing",
        "dnsbl",
    ]
    http_headers: HttpHeadersCheckConfig = Field(default_factory=HttpHeadersCheckConfig)
    tls: TLSCheckConfig = Field(default_factory=TLSCheckConfig)
    components: ComponentsCheckConfig = Field(default_factory=ComponentsCheckConfig)
    email_security: EmailSecurityCheckConfig = Field(default_factory=EmailSecurityCheckConfig)
    cert_transparency: CertTransparencyCheckConfig = Field(default_factory=CertTransparencyCheckConfig)
    open_redirect: OpenRedirectCheckConfig = Field(default_factory=OpenRedirectCheckConfig)
    safe_browsing: SafeBrowsingCheckConfig = Field(default_factory=SafeBrowsingCheckConfig)


class SplunkConfig(BaseModel):
    url: str = ""
    token: str = ""
    index: str = "school_exposures"
    source: str = "exposure_scanner"
    verify_tls: bool = True
    batch_size: int = 100
    #TODO index and source need setting appropriately, these are just place holders for now

class CensysConfig(BaseModel):
    api_id: str = ""
    api_secret: str = ""


class HistoryConfig(BaseModel):
    enabled: bool = True
    db_path: str = "./output/history.db"


class Config(BaseModel):
    run: RunConfig = Field(default_factory=RunConfig)
    input: InputConfig = Field(default_factory=InputConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    checks: ChecksConfig = Field(default_factory=ChecksConfig)
    splunk: SplunkConfig = Field(default_factory=SplunkConfig)
    censys: CensysConfig = Field(default_factory=CensysConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def load_config(yaml_path: str | Path = "./config/settings.yaml") -> Config:
    """Load configuration from the settings.yaml file with environment variable overrides.
       SPLUNK_HEC_TOKEN: splunk.token
       censys.api_id
       CENSYS_API_SECRET: censys.api_secret
       NVD_API_KEY: checks.components.nvd_api_key      
    """
    yaml_path = Path(yaml_path)

    raw: dict[str, Any] = {}
    if yaml_path.exists():
        with yaml_path.open() as fh:
            loaded = yaml.safe_load(fh)
            if loaded:
                raw = loaded

    # Apply env-var overrides onto the raw dict before constructing the model
    env_overrides: dict[str, Any] = {}

    splunk_token = os.environ.get("SPLUNK_HEC_TOKEN", "")
    if splunk_token:
        env_overrides.setdefault("splunk", {})["token"] = splunk_token

    censys_id = os.environ.get("CENSYS_API_ID", "")
    if censys_id:
        env_overrides.setdefault("censys", {})["api_id"] = censys_id

    censys_secret = os.environ.get("CENSYS_API_SECRET", "")
    if censys_secret:
        env_overrides.setdefault("censys", {})["api_secret"] = censys_secret

    nvd_key = os.environ.get("NVD_API_KEY", "")
    if nvd_key:
        env_overrides.setdefault("checks", {}).setdefault("components", {})["nvd_api_key"] = nvd_key

    gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if gsb_key:
        env_overrides.setdefault("checks", {}).setdefault("safe_browsing", {})["api_key"] = gsb_key

    merged = _deep_merge(raw, env_overrides)
    return Config.model_validate(merged)
