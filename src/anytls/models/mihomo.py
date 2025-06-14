"""Pydantic models for mihomo configuration files."""

from pathlib import Path

from pydantic import BaseModel, Field


class Listener(BaseModel):
    """Represents a listener in mihomo's config.yaml."""

    name: str
    type: str = "anytls"
    port: int = 8443
    listen: str = "0.0.0.0"
    users: dict[str, str]
    certificate: Path = Field(..., alias="certificate")
    private_key: Path = Field(..., alias="private-key", alias_priority=False)


class MihomoConfig(BaseModel):
    """Represents the structure of mihomo's config.yaml."""

    listeners: list[Listener]


class ClientConfig(BaseModel):
    """Represents the client-side configuration for connecting to the service."""

    name: str
    type: str = "anytls"
    server: str
    port: int = 8443
    password: str
    client_fingerprint: str = Field("chrome", alias="client-fingerprint")
    udp: bool = True
    idle_session_check_interval: int = Field(30, alias="idle-session-check-interval")
    idle_session_timeout: int = Field(30, alias="idle-session-timeout")
    min_idle_session: int = Field(0, alias="min-idle-session")
    sni: str
    alpn: list[str] = ["h2", "http/1.1"]
    skip_cert_verify: bool = Field(False, alias="skip-cert-verify")
