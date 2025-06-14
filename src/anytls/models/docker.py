"""Pydantic models for docker-compose.yaml"""

from pydantic import BaseModel, Field


class AnyTlsInboundService(BaseModel):
    """Represents the 'anytls-inbound' service in docker-compose."""

    image: str = "metacubex/mihomo:latest"
    container_name: str
    restart: str = "always"
    ports: list[str] = ["8443:8443"]
    working_dir: str = "/app/proxy-inbound/"
    volumes: list[str]
    command: list[str] = ["-f", "config.yaml", "-d", "/"]


class Services(BaseModel):
    """Represents the 'services' block in docker-compose."""

    anytls_inbound: AnyTlsInboundService = Field(..., alias="anytls-inbound")


class DockerCompose(BaseModel):
    """Represents the top-level structure of docker-compose.yaml."""

    services: Services
