"""全局常量配置"""

from pathlib import Path

BASE_DIR = Path("/home/anytls")
DOCKER_COMPOSE_PATH = BASE_DIR / "docker-compose.yaml"
CONFIG_PATH = BASE_DIR / "config.yaml"

LISTEN_PORT = 8443
SERVICE_IMAGE = "metacubex/mihomo:latest"

MIHOMO_PROXIES_DOCS = "https://wiki.metacubex.one/config/proxies/anytls/#anytls"

TOOL_NAME = "AnyTLS"
COMPOSE_SERVICE_NAME = "anytls-inbound"
COMPOSE_CONTAINER_PREFIX = f"{COMPOSE_SERVICE_NAME}-"

MIHOMO_LISTEN_TYPE = "anytls"
MIHOMO_LISTENER_NAME_PREFIX = f"{MIHOMO_LISTEN_TYPE}-in-"

# 客户端配置模板
DEFAULT_CLIENT_CONFIG = {
    "name": "{{DOMAIN}}",
    "type": MIHOMO_LISTEN_TYPE,
    "server": "{{PUBLIC_IP}}",
    "port": "{{PORT}}",
    "password": "{{PASSWORD}}",
    "client_fingerprint": "chrome",
    "udp": True,
    "idle_session_check_interval": 30,
    "idle_session_timeout": 30,
    "min_idle_session": 0,
    "sni": "{{SNI}}",
    "alpn": ["h2", "http/1.1"],
    "skip_cert_verify": False,
}
