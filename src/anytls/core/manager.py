"""AnyTLS 服务核心管理逻辑"""

import logging
import shutil
import subprocess
import sys
import uuid
from typing import Optional

import yaml
from rich.console import Console
from rich.syntax import Syntax

from anytls.core import constants, utils


class AnyTLSManager:
    """封装 AnyTLS 服务管理的所有逻辑"""

    def __init__(self):
        """初始化管理器"""
        self.console = Console()

    @staticmethod
    def _ensure_service_installed():
        """确保服务已安装，否则退出"""
        if not constants.DOCKER_COMPOSE_PATH.is_file():
            logging.error(f"配置文件 ({constants.DOCKER_COMPOSE_PATH}) 未找到。")
            logging.error("请先运行 'install' 命令来安装服务。")
            sys.exit(1)

    @staticmethod
    def _get_domain_from_config() -> str:
        """从 docker-compose.yaml 文件中解析出域名"""
        if not constants.DOCKER_COMPOSE_PATH.exists():
            logging.error(
                f"配置文件 {constants.DOCKER_COMPOSE_PATH} 不存在。您是否已经安装了服务？"
            )
            sys.exit(1)

        with constants.DOCKER_COMPOSE_PATH.open("r") as f:
            data = yaml.safe_load(f)
            container_name = data["services"]["anytls-inbound"]["container_name"]
            domain = container_name.split("anytls-inbound-")[-1]
            if not domain:
                raise ValueError
            return domain

    def _check_dependencies(self):
        """检查 Docker 和 Docker Compose 是否安装"""
        logging.info("正在检查 Docker 和 Docker Compose 环境...")
        try:
            utils.run_command(["docker", "--version"], capture_output=True, install_docker=True)
            utils.run_command(
                ["docker", "compose", "version"], capture_output=True, install_docker=True
            )
            logging.info("Docker 和 Docker Compose 已安装。")
        except (FileNotFoundError, subprocess.CalledProcessError):
            logging.warning("未检测到 Docker 或 Docker Compose。")
            if self.console.input("是否需要自动安装？ (y/n): ").lower() == "y":
                logging.info("开始自动安装 Docker 和 Docker Compose...")
                utils.run_command(["/bin/bash", "-c", utils.DOCKER_INSTALL_SCRIPT])
                logging.info(
                    "安装完成。您可能需要重新登录或运行 `newgrp docker` "
                    "以便非 root 用户无需 sudo 即可运行 docker。请重新运行本脚本。"
                )
                sys.exit(0)
            else:
                logging.error("安装被用户取消。脚本无法继续。")
                sys.exit(1)
        except Exception as e:
            logging.error(e)

    def install(self, domain: str, password: Optional[str], ip: Optional[str]):
        """安装并启动 AnyTLS 服务"""
        logging.info(f"--- 开始安装 AnyTLS 服务 (域名: {domain}) ---")
        if constants.BASE_DIR.exists():
            logging.warning(f"工作目录 {constants.BASE_DIR} 已存在。继续操作将可能覆盖现有配置。")
            if self.console.input("是否继续？ (y/n): ").lower() != "y":
                logging.info("安装已取消。")
                return

        self._check_dependencies()

        public_ip = ip or utils.get_public_ip()
        service_password = password or utils.generate_password()

        logging.info(f"正在为域名 {domain} 申请 Let's Encrypt 证书...")
        utils.run_command(
            [
                "certbot",
                "certonly",
                "--standalone",
                "--register-unsafely-without-email",
                "--agree-tos",
                "--non-interactive",
                "-d",
                domain,
            ]
        )
        logging.info("证书申请成功。")

        logging.info(f"正在创建工作目录: {constants.BASE_DIR}")
        constants.BASE_DIR.mkdir(exist_ok=True)

        # 创建 Mihomo 配置
        mihomo_cfg_dict = {
            "listeners": [
                {
                    "name": f"anytls-in-{uuid.uuid4()}",
                    "type": "anytls",
                    "port": constants.LISTEN_PORT,
                    "listen": "0.0.0.0",
                    "users": {f"user_{uuid.uuid4().hex[:8]}": service_password},
                    "certificate": f"/etc/letsencrypt/live/{domain}/fullchain.pem",
                    "private-key": f"/etc/letsencrypt/live/{domain}/privkey.pem",
                }
            ]
        }

        with constants.CONFIG_PATH.open("w", encoding="utf8") as f:
            yaml.dump(mihomo_cfg_dict, f, sort_keys=False)
        logging.info(f"已生成配置文件: {constants.CONFIG_PATH}")

        # 创建 Docker Compose 配置
        docker_compose_cfg_dict = {
            "services": {
                "anytls-inbound": {
                    "image": constants.SERVICE_IMAGE,
                    "container_name": f"anytls-inbound-{domain}",
                    "restart": "always",
                    "ports": [f"{constants.LISTEN_PORT}:{constants.LISTEN_PORT}"],
                    "working_dir": "/app/proxy-inbound/",
                    "volumes": [
                        "/etc/letsencrypt/:/etc/letsencrypt/",
                        "./config.yaml:/app/proxy-inbound/config.yaml",
                    ],
                    "command": ["-f", "config.yaml", "-d", "/"],
                }
            }
        }
        with constants.DOCKER_COMPOSE_PATH.open("w", encoding="utf8") as f:
            yaml.dump(docker_compose_cfg_dict, f, sort_keys=False)
        logging.info(f"已生成 Docker Compose 文件: {constants.DOCKER_COMPOSE_PATH}")

        logging.info("正在拉取最新的 Docker 镜像...")
        utils.run_command(["docker", "compose", "pull"], cwd=constants.BASE_DIR)
        logging.info("正在启动服务...")
        utils.run_command(["docker", "compose", "down"], cwd=constants.BASE_DIR, check=False)
        utils.run_command(["docker", "compose", "up", "-d"], cwd=constants.BASE_DIR)

        logging.info("--- AnyTLS 服务安装并启动成功！ ---")

        # 打印客户端配置
        client_config_dict = {
            "name": domain,
            "type": "anytls",
            "server": public_ip,
            "port": constants.LISTEN_PORT,
            "password": service_password,
            "client_fingerprint": "chrome",
            "udp": True,
            "idle_session_check_interval": 30,
            "idle_session_timeout": 30,
            "min_idle_session": 0,
            "sni": domain,
            "alpn": ["h2", "http/1.1"],
            "skip_cert_verify": False,
        }

        client_yaml = yaml.dump([client_config_dict], sort_keys=False)
        self.console.print("\n" + "=" * 20 + " 客户端配置信息[mihomo] " + "=" * 20)
        self.console.print(Syntax(client_yaml, "yaml"))
        self.console.print("=" * 58 + "\n")

        self.console.print(
            "详见客户端配置文档：https://wiki.metacubex.one/config/proxies/anytls/#anytls"
        )

    def remove(self):
        """停止并移除 AnyTLS 服务和相关文件"""
        logging.info("--- 开始卸载 AnyTLS 服务 ---")
        if not constants.BASE_DIR.exists():
            logging.warning(f"工作目录 {constants.BASE_DIR} 不存在，可能服务未安装或已被移除。")
            return

        domain = self._get_domain_from_config()
        logging.info(f"检测到正在管理的域名为: {domain}")

        logging.info("正在停止并移除 Docker 容器...")
        utils.run_command(
            ["docker", "compose", "down", "--volumes"], cwd=constants.BASE_DIR, check=False
        )

        logging.info(f"正在删除工作目录: {constants.BASE_DIR}")
        shutil.rmtree(constants.BASE_DIR)

        logging.info(f"正在删除 {domain} 的 Let's Encrypt 证书...")
        utils.run_command(
            ["certbot", "delete", "--cert-name", domain, "--non-interactive"], check=False
        )
        logging.info("--- AnyTLS 服务已成功卸载。 ---")

    def start(self):
        """启动服务"""
        self._ensure_service_installed()
        logging.info("正在启动 AnyTLS 服务...")
        utils.run_command(["docker", "compose", "up", "-d"], cwd=constants.BASE_DIR)
        logging.info("AnyTLS 服务已启动。")

    def stop(self):
        """停止服务"""
        self._ensure_service_installed()
        logging.info("正在停止 AnyTLS 服务...")
        utils.run_command(["docker", "compose", "down"], cwd=constants.BASE_DIR)
        logging.info("AnyTLS 服务已停止。")

    def update(self):
        """更新服务（拉取新镜像并重启）"""
        self._ensure_service_installed()
        logging.info("--- 开始更新 AnyTLS 服务 ---")
        logging.info("正在拉取最新的 Docker 镜像...")
        utils.run_command(["docker", "compose", "pull"], cwd=constants.BASE_DIR)
        logging.info("正在使用新镜像重启服务...")
        utils.run_command(["docker", "compose", "down"], cwd=constants.BASE_DIR, check=False)
        utils.run_command(["docker", "compose", "up", "-d"], cwd=constants.BASE_DIR)
        logging.info("--- AnyTLS 服务更新完成。 ---")

    def log(self):
        """查看服务日志"""
        self._ensure_service_installed()
        logging.info("正在显示服务日志... (按 Ctrl+C 退出)")
        utils.run_command(
            ["docker", "compose", "logs", "-f"], cwd=constants.BASE_DIR, stream_output=True
        )

    def check(self):
        """检查服务状态并打印客户端配置"""
        self._ensure_service_installed()
        self.console.print("\n--- 开始检查 AnyTLS 服务状态 ---")

        # rich Components
        from rich.table import Table

        table = Table(title="AnyTLS 服务状态一览")
        table.add_column("检查项", justify="right", style="cyan", no_wrap=True)
        table.add_column("状态", style="magenta")

        try:
            # 1. 获取域名
            domain = self._get_domain_from_config()
            table.add_row("管理域名", domain)

            # 2. 检查 Docker 容器状态
            container_name = f"anytls-inbound-{domain}"
            try:
                result = utils.run_command(
                    [
                        "docker",
                        "ps",
                        "--filter",
                        f"name={container_name}",
                        "--format",
                        "{{.Status}}",
                    ],
                    capture_output=True,
                    check=True,
                )
                status_output = result.stdout.strip()
                if "Up" in status_output:
                    container_status = f"[green]✔ 正在运行[/green] ({status_output})"
                elif status_output:
                    container_status = f"[yellow]❗ 已停止[/yellow] ({status_output})"
                else:
                    container_status = "[red]❌ 未找到容器[/red]"
            except (subprocess.CalledProcessError, FileNotFoundError):
                container_status = "[red]❌ 检查失败 (Docker 命令错误)[/red]"
            table.add_row("服务容器状态", container_status)

            # 3. 检查配置文件
            if constants.CONFIG_PATH.exists() and constants.DOCKER_COMPOSE_PATH.exists():
                config_status = "[green]✔ 正常[/green]"
            else:
                config_status = "[red]❌ 缺失[/red]"
            table.add_row("核心配置文件", config_status)

        except Exception as e:
            self.console.print(f"[red]检查过程中出现错误: {e}[/red]")
            return

        self.console.print(table)

        # 4. 基于实时服务端配置生成并打印客户端配置
        self.console.print("\n" + "=" * 20 + " 客户端配置信息[mihomo] " + "=" * 20)
        try:
            # 从 config.yaml 获取密码和端口
            with constants.CONFIG_PATH.open("r", encoding="utf8") as f:
                server_config = yaml.safe_load(f)

            listener_config = server_config["listeners"][0]
            port = listener_config["port"]
            # users 的 key 是随机的，所以我们直接取第一个 value
            password = list(listener_config["users"].values())[0]

            # 获取公网 IP
            public_ip = utils.get_public_ip()

            client_config_dict = {
                "name": domain,  # 'domain' from earlier in this method
                "type": "anytls",
                "server": public_ip,
                "port": port,
                "password": password,
                "client_fingerprint": "chrome",
                "udp": True,
                "idle_session_check_interval": 30,
                "idle_session_timeout": 30,
                "min_idle_session": 0,
                "sni": domain,
                "alpn": ["h2", "http/1.1"],
                "skip_cert_verify": False,
            }

            client_yaml = yaml.dump([client_config_dict], sort_keys=False)
            self.console.print(Syntax(client_yaml, "yaml"))
            self.console.print("=" * 58 + "\n")
            self.console.print(
                "详见客户端配置文档：https://wiki.metacubex.one/config/proxies/anytls/#anytls"
            )

        except FileNotFoundError:
            self.console.print("\n[yellow]配置文件未找到，无法生成客户端配置。[/yellow]")
            self.console.print(
                "[yellow]可能是通过旧版本安装的。可以尝试重新运行 'install' 命令以生成。[/yellow]"
            )
            self.console.print("=" * 58 + "\n")
        except Exception as e:
            self.console.print(f"\n[red]生成客户端配置时出错: {e}[/red]")
            self.console.print("=" * 58 + "\n")

        self.console.print("--- 检查完毕 ---\n")
