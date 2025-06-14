"""
mihomo-anytls-inbound 服务管理脚本

本脚本用于自动化安装、配置、管理和卸载基于 Docker 的 mihomo anytls 入站代理。
"""

import argparse
import logging
import os
import secrets
import shutil
import string
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional, Sequence

# --- 全局常量配置 ---
BASE_DIR = Path("/home/anytls")
DOCKER_COMPOSE_PATH = BASE_DIR / "docker-compose.yaml"
CONFIG_PATH = BASE_DIR / "config.yaml"
SCRIPT_PATH = Path(__file__).resolve()
ALIAS_NAME = "anytls"

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)

# --- YAML 模板 ---

DOCKER_COMPOSE_TPL = """
services:
  anytls-inbound:
    image: metacubex/mihomo:latest
    container_name: anytls-inbound-{domain}
    restart: always
    ports:
      - "8443:8443"
    working_dir: /app/proxy-inbound/
    volumes:
      - /etc/letsencrypt/:/etc/letsencrypt/
      - ./config.yaml:/app/proxy-inbound/config.yaml
    command: -f config.yaml -d /
"""

CONFIG_TPL = """
listeners:
- name: anytls-in-{uuid4}
  type: anytls
  port: 8443
  listen: 0.0.0.0
  users:
    # 推荐使用更复杂的用户名以增加安全性
    user_{uuid_short}: {password}
  certificate: /etc/letsencrypt/live/{domain}/fullchain.pem
  private-key: /etc/letsencrypt/live/{domain}/privkey.pem
"""

CLIENT_CONFIG_TPL = """
- name: {domain}
  type: anytls
  server: {ip}
  port: 8443
  password: {password}
  client-fingerprint: chrome
  udp: true
  idle-session-check-interval: 30
  idle-session-timeout: 30
  min-idle-session: 0
  sni: {domain}
  alpn:
    - h2
    - http/1.1
  skip-cert-verify: false
"""

DOCKER_INSTALL_SCRIPT = """
echo ">>> 正在更新软件包索引并安装依赖..."
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release

echo ">>> 正在添加 Docker GPG 密钥..."
mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo ">>> 正在设置 Docker APT 仓库..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

echo ">>> 再次更新软件包索引..."
apt-get update

echo ">>> 正在安装 Docker Engine, CLI, Containerd 和 Docker Compose 插件..."
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo ">>> 正在启动并启用 Docker 服务..."
systemctl start docker
systemctl enable docker

echo ">>> Docker 和 Docker Compose 安装完成。"
"""


class AnyTLSManager:
    """封装 AnyTLS 服务管理的所有逻辑"""

    def __init__(self):
        """初始化管理器"""
        if os.geteuid() != 0:
            logging.error("权限不足：请以 root 用户身份运行此脚本。")
            sys.exit(1)

    def _run_command(
            self,
            command: list[str],
            cwd: Optional[Path] = None,
            capture_output: bool = False,
            check: bool = True,
            stream_output: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        统一的命令执行函数

        Args:
            command: 命令列表.
            cwd: 执行命令的工作目录.
            capture_output: 是否捕获 stdout 和 stderr.
            check: 如果命令返回非零退出码，是否抛出 CalledProcessError.
            stream_output: 是否实时打印输出（用于 logs -f）.

        Returns:
            CompletedProcess 对象.
        """
        logging.info(f"执行命令: {' '.join(command)}")
        try:
            if stream_output:
                # 对于需要交互或持续输出的命令 (如 docker compose logs -f)
                process = subprocess.Popen(command, cwd=cwd, text=True)
                process.wait()
                return subprocess.CompletedProcess(command, process.returncode)
            else:
                return subprocess.run(
                    command,
                    cwd=cwd,
                    capture_output=capture_output,
                    text=True,
                    check=check,
                )
        except FileNotFoundError:
            logging.error(f"命令未找到: {command[0]}。请确保它已安装并在您的 PATH 中。")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            logging.error(f"命令执行失败，返回码: {e.returncode}")
            if e.stdout:
                logging.error(f"STDOUT:\n{e.stdout}")
            if e.stderr:
                logging.error(f"STDERR:\n{e.stderr}")
            sys.exit(1)

    def _check_dependencies(self):
        """检查 Docker 和 Docker Compose 是否安装"""
        logging.info("正在检查 Docker 和 Docker Compose 环境...")
        try:
            self._run_command(["docker", "--version"], capture_output=True)
            self._run_command(["docker", "compose", "version"], capture_output=True)
            logging.info("Docker 和 Docker Compose 已安装。")
        except (FileNotFoundError, subprocess.CalledProcessError):
            logging.warning("未检测到 Docker 或 Docker Compose。")
            choice = input("是否需要自动安装？ (y/n): ").lower()
            if choice == 'y':
                logging.info("开始自动安装 Docker 和 Docker Compose...")
                # 使用 /bin/bash -c 来执行多行脚本
                self._run_command(["/bin/bash", "-c", DOCKER_INSTALL_SCRIPT])
                logging.info("请重新运行脚本以应用更改。")
                # 提示用户可能需要重新登录以使 docker 组生效
                logging.info("注意：您可能需要重新登录或运行 `newgrp docker` 以便非 root 用户无需 sudo 即可运行 docker。")
                sys.exit(0)
            else:
                logging.error("安装被用户取消。脚本无法继续。")
                sys.exit(1)

    def _get_public_ip(self) -> str:
        """获取本机的公网出口 IP"""
        logging.info("正在检测本机公网 IP...")
        try:
            # 尝试多个服务以提高成功率
            ip_services = ["ip.sb", "ifconfig.me", "api.ipify.org", "icanhazip.com"]
            for service in ip_services:
                try:
                    result = self._run_command(
                        ["curl", "-s", "--ipv4", service], capture_output=True, check=True
                    )
                    ip = result.stdout.strip()
                    if ip:
                        logging.info(f"成功获取公网 IP: {ip}")
                        return ip
                except subprocess.CalledProcessError:
                    continue
            raise RuntimeError("所有 IP 服务都无法访问。")
        except (RuntimeError, FileNotFoundError) as e:
            logging.error(f"无法自动获取公网 IP: {e}")
            logging.error("请使用 --ip 参数手动指定 IP 地址。")
            sys.exit(1)

    def _generate_password(self, length: int = 16) -> str:
        """生成一个安全的随机密码"""
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _get_domain_from_config(self) -> str:
        """从 docker-compose.yaml 文件中解析出域名"""
        if not DOCKER_COMPOSE_PATH.exists():
            logging.error(f"配置文件 {DOCKER_COMPOSE_PATH} 不存在。您是否已经安装了服务？")
            sys.exit(1)

        content = DOCKER_COMPOSE_PATH.read_text()
        try:
            # 简单但有效的解析方式，避免引入 PyYAML
            line = next(l for l in content.splitlines() if "container_name" in l)
            domain = line.split("anytls-inbound-")[-1].strip()
            if not domain:
                raise ValueError
            return domain
        except (StopIteration, ValueError):
            logging.error(f"无法从 {DOCKER_COMPOSE_PATH} 中解析出域名。配置文件可能已损坏。")
            sys.exit(1)

    def _setup_shell_alias(self):
        """将脚本别名写入 shell 配置文件"""
        logging.info("正在为您设置 `anytls` 快捷指令...")

        # 检测 shell 类型
        shell_path = os.environ.get("SHELL", "")
        if "zsh" in shell_path:
            config_file = Path.home() / ".zshrc"
        else:
            config_file = Path.home() / ".bashrc"

        alias_command = f"alias {ALIAS_NAME}='{sys.executable} {SCRIPT_PATH}'"

        if not config_file.exists():
            config_file.touch()

        # 检查别名是否已存在
        if alias_command in config_file.read_text():
            logging.info(f"`{ALIAS_NAME}` 快捷指令已经存在。")
            return

        with config_file.open("a") as f:
            f.write(f"\n# mihomo-anytls-inbound 管理脚本别名\n")
            f.write(f"{alias_command}\n")

        logging.info(f"成功将 `{ALIAS_NAME}` 快捷指令写入到 {config_file}")
        logging.warning("请运行 `source {config_file}` 或重新打开终端以使快捷指令生效。")

    def install(self, domain: str, password: Optional[str], ip: Optional[str]):
        """安装并启动 AnyTLS 服务"""
        logging.info(f"--- 开始安装 AnyTLS 服务 (域名: {domain}) ---")
        if BASE_DIR.exists():
            logging.warning(f"工作目录 {BASE_DIR} 已存在。继续操作将可能覆盖现有配置。")
            if input("是否继续？ (y/n): ").lower() != 'y':
                logging.info("安装已取消。")
                return

        self._check_dependencies()

        # 1. 获取 IP 和密码
        public_ip = ip or self._get_public_ip()
        service_password = password or self._generate_password()

        # 2. 申请证书
        logging.info(f"正在为域名 {domain} 申请 Let's Encrypt 证书...")
        self._run_command([
            "certbot", "certonly", "--standalone",
            "--register-unsafely-without-email", "-d", domain, "--agree-tos"
        ])
        logging.info("证书申请成功。")

        # 3. 构建工作目录和配置文件
        logging.info(f"正在创建工作目录: {BASE_DIR}")
        BASE_DIR.mkdir(exist_ok=True)

        config_content = CONFIG_TPL.format(
            uuid4=uuid.uuid4(),
            uuid_short=str(uuid.uuid4())[:8],
            password=service_password,
            domain=domain,
        )
        CONFIG_PATH.write_text(config_content)
        logging.info(f"已生成配置文件: {CONFIG_PATH}")

        docker_compose_content = DOCKER_COMPOSE_TPL.format(domain=domain)
        DOCKER_COMPOSE_PATH.write_text(docker_compose_content)
        logging.info(f"已生成 Docker Compose 文件: {DOCKER_COMPOSE_PATH}")

        # 4. 启动服务
        logging.info("正在拉取最新的 Docker 镜像...")
        self._run_command(["docker", "compose", "pull"], cwd=BASE_DIR)

        logging.info("正在启动服务...")
        self._run_command(["docker", "compose", "down"], cwd=BASE_DIR, check=False)  # 确保旧容器已停止
        self._run_command(["docker", "compose", "up", "-d"], cwd=BASE_DIR)

        logging.info("--- AnyTLS 服务安装并启动成功！ ---")

        # 5. 打印客户端配置
        client_config = CLIENT_CONFIG_TPL.format(
            domain=domain, ip=public_ip, password=service_password
        )
        print("\n" + "=" * 20 + " 客户端配置信息 " + "=" * 20)
        print(client_config.strip())
        print("=" * 58 + "\n")

        # 6. 设置快捷指令
        self._setup_shell_alias()

    def remove(self):
        """停止并移除 AnyTLS 服务和相关文件"""
        logging.info("--- 开始卸载 AnyTLS 服务 ---")
        if not BASE_DIR.exists():
            logging.warning(f"工作目录 {BASE_DIR} 不存在，可能服务未安装或已被移除。")
            return

        domain = self._get_domain_from_config()
        logging.info(f"检测到正在管理的域名为: {domain}")

        confirm = input(
            f"此操作将停止服务、删除证书和所有配置文件 ({BASE_DIR})。\n确定要卸载 {domain} 吗？ (y/n): ").lower()
        if confirm != 'y':
            logging.info("卸载已取消。")
            return

        # 1. 下线容器
        logging.info("正在停止并移除 Docker 容器...")
        self._run_command(["docker", "compose", "down", "--volumes"], cwd=BASE_DIR, check=False)

        # 2. 删除工作目录
        logging.info(f"正在删除工作目录: {BASE_DIR}")
        shutil.rmtree(BASE_DIR)

        # 3. 删除证书
        logging.info(f"正在删除 {domain} 的 Let's Encrypt 证书...")
        self._run_command(["certbot", "delete", "--cert-name", domain, "--non-interactive"], check=False)

        logging.info("--- AnyTLS 服务已成功卸载。 ---")

    def _ensure_service_installed(self):
        """确保服务已安装，否则退出"""
        if not DOCKER_COMPOSE_PATH.is_file():
            logging.error(f"Docker Compose 配置文件 ({DOCKER_COMPOSE_PATH}) 未找到。")
            logging.error("请先运行 'install' 命令来安装服务。")
            sys.exit(1)

    def start(self):
        """启动服务"""
        self._ensure_service_installed()
        logging.info("正在启动 AnyTLS 服务...")
        # down + up -d 确保配置更新和服务重启
        self._run_command(["docker", "compose", "down"], cwd=BASE_DIR, check=False)
        self._run_command(["docker", "compose", "up", "-d"], cwd=BASE_DIR)
        logging.info("AnyTLS 服务已启动。")

    def stop(self):
        """停止服务"""
        self._ensure_service_installed()
        logging.info("正在停止 AnyTLS 服务...")
        self._run_command(["docker", "compose", "down"], cwd=BASE_DIR)
        logging.info("AnyTLS 服务已停止。")

    def update(self):
        """更新服务（拉取新镜像并重启）"""
        self._ensure_service_installed()
        logging.info("--- 开始更新 AnyTLS 服务 ---")
        logging.info("正在拉取最新的 Docker 镜像...")
        self._run_command(["docker", "compose", "pull"], cwd=BASE_DIR)
        logging.info("正在使用新镜像重启服务...")
        self._run_command(["docker", "compose", "down"], cwd=BASE_DIR, check=False)
        self._run_command(["docker", "compose", "up", "-d"], cwd=BASE_DIR)
        logging.info("--- AnyTLS 服务更新完成。 ---")

    def log(self):
        """查看服务日志"""
        self._ensure_service_installed()
        logging.info("正在显示服务日志... (按 Ctrl+C 退出)")
        # 使用 stream_output 来实时显示日志
        self._run_command(["docker", "compose", "logs", "-f"], cwd=BASE_DIR, stream_output=True)


def main(argv: Optional[Sequence[str]] = None):
    """脚本主入口和命令行参数解析"""
    parser = argparse.ArgumentParser(description="mihomo-anytls-inbound 服务管理脚本")
    subparsers = parser.add_subparsers(dest="command", required=True, help="可用的指令")

    # install 指令
    parser_install = subparsers.add_parser("install", help="安装并启动 AnyTLS 服务")
    parser_install.add_argument("-d", "--domain", type=str, required=True, help="绑定的域名")
    parser_install.add_argument("-p", "--password", type=str, help="手动指定连接密码 (可选，默认随机生成)")
    parser_install.add_argument("--ip", type=str, help="手动指定服务器公网 IP (可选，默认自动检测)")

    # 其他指令
    subparsers.add_parser("remove", help="停止并移除 AnyTLS 服务")
    subparsers.add_parser("log", help="查看实时日志")
    subparsers.add_parser("start", help="启动服务")
    subparsers.add_parser("stop", help="停止服务")
    subparsers.add_parser("update", help="更新服务镜像并重启")

    args = parser.parse_args(argv)
    manager = AnyTLSManager()

    match args.command:
        case "install":
            manager.install(domain=args.domain, password=args.password, ip=args.ip)
        case "remove":
            manager.remove()
        case "log":
            manager.log()
        case "start":
            manager.start()
        case "stop":
            manager.stop()
        case "update":
            manager.update()
        case _:
            parser.print_help()


if __name__ == "__main__":
    main()
