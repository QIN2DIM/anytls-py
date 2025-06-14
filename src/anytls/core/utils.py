"""核心工具函数"""

import logging
import secrets
import string
import subprocess
import sys
from pathlib import Path
from typing import Optional

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


def run_command(
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
            with subprocess.Popen(command, cwd=cwd, text=True) as process:
                process.wait()
                return subprocess.CompletedProcess(command, process.returncode)
        else:
            return subprocess.run(
                command, cwd=cwd, capture_output=capture_output, text=True, check=check
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


def get_public_ip() -> str:
    """获取本机的公网出口 IP"""
    logging.info("正在检测本机公网 IP...")
    ip_services = ["ip.sb", "ifconfig.me", "api.ipify.org", "icanhazip.com"]
    for service in ip_services:
        try:
            result = run_command(["curl", "-s", "--ipv4", service], capture_output=True, check=True)
            ip = result.stdout.strip()
            if ip:
                logging.info(f"成功获取公网 IP: {ip}")
                return ip
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    logging.error("无法自动获取公网 IP，请使用 --ip 参数手动指定。")
    raise RuntimeError("所有 IP 服务都无法访问。")


def generate_password(length: int = 16) -> str:
    """生成一个安全的随机密码"""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))
