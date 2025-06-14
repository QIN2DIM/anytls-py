"""Update 命令"""

import typer

from ..core.manager import AnyTLSManager

app = typer.Typer(help="更新服务镜像并重启。")


@app.callback(invoke_without_command=True)
def update():
    """
    更新服务镜像并重启。
    """
    manager = AnyTLSManager()
    manager.update()
