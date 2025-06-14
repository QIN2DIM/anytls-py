"""AnyTLS 服务管理脚本 - 主入口"""

import typer

from anytls.cli import install, log, remove, start, stop, update, check
from anytls.logging_config import setup_logging

app = typer.Typer(
    name="anytls",
    help="mihomo-anytls-inbound 服务管理脚本",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback()
def main():
    """
    mihomo-anytls-inbound 服务管理工具。
    """
    setup_logging()


# 注册子命令
app.add_typer(install.app, name="install")
app.add_typer(remove.app, name="remove")
app.add_typer(log.app, name="log")
app.add_typer(start.app, name="start")
app.add_typer(stop.app, name="stop")
app.add_typer(update.app, name="update")
app.add_typer(check.app, name="check")

if __name__ == "__main__":
    main()
