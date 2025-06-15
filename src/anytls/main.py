"""AnyTLS 服务管理脚本 - 主入口"""

import typer

from anytls.cli import install, log, remove, start, stop, update, check
from anytls.logging_config import setup_logging

app = typer.Typer(
    name="anytls", help="mihomo-anytls-inbound manager", add_completion=False, no_args_is_help=False
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    mihomo-anytls-inbound manager
    """
    setup_logging()

    # 如果没有提供子命令，显示帮助信息
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())
        ctx.exit(0)


# 注册子命令
app.add_typer(install.app, name="install")
app.add_typer(remove.app, name="remove")
app.add_typer(log.app, name="log")
app.add_typer(start.app, name="start")
app.add_typer(stop.app, name="stop")
app.add_typer(update.app, name="update")
app.add_typer(check.app, name="check")

if __name__ == "__main__":
    app()
