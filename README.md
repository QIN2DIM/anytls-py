# anytls-py cli
借助 `mihomo` 构建 AnyTLS 容器服务，具备如下特性：

1. 可配置 SNI 域名
2. 通过 Docker Compose 容器服务管理 AnyTLS server，自启+持久化运行
3. 遵循最佳实践的轻量化部署

## 速通指南

### Installation

> [uv installation](https://docs.astral.sh/uv/getting-started/installation/) 

（可选）确保环境中存在 uv：

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

使用 uv 以 tool 的方式安装 `anytls-py`:

```bash
uv tool install anytls-py
```
### Startup

一键安装指令：

```bash
uv run anytls-py install -d [DOMAIN]
```
| 必选参数         | 简介       |
| ---------------- | ---------- |
| `--domain`, `-d` | 绑定的域名 |

| 可选参数           | 简介                                         |
| ------------------ | -------------------------------------------- |
| `--password`, `-p` | 手动指定连接密码 (可选，默认随机生成)        |
| `--ip`             | 手动指定服务器公网 IPv4 (可选，默认自动检测) |

## 下一步

查看所有管理指令：

```bash
uv run anytls --help
```

![image-20250615082554515](assets/image-20250615082554515.png)