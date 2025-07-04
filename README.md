# Incus API Web - Incus 网页版管理器

**Incus API Web** 是一个功能全面的 Incus 容器管理平台，旨在通过直观的 Web界面和强大的 RESTful API 简化 Incus 容器的日常管理和自动化运维。无论您是希望通过图形化界面轻松管理少量容器，还是需要将容器管理集成到现有的自动化流程中，Incus API Web 都能提供可靠、高效的解决方案。

该平台基于 Flask 构建，并集成了 Socket.IO 以支持实时交互功能（如在线 SSH）。核心功能通过执行 `incus`、`iptables`、`nginx` 等系统命令实现，并通过 SQLite 数据库持久化存储容器元数据、网络规则等信息。

## ✨ 核心功能

  * **全面的容器生命周期管理**: 创建、启停、重启、删除、查看容器详情。
  * **强大的网络管理能力**: NAT 端口转发 (`iptables`) 和 Nginx 反向代理。
  * **自动 HTTPS**: 集成 Certbot，一键为反向代理的域名申请和续订 SSL 证书。
  * **高效的交互与集成**: 内置 Web Shell (在线 SSH) 和远程命令执行功能。
  * **完善的 API 接口**: 提供完整的 RESTful API，并内置 Swagger UI 在线文档。
  * **系统与环境**: 启动时环境自检，使用 SQLite 作为数据库，并提供一键安装脚本。

## 🚀 安装与部署

本节提供在 **Debian 12** 系统上进行部署的详细步骤。

### 1\. 系统环境准备 (APT 包)

首先，更新您的包列表，并安装项目所需的所有系统级依赖。

```bash
# 更新 apt 包索引
sudo apt update

# 安装核心依赖：Python、Pip、Git、Nginx 以及 Certbot
sudo apt install -y python3 python3-pip git nginx certbot python3-certbot-nginx
```

  * `python3`, `python3-pip`: 运行应用和安装 Python 库的基础。
  * `git`: 用于从 GitHub 克隆项目代码。
  * `nginx`: 用于实现反向代理功能。
  * `certbot`, `python3-certbot-nginx`: 用于自动申请和配置 SSL/TLS 证书。

### 2\. 安装并配置 Incus

我们提供了一个便捷的一键式脚本来安装和初始化 Incus。

```bash
curl -s https://raw.githubusercontent.com/xkatld/incus-api-web/main/install_incus.sh | sudo bash
```

该脚本会自动处理 Incus 的安装、初始化默认配置，并下载一个 Debian 12 镜像作为基础。

### 3\. 克隆并进入项目

```bash
git clone https://github.com/xkatld/incus-api-web.git
cd incus-api-web
```

### 4\. 安装 Python 库 (Pip 包)

在 Debian 12 上，直接使用 `pip` 可能受系统保护限制。您可以临时移除该限制来安装库。

```bash
# [可选] 仅当在 Debian 12 上遇到 'EXTERNALLY-MANAGED' 错误时执行
sudo rm /usr/lib/python3.11/EXTERNALLY-MANAGED

# 安装所有必需的 Python 库
pip install Flask Flask-SocketIO pexpect cryptography Flask-RESTx gunicorn
```

  * `Flask`, `Flask-RESTx`: Web 框架核心。
  * `Flask-SocketIO`: 提供 WebSockets 支持，用于实时通信 (如 Web Shell)。
  * `pexpect`: 用于与 Shell 命令进行交互，是 Web Shell 功能的关键。
  * `cryptography`: 提供加密功能，用于生成自签名证书等。
  * `gunicorn`: 一个生产级的 WSGI 服务器，用于部署 Flask 应用 (推荐)。

### 5\. 初始化数据库

**此步骤至关重要！** 它将创建数据库文件、表结构，并生成默认的管理员账户和 API 密钥。

```bash
python3 init_db.py
```

  * **默认管理员用户名**: `admin`
  * **默认管理员密码**: `password` (请务必在首次登录后修改！)
  * 脚本会输出用于 API 访问的 **`X-API-Key-Hash`**，请**妥善保存**此哈希值。

### 6\. 运行应用

**重要提示**: 应用需要执行 `incus`, `iptables`, `nginx`, `certbot` 等系统命令，因此必须以 `root` 权限或通过 `sudo` 运行。

#### 开发模式 (用于测试):

```bash
sudo python3 app.py
```

服务将在 `0.0.0.0:5000` 启动，并使用自签名证书。

#### 生产模式 (推荐):

建议使用 `gunicorn` 配合 `sudo` 运行。

```bash
sudo gunicorn --workers 4 --bind 0.0.0.0:5000 'app:app' --keyfile selfsigned.key --certfile selfsigned.crt
```

这会启动一个更稳定、性能更好的服务。

## 📝 API 使用

项目的 RESTful API 文档 (Swagger UI) 位于 `/api/doc/`。

  * **访问地址**: `https://<服务器IP>:5000/api/doc/`
  * **认证方式**: 在 HTTP 请求的 Header 中添加 `X-API-Key-Hash`，其值为 `init_db.py` 脚本生成的哈希值。