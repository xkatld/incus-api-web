# Incus Web 管理器

一个基于 Flask 的 Web 应用，提供了一个友好的图形用户界面（Web UI）和 RESTful API，用于简化对 Incus 容器的管理。它使得创建、管理、监控容器以及配置网络（NAT、反向代理）变得更加直观和高效。

## ✨ 主要功能

  * **直观的 Web 界面**：通过 Web 浏览器轻松管理您的所有 Incus 容器。
  * **容器生命周期管理**：支持容器的创建、启动、停止、重启和删除。
  * **实时信息查看**：获取容器的实时状态、IP地址、资源使用情况等详细信息。
  * **在线 SSH 终端**：直接在浏览器中通过 SSH 连接到容器，无需本地终端工具。
  * **命令执行**：在容器内部远程执行Shell命令。
  * **快捷命令管理**：创建和管理常用的命令，方便一键执行。
  * **网络管理**：
      * **NAT 端口转发**：为容器添加基于 `iptables` 的端口转发规则。
      * **Nginx 反向代理**：(新功能) 为容器的 Web 服务一键添加基于 Nginx 的域名反向代理。
  * **RESTful API**：提供了一套完整的 API，并通过 Swagger UI 提供了交互式文档，方便进行自动化和二次开发。

## 📸 界面截图

## 🚀 开始使用

### 1\. 环境要求

在开始之前，请确保您的系统（推荐 **Debian 12**）已安装以下软件：

  * Python 3.11+ 和 Pip
  * Incus
  * Git
  * Nginx (用于反向代理功能)

### 2\. 安装步骤

#### (1) 安装 Python

```bash
sudo apt update
sudo apt install python3 python3-pip git -y
# Debian 12/Ubuntu 24.04+ 可能需要移除此限制
sudo rm /usr/lib/python3.11/EXTERNALLY-MANAGED
```

#### (2) 安装 Incus

我们提供了一个一键安装脚本来简化 Incus 的安装和初始化过程。

```bash
curl -s https://raw.githubusercontent.com/xkatld/incus-api-web/main/install_incus.sh | sudo bash
```

脚本会自动处理依赖、添加仓库并引导您完成 Incus 的初始化配置。

#### (3) 安装 Nginx

```bash
sudo apt install nginx -y
```

#### (4) 克隆并安装项目

```bash
git clone https://github.com/xkatld/incus-api-web.git
cd incus-api-web
pip install -r requirements.txt
```

### 3\. 配置

#### (1) 配置 Sudo 权限 (用于 Nginx)

为了让应用能够自动管理 Nginx 配置，需要为运行此应用的Linux用户授予特定的 `sudo`权限，且无需密码。

运行 `sudo visudo` 并将以下行添加到文件末尾 (请将 `your_user` 替换为您运行应用的实际用户名):

```
your_user ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
your_user ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
your_user ALL=(ALL) NOPASSWD: /bin/mv /tmp/nginx_temp_conf /etc/nginx/sites-available/*
your_user ALL=(ALL) NOPASSWD: /bin/ln -s /etc/nginx/sites-available/* /etc/nginx/sites-enabled/*
your_user ALL=(ALL) NOPASSWD: /bin/rm /etc/nginx/sites-available/*
your_user ALL=(ALL) NOPASSWD: /bin/rm /etc/nginx/sites-enabled/*
```

**安全警告**: 这允许应用在没有密码的情况下执行系统级操作，请确保您了解其安全 implications。

#### (2) 初始化数据库和管理员账户

在首次运行前，必须执行初始化脚本。它将创建数据库、表结构，并设置默认的管理员账户和API密钥。

```bash
python3 init_db.py
```

您可以在 `init_db.py` 文件中修改默认的管理员用户名和密码。脚本执行时，会打印出用于API访问的 **API密钥明文** 和 **SHA256哈希值**，请妥善保管。

### 4\. 运行项目

一切准备就绪后，运行以下命令启动Web服务：

```bash
python3 app.py
```

项目会尝试生成自签名SSL证书并在 **HTTPS** ([https://0.0.0.0:5000](https://0.0.0.0:5000)) 上运行。如果证书生成失败，它将回退到 **HTTP** 模式。

首次通过 HTTPS 访问时，您的浏览器会显示安全警告，您需要接受该警告才能继续。

## 📖 使用指南

### Web UI

访问 `http://<你的服务器IP>:5000` 或 `https://<你的服务器IP>:5000`，使用您在 `init_db.py` 中设置的管理员账户登录。之后，您可以通过图形界面直观地管理您的容器。

### REST API

项目启动后，可以通过访问 `https://<你的服务器IP>:5000/api/doc/` 来查看和测试所有可用的 API 端点 (Swagger UI)。

  * **API 基础路径**: `/api/v1`
  * **认证**: 所有 API 请求都必须在请求头 (Header) 中包含 `X-API-Key-Hash`。该值是您在运行 `init_db.py` 时生成的 API 密钥的 SHA256 哈希字符串。

**示例 (使用 curl 停止容器):**

```bash
# 假设 API Key 的 SHA256 哈希为 a2390e...
# 并且应用运行在 HTTPS 模式下
curl -k -X POST \
  -H "X-API-Key-Hash: a2390e4fd8c337a3ea4ceb0a71ca086e9b6426ebf5be1bc92dbb3cb0c1f72909" \
  -H "Content-Type: application/json" \
  -d '{"action": "stop"}' \
  https://127.0.0.1:5000/api/v1/containers/my-container/action
```

### 拉取推荐镜像

我们提供了一个预配置好SSH服务的 Debian 12 镜像，方便您快速开始。

```bash
# 镜像包含 root 用户，默认密码为 123456
bash -c "$(curl -sSL https://raw.githubusercontent.com/xkatld/incus-api-web/main/image/debian12.sh)"
```
