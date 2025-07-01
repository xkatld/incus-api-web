## 版本

**v7.0 (Refactored)**: 此版本使用应用工厂模式重构了整个项目，提升了代码的模块化和可维护性。

## 安装方法

**环境要求**:

  * Debian 12
  * Python 3

**安装步骤**:

1.  **安装依赖包**

    ```bash
    apt update
    apt install python3 python3-pip git -y
    ```

2.  **移除 `EXTERNALLY-MANAGED` 限制 (适用于 Debian 12)**

    ```bash
    rm /usr/lib/python3.11/EXTERNALLY-MANAGED
    ```

3.  **安装 Incus**
    使用项目提供的脚本一键安装 Incus。

    ```bash
    curl -s https://raw.githubusercontent.com/xkatld/incus-api-web/refs/heads/main/scripts/install_incus.sh | sudo bash
    ```

4.  **克隆本项目**

    ```bash
    git clone https://github.com/xkatld/incus-api-web.git
    cd incus-api-web
    ```

5.  **安装 Python 库**

    ```bash
    pip install Flask Flask-SocketIO pexpect cryptography Flask-RESTx
    ```

## 注意事项

1.  **初始化数据库**:
    在首次运行项目之前，**必须**先初始化数据库。此操作将创建所需的数据库文件和表结构，并设置初始管理员账户。

    ```bash
    python3 scripts/init_db.py
    ```

      * 默认管理员用户名: `admin`
      * 默认管理员密码: `password`
      * 默认 API Secret Key: 随机生成
        您可以通过环境变量 `DEFAULT_ADMIN_USERNAME`, `DEFAULT_ADMIN_PASSWORD`, `DEFAULT_API_SECRET_KEY` 在初始化前修改这些默认值。

2.  **运行项目**:
    完成初始化后，直接运行 `app.py` 启动 Web 服务。

    ```bash
    python3 app.py
    ```

      * 服务将默认监听在 `0.0.0.0:5000`。
      * 项目会尝试自动生成自签名 SSL 证书并以 HTTPS 方式运行。如果失败，则会回退到 HTTP 模式。
      * 请确保防火墙已放行 `5000` 端口。

3.  **API 文档**:
    项目提供了完整的 RESTful API。API 文档 (Swagger UI) 位于 `/api/doc/` 路径下。

      * 例如: `https://<您的IP>:5000/api/doc/`

4.  **权限说明**:
    部分功能（如添加 NAT 规则、管理 Nginx 反向代理）需要 `sudo` 权限来执行 `iptables` 和 `nginx` 相关命令。请确保运行本应用的用户拥有必要的 `sudo` 权限，或者已配置好相应的免密 `sudo` 规则。
