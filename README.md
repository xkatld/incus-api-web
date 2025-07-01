### **v7.0 (Refactored)**

此版本为项目的重构版本，采用了应用工厂（Application Factory）模式，优化了项目结构，增强了代码的模块化和可维护性。

-----

### **安装方法**

**环境要求**:

  * 操作系统: Debian 12
  * 必备软件: Python 3, Nginx

**安装步骤**:

1.  **安装核心依赖**

    ```bash
    apt update
    apt install python3 python3-pip git nginx -y
    ```

2.  **处理 Debian 12 Python 环境 (如果需要)**

    ```bash
    rm /usr/lib/python3.11/EXTERNALLY-MANAGED
    ```

3.  **使用脚本一键安装 Incus**

    ```bash
    curl -s https://raw.githubusercontent.com/xkatld/incus-api-web/refs/heads/main/scripts/install_incus.sh | sudo bash
    ```

4.  **克隆本项目代码**

    ```bash
    git clone https://github.com/xkatld/incus-api-web.git
    cd incus-api-web
    ```

5.  **安装 Python 库**

    ```bash
    pip install Flask Flask-SocketIO pexpect cryptography Flask-RESTx
    ```

-----

### **注意事项**

1.  **必须初始化数据库**
    首次运行前，必须执行初始化脚本以创建数据库和管理员账户。

    ```bash
    python3 scripts/init_db.py
    ```

      * **默认管理员用户名**: `admin`
      * **默认管理员密码**: `password`

2.  **Sudo 权限是必须的**
    本项目的核心功能，如自动管理 NAT 规则和 Nginx 反向代理，依赖于执行 `iptables` 和 `nginx` 命令。请务必确保运行 `app.py` 的用户拥有免密 `sudo` 权限。

3.  **运行项目**
    初始化完成后，使用以下命令启动 Web 服务：

    ```bash
    python3 app.py
    ```

      * 服务默认运行在 `0.0.0.0:5000`。
      * 请确保防火墙已放行 `5000` 端口以及您计划用于反向代理的公网端口（如 80, 443）。

4.  **API 文档地址**
    项目的 RESTful API 文档 (Swagger UI) 位于 `/api/doc/`。

      * 访问地址示例: `https://<服务器IP>:5000/api/doc/`
