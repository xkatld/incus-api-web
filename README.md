v7.0 (Refactored): 项目结构已使用应用工厂模式重构。

## 环境
Debian 12

## 安装
```bash
apt install python3 python3-pip -y
rm /usr/lib/python3.11/EXTERNALLY-MANAGED
curl -s [https://raw.githubusercontent.com/xkatld/incus-api-web/refs/heads/main/scripts/install_incus.sh](https://raw.githubusercontent.com/xkatld/incus-api-web/refs/heads/main/scripts/install_incus.sh) | sudo bash
git clone [https://github.com/xkatld/incus-api-web.git](https://github.com/xkatld/incus-api-web.git)
cd incus-api-web
pip install Flask Flask-SocketIO pexpect cryptography Flask-RESTx
````

## 初始化和运行

1.  **初始化数据库**

    ```bash
    python3 scripts/init_db.py
    ```

2.  **运行项目**

    ```bash
    python3 app.py
    ```

项目将运行在 `https://0.0.0.0:5000` (HTTPS) 或 `http://0.0.0.0:5000` (HTTP)。
API 文档: `https://<你的IP>:5000/api/doc/`
