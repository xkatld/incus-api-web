v6.0: 添加 RESTful API 功能 (基于 Flask-RESTx) 和 API 文档。

环境：Debian12

## 安装python3
~~~
apt install python3 python3-pip -y
rm /usr/lib/python3.11/EXTERNALLY-MANAGED
~~~

## 安装incus
~~~
curl -s https://raw.githubusercontent.com/xkatld/incus-api-web/refs/heads/main/install_incus.sh | sudo bash
~~~

## git 项目
~~~
git clone https://github.com/xkatld/incus-api-web.git
cd incus-api-web
pip install flask flask-socketio pexpect cryptography flask-restx
~~~

## 运行项目
~~~
#先修改init_db中默认账号密码
python3 init_db.py
python3 app.py
~~~
项目现在将尝试生成自签名证书 (`cert.pem`, `key.pem`) 并在 HTTPS (https://0.0.0.0:5000) 上运行。如果生成失败或缺少 `cryptography` 库，它将回退到 HTTP。

**注意：** 首次通过 HTTPS 访问时，您的浏览器会显示安全警告，因为证书是自签名的。您需要接受该警告（通常在“高级”或“详细信息”选项中）才能继续访问。

## 拉取镜像
~~~
# Debian12 ssh root 123456
bash -c "$(curl -sSL https://raw.githubusercontent.com/xkatld/incus-api-web/refs/heads/main/image/debian12.sh)"
~~~

## REST API 使用方法

**API 认证：**

所有 API 端点都需要通过在请求 Header 中包含 `X-API-Key-Hash` 进行认证。`X-API-Key-Hash` 的值应为配置的 API 密钥（明文）的 SHA256 哈希（十六进制字符串）。API 密钥在运行 `init_db.py` 时设置或生成。

**API 文档：**

项目启动后，可以通过访问 `https://<你的服务器IP>:5000/api/doc/` (或 HTTP) 来查看交互式 API 文档 (Swagger UI)。文档中包含了所有可用的 API 端点、请求参数、响应模型和在线测试功能。

**API 基础路径:**

所有 API 端点的基础路径为 `/api/v1`。

**示例 (使用 curl):**
~~~
# 注意：如果启用了HTTPS，请使用 https:// 和可能的 -k (curl) 选项
# 假设 API Key 的 SHA256 哈希为 a2390e4fd8c337a3ea4ceb0a71ca086e9b6426ebf5be1bc92dbb3cb0c1f72909
# 停止名为 debian12-ssh 的容器

curl -X POST \
  -H "X-API-Key-Hash: a2390e4fd8c337a3ea4ceb0a71ca086e9b6426ebf5be1bc92dbb3cb0c1f72909" \
  -H "Content-Type: application/json" \
  -d '{"action": "stop"}' \
  https://127.0.0.1:5000/api/v1/containers/debian12-ssh/action -k
~~~

**主要端点 (详情请查看 API 文档):**

* `GET /api/v1/containers`: 获取容器列表。
* `POST /api/v1/containers`: 创建新容器。
* `GET /api/v1/containers/{name}`: 获取指定容器信息。
* `POST /api/v1/containers/{name}/action`: 对容器执行操作。
* `POST /api/v1/containers/{name}/exec`: 在容器内执行命令。
* `GET /api/v1/containers/{name}/nat`: 获取容器 NAT 规则。
* `POST /api/v1/containers/{name}/nat`: 添加容器 NAT 规则。
* `DELETE /api/v1/containers/nat/{rule_id}`: 删除 NAT 规则。
* `GET /api/v1/quick-commands`: 获取快捷命令。
* `POST /api/v1/quick-commands`: 添加快捷命令。
* `DELETE /api/v1/quick-commands/{command_id}`: 删除快捷命令。

---
## 演示图片 (Web UI)
![image](https://github.com/user-attachments/assets/d11e24e7-d469-43b0-9f3d-e1e8d2f7d0d1)
![image](https://github.com/user-attachments/assets/b9b72320-311b-4885-8583-323ae2896f4b)
![image](https://github.com/user-attachments/assets/22a12c0f-bf72-49f2-abf6-6602e04dce21)
![image](https://github.com/user-attachments/assets/6eb56a4d-aa48-49fe-8708-3eebaa801100)
![image](https://github.com/user-attachments/assets/2ee01dec-40ff-45ee-9bb3-3c4c21e208b7)
![image](https://github.com/user-attachments/assets/b9ddffba-58e1-4009-92fc-6ef9a4c03d3d)
