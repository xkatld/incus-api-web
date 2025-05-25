~~~
v5:重构代码文件和主题,优化资源限制,添加在线ssh功能,优化快捷命令功能,更新使用文档。
~~~

环境：Debian12

## 安装python3
~~~
apt install python3
apt install python3-pip
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
pip install flask flask-socketio pexpect
~~~

## 运行项目
~~~
python3 init_db.py
python3 app.py
~~~

## 拉取镜像
~~~
# Debian12 ssh root 123456
bash -c "$(curl -sSL https://raw.githubusercontent.com/xkatld/incus-api-web/refs/heads/main/image/debian12.sh)"
~~~

## API使用方法

**API 认证：**

所有以下列出的 API 端点都需要通过在请求 Header 中包含 `X-API-Key-Hash` 进行认证。`X-API-Key-Hash` 的值应为配置的 API 密钥（明文）的 SHA256 哈希（十六进制字符串）。API 密钥在运行 `init_db.py` 时设置或生成。

**API 端点表格：**

| 方法     | 端点                             | 描述                                       | 参数 (表单 `x-www-form-urlencoded` / 路径)                               | 成功响应 (Status) | 主要错误响应 (Status)        |
| :------- | :------------------------------- | :----------------------------------------- | :----------------------------------------------------------------------- | :---------------- | :--------------------------- |
| `POST`   | `/container/create`              | 创建新容器。                               | `name` (Form), `image` (Form) - 必填                                     | `200 OK`          | `400`, `401`, `409`, `500`   |
| `POST`   | `/container/{name}/action`       | 对容器执行 `start`, `stop`, `restart`, `delete` 操作。`delete` 会尝试删除关联规则。 | `name` (Path), `action` (Form: `start`, `stop`, `restart`, `delete`) - 必填 | `200 OK`          | `400`, `401`, `500`          |
| `POST`   | `/container/{name}/exec`         | 在容器内执行命令。                         | `name` (Path), `command` (Form) - 必填                                   | `200 OK`          | `400`, `401`, `500`          |
| `GET`    | `/container/{name}/info`         | 获取容器详细信息 (优先 Incus 实时，失败 fallback DB)。 | `name` (Path)                                                            | `200 OK`          | `401`, `404`                 |
| `POST`   | `/container/{name}/add_nat_rule` | 为运行中的容器添加 NAT 规则 (iptables + DB 记录)。 | `name` (Path), `host_port` (Form), `container_port` (Form), `protocol` (Form: `tcp`/`udp`) - 必填 | `200 OK` (含Warning可能) | `400`, `401`, `404`, `500`   |
| `GET`    | `/container/{name}/nat_rules`    | 列出容器在数据库中的 NAT 规则记录。        | `name` (Path)                                                            | `200 OK`          | `401`, `500`                 |
| `DELETE` | `/container/nat_rule/{rule_id}`  | 删除指定 ID 的 NAT 规则 (尝试 iptables + DB 记录)。 | `rule_id` (Path, integer)                                                | `200 OK` (含Warning可能) | `401`, `500`                 |

---

**示例：**
~~~
curl -X POST \
  -H "X-API-Key-Hash: a2390e4fd8c337a3ea4ceb0a71ca086e9b6426ebf5be1bc92dbb3cb0c1f72909" \
  -d "action=delete" \
  http://127.0.0.1:5000/container/debian12-ssh/action
~~~

## 演示图片
![image](https://github.com/user-attachments/assets/a38f22e6-b3a9-4904-a462-22f265fa90e7)
![image](https://github.com/user-attachments/assets/1f784245-d323-47f7-b7c5-4c7c738e845c)
![image](https://github.com/user-attachments/assets/1924aa49-0873-4161-aedd-c10861bea988)
