~~~
v3.5:实现基础安全功能,管理员用户和apiHash,重写安装文档。
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
pip install flask
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

**API 认证：**

所有以下列出的 API 端点都需要通过在请求 Header 中包含 `X-API-Hash` 进行认证。`X-API-Hash` 的值应为配置的 `API_SECRET_KEY` 的 SHA256 哈希（十六进制字符串）。

**API 端点表格：**

| 方法   | 端点                             | 描述                                       | 参数 (表单 `x-www-form-urlencoded` / 路径)                               | 成功响应 (Status) | 主要错误响应 (Status)        |
| :----- | :------------------------------- | :----------------------------------------- | :----------------------------------------------------------------------- | :---------------- | :--------------------------- |
| `POST` | `/container/create`              | 创建新容器。                               | `name` (Form), `image` (Form) - 必填                                     | `200 OK`          | `400`, `401`, `409`, `500`   |
| `POST` | `/container/{name}/action`       | 对容器执行 `start`, `stop`, `restart`, `delete` 操作。`delete` 会尝试删除关联规则。 | `name` (Path), `action` (Form: `start`, `stop`, `restart`, `delete`) - 必填 | `200 OK`          | `400`, `401`, `500`          |
| `POST` | `/container/{name}/exec`         | 在容器内执行命令。                         | `name` (Path), `command` (Form) - 必填                                   | `200 OK`          | `400`, `401`, `500`          |
| `GET`  | `/container/{name}/info`         | 获取容器详细信息 (优先 Incus 实时，失败 fallback DB)。 | `name` (Path)                                                            | `200 OK`          | `401`, `404`                 |
| `POST` | `/container/{name}/add_nat_rule` | 为运行中的容器添加 NAT 规则 (iptables + DB 记录)。 | `name` (Path), `host_port` (Form), `container_port` (Form), `protocol` (Form: `tcp`/`udp`) - 必填 | `200 OK` (含Warning可能) | `400`, `401`, `404`, `500`   |
| `GET`  | `/container/{name}/nat_rules`    | 列出容器在数据库中的 NAT 规则记录。        | `name` (Path)                                                            | `200 OK`          | `401`, `500`                 |
| `DELETE` | `/container/nat_rule/{rule_id}`  | 删除指定 ID 的 NAT 规则 (尝试 iptables + DB 记录)。 | `rule_id` (Path, integer)                                              | `200 OK` (含Warning可能) | `401`, `500`                 |

---

**注意:**

*   表格中的 `{name}` 和 `{rule_id}` 表示路径参数，调用时需要替换为实际值。
*   `成功响应 (Status)` 仅表示 HTTP 状态码，具体结果请检查 JSON 响应体中的 `"status"` 字段 (`"success"`, `"error"`, `"warning"`, `"NotFound"`) 及 `"message"`。
*   `主要错误响应 (Status)` 列出了代码中明确返回的不同错误 HTTP 状态码。
*   参数中的 `(Form)` 表示该参数应通过 `application/x-www-form-urlencoded` 形式提交。
*   此文档严格基于现有代码生成，未进行任何逻辑修改。

## 演示图片
![image](https://github.com/user-attachments/assets/a38f22e6-b3a9-4904-a462-22f265fa90e7)
![image](https://github.com/user-attachments/assets/1f784245-d323-47f7-b7c5-4c7c738e845c)
![image](https://github.com/user-attachments/assets/1924aa49-0873-4161-aedd-c10861bea988)
