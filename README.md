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
#Debian12 ssh root 123456
bash -c "$(curl -sSL https://raw.githubusercontent.com/xkatld/incus-api-web/refs/heads/main/image/debian12.sh)"
~~~

## API端点表格
| 功能 (Function)             | HTTP 方法 (HTTP Method) | URL 路径 (URL Path)                  | 请求体参数 (Request Body Parameters)           | 返回类型 (Return Type) | 示例 (Example)                                                                                   |
|-------------------------------|-------------------------|--------------------------------------|----------------------------------------------|--------------------|------------------------------------------------------------------------------------------------|
| 获取容器列表 (Web UI 使用)        | GET                     | `/`                                  | 无                                           | HTML               | (直接在浏览器中打开)                                                                               |
| 获取单个容器信息 (Web UI 使用)    | GET                     | `/container/<name>/info`             | 无                                           | JSON               | `curl http://localhost:5000/container/mycontainer/info`                                        |
| 创建容器 (Web UI 使用)          | POST                    | `/container/create`                  | `name=...&image=...`                         | JSON               | `curl -X POST -d "name=new-container&image=ubuntu/22.04" http://localhost:5000/container/create` |
| 执行容器动作 (Web UI 使用)      | POST                    | `/container/<name>/action`           | `action=start\|stop\|restart\|delete`        | JSON               | `curl -X POST -d "action=start" http://localhost:5000/container/mycontainer/action`              |
| 在容器内执行命令 (Web UI 使用)  | POST                    | `/container/<name>/exec`             | `command=...`                                | JSON               | `curl -X POST -d "command=ls%20-l%20/" http://localhost:5000/container/mycontainer/exec`       |
| 添加 NAT 规则 (Web UI 使用)     | POST                    | `/container/<name>/add_nat_rule`     | `host_port=...&container_port=...&protocol=tcp\|udp` | JSON               | `curl -X POST -d "host_port=8080&container_port=80&protocol=tcp" http://localhost:5000/container/mycontainer/add_nat_rule` |
| 列出容器的 NAT 规则 (Web UI 使用) | GET                     | `/container/<name>/nat_rules`        | 无                                           | JSON               | `curl http://localhost:5000/container/mycontainer/nat_rules`                                   |
| 删除 NAT 规则 (Web UI 使用)     | DELETE                  | `/container/nat_rule/<rule_id>`      | 无                                           | JSON               | `curl -X DELETE http://localhost:5000/container/nat_rule/123`                                  |

**关于 “获取容器列表” 的说明：**

如原文所述，`/` 端点直接返回 HTML。如果需要一个纯 JSON API 来获取容器列表，建议添加一个新的路由或修改现有 `/` 的行为以根据 `Accept` 请求头返回 JSON。当前的表格反映了现有实现。

## 演示图片
![image](https://github.com/user-attachments/assets/a38f22e6-b3a9-4904-a462-22f265fa90e7)
![image](https://github.com/user-attachments/assets/1f784245-d323-47f7-b7c5-4c7c738e845c)
![image](https://github.com/user-attachments/assets/1924aa49-0873-4161-aedd-c10861bea988)
