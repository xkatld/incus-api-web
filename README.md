v6.0: 添加 RESTful API 功能 (基于 Flask-RESTx) 和 API 文档。

安装教程看wiki

待加功能
~~~
安全强化：

强制修改初始密码：应在管理员首次登录后，强制要求修改默认密码。

在线SSH认证改进：移除对固定密码的依赖。可以改为在连接时弹出对话框让用户输入密码，或者实现更安全的密钥认证方式。

API密钥管理界面：在Web UI中增加一个专门的页面，用于查看、生成新的API密钥以及废除旧的密钥。

核心功能扩展：

容器快照管理：增加创建、还原、删除容器快照的界面和API。这是容器管理中非常重要的一项功能。

容器资源在线调整：允许用户在容器运行中或停止后，修改其CPU、内存、硬盘等资源限制。

Incus配置文件(Profile)管理：提供查看和为容器应用不同配置文件的功能。

反向代理SSL支持：既然已经集成了Nginx反向代理功能，可以进一步集成 Let's Encrypt，实现一键为绑定的域名申请和自动续签SSL证书。

监控与日志：

资源监控图表：为每个容器提供CPU、内存、网络和磁盘I/O的实时监控图表，帮助用户更直观地了解容器状态。

操作审计日志：记录所有重要的用户操作（如登录、创建/删除容器、修改规则等），方便追踪和审计。
~~~

## 演示图片 (Web UI)
![image](https://github.com/user-attachments/assets/d11e24e7-d469-43b0-9f3d-e1e8d2f7d0d1)
![image](https://github.com/user-attachments/assets/b9b72320-311b-4885-8583-323ae2896f4b)
![image](https://github.com/user-attachments/assets/22a12c0f-bf72-49f2-abf6-6602e04dce21)
![image](https://github.com/user-attachments/assets/6eb56a4d-aa48-49fe-8708-3eebaa801100)
![image](https://github.com/user-attachments/assets/2ee01dec-40ff-45ee-9bb3-3c4c21e208b7)
![image](https://github.com/user-attachments/assets/b9ddffba-58e1-4009-92fc-6ef9a4c03d3d)
