#!/bin/bash

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请以 root 权限运行此脚本"
  exit 1
fi

# 1. 更新系统并安装必要工具
echo "正在更新系统并安装必要工具..."
apt update
apt install curl wget sudo dos2unix ufw jq -y
ufw disable

# 2. 处理 dnsmasq 问题
echo "正在处理 dnsmasq..."
systemctl stop dnsmasq
systemctl disable dnsmasq
apt remove dnsmasq -y
apt purge dnsmasq -y
apt autoremove -y

# 3. 安装 Incus
echo "正在安装 Incus..."
mkdir -p /etc/apt/keyrings/
curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc
cat <<EOF > /etc/apt/sources.list.d/zabbly-incus-stable.sources
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: $(. /etc/os-release && echo ${VERSION_CODENAME})
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF

apt-get update
apt-get install incus -y

# 检查 Incus 是否安装成功
if ! command -v incus &> /dev/null; then
    echo "Incus 安装失败"
    exit 1
fi

echo "Incus 安装成功"

# 初始化 Incus
echo "正在初始化 Incus..."
incus admin init

echo "Incus 安装和初始化完成"
