#!/bin/bash

# Incus 安装脚本 - 优化版本
# 支持 Debian 12 和 Ubuntu 24

# 显示彩色输出的函数
print_info() {
    echo -e "\e[1;34m[信息]\e[0m $1"
}

print_success() {
    echo -e "\e[1;32m[成功]\e[0m $1"
}

print_error() {
    echo -e "\e[1;31m[错误]\e[0m $1"
}

print_warning() {
    echo -e "\e[1;33m[警告]\e[0m $1"
}

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    print_error "请以 root 权限运行此脚本"
    echo "使用: sudo $0"
    exit 1
fi

# 检测系统版本
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
    CODENAME=$VERSION_CODENAME
    print_info "检测到系统: $OS $VERSION ($CODENAME)"
else
    print_error "无法检测操作系统版本"
    exit 1
fi

# 检查是否为支持的系统
if [[ "$OS" == "debian" && "$VERSION" == "12" ]] || [[ "$OS" == "ubuntu" && "$VERSION" == "24.04" ]]; then
    print_info "系统版本兼容，继续安装..."
else
    print_warning "此脚本针对 Debian 12 和 Ubuntu 24.04 优化，当前系统: $OS $VERSION"
    read -p "是否继续? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        print_info "安装已取消"
        exit 0
    fi
fi

# 1. 更新系统并安装必要工具
print_info "正在更新系统并安装必要工具..."
apt update || { print_error "系统更新失败"; exit 1; }
apt install curl wget sudo dos2unix ufw jq apt-transport-https ca-certificates gnupg lsb-release -y || { 
    print_error "安装必要工具失败"; 
    exit 1; 
}

print_info "配置防火墙..."
if systemctl is-active --quiet ufw; then
    print_info "关闭 UFW 防火墙..."
    ufw disable
else
    print_info "UFW 防火墙未运行"
fi

# 2. 处理 dnsmasq 问题
print_info "检查 dnsmasq 状态..."
if systemctl is-active --quiet dnsmasq; then
    print_info "正在停止并移除 dnsmasq..."
    systemctl stop dnsmasq
    systemctl disable dnsmasq
    apt remove dnsmasq -y
    apt purge dnsmasq -y
    apt autoremove -y
else
    print_info "dnsmasq 未运行，跳过移除步骤"
fi

# 3. 安装 Incus
print_info "正在安装 Incus..."

# 确保目录存在
mkdir -p /etc/apt/keyrings/

# 备份原来的源文件（如果存在）
if [ -f /etc/apt/sources.list.d/zabbly-incus-stable.sources ]; then
    mv /etc/apt/sources.list.d/zabbly-incus-stable.sources /etc/apt/sources.list.d/zabbly-incus-stable.sources.bak
    print_info "已备份原有的 Incus 源文件"
fi

# 下载密钥
print_info "添加 Zabbly 仓库密钥..."
curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc || {
    print_error "下载 Zabbly 仓库密钥失败"
    exit 1
}

# 创建源文件
print_info "配置 Incus 软件源..."
cat <<EOF > /etc/apt/sources.list.d/zabbly-incus-stable.sources
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: $CODENAME
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF

# 更新并安装 Incus
print_info "更新软件源并安装 Incus..."
apt-get update || {
    print_error "更新软件源失败"
    exit 1
}

apt-get install incus -y || {
    print_error "Incus 安装失败"
    exit 1
}

# 检查 Incus 是否安装成功
if ! command -v incus &> /dev/null; then
    print_error "Incus 安装失败，未找到 incus 命令"
    exit 1
fi

print_success "Incus 安装成功！"

# 初始化 Incus
print_info "正在初始化 Incus..."
incus admin init || {
    print_error "Incus 初始化失败"
    exit 1
}

print_success "Incus 安装和初始化完成！"

# 显示 Incus 版本和状态信息
print_info "Incus 版本信息:"
incus version

print_info "Incus 状态信息:"
incus admin list

# 提供一些使用建议
cat << EOF

$(print_success "Incus 已成功安装在您的系统上!")

以下是一些常用命令:
- 列出所有容器: incus list
- 创建容器: incus launch images:debian/12 my-container
- 进入容器: incus exec my-container -- bash
- 查看容器信息: incus info my-container
- 启动/停止容器: incus start/stop my-container

更多信息请访问: https://linuxcontainers.org/incus/docs/
EOF
