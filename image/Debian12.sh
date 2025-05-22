#!/bin/bash

# 镜像下载地址
IMAGE_URL="https://lsez.site/f/qqHM/debian12-ssh.tar.gz"
IMAGE_FILE="debian12-ssh.tar.gz"
IMAGE_ALIAS="debian12-ssh"

# 创建临时工作目录
WORKDIR=$(mktemp -d)
cd "$WORKDIR" || exit 1

echo "📥 正在下载镜像文件..."
curl -L -o "$IMAGE_FILE" "$IMAGE_URL"

# 检查下载是否成功
if [[ ! -f "$IMAGE_FILE" ]]; then
    echo "❌ 镜像下载失败！"
    exit 1
fi

echo "✅ 下载完成：$IMAGE_FILE"

# 尝试导入镜像
echo "📦 正在导入镜像到 Incus..."
incus image import "$IMAGE_FILE" --alias "$IMAGE_ALIAS"

# 检查是否导入成功
if [[ $? -eq 0 ]]; then
    echo "🎉 镜像导入成功，别名为：$IMAGE_ALIAS"
else
    echo "❌ 镜像导入失败，请检查文件格式或 Incus 状态。"
    exit 1
fi

# 可选：清理临时文件
cd ~
rm -rf "$WORKDIR"
