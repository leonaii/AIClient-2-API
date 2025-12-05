#!/bin/bash
# run-docker.sh
# 本地编译、打包并运行 Docker 容器

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 日志函数
log_info() { echo -e "${GREEN}$1${NC}"; }
log_warn() { echo -e "${YELLOW}$1${NC}"; }
log_error() { echo -e "${RED}$1${NC}"; }
log_cyan() { echo -e "${CYAN}$1${NC}"; }

# 错误处理函数
error_exit() {
    log_error "错误: $1"
    exit 1
}

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || error_exit "无法切换到脚本目录"

log_info "正在准备 Docker 环境..."
echo ""

# ========== 前置检查 ==========
log_info "检查前置依赖..."

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    error_exit "未找到 Docker，请先安装 Docker"
fi

# 检查 Docker 是否运行
if ! docker info &> /dev/null; then
    error_exit "Docker 未运行，请先启动 Docker 服务"
fi

log_cyan "Docker 环境正常"
echo ""

# ========== 配置文件处理 ==========
log_info "检查配置文件..."

CONFIG_JSON_PATH="$SCRIPT_DIR/config.json"
CONFIG_EXAMPLE_PATH="$SCRIPT_DIR/config.json.example"

if [ ! -f "$CONFIG_EXAMPLE_PATH" ]; then
    error_exit "未找到 config.json.example 文件！"
fi

# 检查是否安装了 jq（用于 JSON 处理）
if command -v jq &> /dev/null; then
    HAS_JQ=true
else
    HAS_JQ=false
    log_warn "未安装 jq，将使用简单的配置文件处理方式"
fi

if [ -f "$CONFIG_JSON_PATH" ]; then
    log_cyan "发现现有配置文件"
    if [ "$HAS_JQ" = true ]; then
        log_cyan "正在合并新字段..."
        # 使用 jq 合并配置：保留现有值，添加 example 中的新字段
        MERGED=$(jq -s '.[0] * .[1] | .[1] * .' "$CONFIG_EXAMPLE_PATH" "$CONFIG_JSON_PATH" 2>/dev/null) || {
            log_warn "配置合并失败，保留现有配置"
            MERGED=""
        }
        if [ -n "$MERGED" ]; then
            echo "$MERGED" > "$CONFIG_JSON_PATH"
            log_info "配置文件已更新"
        fi
    else
        log_cyan "保留现有配置文件"
    fi
else
    log_warn "未找到 config.json，从 config.json.example 创建..."
    cp "$CONFIG_EXAMPLE_PATH" "$CONFIG_JSON_PATH" || error_exit "无法创建配置文件"
    log_info "已创建 config.json，请根据需要修改配置"
fi
echo ""

# ========== 凭证路径设置 ==========
AWS_SSO_CACHE_PATH="/home/aiclient/cache/.aws/sso/cache"
GEMINI_CONFIG_PATH="/home/aiclient/cache/.gemini/oauth_creds.json"

# 检查 AWS SSO 缓存目录
if [ -d "$AWS_SSO_CACHE_PATH" ]; then
    log_cyan "发现 AWS SSO 缓存目录: $AWS_SSO_CACHE_PATH"
    AWS_MOUNT="-v $AWS_SSO_CACHE_PATH:/root/.aws/sso/cache"
else
    log_warn "未找到 AWS SSO 缓存目录: $AWS_SSO_CACHE_PATH"
    log_warn "注意：Docker 容器可能无法访问 AWS 凭证"
    AWS_MOUNT=""
fi

# 检查 Gemini 配置文件
if [ -f "$GEMINI_CONFIG_PATH" ]; then
    log_cyan "发现 Gemini 配置文件: $GEMINI_CONFIG_PATH"
    GEMINI_MOUNT="-v $GEMINI_CONFIG_PATH:/root/.gemini/oauth_creds.json"
else
    log_warn "未找到 Gemini 配置文件: $GEMINI_CONFIG_PATH"
    log_warn "注意：Docker 容器可能无法访问 Gemini API"
    GEMINI_MOUNT=""
fi
echo ""

# ========== 清理旧容器 ==========
log_info "检查是否存在旧容器..."

CONTAINER_ID=$(docker ps -a -q -f name=aiclient2api 2>/dev/null)
if [ -n "$CONTAINER_ID" ]; then
    log_warn "发现已存在的容器 'aiclient2api'，正在停止并删除..."
    docker stop aiclient2api 2>/dev/null || true
    docker rm aiclient2api 2>/dev/null || true
    log_info "旧容器已清理"
else
    log_cyan "未发现旧容器"
fi
echo ""

# ========== 本地编译构建镜像 ==========
log_info "检查 Docker 镜像..."

# 询问是否强制重新构建
FORCE_BUILD=false
if docker images -q aiclient2api 2>/dev/null | grep -q .; then
    log_cyan "发现已存在的 Docker 镜像 'aiclient2api'"
    read -p "是否强制重新构建镜像？(y/n，默认n): " REBUILD_CHOICE
    if [ "$REBUILD_CHOICE" = "y" ] || [ "$REBUILD_CHOICE" = "Y" ]; then
        FORCE_BUILD=true
        log_warn "将删除旧镜像并重新构建..."
        docker rmi aiclient2api 2>/dev/null || log_warn "删除旧镜像失败，继续构建..."
    fi
else
    FORCE_BUILD=true
fi

if [ "$FORCE_BUILD" = true ]; then
    log_info "开始本地编译构建 Docker 镜像..."
    log_cyan "执行: docker build -t aiclient2api ."
    echo ""
    
    # 构建镜像，带进度显示
    if ! docker build -t aiclient2api . ; then
        error_exit "Docker 镜像构建失败！请检查 Dockerfile 和源代码"
    fi
    
    log_info "Docker 镜像构建成功！"
fi
echo ""

# ========== 构建运行命令 ==========
log_info "准备 Docker 运行命令..."

# 构建挂载参数
VOLUME_MOUNTS=""
[ -n "$AWS_MOUNT" ] && VOLUME_MOUNTS="$VOLUME_MOUNTS $AWS_MOUNT"
[ -n "$GEMINI_MOUNT" ] && VOLUME_MOUNTS="$VOLUME_MOUNTS $GEMINI_MOUNT"

# 挂载 config.json
if [ -f "$CONFIG_JSON_PATH" ]; then
    VOLUME_MOUNTS="$VOLUME_MOUNTS -v $CONFIG_JSON_PATH:/app/config.json"
    log_cyan "将挂载 config.json 到容器"
fi

# 构建完整命令
DOCKER_CMD="docker run -d \
  --restart=always \
  --privileged=true \
  -p 3000:3000 \
  $VOLUME_MOUNTS \
  --name aiclient2api \
  aiclient2api"

# 显示命令
echo ""
log_info "生成的 Docker 命令:"
echo "$DOCKER_CMD"
echo ""

# 保存命令到文件
echo "$DOCKER_CMD" > docker-run-command.txt
log_info "命令已保存到 docker-run-command.txt"
echo ""

# ========== 执行容器 ==========
read -p "是否要立即执行该 Docker 命令？(y/n，默认y): " EXECUTE_CMD
EXECUTE_CMD=${EXECUTE_CMD:-y}

if [ "$EXECUTE_CMD" = "y" ] || [ "$EXECUTE_CMD" = "Y" ]; then
    log_info "正在启动 Docker 容器..."
    
    if eval "$DOCKER_CMD"; then
        echo ""
        log_info "Docker 容器已成功启动！"
        log_cyan "您可以通过 http://localhost:3000 访问 API 服务"
        echo ""
        
        # 显示容器状态
        log_info "容器状态:"
        docker ps -f name=aiclient2api --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        
        # 等待几秒后检查容器是否正常运行
        sleep 3
        if docker ps -q -f name=aiclient2api -f status=running | grep -q .; then
            log_info "容器运行正常"
        else
            log_warn "容器可能启动失败，查看日志:"
            docker logs aiclient2api 2>&1 | tail -20
        fi
    else
        error_exit "Docker 容器启动失败！"
    fi
else
    log_warn "命令未执行，您可以手动从 docker-run-command.txt 复制并执行命令"
fi

echo ""
log_info "脚本执行完成"
