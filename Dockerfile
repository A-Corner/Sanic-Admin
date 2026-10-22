# ============================================================================
# Sanic-Admin 应用镜像
#
# 镜像内不含任何密钥：所有密钥通过运行时环境变量（.env / compose env_file）注入。
# 容器内固定 SANIC_ENV=production，production 对缺失密钥是 fail-closed 的，
# 因此"能起来"就等价于"密钥确实由 .env 提供"。
#
# 构建：docker compose build
# 运行：docker compose up -d
# ============================================================================

FROM python:3.12-slim

# 镜像元信息
LABEL org.opencontainers.image.title="Sanic-Admin" \
      org.opencontainers.image.description="Sanic + Tortoise ORM + Redis + JWT 后台管理系统" \
      org.opencontainers.image.source="https://github.com/A-Corner/Sanic-Admin"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SANIC_ENV=production \
    HOST=0.0.0.0 \
    PORT=22222 \
    PYTHONPATH=/app

WORKDIR /app

# 系统依赖：
#   libmagic1  —— python-magic 运行时依赖，缺失会导致 app/api/resources/upload.py
#                 在 import magic 时报 "libmagic not found"；
#   curl       —— 健康检查用；
#   tzdata     —— 让容器内时区可配置（Asia/Shanghai）。
# build-essential 与 libffi-dev 只用于编译期，最终镜像不含编译器。
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libmagic1 \
        curl \
        tzdata \
        build-essential \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 先装依赖再拷代码：代码变更不会让依赖层缓存失效。
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove build-essential \
    && rm -rf /var/lib/apt/lists/*

# 应用代码
COPY . /app

# 数据目录（sqlite 数据库与上传文件）；由 compose 挂载为 volume 以便持久化。
RUN mkdir -p /app/data /app/uploads /app/logs

# 以非 root 用户运行
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

# 容器内监听端口
EXPOSE 22222

# 健康检查：/health 由 app/__init__.py 注册，返回 {"status":"ok","env":"production"}
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -fsS http://127.0.0.1:22222/health || exit 1

# 默认启动命令；compose 用 CMD 启动即可
CMD ["python", "main.py"]
