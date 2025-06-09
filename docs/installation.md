# YL-analysis 安装与部署指南

## 概述

本文档提供了 YL-analysis 代码分析工具的详细安装和部署指南，包括环境要求、安装步骤、配置选项和常见问题解决方案。YL-analysis 是一个基于大语言模型的代码漏洞分析工具，支持多种漏洞类型的检测，并提供可视化的分析结果。

## 系统要求

### 硬件要求

- **CPU**: 至少 2 核心
- **内存**: 至少 4GB RAM，推荐 8GB 或更高
- **存储**: 至少 2GB 可用空间
- **网络**: 稳定的互联网连接（用于 LLM API 调用）

### 软件要求

- **操作系统**: 
  - Windows 10/11
  - macOS 10.15+
  - Ubuntu 20.04+/Debian 10+/CentOS 8+
- **Python**: 3.8 或更高版本
- **Node.js**: 14.0 或更高版本（用于前端构建）
- **包管理器**: pip, uv (推荐)

## 安装步骤

### 1. 克隆代码仓库

```bash
git clone https://github.com/your-username/YL-analysis.git
cd YL-analysis
```

### 2. 安装后端依赖

#### 使用 uv (推荐)

[uv](https://github.com/astral-sh/uv) 是一个快速的 Python 包管理器，可以显著提高依赖安装速度。

```bash
# 安装 uv
pip install uv

# 使用 uv 安装依赖
uv pip install -r requirements.txt
```

#### 使用 pip

```bash
pip install -r requirements.txt
```

### 3. 安装前端依赖

```bash
cd front
npm install
```

### 4. 构建前端

```bash
npm run build
```

### 5. 配置 LLM API 密钥

创建 `.env` 文件并设置 LLM API 密钥：

```
# OpenAI API 密钥
OPENAI_API_KEY=your_openai_api_key

# Anthropic API 密钥 (可选)
ANTHROPIC_API_KEY=your_anthropic_api_key

# 本地 LLM API 地址 (可选)
LOCAL_LLM_API_URL=http://localhost:8000/v1
```

### 6. 启动应用

```bash
python server.py
```

默认情况下，应用将在 `http://localhost:8080` 上运行。

## 使用 Docker 部署

### 1. 构建 Docker 镜像

```bash
docker build -t yl-analysis .
```

### 2. 运行 Docker 容器

```bash
docker run -d -p 8080:8080 --name yl-analysis-container \
  -e OPENAI_API_KEY=your_openai_api_key \
  yl-analysis
```

## 配置选项

### 命令行参数

启动服务器时可以使用以下命令行参数：

```bash
python server.py --host 0.0.0.0 --port 8080 --log-level info
```

| 参数 | 描述 | 默认值 |
|------|------|--------|
| `--host` | 监听地址 | `127.0.0.1` |
| `--port` | 监听端口 | `8080` |
| `--log-level` | 日志级别 (debug, info, warning, error, critical) | `info` |

### 配置文件

系统配置存储在 `config.json` 文件中，可以根据需要进行修改：

```json
{
  "llm": {
    "provider": "openai",
    "model": "gpt-4",
    "temperature": 0.2,
    "max_tokens": 4096,
    "timeout": 60,
    "retry_count": 3
  },
  "analysis": {
    "max_file_size": 1048576,
    "max_files": 100,
    "timeout": 300,
    "emergency_mode_enabled": true
  },
  "system": {
    "log_level": "info",
    "max_queue_size": 10,
    "challenges_dir": "challenges",
    "logs_dir": "logs",
    "static_dir": "static"
  }
}
```

## 目录结构

安装完成后，YL-analysis 的目录结构如下：

```
YL-analysis/
├── api/                  # 后端 API 代码
│   ├── __init__.py
│   ├── analysis_queue.py  # 分析队列管理
│   ├── analysis_router.py # 分析路由
│   ├── config.py         # 配置管理
│   ├── objects.py        # 数据对象定义
│   ├── projects_router.py # 项目管理路由
│   ├── router_base.py    # 路由基类
│   ├── service_manager.py # 服务管理器
│   ├── settings_router.py # 设置路由
│   ├── static_router.py  # 静态文件路由
│   ├── terminal_service.py # 终端服务
│   └── utils.py          # 工具函数
├── front/                # 前端代码
│   ├── public/
│   ├── src/
│   ├── package.json
│   └── vite.config.js
├── main/                 # 主要业务逻辑
│   ├── __init__.py
│   ├── challenge.py      # Challenge 类
│   ├── llm_service.py    # LLM 服务
│   ├── prompt_templates/ # 提示词模板
│   └── vuln_detector.py  # 漏洞检测器
├── static/               # 静态文件
│   └── dist/             # 前端构建输出
├── challenges/           # 项目目录
├── logs/                 # 日志目录
├── .env                  # 环境变量
├── config.json           # 配置文件
├── requirements.txt      # 依赖列表
├── server.py             # 服务器入口
└── README.md             # 项目说明
```

## 环境变量

YL-analysis 支持以下环境变量：

| 环境变量 | 描述 | 默认值 |
|----------|------|--------|
| `OPENAI_API_KEY` | OpenAI API 密钥 | 无 |
| `ANTHROPIC_API_KEY` | Anthropic API 密钥 | 无 |
| `LOCAL_LLM_API_URL` | 本地 LLM API 地址 | 无 |
| `YL_HOST` | 监听地址 | `127.0.0.1` |
| `YL_PORT` | 监听端口 | `8080` |
| `YL_LOG_LEVEL` | 日志级别 | `info` |
| `YL_CONFIG_PATH` | 配置文件路径 | `config.json` |
| `YL_CHALLENGES_DIR` | 项目目录 | `challenges` |
| `YL_LOGS_DIR` | 日志目录 | `logs` |
| `YL_STATIC_DIR` | 静态文件目录 | `static` |

## 开发环境设置

### 1. 设置开发环境

```bash
# 安装开发依赖
uv pip install -r requirements-dev.txt

# 安装前端开发依赖
cd front
npm install
```

### 2. 启动后端开发服务器

```bash
python server.py --log-level debug
```

### 3. 启动前端开发服务器

```bash
cd front
npm run dev
```

前端开发服务器将在 `http://localhost:5173` 上运行，并自动代理 API 请求到后端服务器。

## 多人协作开发

在多人协作开发环境中，建议使用 uv 作为包管理器，以确保依赖版本的一致性。

```bash
# 创建虚拟环境
uv venv

# 激活虚拟环境
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# 安装依赖
uv pip install -r requirements.txt
```

## 生产环境部署

### 使用 Gunicorn 部署（Linux/macOS）

```bash
pip install gunicorn
gunicorn server:app --bind 0.0.0.0:8080 --worker-class aiohttp.GunicornWebWorker --workers 4
```

### 使用 Supervisor 管理进程（Linux/macOS）

1. 安装 Supervisor：

```bash
pip install supervisor
```

2. 创建 Supervisor 配置文件 `/etc/supervisor/conf.d/yl-analysis.conf`：

```ini
[program:yl-analysis]
command=gunicorn server:app --bind 0.0.0.0:8080 --worker-class aiohttp.GunicornWebWorker --workers 4
directory=/path/to/YL-analysis
user=www-data
autostart=true
autorestart=true
stdout_logfile=/var/log/yl-analysis/stdout.log
stderr_logfile=/var/log/yl-analysis/stderr.log
environment=OPENAI_API_KEY="your_openai_api_key"
```

3. 更新 Supervisor 配置并启动服务：

```bash
supervisorctl reread
supervisorctl update
supervisorctl start yl-analysis
```

### 使用 Nginx 作为反向代理

1. 安装 Nginx：

```bash
# Ubuntu/Debian
apt-get install nginx

# CentOS/RHEL
yum install nginx
```

2. 创建 Nginx 配置文件 `/etc/nginx/sites-available/yl-analysis`：

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3. 启用站点并重启 Nginx：

```bash
# Ubuntu/Debian
ln -s /etc/nginx/sites-available/yl-analysis /etc/nginx/sites-enabled/
systemctl restart nginx

# CentOS/RHEL
cp /etc/nginx/sites-available/yl-analysis /etc/nginx/conf.d/
systemctl restart nginx
```

## 常见问题解决

### 1. LLM API 连接问题

**问题**: 无法连接到 LLM API 服务。

**解决方案**:
- 检查 API 密钥是否正确设置
- 检查网络连接是否正常
- 检查 API 服务是否可用
- 尝试使用代理服务器

### 2. 依赖安装失败

**问题**: 安装依赖时出现错误。

**解决方案**:
- 更新 pip: `pip install --upgrade pip`
- 尝试使用 uv: `uv pip install -r requirements.txt`
- 检查 Python 版本是否满足要求
- 在虚拟环境中安装依赖

### 3. 前端构建失败

**问题**: 前端构建时出现错误。

**解决方案**:
- 更新 Node.js 到最新版本
- 清除 npm 缓存: `npm cache clean --force`
- 删除 `node_modules` 目录并重新安装依赖
- 检查 `package.json` 中的依赖版本

### 4. WebSocket 连接问题

**问题**: WebSocket 连接失败或断开。

**解决方案**:
- 检查浏览器是否支持 WebSocket
- 检查网络连接是否正常
- 检查防火墙或代理设置
- 如果使用 Nginx，确保 WebSocket 配置正确

### 5. 分析任务超时

**问题**: 分析任务执行时间过长或超时。

**解决方案**:
- 增加分析超时时间: 修改 `config.json` 中的 `analysis.timeout` 值
- 启用应急模式: 修改 `config.json` 中的 `analysis.emergency_mode_enabled` 为 `true`
- 减小项目规模或文件数量
- 使用更强大的硬件

## 升级指南

### 1. 备份配置和数据

```bash
cp .env .env.backup
cp config.json config.json.backup
cp -r challenges challenges.backup
```

### 2. 更新代码

```bash
git pull origin main
```

### 3. 更新依赖

```bash
uv pip install -r requirements.txt
cd front
npm install
```

### 4. 重新构建前端

```bash
cd front
npm run build
```

### 5. 重启服务

```bash
# 如果使用 Supervisor
supervisorctl restart yl-analysis

# 如果直接运行
python server.py
```

## 总结

本文档提供了 YL-analysis 代码分析工具的详细安装和部署指南，包括环境要求、安装步骤、配置选项和常见问题解决方案。通过按照本指南进行操作，您可以成功安装和部署 YL-analysis 系统，并开始使用其强大的代码漏洞分析功能。

如果您在安装或使用过程中遇到任何问题，请参考常见问题解决部分，或者联系项目维护者获取帮助。