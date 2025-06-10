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

构建后的前端文件已经被包含在`front/`文件中，因此安装和构建前端不是必须的。

如果您需要修改前端代码，请前往前端仓库。

### 6. 启动应用

如果使用uv安装依赖，需要使用以下命令启动服务器：

```bash
uv run server.py
```

如果使用pip安装依赖，需要使用以下命令启动服务器：

```bash
python server.py
```

默认情况下，应用将在 `http://localhost:5000` 上运行。

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

## 目录结构

安装完成后，YL-analysis 的目录结构如下：

```
YL-analysis/
├── src/                  # 源代码目录
│   ├── api/              # 后端 API 代码
│   │   ├── ...
│   ├── libs/                 # 主要业务逻辑库
│   │   ├── 
├── front/                # 前端文件
│   ├── ...
├── challenges/           # 项目目录
├── results/               # 结果目录
├── .venv                  # 环境变量
├── requirements.txt      # 依赖列表
├── server.py             # 服务器入口
└── README.md             # 项目说明
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

### 5. 分析任务超时

**问题**: 分析任务执行时间过长或超时。

**解决方案**:
- 增加分析超时时间
- 减小项目规模或文件数量
- 使用更强大的硬件

## 总结

本文档提供了 YL-analysis 代码分析工具的详细安装和部署指南，包括环境要求、安装步骤、配置选项和常见问题解决方案。通过按照本指南进行操作，您可以成功安装和部署 YL-analysis 系统，并开始使用其强大的代码漏洞分析功能。

如果您在安装或使用过程中遇到任何问题，请参考常见问题解决部分，或者联系项目维护者获取帮助。