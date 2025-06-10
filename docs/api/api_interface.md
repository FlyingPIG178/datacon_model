# API 接口设计

## 概述

YL-analysis 系统采用前后端分离架构，后端使用 Python + aiohttp 实现 API 服务，前端使用 Vue.js + Element Plus 构建用户界面。本文档详细介绍了系统的 API 接口设计，包括 RESTful API 和 WebSocket 接口。

## API 设计原则

YL-analysis 系统的 API 设计遵循以下原则：

1. **RESTful 风格**：API 遵循 RESTful 设计风格，使用标准的 HTTP 方法（GET, POST, PUT, DELETE）表示不同的操作。
2. **JSON 数据格式**：API 请求和响应均使用 JSON 格式，便于前端处理。
3. **统一响应格式**：所有 API 响应使用统一的格式，包含状态码、消息和数据。
4. **版本控制**：API 路径包含版本信息，便于后续升级和兼容性维护。
5. **错误处理**：API 提供清晰的错误信息和状态码，便于前端处理异常情况。

## API 基础路径

所有 API 请求的基础路径为：`/api`

## 统一响应格式

所有 API 响应均使用以下统一格式：

```json
{
  "status": "success",  // 或 "error"
  "message": "操作成功",  // 成功或错误消息
  "data": {}  // 响应数据，可能是对象、数组或 null
}
```

## RESTful API 接口

### 1. 项目管理接口

#### 1.1 获取项目列表

- **URL**: `/api/list-challenges`
- **方法**: `GET`
- **描述**: 获取所有可用的项目列表
- **参数**: 无
- **响应示例**:

```json
{
  "status": "success",
  "message": "获取项目列表成功",
  "data": [
    {
      "name": "project1",
      "size": 1024,
      "created_at": "2023-01-01T12:00:00Z"
    },
    {
      "name": "project2",
      "size": 2048,
      "created_at": "2023-01-02T12:00:00Z"
    }
  ]
}
```

#### 1.2 上传项目

- **URL**: `upload-folder`
- **方法**: `POST`
- **描述**: 上传新项目
- **参数**:
  - `folder_name`: 项目名称
  - `files[]`: 项目文件（多个）
- **响应示例**:

```json
{
  "status": "success",
  "message": "项目 {project_name} 上传成功，共 {file_count} 个文件",
  "data": {}
}
```

#### 1.3 删除项目

- **URL**: `/api/delete-project/{project_name}`
- **方法**: `DELETE`
- **描述**: 删除指定项目
- **参数**:
  - `project_name`: 项目名称（路径参数）
- **响应示例**:

```json
{
  "status": "success",
  "message": "项目删除成功",
  "data": null
}
```

### 2. 分析管理接口

#### 2.1 启动分析任务

- **URL**: `/api/start-analysis`
- **方法**: `POST`
- **描述**: 启动代码分析任务
- **参数**:
  - `project_name`: 项目名称
  - `vuln_type`: 漏洞类型
  - `emergency_mode`: 是否使用应急模式（可选，默认为 false）
- **响应示例**:

```json
{
  "status": "success",
  "message": "分析任务已启动",
  "data": {
    "task_id": "task-123456",
    "project_name": "project1",
    "vuln_type": "sql_injection",
    "status": "queued",
    "created_at": "2023-01-03T12:00:00Z"
  }
}
```

#### 2.2 获取分析任务状态

- **URL**: `/api/analysis-status`
- **方法**: `GET`
- **描述**: 获取分析任务的状态
- **参数**:
  - `task_id`: 任务 ID（查询参数，可选）
- **响应示例**:

```json
{
  "status": "success",
  "message": "获取任务状态成功",
  "data": {
    "task": {
      "id": "task-123456",
      "project_name": "project1",
      "vul_type": "sql_injection",
      "status": "processing",
      "start_time": "",
      "end_time": "",
      "progress": ""
    }
  }
}
```

#### 2.3 停止分析任务

- **URL**: `/api/stop-analysis`
- **方法**: `POST`
- **描述**: 停止当前正在执行的分析任务
- **参数**: 无
- **响应示例**:

```json
{
  "status": "success",
  "message": "分析任务已停止",
  "data": null
}
```

#### 2.4 获取分析结果

- **URL**: `/api/call-graph/{project_name}`
- **方法**: `GET`
- **描述**: 获取指定任务的分析结果
- **参数**:
  - `project_name`: 项目名称
- **响应示例**:

```json
{
  "status": "success",
  "message": "获取分析结果成功",
  "data": {
    [
      {
        "function": "entry",
        "taint_params": [],
        "taint_actions": [],
        "calls": [
          {
            "function": "process",
            "taint_params": [],
            "taint_actions": [],
            "calls": [
              {
                "function": "execute",
                "taint_params": [
                  "cmd"
                ],
                "taint_actions": [
                  "b'def execute(cmd):\\n    eval(cmd)'"
                ],
                "calls": []
              }
            ]
          }
        ],
        "漏洞分析": {
          "存在漏洞": true,
          "漏洞函数": "execute",
          "漏洞类型": "Command_injection_CWE_78",
          "利用方式": "cmd; ls",
          "威胁评分": 9,
          "修复建议": "避免使用 eval 或者其他可能执行任意代码的函数，使用参数化查询或者白名单验证输入。",
          "分析理由": "在调用链中，函数 'execute' 接收了一个名为 'cmd' 的参数，并且这个参数被用于执行 eval 函数。由于 eval 函数可以执行任意代码，如果 'cmd' 参数被攻击者控制，那么攻击者可以注入任意命令执行，从而实现命令注入攻击。因此，存在一个明显的命令注入漏洞。"
        }
      }
    ]
  }
}
```

### 3. 设置管理接口

#### 3.1 获取系统设置

- **URL**: `/api/settings`
- **方法**: `GET`
- **描述**: 获取系统设置
- **参数**: 无
- **响应示例**:

```json
{
  "status": "success",
  "message": "获取设置成功",
  "data": {
    "test_mode": false,
    "retry_times": 10,
    "openai_api_key": "",
    "openai_api_base": "",
    "model_name": "moonshot-v1-8k",
    "timeout": 300
  }
}
```

#### 3.2 更新系统设置

- **URL**: `/api/settings`
- **方法**: `POST`
- **描述**: 更新系统设置
- **参数**:
  - 设置对象（JSON 格式）
- **请求示例**:

```json
{
  "test_mode": false,
  "retry_times": 10,
  "openai_api_key": "",
  "openai_api_base": "",
  "model_name": "moonshot-v1-8k",
  "timeout": 300
}
```

- **响应示例**:

```json
{
  "status": "success",
  "message": "设置更新成功",
  "data": null
}
```

## 错误处理

### 错误响应格式

```json
{
  "status": "error",
  "message": "错误消息",
  "data": null,
  "error_code": "ERROR_CODE",  // 可选，错误代码
  "details": {}  // 可选，错误详情
}
```

### 常见错误代码

| 错误代码 | HTTP 状态码 | 描述 |
|---------|------------|------|
| `INVALID_REQUEST` | 400 | 请求参数无效 |
| `PROJECT_NOT_FOUND` | 404 | 项目不存在 |
| `TASK_NOT_FOUND` | 404 | 任务不存在 |
| `FILE_TOO_LARGE` | 413 | 文件过大 |
| `UNSUPPORTED_FILE_TYPE` | 415 | 不支持的文件类型 |
| `QUEUE_FULL` | 429 | 队列已满 |
| `INTERNAL_ERROR` | 500 | 内部服务器错误 |
| `LLM_ERROR` | 502 | LLM 服务错误 |
| `TIMEOUT` | 504 | 请求超时 |

## API 认证

目前，YL-analysis 系统的 API 接口不需要认证。在生产环境中，建议实现适当的认证机制，如 API 密钥、JWT 令牌或 OAuth2。

## API 版本控制

当前 API 版本为 v1。未来版本更新时，将在 URL 路径中包含版本信息，如 `/api/v2/challenges`。

## 总结

YL-analysis 系统的 API 接口设计遵循 RESTful 风格，提供了项目管理、分析管理和设置管理等功能。API 接口使用统一的响应格式和错误处理机制，便于前端处理。

系统的 API 设计考虑了可扩展性、安全性和性能，为前端提供了丰富的功能和良好的用户体验。通过这些接口，前端可以方便地管理项目、启动分析任务、监控分析进度和查看分析结果。