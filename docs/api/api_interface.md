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
6. **实时通信**：使用 WebSocket 实现实时日志和状态更新。

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

- **URL**: `/api/challenges`
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
      "path": "/challenges/project1",
      "size": 1024,
      "created_at": "2023-01-01T12:00:00Z"
    },
    {
      "name": "project2",
      "path": "/challenges/project2",
      "size": 2048,
      "created_at": "2023-01-02T12:00:00Z"
    }
  ]
}
```

#### 1.2 获取项目详情

- **URL**: `/api/challenges/{project_name}`
- **方法**: `GET`
- **描述**: 获取指定项目的详细信息
- **参数**:
  - `project_name`: 项目名称（路径参数）
- **响应示例**:

```json
{
  "status": "success",
  "message": "获取项目详情成功",
  "data": {
    "name": "project1",
    "path": "/challenges/project1",
    "size": 1024,
    "created_at": "2023-01-01T12:00:00Z",
    "files": [
      {
        "name": "main.py",
        "path": "/challenges/project1/main.py",
        "size": 512,
        "content": "def main():\n    print('Hello, world!')\n\nif __name__ == '__main__':\n    main()"
      },
      {
        "name": "utils.py",
        "path": "/challenges/project1/utils.py",
        "size": 256,
        "content": "def helper():\n    return 'Helper function'"
      }
    ]
  }
}
```

#### 1.3 上传项目

- **URL**: `/api/upload-challenge`
- **方法**: `POST`
- **描述**: 上传新项目（ZIP 文件）
- **参数**:
  - `file`: 项目 ZIP 文件（表单数据）
  - `name`: 项目名称（表单数据，可选）
- **响应示例**:

```json
{
  "status": "success",
  "message": "项目上传成功",
  "data": {
    "name": "project3",
    "path": "/challenges/project3",
    "size": 3072,
    "created_at": "2023-01-03T12:00:00Z"
  }
}
```

#### 1.4 删除项目

- **URL**: `/api/challenges/{project_name}`
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

- **URL**: `/api/analysis/start`
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

- **URL**: `/api/analysis/status`
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
    "current_task": {
      "task_id": "task-123456",
      "project_name": "project1",
      "vuln_type": "sql_injection",
      "status": "running",
      "progress": 45,
      "created_at": "2023-01-03T12:00:00Z",
      "started_at": "2023-01-03T12:01:00Z"
    },
    "queue": [
      {
        "task_id": "task-123457",
        "project_name": "project2",
        "vuln_type": "xss",
        "status": "queued",
        "created_at": "2023-01-03T12:02:00Z"
      }
    ]
  }
}
```

#### 2.3 停止分析任务

- **URL**: `/api/analysis/stop`
- **方法**: `POST`
- **描述**: 停止当前正在执行的分析任务
- **参数**: 无
- **响应示例**:

```json
{
  "status": "success",
  "message": "分析任务已停止",
  "data": {
    "task_id": "task-123456",
    "project_name": "project1",
    "vuln_type": "sql_injection",
    "status": "stopped",
    "progress": 45,
    "created_at": "2023-01-03T12:00:00Z",
    "started_at": "2023-01-03T12:01:00Z",
    "stopped_at": "2023-01-03T12:05:00Z"
  }
}
```

#### 2.4 清空分析队列

- **URL**: `/api/analysis/clear-queue`
- **方法**: `POST`
- **描述**: 清空分析任务队列
- **参数**: 无
- **响应示例**:

```json
{
  "status": "success",
  "message": "分析队列已清空",
  "data": null
}
```

#### 2.5 获取分析结果

- **URL**: `/api/analysis/results/{task_id}`
- **方法**: `GET`
- **描述**: 获取指定任务的分析结果
- **参数**:
  - `task_id`: 任务 ID（路径参数）
- **响应示例**:

```json
{
  "status": "success",
  "message": "获取分析结果成功",
  "data": {
    "task_id": "task-123456",
    "project_name": "project1",
    "vuln_type": "sql_injection",
    "status": "completed",
    "created_at": "2023-01-03T12:00:00Z",
    "completed_at": "2023-01-03T12:10:00Z",
    "vuln_chains": [
      {
        "id": "chain-1",
        "entry_point": "login",
        "sink": "execute_query",
        "risk_level": "high",
        "description": "SQL 注入漏洞链",
        "path": ["login", "authenticate", "get_user", "execute_query"],
        "code_snippets": [
          {
            "function": "login",
            "file": "auth.py",
            "line": 10,
            "code": "def login(username, password):\n    return authenticate(username, password)"
          },
          {
            "function": "authenticate",
            "file": "auth.py",
            "line": 15,
            "code": "def authenticate(username, password):\n    user = get_user(username)\n    if user and user['password'] == password:\n        return user\n    return None"
          },
          {
            "function": "get_user",
            "file": "auth.py",
            "line": 25,
            "code": "def get_user(username):\n    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n    return execute_query(query)"
          },
          {
            "function": "execute_query",
            "file": "db.py",
            "line": 5,
            "code": "def execute_query(query):\n    # Execute SQL query\n    return db.execute(query)"
          }
        ]
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
    "llm": {
      "provider": "openai",
      "model": "gpt-4",
      "temperature": 0.2
    },
    "analysis": {
      "max_file_size": 1048576,
      "max_files": 100,
      "timeout": 300
    },
    "system": {
      "log_level": "info",
      "max_queue_size": 10
    }
  }
}
```

#### 3.2 更新系统设置

- **URL**: `/api/settings`
- **方法**: `PUT`
- **描述**: 更新系统设置
- **参数**:
  - 设置对象（JSON 格式）
- **请求示例**:

```json
{
  "llm": {
    "provider": "openai",
    "model": "gpt-4-turbo",
    "temperature": 0.3
  },
  "analysis": {
    "timeout": 600
  }
}
```

- **响应示例**:

```json
{
  "status": "success",
  "message": "设置更新成功",
  "data": {
    "llm": {
      "provider": "openai",
      "model": "gpt-4-turbo",
      "temperature": 0.3
    },
    "analysis": {
      "max_file_size": 1048576,
      "max_files": 100,
      "timeout": 600
    },
    "system": {
      "log_level": "info",
      "max_queue_size": 10
    }
  }
}
```

#### 3.3 重置系统设置

- **URL**: `/api/settings/reset`
- **方法**: `POST`
- **描述**: 重置系统设置为默认值
- **参数**: 无
- **响应示例**:

```json
{
  "status": "success",
  "message": "设置已重置为默认值",
  "data": {
    "llm": {
      "provider": "openai",
      "model": "gpt-3.5-turbo",
      "temperature": 0.2
    },
    "analysis": {
      "max_file_size": 1048576,
      "max_files": 100,
      "timeout": 300
    },
    "system": {
      "log_level": "info",
      "max_queue_size": 10
    }
  }
}
```

## WebSocket 接口

### 1. 终端日志 WebSocket

- **URL**: `/ws/terminal`
- **描述**: 接收实时终端日志消息
- **消息格式**:

```json
{
  "type": "log",
  "level": "info",  // 日志级别：debug, info, warning, error, critical
  "message": "正在分析函数：login",
  "timestamp": "2023-01-03T12:05:30Z"
}
```

### 2. 分析状态 WebSocket

- **URL**: `/ws/analysis`
- **描述**: 接收实时分析状态更新
- **消息格式**:

```json
{
  "type": "status_update",
  "task_id": "task-123456",
  "status": "running",  // 任务状态：queued, running, completed, failed, stopped
  "progress": 60,  // 进度百分比
  "message": "正在分析函数调用图",
  "timestamp": "2023-01-03T12:06:00Z"
}
```

```json
{
  "type": "queue_update",
  "queue_size": 2,
  "tasks": [
    {
      "task_id": "task-123457",
      "project_name": "project2",
      "vuln_type": "xss",
      "status": "queued"
    },
    {
      "task_id": "task-123458",
      "project_name": "project3",
      "vuln_type": "command_injection",
      "status": "queued"
    }
  ],
  "timestamp": "2023-01-03T12:06:30Z"
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

## API 限流

为了防止 API 滥用，系统实现了基本的限流机制：

- 每个 IP 地址每分钟最多发送 60 个请求
- 上传文件的大小限制为 10MB
- 分析队列的最大长度为 10

## API 版本控制

当前 API 版本为 v1。未来版本更新时，将在 URL 路径中包含版本信息，如 `/api/v2/challenges`。

## WebSocket 连接管理

### 连接建立

前端通过以下方式建立 WebSocket 连接：

```javascript
const terminalSocket = new WebSocket('ws://localhost:8080/ws/terminal');
const analysisSocket = new WebSocket('ws://localhost:8080/ws/analysis');

terminalSocket.onopen = () => {
  console.log('Terminal WebSocket 连接已建立');
};

analysisSocket.onopen = () => {
  console.log('Analysis WebSocket 连接已建立');
};
```

### 消息处理

前端通过以下方式处理 WebSocket 消息：

```javascript
terminalSocket.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'log') {
    console.log(`[${data.level}] ${data.message}`);
    // 更新 UI 显示日志消息
  }
};

analysisSocket.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'status_update') {
    console.log(`任务 ${data.task_id} 状态更新: ${data.status}, 进度: ${data.progress}%`);
    // 更新 UI 显示任务状态
  } else if (data.type === 'queue_update') {
    console.log(`队列更新: ${data.queue_size} 个任务在队列中`);
    // 更新 UI 显示队列状态
  }
};
```

### 连接关闭和重连

前端通过以下方式处理 WebSocket 连接关闭和重连：

```javascript
terminalSocket.onclose = (event) => {
  console.log(`Terminal WebSocket 连接已关闭: ${event.code} ${event.reason}`);
  // 尝试重新连接
  setTimeout(() => {
    console.log('尝试重新连接 Terminal WebSocket...');
    // 重新创建 WebSocket 连接
  }, 3000);
};

analysisSocket.onclose = (event) => {
  console.log(`Analysis WebSocket 连接已关闭: ${event.code} ${event.reason}`);
  // 尝试重新连接
  setTimeout(() => {
    console.log('尝试重新连接 Analysis WebSocket...');
    // 重新创建 WebSocket 连接
  }, 3000);
};
```

## 总结

YL-analysis 系统的 API 接口设计遵循 RESTful 风格，提供了项目管理、分析管理和设置管理等功能，并通过 WebSocket 实现了实时日志和状态更新。API 接口使用统一的响应格式和错误处理机制，便于前端处理。

系统的 API 设计考虑了可扩展性、安全性和性能，为前端提供了丰富的功能和良好的用户体验。通过这些接口，前端可以方便地管理项目、启动分析任务、监控分析进度和查看分析结果。