# YL-analysis安全分析前端API接口文档

本文档详细说明了前端与后端的交互接口，包括请求方法、URL、参数和响应格式。

*注意，本文档只列出部分api接口，完整的接口列表请参考后端项目的api文档*

## 基础配置

前端使用Axios库进行HTTP请求，基础配置如下：

```javascript
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000',
  timeout: 60000,
})
```

请求和响应拦截器配置：

```javascript
// 请求拦截器
api.interceptors.request.use(
  (config) => {
    // 在发送请求之前做些什么
    return config
  },
  (error) => {
    // 对请求错误做些什么
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  (response) => {
    // 对响应数据做点什么
    return response
  },
  (error) => {
    // 对响应错误做点什么
    return Promise.reject(error)
  }
)
```

## 项目管理接口

### 获取项目列表

**请求方法**: GET

**URL**: `/api/challenges`

**描述**: 获取所有已上传的项目列表

**参数**: 无

**响应示例**:
```json
{
  "data": [
    {
      "id": "1",
      "name": "project1",
      "created_at": "2023-01-01T12:00:00Z"
    },
    {
      "id": "2",
      "name": "project2",
      "created_at": "2023-01-02T12:00:00Z"
    }
  ]
}
```

### 删除项目

**请求方法**: DELETE

**URL**: `/api/challenges/:id`

**描述**: 删除指定ID的项目

**参数**:
- `id`: 项目ID (路径参数)

**响应示例**:
```json
{
  "message": "Project deleted successfully"
}
```

### 上传项目文件夹

**请求方法**: POST

**URL**: `/api/challenges-upload`

**描述**: 上传项目文件夹

**参数**:
- `name`: 项目名称 (FormData)
- `files`: 项目文件 (FormData)

**响应示例**:
```json
{
  "message": "Project uploaded successfully",
  "id": "3"
}
```

## 分析接口

### 开始分析

**请求方法**: POST

**URL**: `/api/analysis-start`

**描述**: 开始对指定项目进行漏洞分析

**参数**:
- `challenge_id`: 项目ID
- `vulnerability_types`: 漏洞类型数组

**请求示例**:
```json
{
  "challenge_id": "1",
  "vulnerability_types": ["sql_injection", "xss"]
}
```

**响应示例**:
```json
{
  "message": "Analysis started",
  "task_id": "task-123"
}
```


## 设置接口

### 获取系统设置

**请求方法**: GET

**URL**: `/api/settings`

**描述**: 获取系统设置

**参数**: 无

**响应示例**:
```json
{
  "settings": {
    "test_mode": true,
    "retry_times": 3,
    "timeout": 30,
    "openai_api_key": "sk-***",
    "openai_api_base": "https://api.openai.com/v1",
    "model_name": "gpt-4"
  }
}
```

### 保存系统设置

**请求方法**: POST

**URL**: `/api/settings`

**描述**: 保存系统设置

**参数**:
- `settings`: 设置对象

**请求示例**:
```json
{
  "settings": {
    "test_mode": false,
    "retry_times": 5,
    "timeout": 60,
    "openai_api_key": "sk-newkey",
    "openai_api_base": "https://api.openai.com/v1",
    "model_name": "gpt-4-turbo"
  }
}
```

**响应示例**:
```json
{
  "message": "Settings saved successfully"
}
```

## 错误处理

所有API接口在发生错误时，将返回适当的HTTP状态码和错误信息：

```json
{
  "error": "错误信息",
  "code": "错误代码",
  "details": "错误详情（可选）"
}
```

常见HTTP状态码：

- 200: 请求成功
- 400: 请求参数错误
- 401: 未授权
- 404: 资源不存在
- 500: 服务器内部错误

## 注意事项

1. 所有请求和响应的Content-Type均为application/json，除非特别说明（如文件上传使用multipart/form-data）
2. 分析任务可能需要较长时间，客户端应定期轮询分析状态接口获取最新状态
3. 调用图数据可能较大，支持分页获取
4. API密钥等敏感信息在响应中会被部分隐藏