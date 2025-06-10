# 路由系统

## 概述

YL-analysis 系统的路由系统负责管理和处理所有 API 请求，将客户端请求路由到相应的处理函数。该系统采用模块化设计，通过基类和继承机制实现路由的统一管理。本文档详细介绍了路由系统的架构和工作流程。

## 核心组件

### 1. RouterBase 类

`RouterBase` 是所有路由管理器的基类，定义了路由管理器的基本接口。

**主要方法**：
- `add_routes(app)`: 向 aiohttp 应用添加路由

```python
class RouterBase:
    def add_routes(self, app):
        """向应用添加路由"""
        raise NotImplementedError("Subclasses must implement add_routes method")
```

### 2. 具体路由管理器

系统包含多个具体的路由管理器，每个管理器负责一组相关的 API 路由。

#### 2.1 SettingsRouter

`SettingsRouter` 负责处理与系统设置相关的 API 请求。

**主要路由**：
- `GET /api/settings`: 获取系统设置
- `POST /api/settings`: 更新系统设置

```python
class SettingsRouter(RouterBase):
    def add_routes(self, app):
        app.router.add_get('/api/settings', self.get_settings)
        app.router.add_post('/api/settings', self.update_settings)
        
    async def get_settings(self, request):
        # 获取系统设置
        # ...
        
    async def update_settings(self, request):
        # 更新系统设置
        # ...
```

#### 2.2 AnalysisRouter

`AnalysisRouter` 负责处理与漏洞分析相关的 API 请求。

**主要路由**：
- `POST /api/start-analysis`: 启动漏洞分析
- `GET /api/analysis-status`: 获取分析状态
- `POST /api/stop-analysis`: 停止当前分析
- `POST /api/clear-queue`: 清空分析队列

```python
class AnalysisRouter(RouterBase):
    def __init__(self):
        self.queue_manager = AnalysisQueueManager()
        
    def add_routes(self, app):
        app.router.add_post('/api/start-analysis', self.start_analysis)
        app.router.add_get('/api/analysis-status', self.get_analysis_status)
        app.router.add_post('/api/stop-analysis', self.stop_analysis)
        app.router.add_post('/api/clear-queue', self.clear_queue)
        
    async def start_analysis(self, request):
        # 启动漏洞分析
        # ...
        
    async def get_analysis_status(self, request):
        # 获取分析状态
        # ...
        
    async def stop_analysis(self, request):
        # 停止当前分析
        # ...
        
    async def clear_queue(self, request):
        # 清空分析队列
        # ...
```

#### 2.3 ProjectsRouter

`ProjectsRouter` 负责处理与项目管理相关的 API 请求。

**主要路由**：
- `GET /api/list-challenges`: 获取项目列表
- `POST /api/upload-challenge`: 上传项目
- `DELETE /api/delete-challenge`: 删除项目

```python
class ProjectsRouter(RouterBase):
    def add_routes(self, app):
        app.router.add_get('/api/list-challenges', self.list_challenges)
        app.router.add_post('/api/upload-challenge', self.upload_challenge)
        app.router.add_delete('/api/delete-challenge', self.delete_challenge)
        
    async def list_challenges(self, request):
        # 获取项目列表
        # ...
        
    async def upload_challenge(self, request):
        # 上传项目
        # ...
        
    async def delete_challenge(self, request):
        # 删除项目
        # ...
```

#### 2.4 StaticRouter

`StaticRouter` 负责处理静态文件请求，包括前端资源和文档。

**主要路由**：
- `GET /static/{filename}`: 获取静态文件
- `GET /{path:.*}`: 获取前端页面

```python
class StaticRouter(RouterBase):
    def add_routes(self, app):
        app.router.add_static('/static/', path=Config().STATIC_DIR, name='static')
        app.router.add_get('/{path:.*}', self.index)
        
    async def index(self, request):
        # 返回前端页面
        # ...
```

### 3. 路由设置函数

`setup_all_routes` 函数负责初始化并添加所有路由管理器到应用程序。

```python
def setup_all_routes(app):
    routers = [
        SettingsRouter(),
        AnalysisRouter(),
        ProjectsRouter(),
        # 静态文件路由应该最后添加
        StaticRouter()
    ]
    
    for router in routers:
        router.add_routes(app)
```

## 路由处理流程

### 1. 请求接收

1. 客户端发送 HTTP 请求到服务器
2. aiohttp 服务器接收请求并根据 URL 路径查找对应的处理函数

### 2. 路由匹配

1. aiohttp 根据请求的 URL 路径和 HTTP 方法匹配路由表中的路由
2. 如果找到匹配的路由，调用对应的处理函数
3. 如果没有找到匹配的路由，返回 404 错误

### 3. 请求处理

1. 处理函数接收 `request` 对象
2. 处理函数解析请求参数（URL 参数、查询参数、请求体等）
3. 处理函数执行业务逻辑
4. 处理函数返回 HTTP 响应

### 4. 响应返回

1. aiohttp 将处理函数返回的响应发送给客户端
2. 客户端接收响应并处理

## API 响应格式

系统使用统一的 JSON 响应格式：

### 成功响应

```json
{
    "status": "success",
    "data": { ... }
}
```

### 错误响应

```json
{
    "status": "error",
    "error": "错误信息"
}
```

## 路由示例

### 1. 启动分析

```python
async def start_analysis(self, request):
    try:
        data = await request.json()
        project_name = data.get('project_name')
        vuln_type = data.get('vuln_type')
        
        if not project_name or not vuln_type:
            return web.json_response({
                "status": "error",
                "error": "Missing required parameters"
            }, status=400)
        
        task = AnalysisTask(project_name=project_name, vuln_type=vuln_type)
        task_id = self.queue_manager.add_task(task)
        
        return web.json_response({
            "status": "success",
            "data": {"task_id": task_id}
        })
    except Exception as e:
        return web.json_response({
            "status": "error",
            "error": str(e)
        }, status=500)
```

### 2. 获取分析状态

```python
async def get_analysis_status(self, request):
    try:
        status = self.queue_manager.get_status()
        return web.json_response({
            "status": "success",
            "data": status
        })
    except Exception as e:
        return web.json_response({
            "status": "error",
            "error": str(e)
        }, status=500)
```

### 3. 获取项目列表

```python
async def list_challenges(self, request):
    try:
        challenges_dir = Config().CHALLENGES_DIR
        challenges = []
        
        for item in os.listdir(challenges_dir):
            item_path = os.path.join(challenges_dir, item)
            if os.path.isdir(item_path):
                challenges.append(item)
        
        return web.json_response({
            "status": "success",
            "data": {"challenges": challenges}
        })
    except Exception as e:
        return web.json_response({
            "status": "error",
            "error": str(e)
        }, status=500)
```

## 错误处理

系统使用 try-except 结构处理请求处理过程中可能出现的异常：

```python
async def some_handler(self, request):
    try:
        # 处理请求
        # ...
        return web.json_response({
            "status": "success",
            "data": { ... }
        })
    except Exception as e:
        return web.json_response({
            "status": "error",
            "error": str(e)
        }, status=500)
```

## 中间件

系统可以使用 aiohttp 中间件处理所有请求和响应：

```python
@web.middleware
async def error_middleware(request, handler):
    try:
        return await handler(request)
    except web.HTTPException as ex:
        return web.json_response({
            "status": "error",
            "error": str(ex)
        }, status=ex.status)
    except Exception as e:
        return web.json_response({
            "status": "error",
            "error": str(e)
        }, status=500)
```

## 总结

路由系统是 YL-analysis 系统的重要组件，负责管理和处理所有 API 请求。通过模块化设计和基类继承机制，系统实现了路由的统一管理和灵活扩展。每个路由管理器负责一组相关的 API 路由，使得系统的 API 结构清晰、易于维护。系统还支持通过 WebSocket 向客户端推送实时更新，提供了更好的用户体验。