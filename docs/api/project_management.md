# 项目管理模块

## 概述

YL-analysis 系统的项目管理模块负责管理代码项目的上传、存储、列表和删除操作。该模块提供了一组 API 接口，允许用户上传新项目、获取项目列表、查看项目详情和删除现有项目。本文档详细介绍了项目管理模块的架构和工作流程。

## 核心组件

### ProjectsRouter 类

`ProjectsRouter` 类是项目管理模块的核心，负责处理与项目相关的 API 请求。

**主要方法**：
- `add_routes()`: 向应用添加项目相关路由
- `list_challenges()`: 获取项目列表
- `get_challenge_details()`: 获取项目详情
- `upload_challenge()`: 上传新项目
- `delete_challenge()`: 删除项目

```python
class ProjectsRouter(RouterBase):
    def __init__(self):
        self.config = ServiceManager().config
        
    def add_routes(self, app):
        app.router.add_get('/api/list-challenges', self.list_challenges)
        app.router.add_get('/api/challenge-details', self.get_challenge_details)
        app.router.add_post('/api/upload-challenge', self.upload_challenge)
        app.router.add_delete('/api/delete-challenge', self.delete_challenge)
        
    async def list_challenges(self, request):
        """获取项目列表"""
        try:
            challenges_dir = self.config.CHALLENGES_DIR
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
            
    async def get_challenge_details(self, request):
        """获取项目详情"""
        try:
            challenge_name = request.query.get('name')
            if not challenge_name:
                return web.json_response({
                    "status": "error",
                    "error": "Missing challenge name"
                }, status=400)
                
            challenge_dir = os.path.join(self.config.CHALLENGES_DIR, challenge_name)
            if not os.path.isdir(challenge_dir):
                return web.json_response({
                    "status": "error",
                    "error": f"Challenge '{challenge_name}' not found"
                }, status=404)
                
            # 获取项目文件列表
            files = []
            for root, _, filenames in os.walk(challenge_dir):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, challenge_dir)
                    files.append({
                        "path": rel_path,
                        "size": os.path.getsize(file_path)
                    })
            
            return web.json_response({
                "status": "success",
                "data": {
                    "name": challenge_name,
                    "files": files
                }
            })
        except Exception as e:
            return web.json_response({
                "status": "error",
                "error": str(e)
            }, status=500)
            
    async def upload_challenge(self, request):
        """上传新项目"""
        try:
            reader = await request.multipart()
            
            # 获取项目名称
            field = await reader.next()
            if field.name != 'name':
                return web.json_response({
                    "status": "error",
                    "error": "First field must be 'name'"
                }, status=400)
                
            challenge_name = await field.text()
            if not challenge_name:
                return web.json_response({
                    "status": "error",
                    "error": "Challenge name cannot be empty"
                }, status=400)
                
            # 检查项目名称是否合法
            if not re.match(r'^[a-zA-Z0-9_-]+$', challenge_name):
                return web.json_response({
                    "status": "error",
                    "error": "Challenge name can only contain letters, numbers, underscores and hyphens"
                }, status=400)
                
            # 检查项目是否已存在
            challenge_dir = os.path.join(self.config.CHALLENGES_DIR, challenge_name)
            if os.path.exists(challenge_dir):
                return web.json_response({
                    "status": "error",
                    "error": f"Challenge '{challenge_name}' already exists"
                }, status=400)
                
            # 创建项目目录
            os.makedirs(challenge_dir)
            
            # 处理项目文件
            field = await reader.next()
            if field.name != 'file':
                # 删除已创建的目录
                shutil.rmtree(challenge_dir)
                return web.json_response({
                    "status": "error",
                    "error": "Second field must be 'file'"
                }, status=400)
                
            # 保存项目文件
            filename = field.filename
            if not filename.endswith('.zip'):
                # 删除已创建的目录
                shutil.rmtree(challenge_dir)
                return web.json_response({
                    "status": "error",
                    "error": "File must be a ZIP archive"
                }, status=400)
                
            # 保存 ZIP 文件
            zip_path = os.path.join(challenge_dir, filename)
            with open(zip_path, 'wb') as f:
                while True:
                    chunk = await field.read_chunk()
                    if not chunk:
                        break
                    f.write(chunk)
                    
            # 解压 ZIP 文件
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(challenge_dir)
                
            # 删除 ZIP 文件
            os.remove(zip_path)
            
            return web.json_response({
                "status": "success",
                "data": {"name": challenge_name}
            })
        except Exception as e:
            # 删除已创建的目录
            if 'challenge_dir' in locals() and os.path.exists(challenge_dir):
                shutil.rmtree(challenge_dir)
                
            return web.json_response({
                "status": "error",
                "error": str(e)
            }, status=500)
            
    async def delete_challenge(self, request):
        """删除项目"""
        try:
            data = await request.json()
            challenge_name = data.get('name')
            if not challenge_name:
                return web.json_response({
                    "status": "error",
                    "error": "Missing challenge name"
                }, status=400)
                
            challenge_dir = os.path.join(self.config.CHALLENGES_DIR, challenge_name)
            if not os.path.isdir(challenge_dir):
                return web.json_response({
                    "status": "error",
                    "error": f"Challenge '{challenge_name}' not found"
                }, status=404)
                
            # 删除项目目录
            shutil.rmtree(challenge_dir)
            
            return web.json_response({"status": "success"})
        except Exception as e:
            return web.json_response({
                "status": "error",
                "error": str(e)
            }, status=500)
```

## 项目存储结构

系统将项目存储在 `challenges` 目录下，每个项目有自己的子目录：

```
challenges/
├── project1/
│   ├── file1.py
│   ├── file2.py
│   └── ...
├── project2/
│   ├── file1.py
│   ├── file2.py
│   └── ...
└── ...
```

## 工作流程

### 1. 获取项目列表

1. 客户端发送 GET 请求到 `/api/list-challenges`
2. 服务器遍历 `challenges` 目录，获取所有子目录名称
3. 服务器返回项目列表

```http
GET /api/list-challenges HTTP/1.1
Host: localhost:8080
```

```json
{
    "status": "success",
    "data": {
        "challenges": ["project1", "project2", "project3"]
    }
}
```

### 2. 获取项目详情

1. 客户端发送 GET 请求到 `/api/challenge-details?name=project1`
2. 服务器检查项目是否存在
3. 服务器遍历项目目录，获取所有文件信息
4. 服务器返回项目详情

```http
GET /api/challenge-details?name=project1 HTTP/1.1
Host: localhost:8080
```

```json
{
    "status": "success",
    "data": {
        "name": "project1",
        "files": [
            {"path": "file1.py", "size": 1024},
            {"path": "file2.py", "size": 2048},
            {"path": "subdir/file3.py", "size": 3072}
        ]
    }
}
```

### 3. 上传新项目

1. 客户端发送 POST 请求到 `/api/upload-challenge`，包含项目名称和 ZIP 文件
2. 服务器检查项目名称是否合法
3. 服务器检查项目是否已存在
4. 服务器创建项目目录
5. 服务器保存并解压 ZIP 文件
6. 服务器返回成功响应

```http
POST /api/upload-challenge HTTP/1.1
Host: localhost:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="name"

project4
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="project4.zip"
Content-Type: application/zip

[ZIP file content]
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```json
{
    "status": "success",
    "data": {"name": "project4"}
}
```

### 4. 删除项目

1. 客户端发送 DELETE 请求到 `/api/delete-challenge`，包含项目名称
2. 服务器检查项目是否存在
3. 服务器删除项目目录
4. 服务器返回成功响应

```http
DELETE /api/delete-challenge HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{"name": "project4"}
```

```json
{"status": "success"}
```

## 项目验证

系统在上传项目时会进行以下验证：

1. **项目名称验证**：项目名称只能包含字母、数字、下划线和连字符
2. **项目存在验证**：检查项目是否已存在
3. **文件类型验证**：上传的文件必须是 ZIP 归档文件

## 错误处理

系统使用统一的错误处理机制，返回包含错误信息的 JSON 响应：

```json
{
    "status": "error",
    "error": "错误信息"
}
```

常见错误包括：

1. **缺少参数**：缺少必要的参数，如项目名称
2. **项目不存在**：请求的项目不存在
3. **项目已存在**：尝试上传的项目已存在
4. **无效的项目名称**：项目名称包含无效字符
5. **无效的文件类型**：上传的文件不是 ZIP 归档文件
6. **服务器错误**：服务器内部错误

## 与其他模块的交互

### 1. 与配置管理模块的交互

`ProjectsRouter` 类使用配置对象获取项目目录路径：

```python
def __init__(self):
    self.config = ServiceManager().config
    
def list_challenges(self, request):
    challenges_dir = self.config.CHALLENGES_DIR
    # ...
```

### 2. 与分析队列模块的交互

分析队列模块使用项目管理模块提供的项目路径执行漏洞分析：

```python
def _perform_analysis(self, task):
    project_dir = os.path.join(config.CHALLENGES_DIR, task.project_name)
    result = vuln_detector.analyze_challenge(project_dir, task.vuln_type, task)
    return result
```

### 3. 与漏洞检测器的交互

漏洞检测器使用项目管理模块提供的项目路径加载和分析代码：

```python
def analyze_challenge(project_dir, vuln_type, task=None):
    # 加载项目
    challenge = get_challenge(project_dir, vuln_type)
    
    # 分析漏洞
    result = run_single_challenge(challenge, task)
    
    return result
```

## 安全考虑

### 1. 路径遍历防护

系统使用 `os.path.join()` 和 `os.path.abspath()` 函数构建文件路径，防止路径遍历攻击：

```python
challenge_dir = os.path.join(self.config.CHALLENGES_DIR, challenge_name)
```

### 2. 文件类型验证

系统验证上传的文件是否为 ZIP 归档文件，防止上传恶意文件：

```python
if not filename.endswith('.zip'):
    # 删除已创建的目录
    shutil.rmtree(challenge_dir)
    return web.json_response({
        "status": "error",
        "error": "File must be a ZIP archive"
    }, status=400)
```

### 3. 项目名称验证

系统验证项目名称是否只包含安全字符，防止注入攻击：

```python
if not re.match(r'^[a-zA-Z0-9_-]+$', challenge_name):
    return web.json_response({
        "status": "error",
        "error": "Challenge name can only contain letters, numbers, underscores and hyphens"
    }, status=400)
```

### 4. 错误处理和清理

系统在发生错误时会清理已创建的资源，防止资源泄漏：

```python
try:
    # 处理请求
    # ...
except Exception as e:
    # 删除已创建的目录
    if 'challenge_dir' in locals() and os.path.exists(challenge_dir):
        shutil.rmtree(challenge_dir)
        
    return web.json_response({
        "status": "error",
        "error": str(e)
    }, status=500)
```

## 总结

项目管理模块是 YL-analysis 系统的重要组件，负责管理代码项目的上传、存储、列表和删除操作。通过提供一组 API 接口，该模块使用户能够方便地管理待分析的代码项目。项目管理模块采用了安全的文件处理机制，防止常见的安全漏洞，如路径遍历和文件上传攻击。该模块与系统的其他组件紧密集成，为漏洞分析提供了必要的代码资源。