# 配置管理模块

## 概述

YL-analysis 系统的配置管理模块负责加载、存储和管理系统配置，为其他模块提供统一的配置访问接口。该模块定义了系统的基本路径、目录结构和运行参数，确保系统各组件能够正确访问资源和数据。本文档详细介绍了配置管理模块的架构和工作流程。

## 核心组件

### Config 类

`Config` 类是配置管理模块的核心，负责定义和管理系统配置。

**主要属性**：
- `BASE_DIR`: 项目基础目录
- `CHALLENGES_DIR`: 项目目录
- `LOGS_DIR`: 日志目录
- `STATIC_DIR`: 静态文件目录
- `MODELS`: 支持的 AI 模型列表
- `DEFAULT_MODEL`: 默认 AI 模型
- `API_KEYS`: API 密钥配置

**主要方法**：
- `__init__()`: 初始化配置对象
- `ensure_directories()`: 确保必要的目录存在
- `load_settings()`: 加载设置文件
- `save_settings()`: 保存设置到文件
- `get_setting()`: 获取设置值
- `update_setting()`: 更新设置值

```python
class Config:
    def __init__(self):
        # 基本路径
        self.BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.CHALLENGES_DIR = os.path.join(self.BASE_DIR, "challenges")
        self.LOGS_DIR = os.path.join(self.BASE_DIR, "logs")
        self.STATIC_DIR = os.path.join(self.BASE_DIR, "static")
        self.SETTINGS_FILE = os.path.join(self.BASE_DIR, "settings.json")
        
        # AI 模型配置
        self.MODELS = ["gpt-3.5-turbo", "gpt-4", "claude-v1"]
        self.DEFAULT_MODEL = "gpt-3.5-turbo"
        
        # API 密钥配置
        self.API_KEYS = {
            "openai": "",
            "anthropic": ""
        }
        
        # 确保目录存在
        self.ensure_directories()
        
        # 加载设置
        self.settings = self.load_settings()
        
    def ensure_directories(self):
        """确保必要的目录存在"""
        os.makedirs(self.CHALLENGES_DIR, exist_ok=True)
        os.makedirs(self.LOGS_DIR, exist_ok=True)
        os.makedirs(self.STATIC_DIR, exist_ok=True)
        
    def load_settings(self):
        """加载设置文件"""
        if os.path.exists(self.SETTINGS_FILE):
            try:
                with open(self.SETTINGS_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading settings: {e}")
        
        # 默认设置
        default_settings = {
            "model": self.DEFAULT_MODEL,
            "api_keys": self.API_KEYS,
            "max_tokens": 4096,
            "temperature": 0.7
        }
        
        # 保存默认设置
        self.save_settings(default_settings)
        
        return default_settings
        
    def save_settings(self, settings):
        """保存设置到文件"""
        try:
            with open(self.SETTINGS_FILE, 'w') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            print(f"Error saving settings: {e}")
        
    def get_setting(self, key, default=None):
        """获取设置值"""
        return self.settings.get(key, default)
        
    def update_setting(self, key, value):
        """更新设置值"""
        self.settings[key] = value
        self.save_settings(self.settings)
```

## 配置文件

系统使用 JSON 格式的配置文件存储设置：

```json
{
    "model": "gpt-3.5-turbo",
    "api_keys": {
        "openai": "sk-...",
        "anthropic": "sk-..."
    },
    "max_tokens": 4096,
    "temperature": 0.7
}
```

## 目录结构

系统定义了以下目录结构：

```
/
├── challenges/    # 项目目录
├── logs/          # 日志目录
├── static/        # 静态文件目录
├── settings.json  # 设置文件
└── ...
```

## 配置加载流程

### 1. 初始化配置对象

1. 创建 `Config` 对象
2. 定义基本路径和目录
3. 定义 AI 模型配置和 API 密钥配置

### 2. 确保目录存在

1. 调用 `ensure_directories()` 方法
2. 创建项目目录、日志目录和静态文件目录（如果不存在）

### 3. 加载设置

1. 调用 `load_settings()` 方法
2. 如果设置文件存在，从文件加载设置
3. 如果设置文件不存在或加载失败，使用默认设置并保存到文件

## 配置访问流程

### 1. 获取设置值

1. 调用 `get_setting()` 方法
2. 传入设置键和默认值
3. 返回设置值或默认值

```python
def get_model(self):
    return self.get_setting("model", self.DEFAULT_MODEL)
```

### 2. 更新设置值

1. 调用 `update_setting()` 方法
2. 传入设置键和新值
3. 更新内存中的设置
4. 保存设置到文件

```python
def set_model(self, model):
    if model in self.MODELS:
        self.update_setting("model", model)
        return True
    return False
```

## 与其他模块的交互

### 1. 与服务管理器的交互

`ServiceManager` 类在初始化时创建配置对象：

```python
def __init__(self):
    if not hasattr(self, "initialized") or not self.initialized:
        self.config = Config()
        # ...
```

### 2. 与设置路由的交互

`SettingsRouter` 类使用配置对象处理设置相关的 API 请求：

```python
class SettingsRouter(RouterBase):
    def __init__(self):
        self.config = ServiceManager().config
        
    async def get_settings(self, request):
        settings = {
            "model": self.config.get_setting("model"),
            "models": self.config.MODELS,
            "max_tokens": self.config.get_setting("max_tokens"),
            "temperature": self.config.get_setting("temperature")
        }
        return web.json_response({"status": "success", "data": settings})
        
    async def update_settings(self, request):
        data = await request.json()
        
        if "model" in data:
            if data["model"] not in self.config.MODELS:
                return web.json_response({
                    "status": "error",
                    "error": f"Invalid model. Supported models: {', '.join(self.config.MODELS)}"
                }, status=400)
            self.config.update_setting("model", data["model"])
            
        if "max_tokens" in data:
            try:
                max_tokens = int(data["max_tokens"])
                if max_tokens < 1 or max_tokens > 8192:
                    return web.json_response({
                        "status": "error",
                        "error": "max_tokens must be between 1 and 8192"
                    }, status=400)
                self.config.update_setting("max_tokens", max_tokens)
            except ValueError:
                return web.json_response({
                    "status": "error",
                    "error": "max_tokens must be an integer"
                }, status=400)
                
        if "temperature" in data:
            try:
                temperature = float(data["temperature"])
                if temperature < 0 or temperature > 2:
                    return web.json_response({
                        "status": "error",
                        "error": "temperature must be between 0 and 2"
                    }, status=400)
                self.config.update_setting("temperature", temperature)
            except ValueError:
                return web.json_response({
                    "status": "error",
                    "error": "temperature must be a number"
                }, status=400)
                
        return web.json_response({"status": "success"})
```

### 3. 与 LLM 服务的交互

`LLMService` 类使用配置对象获取 AI 模型和 API 密钥：

```python
class LLMService:
    def __init__(self):
        self.config = ServiceManager().config
        
    async def get_completion(self, prompt, max_tokens=None, temperature=None):
        model = self.config.get_setting("model")
        max_tokens = max_tokens or self.config.get_setting("max_tokens")
        temperature = temperature or self.config.get_setting("temperature")
        
        if model.startswith("gpt-"):
            return await self._get_openai_completion(prompt, model, max_tokens, temperature)
        elif model.startswith("claude-"):
            return await self._get_anthropic_completion(prompt, model, max_tokens, temperature)
        else:
            raise ValueError(f"Unsupported model: {model}")
            
    async def _get_openai_completion(self, prompt, model, max_tokens, temperature):
        api_key = self.config.get_setting("api_keys", {}).get("openai")
        if not api_key:
            raise ValueError("OpenAI API key not configured")
            
        # 使用 OpenAI API
        # ...
        
    async def _get_anthropic_completion(self, prompt, model, max_tokens, temperature):
        api_key = self.config.get_setting("api_keys", {}).get("anthropic")
        if not api_key:
            raise ValueError("Anthropic API key not configured")
            
        # 使用 Anthropic API
        # ...
```

## 环境变量支持

系统可以通过环境变量覆盖配置文件中的设置：

```python
def __init__(self):
    # ...
    
    # 从环境变量加载 API 密钥
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if openai_api_key:
        self.API_KEYS["openai"] = openai_api_key
        
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_api_key:
        self.API_KEYS["anthropic"] = anthropic_api_key
        
    # ...
```

## 命令行参数支持

系统可以通过命令行参数设置运行参数：

```python
def main():
    parser = argparse.ArgumentParser(description='YL-analysis Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind the server to')
    parser.add_argument('--log-level', default='info', choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Logging level')
    args = parser.parse_args()
    
    # 设置日志级别
    log_level = getattr(logging, args.log_level.upper())
    logging.getLogger().setLevel(log_level)
    
    # 启动应用
    app = api.create_app()
    web.run_app(app, host=args.host, port=args.port, access_log=None)
```

## 配置验证

系统在更新设置时会验证设置值的有效性：

```python
async def update_settings(self, request):
    data = await request.json()
    
    if "model" in data:
        if data["model"] not in self.config.MODELS:
            return web.json_response({
                "status": "error",
                "error": f"Invalid model. Supported models: {', '.join(self.config.MODELS)}"
            }, status=400)
        self.config.update_setting("model", data["model"])
        
    if "max_tokens" in data:
        try:
            max_tokens = int(data["max_tokens"])
            if max_tokens < 1 or max_tokens > 8192:
                return web.json_response({
                    "status": "error",
                    "error": "max_tokens must be between 1 and 8192"
                }, status=400)
            self.config.update_setting("max_tokens", max_tokens)
        except ValueError:
            return web.json_response({
                "status": "error",
                "error": "max_tokens must be an integer"
            }, status=400)
            
    # ...
```

## 总结

配置管理模块是 YL-analysis 系统的基础组件，负责加载、存储和管理系统配置。通过提供统一的配置访问接口，该模块确保系统各组件能够正确访问资源和数据。配置管理模块支持从文件、环境变量和命令行参数加载配置，并提供配置验证机制，确保配置的有效性。该模块的设计使得系统能够灵活地适应不同的运行环境和用户需求。