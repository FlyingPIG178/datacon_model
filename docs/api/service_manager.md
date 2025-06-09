# 服务管理模块

## 概述

YL-analysis 系统的服务管理模块是整个后端 API 的核心，负责应用的初始化、配置加载、路由设置和生命周期管理。该模块采用单例模式实现，确保整个应用中只有一个服务管理器实例。本文档详细介绍了服务管理模块的架构和工作流程。

## 核心组件

### ServiceManager 类

`ServiceManager` 类是服务管理模块的核心，负责管理整个应用的生命周期。

**主要属性**：
- `_instance`: 类变量，用于实现单例模式
- `config`: 配置对象
- `app`: aiohttp 应用对象
- `startup_callbacks`: 启动回调函数列表
- `shutdown_callbacks`: 关闭回调函数列表

**主要方法**：
- `__new__()`: 实现单例模式
- `__init__()`: 初始化服务管理器
- `register_startup_callback()`: 注册启动回调函数
- `register_shutdown_callback()`: 注册关闭回调函数
- `_on_startup()`: 应用启动时执行回调函数
- `_on_shutdown()`: 应用关闭时执行回调函数
- `_ensure_directories()`: 确保必要的目录存在
- `init_app()`: 初始化 aiohttp 应用
- `create_app()`: 创建 aiohttp 应用

## 单例模式实现

`ServiceManager` 类使用 `__new__()` 方法实现单例模式，确保整个应用中只有一个服务管理器实例：

```python
@classmethod
def __new__(cls, *args, **kwargs):
    if not hasattr(cls, "_instance") or cls._instance is None:
        cls._instance = super(ServiceManager, cls).__new__(cls)
    return cls._instance
```

## 初始化流程

### 1. 服务管理器初始化

```python
def __init__(self):
    if not hasattr(self, "initialized") or not self.initialized:
        self.config = Config()
        self.app = None
        self.startup_callbacks = []
        self.shutdown_callbacks = []
        self.initialized = True
```

初始化过程中，服务管理器会：
1. 创建配置对象
2. 初始化应用对象为 None
3. 初始化启动和关闭回调函数列表
4. 标记初始化完成

### 2. 应用初始化

```python
def init_app(self):
    self.app = web.Application()
    self._ensure_directories()
    setup_all_routes(self.app)
    self.app.on_startup.append(self._on_startup)
    self.app.on_shutdown.append(self._on_shutdown)
    return self.app
```

应用初始化过程中，服务管理器会：
1. 创建 aiohttp 应用对象
2. 确保必要的目录存在
3. 设置所有路由
4. 注册启动和关闭钩子
5. 返回应用对象

### 3. 确保目录存在

```python
def _ensure_directories(self):
    os.makedirs(self.config.CHALLENGES_DIR, exist_ok=True)
    os.makedirs(self.config.LOGS_DIR, exist_ok=True)
```

服务管理器会确保以下目录存在：
1. 项目目录（CHALLENGES_DIR）
2. 日志目录（LOGS_DIR）

## 回调函数管理

### 1. 注册回调函数

```python
def register_startup_callback(self, callback):
    self.startup_callbacks.append(callback)

def register_shutdown_callback(self, callback):
    self.shutdown_callbacks.append(callback)
```

服务管理器允许其他组件注册启动和关闭回调函数，这些函数将在应用启动和关闭时执行。

### 2. 执行回调函数

```python
async def _on_startup(self, app):
    for callback in self.startup_callbacks:
        if asyncio.iscoroutinefunction(callback):
            await callback(app)
        else:
            callback(app)

async def _on_shutdown(self, app):
    for callback in self.shutdown_callbacks:
        if asyncio.iscoroutinefunction(callback):
            await callback(app)
        else:
            callback(app)
```

服务管理器会在应用启动和关闭时执行注册的回调函数。它会检查回调函数是否是协程函数，如果是，则使用 `await` 调用；否则，直接调用。

## 应用创建

```python
def create_app(self):
    if self.app is None:
        self.init_app()
    return self.app
```

`create_app()` 方法是应用的工厂函数，它会检查应用对象是否已经存在，如果不存在，则初始化应用；然后返回应用对象。

## 与其他模块的交互

### 1. 与路由系统的交互

服务管理器通过 `setup_all_routes()` 函数设置所有路由：

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

每个路由管理器都实现了 `add_routes()` 方法，用于向应用添加路由。

### 2. 与配置系统的交互

服务管理器在初始化时创建配置对象，并在确保目录存在时使用配置中的路径：

```python
def __init__(self):
    if not hasattr(self, "initialized") or not self.initialized:
        self.config = Config()
        # ...

def _ensure_directories(self):
    os.makedirs(self.config.CHALLENGES_DIR, exist_ok=True)
    os.makedirs(self.config.LOGS_DIR, exist_ok=True)
```

### 3. 与分析队列管理器的交互

分析队列管理器可以注册启动和关闭回调函数：

```python
def __init__(self):
    # ...
    service_manager = ServiceManager()
    service_manager.register_startup_callback(self.start)
    service_manager.register_shutdown_callback(self.stop)

def start(self, app):
    # 启动队列管理器
    # ...

def stop(self, app):
    # 停止队列管理器
    # ...
```

### 4. 与终端服务的交互

终端服务也可以注册启动和关闭回调函数：

```python
def __init__(self):
    # ...
    service_manager = ServiceManager()
    service_manager.register_startup_callback(self.start)
    service_manager.register_shutdown_callback(self.stop)

def start(self, app):
    # 启动终端服务
    # ...

def stop(self, app):
    # 停止终端服务
    # ...
```

## 应用启动流程

1. 在 `server.py` 中，调用 `api.create_app()` 创建应用：

```python
app = api.create_app()
```

2. `api.create_app()` 调用 `ServiceManager.create_app()`：

```python
def create_app():
    return ServiceManager().create_app()
```

3. `ServiceManager.create_app()` 调用 `init_app()` 初始化应用：

```python
def create_app(self):
    if self.app is None:
        self.init_app()
    return self.app
```

4. `init_app()` 创建应用对象，确保目录存在，设置路由，注册钩子：

```python
def init_app(self):
    self.app = web.Application()
    self._ensure_directories()
    setup_all_routes(self.app)
    self.app.on_startup.append(self._on_startup)
    self.app.on_shutdown.append(self._on_shutdown)
    return self.app
```

5. 在 `server.py` 中，调用 `web.run_app()` 启动应用：

```python
web.run_app(app, host=args.host, port=args.port, access_log=None)
```

6. 应用启动时，执行 `_on_startup()` 方法，调用所有注册的启动回调函数。

## 应用关闭流程

1. 当应用收到关闭信号时，执行 `_on_shutdown()` 方法。
2. `_on_shutdown()` 方法调用所有注册的关闭回调函数。
3. 各组件执行清理操作，释放资源。

## 配置管理

服务管理器使用 `Config` 类管理配置：

```python
class Config:
    def __init__(self):
        self.BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.CHALLENGES_DIR = os.path.join(self.BASE_DIR, "challenges")
        self.LOGS_DIR = os.path.join(self.BASE_DIR, "logs")
        self.STATIC_DIR = os.path.join(self.BASE_DIR, "static")
        self.ensure_directories()
        
    def ensure_directories(self):
        os.makedirs(self.CHALLENGES_DIR, exist_ok=True)
        os.makedirs(self.LOGS_DIR, exist_ok=True)
        os.makedirs(self.STATIC_DIR, exist_ok=True)
```

`Config` 类定义了应用的基本路径和目录，并确保这些目录存在。

## 总结

服务管理模块是 YL-analysis 系统的核心组件，负责应用的初始化、配置加载、路由设置和生命周期管理。通过单例模式和回调函数机制，该模块提供了一个灵活、可扩展的应用框架，使其他组件能够方便地集成到应用中。服务管理器的设计使得应用的启动和关闭过程变得有序和可控，确保各组件能够正确地初始化和清理资源。