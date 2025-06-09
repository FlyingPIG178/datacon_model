# API 架构设计

## 概述

YL-analysis 系统的后端 API 采用 aiohttp 框架实现，采用模块化的路由管理方式，所有路由管理器都继承自 `RouterBase` 抽象基类。系统使用 `ServiceManager` 单例来管理应用的生命周期和路由注册。

## 核心组件

### 1. 服务管理器 (ServiceManager)

`ServiceManager` 是 API 服务的核心管理组件，采用单例模式实现，确保整个应用中只有一个服务管理器实例。

**主要职责**：
- 初始化 aiohttp 应用
- 设置路由
- 管理应用的启动和关闭回调
- 确保必要的目录结构存在

**关键方法**：
- `init_app()`: 初始化应用，设置路由和钩子
- `register_startup_callback()`: 注册应用启动时的回调函数
- `register_shutdown_callback()`: 注册应用关闭时的回调函数
- `_on_startup()`: 应用启动时执行所有回调
- `_on_shutdown()`: 应用关闭时执行所有回调

### 2. 路由基类 (RouterBase)

`RouterBase` 是所有路由管理器的抽象基类，定义了路由管理器的基本接口。

**主要方法**：
- `add_routes(app: web.Application)`: 抽象方法，子类必须实现，用于添加路由到应用
- 各种响应辅助方法，如成功响应、错误响应等

### 3. 路由管理器

系统包含多个专门的路由管理器，每个管理器负责特定功能领域的 API 路由。

#### 3.1 分析路由管理器 (AnalysisRouter)

负责处理代码分析相关的 API 请求。

**主要路由**：
- `POST /api/start-analysis`: 启动分析任务
- `POST /api/stop-analysis`: 停止分析任务
- `GET /api/analysis-status`: 获取分析状态
- `GET /api/call-graph/{project_name}`: 获取调用图
- `GET /api/get-vul-types`: 列出所有可用的漏洞类型

#### 3.2 项目路由管理器 (ProjectsRouter)

负责管理项目相关的 API 请求。

**主要路由**：
- `GET /api/list-challenges`: 列出所有项目
- `DELETE /api/delete-project/{project_name}`: 删除项目
- `POST /api/upload-folder`: 上传项目文件夹

#### 3.3 设置路由管理器 (SettingsRouter)

负责处理系统设置相关的 API 请求。

**主要路由**：
- `GET /api/settings`: 获取系统设置
- `POST /api/settings`: 更新系统设置

#### 3.4 静态文件路由管理器 (StaticRouter)

负责管理静态文件的路由。

**主要功能**：
- 提供前端静态资源访问
- 处理 favicon.ico 请求
- 提供 SPA 应用的入口点

## 分析队列管理

### 1. 分析任务 (AnalysisTask)

表示一个代码分析任务，包含任务的状态和结果信息。

**主要属性**：
- `id`: 任务唯一标识符
- `project_name`: 项目名称
- `vul_type`: 漏洞类型
- `status`: 任务状态（排队中、运行中、已完成、失败、已终止）
- `start_time`: 开始时间
- `end_time`: 结束时间
- `progress`: 进度
- `results`: 分析结果

**主要方法**：
- `start()`: 开始任务
- `complete()`: 完成任务
- `fail()`: 任务失败
- `terminate()`: 终止任务
- `update_progress()`: 更新进度

### 2. 分析队列管理器 (AnalysisQueueManager)

负责管理和执行代码分析任务队列。

**主要属性**：
- `queue`: 任务队列
- `current_task`: 当前正在执行的任务
- `lock`: 线程锁，确保队列操作的线程安全
- `worker_thread`: 工作线程
- `should_stop`: 停止标志
- `listeners`: 状态监听器列表

**主要方法**：
- `add_task()`: 添加任务到队列
- `_start_worker()`: 启动工作线程
- `_process_queue()`: 处理队列中的任务
- `_perform_analysis()`: 执行分析
- `stop_current_task()`: 停止当前任务
- `clear_queue()`: 清空队列
- `get_status()`: 获取当前状态
- `add_listener()`: 添加状态监听器
- `_notify_status_updated()`: 通知状态更新
- `_notify_queue_updated()`: 通知队列更新

## 终端服务

### 终端服务 (TerminalService)

负责管理系统日志，并支持将日志实时推送给监听器。

**主要组件**：
- `LogHandler`: 自定义日志处理器，收集日志并通知监听器

**主要方法**：
- `add_listener()`: 添加日志监听器
- `remove_listener()`: 移除日志监听器
- `get_logs()`: 获取所有日志

## 配置管理

### 配置管理器 (Config)

负责管理应用程序的各种配置和路径。

**主要属性**：
- `root_dir`: 项目根目录
- `challenges_dir`: 挑战目录
- `results_dir`: 结果目录
- `settings_dir`: 设置目录

**主要方法**：
- `_ensure_directories()`: 确保必要的目录存在
- `get_challenge_path()`: 获取指定项目的挑战路径
- `get_result_path()`: 获取指定项目的结果路径
- `get_settings_path()`: 获取设置文件路径

## 应用启动流程

1. 创建 `ServiceManager` 单例
2. 调用 `create_app()` 函数获取配置好的 aiohttp 应用
3. 设置路由和钩子
4. 启动应用，监听指定端口
5. 执行注册的启动回调

## API 响应格式

系统 API 采用统一的 JSON 响应格式：

**成功响应**：
```json
{
  "status": "success",
  "data": { ... }
}
```

**错误响应**：
```json
{
  "status": "error",
  "message": "错误信息"
}
```

## WebSocket 通知

系统使用 WebSocket 实现实时通知功能，包括：

- 分析状态更新通知
- 队列更新通知
- 日志更新通知

这些通知使用监听器模式实现，当状态变化时，系统会通知所有注册的监听器。