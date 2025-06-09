# 分析队列管理模块

## 概述

YL-analysis 系统的分析队列管理模块负责管理和调度漏洞分析任务。该模块实现了一个任务队列系统，确保分析任务按顺序执行，并提供任务状态的实时更新。本文档详细介绍了分析队列管理模块的架构和工作流程。

## 核心组件

### 1. AnalysisTask 类

`AnalysisTask` 类表示一个分析任务，包含任务的所有相关信息。

**主要属性**：
- `task_id`: 任务唯一标识符
- `project_name`: 项目名称
- `vuln_type`: 漏洞类型
- `status`: 任务状态（等待中、运行中、完成、失败、终止）
- `created_at`: 创建时间戳
- `started_at`: 开始时间戳
- `completed_at`: 完成时间戳
- `progress`: 任务进度（0-100）
- `result`: 分析结果

**主要方法**：
- `start()`: 标记任务开始
- `complete()`: 标记任务完成
- `fail()`: 标记任务失败
- `terminate()`: 标记任务终止
- `update_progress()`: 更新任务进度
- `to_dict()`: 将任务转换为字典格式

### 2. AnalysisQueueManager 类

`AnalysisQueueManager` 类是分析队列管理的核心，负责管理任务队列和执行分析任务。

**主要属性**：
- `queue`: 任务队列
- `current_task`: 当前正在执行的任务
- `lock`: 线程锁，用于保护共享资源
- `worker_thread`: 工作线程
- `listeners`: 状态更新监听器列表

**主要方法**：
- `add_task()`: 添加分析任务到队列
- `_start_worker()`: 启动工作线程
- `_process_queue()`: 处理队列中的任务
- `_perform_analysis()`: 执行分析任务
- `_notify_status_updated()`: 通知任务状态更新
- `_notify_queue_updated()`: 通知队列状态更新
- `get_status()`: 获取队列和任务状态
- `add_listener()`: 添加状态更新监听器
- `clear_queue()`: 清空任务队列
- `stop_current_task()`: 停止当前任务

## 工作流程

### 1. 任务创建和添加

1. 通过 API 或其他方式创建 `AnalysisTask` 对象
2. 调用 `AnalysisQueueManager.add_task()` 方法将任务添加到队列
3. 如果工作线程未运行，启动工作线程
4. 通知所有监听器队列已更新

```python
def add_task(self, task):
    with self.lock:
        self.queue.append(task)
        if not self.worker_thread or not self.worker_thread.is_alive():
            self._start_worker()
    self._notify_queue_updated()
    return task.task_id
```

### 2. 任务处理

1. 工作线程从队列中获取任务
2. 更新任务状态为「运行中」
3. 调用 `_perform_analysis()` 方法执行分析
4. 根据分析结果更新任务状态（完成或失败）
5. 通知所有监听器任务状态已更新

```python
def _process_queue(self):
    while True:
        with self.lock:
            if not self.queue:
                self.current_task = None
                break
            self.current_task = self.queue.pop(0)

        try:
            self.current_task.start()
            self._notify_status_updated(self.current_task)
            result = self._perform_analysis(self.current_task)
            self.current_task.complete(result)
        except Exception as e:
            self.current_task.fail(str(e))
        finally:
            self._notify_status_updated(self.current_task)
```

### 3. 分析执行

1. 获取项目目录路径
2. 调用 `vuln_detector.analyze_challenge()` 函数执行漏洞分析
3. 返回分析结果

```python
def _perform_analysis(self, task):
    project_dir = os.path.join(config.CHALLENGES_DIR, task.project_name)
    result = vuln_detector.analyze_challenge(project_dir, task.vuln_type, task)
    return result
```

### 4. 状态更新和通知

1. 任务状态变化时，调用 `_notify_status_updated()` 方法
2. 队列状态变化时，调用 `_notify_queue_updated()` 方法
3. 这些方法会通知所有注册的监听器

```python
def _notify_status_updated(self, task):
    for listener in self.listeners:
        try:
            listener.on_status_updated(task)
        except Exception as e:
            print(f"Error notifying listener: {e}")

def _notify_queue_updated(self):
    for listener in self.listeners:
        try:
            listener.on_queue_updated()
        except Exception as e:
            print(f"Error notifying listener: {e}")
```

### 5. 任务状态获取

1. 调用 `get_status()` 方法获取队列和任务状态
2. 返回包含当前任务和队列中任务的字典

```python
def get_status(self):
    with self.lock:
        status = {
            "current_task": self.current_task.to_dict() if self.current_task else None,
            "queue": [task.to_dict() for task in self.queue]
        }
    return status
```

### 6. 任务控制

1. 清空队列：调用 `clear_queue()` 方法
2. 停止当前任务：调用 `stop_current_task()` 方法

```python
def clear_queue(self):
    with self.lock:
        self.queue.clear()
    self._notify_queue_updated()

def stop_current_task(self):
    with self.lock:
        if self.current_task and self.current_task.status == "running":
            self.current_task.terminate()
            self._notify_status_updated(self.current_task)
            return True
    return False
```

## 监听器接口

任何想要接收队列和任务状态更新的组件都可以实现监听器接口，并通过 `add_listener()` 方法注册。

**监听器接口**：
- `on_status_updated(task)`: 当任务状态更新时调用
- `on_queue_updated()`: 当队列状态更新时调用

```python
def add_listener(self, listener):
    if hasattr(listener, 'on_status_updated') and hasattr(listener, 'on_queue_updated'):
        self.listeners.append(listener)
    else:
        raise ValueError("Listener must implement on_status_updated and on_queue_updated methods")
```

## 任务状态

任务可以处于以下状态之一：

1. **等待中 (waiting)**：任务已添加到队列，等待执行
2. **运行中 (running)**：任务正在执行
3. **完成 (completed)**：任务已成功完成
4. **失败 (failed)**：任务执行失败
5. **终止 (terminated)**：任务被手动终止

## 与其他模块的交互

### 1. 与 API 路由的交互

`AnalysisRouter` 类通过 `start_analysis` 方法创建分析任务并添加到队列：

```python
async def start_analysis(self, request):
    data = await request.json()
    project_name = data.get('project_name')
    vuln_type = data.get('vuln_type')
    
    if not project_name or not vuln_type:
        return web.json_response({"error": "Missing required parameters"}, status=400)
    
    task = AnalysisTask(project_name=project_name, vuln_type=vuln_type)
    task_id = self.queue_manager.add_task(task)
    
    return web.json_response({"task_id": task_id})
```

### 2. 与 WebSocket 的交互

`WebSocketHandler` 类实现了监听器接口，通过 WebSocket 向客户端发送状态更新：

```python
def on_status_updated(self, task):
    message = {
        "type": "status_updated",
        "task": task.to_dict()
    }
    asyncio.create_task(self.send_message(message))

def on_queue_updated(self):
    message = {
        "type": "queue_updated",
        "status": self.queue_manager.get_status()
    }
    asyncio.create_task(self.send_message(message))
```

### 3. 与漏洞检测器的交互

`AnalysisQueueManager` 类通过 `_perform_analysis()` 方法调用 `vuln_detector.analyze_challenge()` 函数执行漏洞分析：

```python
def _perform_analysis(self, task):
    project_dir = os.path.join(config.CHALLENGES_DIR, task.project_name)
    result = vuln_detector.analyze_challenge(project_dir, task.vuln_type, task)
    return result
```

## 进度更新

漏洞检测器可以通过 `AnalysisTask` 对象的 `update_progress()` 方法更新任务进度：

```python
def update_progress(self, progress):
    self.progress = progress
```

这样，前端可以实时显示分析任务的进度。

## 并发控制

`AnalysisQueueManager` 类使用线程锁 (`threading.Lock`) 保护共享资源，确保线程安全：

```python
def __init__(self):
    self.queue = []
    self.current_task = None
    self.lock = threading.Lock()
    self.worker_thread = None
    self.listeners = []
```

所有访问或修改共享资源的方法都使用 `with self.lock:` 语句确保线程安全。

## 错误处理

`_process_queue()` 方法使用 try-except-finally 结构处理分析过程中可能出现的异常：

```python
try:
    self.current_task.start()
    self._notify_status_updated(self.current_task)
    result = self._perform_analysis(self.current_task)
    self.current_task.complete(result)
except Exception as e:
    self.current_task.fail(str(e))
finally:
    self._notify_status_updated(self.current_task)
```

如果分析过程中出现异常，任务状态将被设置为「失败」，并记录错误信息。

## 总结

分析队列管理模块是 YL-analysis 系统的核心组件之一，它提供了一个可靠的任务队列系统，确保分析任务按顺序执行，并提供任务状态的实时更新。通过线程安全的设计和完善的错误处理机制，该模块能够稳定地管理和执行漏洞分析任务，为系统的其他组件提供可靠的服务。