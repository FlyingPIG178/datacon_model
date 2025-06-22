### 终端服务模块

#### 概述

YL-analysis 系统的终端服务模块负责管理系统日志和终端输出，提供实时日志捕获和转发功能。该模块通过拦截标准输出和标准错误流，并推送给客户端。本文档详细介绍了终端服务模块的架构和工作流程。

#### 核心组件

##### 1. LogHandler 类

`LogHandler` 类继承自 `logging.Handler`，负责处理日志记录并转发给监听器。

**主要属性**：
- `listeners`: 日志监听器列表

**主要方法**：
- `emit()`: 处理日志记录
- `add_listener()`: 添加日志监听器
- `remove_listener()`: 移除日志监听器

```python
class LogHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self.listeners = []
        
    def emit(self, record):
        log_entry = self.format(record)
        for listener in self.listeners:
            try:
                listener.on_log(log_entry, record.levelname.lower())
            except Exception as e:
                print(f"Error notifying listener: {e}")
                
    def add_listener(self, listener):
        if hasattr(listener, 'on_log'):
            self.listeners.append(listener)
        else:
            raise ValueError("Listener must implement on_log method")
            
    def remove_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)
```

##### 2. TerminalService 类

`TerminalService` 类是终端服务模块的核心，负责管理日志处理器和输出流重定向。

**主要属性**：
- `log_handler`: 日志处理器
- `stdout_listener`: 标准输出监听器
- `stderr_listener`: 标准错误监听器
- `original_stdout`: 原始标准输出
- `original_stderr`: 原始标准错误
- `log_file`: 日志文件

**主要方法**：
- `start()`: 启动终端服务
- `stop()`: 停止终端服务
- `add_listener()`: 添加日志监听器
- `remove_listener()`: 移除日志监听器

```python
class TerminalService:
    def __init__(self):
        self.log_handler = LogHandler()
        self.stdout_listener = None
        self.stderr_listener = None
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.log_file = None
        
        # 注册服务管理器回调
        service_manager = ServiceManager()
        service_manager.register_startup_callback(self.start)
        service_manager.register_shutdown_callback(self.stop)
        
    def start(self, app):
        # 配置日志处理器
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        
        # 添加日志处理器到根日志记录器
        root_logger = logging.getLogger()
        root_logger.addHandler(self.log_handler)
        
        # 设置日志级别
        root_logger.setLevel(logging.INFO)
        
        # 创建日志文件
        log_dir = ServiceManager().config.LOGS_DIR
        log_file_path = os.path.join(log_dir, f"app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        self.log_file = open(log_file_path, 'a', encoding='utf-8')
        
        # 重定向标准输出和标准错误
        self.stdout_listener = StdoutListener(self.original_stdout, self.log_file, self.log_handler)
        self.stderr_listener = StdoutListener(self.original_stderr, self.log_file, self.log_handler, is_error=True)
        sys.stdout = self.stdout_listener
        sys.stderr = self.stderr_listener
        
        print(f"Terminal service started, logging to {log_file_path}")
        
    def stop(self, app):
        # 恢复标准输出和标准错误
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        
        # 关闭日志文件
        if self.log_file:
            self.log_file.close()
            
        # 移除日志处理器
        root_logger = logging.getLogger()
        root_logger.removeHandler(self.log_handler)
        
        print("Terminal service stopped")
        
    def add_listener(self, listener):
        self.log_handler.add_listener(listener)
        
    def remove_listener(self, listener):
        self.log_handler.remove_listener(listener)
```

##### 3. StdoutListener 类

`StdoutListener` 类负责拦截标准输出和标准错误流，将输出内容转发给日志处理器和原始输出流。

**主要属性**：
- `original_stream`: 原始输出流
- `log_file`: 日志文件
- `log_handler`: 日志处理器
- `is_error`: 是否为错误流

**主要方法**：
- `write()`: 写入输出内容
- `flush()`: 刷新输出流

```python
class StdoutListener:
    def __init__(self, original_stream, log_file, log_handler, is_error=False):
        self.original_stream = original_stream
        self.log_file = log_file
        self.log_handler = log_handler
        self.is_error = is_error
        
    def write(self, text):
        # 写入原始输出流
        self.original_stream.write(text)
        
        # 写入日志文件
        if self.log_file:
            self.log_file.write(text)
            self.log_file.flush()
            
        # 通知监听器
        if text.strip():
            log_type = "error" if self.is_error else "info"
            for listener in self.log_handler.listeners:
                try:
                    listener.on_log(text, log_type)
                except Exception as e:
                    self.original_stream.write(f"Error notifying listener: {e}\n")
                    
    def flush(self):
        self.original_stream.flush()
        if self.log_file:
            self.log_file.flush()
```

#### 监听器接口

任何想要接收日志更新的组件都可以实现监听器接口，并通过 `add_listener()` 方法注册。

**监听器接口**：
- `on_log(log_entry, log_type)`: 当有新的日志条目时调用

```python
class WebSocketLogListener:
    def __init__(self, websocket):
        self.websocket = websocket
        
    async def on_log(self, log_entry, log_type):
        message = {
            "type": "log",
            "log_entry": log_entry,
            "log_type": log_type
        }
        await self.websocket.send_json(message)
```

#### 工作流程

##### 1. 服务启动

1. 在应用启动时，`TerminalService.start()` 方法被调用
2. 配置日志处理器并添加到根日志记录器
3. 创建日志文件
4. 重定向标准输出和标准错误流

##### 2. 日志捕获

1. 当系统输出日志时，日志记录被发送到 `LogHandler`
2. `LogHandler.emit()` 方法处理日志记录并转发给所有监听器

##### 3. 标准输出捕获

1. 当系统使用 `print()` 函数或直接写入 `sys.stdout` 时，输出被 `StdoutListener` 拦截
2. `StdoutListener.write()` 方法将输出内容写入原始输出流、日志文件，并通知所有监听器

##### 4. 标准错误捕获

1. 当系统写入 `sys.stderr` 时，输出被 `StdoutListener` 拦截（`is_error=True`）
2. `StdoutListener.write()` 方法将输出内容写入原始错误流、日志文件，并通知所有监听器

##### 5. 日志转发

1. 监听器接收到日志条目和日志类型
2. 监听器可以将日志转发给客户端或进行其他处理

##### 6. 服务停止

1. 在应用关闭时，`TerminalService.stop()` 方法被调用
2. 恢复标准输出和标准错误流
3. 关闭日志文件
4. 移除日志处理器

#### 与其他模块的交互

##### 1. 与服务管理器的交互

`TerminalService` 在初始化时注册启动和关闭回调函数：

```python
def __init__(self):
    # ...
    service_manager = ServiceManager()
    service_manager.register_startup_callback(self.start)
    service_manager.register_shutdown_callback(self.stop)
```

##### 3. 与漏洞检测器的交互

漏洞检测器可以使用标准的 Python 日志记录器记录日志，这些日志会被 `LogHandler` 捕获并转发：

```python
def analyze_challenge(project_dir, vuln_type, task=None):
    logger = logging.getLogger(__name__)
    logger.info(f"Starting analysis of {project_dir} for vulnerability type {vuln_type}")
    
    # 执行分析
    # ...
    
    logger.info(f"Analysis completed for {project_dir}")
    return result
```

#### 日志级别

系统支持以下日志级别：

1. **DEBUG**: 详细的调试信息
2. **INFO**: 一般信息
3. **WARNING**: 警告信息
4. **ERROR**: 错误信息
5. **CRITICAL**: 严重错误信息

日志级别可以通过命令行参数设置：

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
    # ...
```

#### 日志格式

系统使用以下日志格式：

```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

例如：

```
2023-06-01 12:34:56 - vuln_detector - INFO - Starting analysis of /path/to/project for vulnerability type Command_injection_CWE_78
```


#### 总结

终端服务模块是 YL-analysis 系统的重要组件，负责管理系统日志和终端输出。通过拦截标准输出和标准错误流，该模块将日志信息推送给客户端，提供了完整的日志捕获和转发功能。该模块的设计使得系统能够方便地记录和查看日志，有助于调试和监控系统运行状态。