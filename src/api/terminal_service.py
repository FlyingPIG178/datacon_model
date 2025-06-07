import logging
import json
import asyncio
from typing import List, Dict, Any, Callable, Set

class LogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.logs = []
        self.listeners: Set[Callable] = set()  # 修改为Set类型
        # 设置日志格式
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.setFormatter(formatter)

    def add_listener(self, listener):
        """添加监听器"""
        self.listeners.add(listener)
        
    def remove_listener(self, listener):
        """移除监听器"""
        if listener in self.listeners:
            self.listeners.remove(listener)
        
    def emit(self, record):
        log_entry = self.format(record)
        log_data = {
            'type': 'log',
            'message': log_entry,
            'level': record.levelname.lower(),
            'time': record.created
        }
        
        # 同时输出到命令行
        print(log_entry)
        
        # 保存日志到内存
        self.logs.append(log_data)
        if len(self.logs) > 1000:
            self.logs = self.logs[-1000:]
        
        # 分发日志到所有监听器
        for callback in list(self.listeners):  # 创建副本避免迭代时修改
            try:
                # 尝试异步调用
                if asyncio.iscoroutinefunction(callback):
                    # 使用try-except包装异步任务，避免未捕获的异常
                    async def safe_callback(data):
                        try:
                            await callback(data)
                        except Exception as e:
                            logging.error(f"Error in async listener callback: {e}")
                    
                    asyncio.create_task(safe_callback(log_data))
                else:
                    callback(log_data)
            except Exception as e:
                logging.error(f"Error sending log to listener: {e}")
                # 如果回调失败，考虑移除这个监听器
                if callback in self.listeners:
                    self.listeners.remove(callback)

class TerminalService:
    def __init__(self):
        self.log_handler = LogHandler()
        # # 设置日志级别
        # logging.getLogger().setLevel(logging.INFO)
        # 添加到全局日志处理
        logging.getLogger().addHandler(self.log_handler)
        # 确保日志处理器已正确初始化
        logger = logging.getLogger(__name__)
        logger.info("终端日志服务已初始化")
    
    def add_listener(self, listener):
        """添加监听器"""
        self.log_handler.add_listener(listener)
        
    def remove_listener(self, listener):
        """移除监听器"""
        self.log_handler.remove_listener(listener)
    
    async def broadcast(self, message):
        """广播消息给所有监听器"""
        for listener in list(self.log_handler.listeners):
            try:
                await listener(message)
            except Exception as e:
                logging.error(f"Error broadcasting to listener: {e}")
                self.log_handler.remove_listener(listener)

# 创建全局实例
terminal_service = TerminalService()