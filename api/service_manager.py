import logging
import os
import asyncio
from aiohttp import web
import aiohttp_cors
from typing import Callable

from .config import Config, config
from .routers import setup_all_routes

# 配置日志
logger = logging.getLogger(__name__)

class ServiceManager:
    """服务管理器，负责初始化和协调所有API服务"""
    
    _instance = None
    
    def __new__(cls):
        """单例模式实现"""
        if cls._instance is None:
            cls._instance = super(ServiceManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """初始化服务管理器"""
        if self._initialized:
            return
            
        self.config = config
        self.app = None
        self.startup_callbacks = []
        self.shutdown_callbacks = []
        self._initialized = True
        
        # 注册默认回调
        self.register_startup_callback(self._ensure_directories)
        
        logger.info("服务管理器初始化完成")
    
    def register_startup_callback(self, callback: Callable):
        """注册应用启动时的回调函数"""
        self.startup_callbacks.append(callback)
    
    def register_shutdown_callback(self, callback: Callable):
        """注册应用关闭时的回调函数"""
        self.shutdown_callbacks.append(callback)
    
    async def _on_startup(self, app: web.Application):
        """应用启动时执行所有回调"""
        logger.info("执行应用启动回调...")
        for callback in self.startup_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(app)
                else:
                    callback(app)
            except Exception as e:
                logger.error(f"执行启动回调时出错: {e}")
    
    async def _on_shutdown(self, app: web.Application):
        """应用关闭时执行所有回调"""
        logger.info("执行应用关闭回调...")
        for callback in self.shutdown_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(app)
                else:
                    callback(app)
            except Exception as e:
                logger.error(f"执行关闭回调时出错: {e}")
    
    def _ensure_directories(self, app: web.Application = None):
        """确保所有必要的目录都存在"""
        self.config._ensure_directories()
        logger.info("所有必要目录已创建")
    
    def setup_cors(self, app: web.Application):
        """设置CORS支持"""
        # 添加CORS支持
        cors = aiohttp_cors.setup(app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
            )
        })
        
        for route in list(app.router.routes()):
            try:
                cors.add(route)
            except ValueError as e:
                # 如果路由已经配置了CORS，则跳过
                logger.debug(f"跳过已配置CORS的路由: {e}")
                continue
    
    def init_app(self):
        """初始化应用"""
        if self.app is not None:
            return self.app
            
        logger.info("初始化应用...")
        
        # 创建应用
        self.app = web.Application()
        
        # 设置路由
        setup_all_routes(self.app)
        
        # 设置CORS
        self.setup_cors(self.app)
        
        # 注册启动和关闭钩子
        self.app.on_startup.append(self._on_startup)
        self.app.on_shutdown.append(self._on_shutdown)
        
        logger.info("应用初始化完成")
        return self.app

# 创建全局服务管理器实例
service_manager = ServiceManager()

# 创建应用工厂函数
def create_app():
    """应用工厂函数，返回配置好的aiohttp应用"""
    return service_manager.init_app()