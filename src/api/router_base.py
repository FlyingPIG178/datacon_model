from abc import ABC, abstractmethod

from aiohttp import web
import logging
from typing import Dict, Any, List, Optional, Callable

# 基础路由管理器类
class RouterBase(ABC):
    """基础路由管理器类，所有功能路由管理器的基类"""
    
    def __init__(self):
        """初始化基础路由管理器"""
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def add_routes(self, app: web.Application) -> None:
        """
        添加路由到应用
        
        子类必须重写此方法，实现自己的路由注册逻辑
        """
        pass
    
    async def handle_error(self, func_name: str, error: Exception) -> web.Response:
        """统一错误处理方法"""
        self.logger.exception(f"{func_name}失败: {error}")
        return web.json_response({
            'success': False,
            'message': f'{func_name}失败: {str(error)}'
        }, status=500)
    
    def json_response(self, data: Dict[str, Any], status: int = 200) -> web.Response:
        """创建JSON响应"""
        return web.json_response(data, status=status)
    
    def _validate_project_name(self, project_name: str) -> bool:
        """验证项目名称是否合法
        
        Args:
            project_name: 项目名称
            
        Returns:
            bool: 项目名称是否合法
        """
        # 检查是否包含路径分隔符或其他特殊字符
        invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        return not any(char in project_name for char in invalid_chars)

    def success_response(self, message: str = None, data: Dict[str, Any] = None) -> web.Response:
        """创建成功响应"""
        response = {'success': True}
        if message:
            response['message'] = message
        if data:
            response.update(data)
        return self.json_response(response)
    
    def error_response(self, message: str, status: int = 400) -> web.Response:
        """创建错误响应"""
        self.logger.warning(f"返回错误响应: {message}, 状态码: {status}")
        return self.json_response({
            'success': False,
            'message': message
        }, status=status) 