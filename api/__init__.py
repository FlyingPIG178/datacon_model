import logging
from .service_manager import create_app

# 配置日志
logger = logging.getLogger(__name__)

# 重用service_manager.py中定义的创建应用函数
__all__ = ['create_app']