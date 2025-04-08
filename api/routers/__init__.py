from aiohttp import web
import logging

from .analysis_router import AnalysisRouter
from .projects_router import ProjectsRouter
from .settings_router import SettingsRouter
from .prompts_router import PromptsRouter
from .static_router import StaticRouter

logger = logging.getLogger(__name__)

# 所有路由管理器实例
analysis_router = AnalysisRouter()
projects_router = ProjectsRouter()
settings_router = SettingsRouter()
prompts_router = PromptsRouter()
static_router = StaticRouter()

def setup_all_routes(app: web.Application) -> None:
    """设置所有路由到应用程序"""
    
    logger.info("初始化所有API路由...")
    
    # 添加各种功能路由
    analysis_router.add_routes(app)
    projects_router.add_routes(app)
    settings_router.add_routes(app)
    prompts_router.add_routes(app)
    
    # 添加静态文件路由（必须在最后添加，避免覆盖API路由）
    static_router.add_routes(app)
    
    logger.info("路由初始化完成")