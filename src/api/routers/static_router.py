import os
from aiohttp import web
from aiohttp.web_urldispatcher import StaticResource

from ..router_base import RouterBase
from ..config import config

class StaticRouter(RouterBase):
    """静态文件相关的路由管理器"""
    
    def __init__(self):
        super().__init__()
    
    def add_routes(self, app: web.Application) -> None:
        """添加静态文件相关路由"""
        # 获取项目根目录
        base_dir = config.root_dir
        dist_dir = os.path.join(base_dir, 'front')
        
        # 检查dist目录是否存在
        if not os.path.exists(dist_dir):
            self.logger.warning(f"前端静态文件目录不存在")
            return
        
        self.logger.info(f"添加前端静态文件路由")
        
        # 创建assets目录的静态资源处理器
        assets_dir = os.path.join(dist_dir, 'assets')
        if os.path.exists(assets_dir):
            assets_static = StaticResource('/assets', assets_dir)
            app.router.register_resource(assets_static)
            self.logger.debug(f"已添加assets静态资源路由")
        
        # 添加favicon.ico路由
        favicon_path = os.path.join(dist_dir, 'favicon.ico')
        if os.path.exists(favicon_path):
            async def favicon_handler(request):
                return web.FileResponse(favicon_path)
            app.router.add_get('/favicon.ico', favicon_handler)
            self.logger.debug("已添加favicon.ico路由")
        
        # 添加index.html路由
        index_path = os.path.join(dist_dir, 'index.html')
        if os.path.exists(index_path):
            async def index_handler(request):
                return web.FileResponse(index_path)
            app.router.add_get('/', index_handler)
            # 添加通配符路由，处理所有未匹配的路由，返回index.html
            app.router.add_get('/{tail:.*}', index_handler)
            self.logger.debug("已添加index.html路由")
        
        self.logger.info("静态文件路由添加完成")