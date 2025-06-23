import os
import json
from aiohttp import web
from typing import Dict, Any, List, Optional

from ..router_base import RouterBase
from ..config import config

from libs.config import Config as LibsConfig
from openai import OpenAI

class SettingsRouter(RouterBase):
    """设置相关的路由管理器"""
    
    def __init__(self):
        super().__init__()
        self.load_settings()

    def get_libsconfig(self):
        return {
            "test_mode" : LibsConfig.test_mode,
            "retry_times" : LibsConfig.retry_times,
            "openai_api_key" : LibsConfig.openai_api_key,
            "openai_api_base" : LibsConfig.openai_api_base,
            "model_name" : LibsConfig.model_name,
            "timeout" : LibsConfig.timeout
        }
    
    def set_libsconfig(self, data: Dict[str, Any]):
        LibsConfig.test_mode = data.get('test_mode', LibsConfig.test_mode)
        LibsConfig.retry_times = data.get('retry_times', LibsConfig.retry_times)
        LibsConfig.openai_api_key = data.get('openai_api_key', LibsConfig.openai_api_key)
        LibsConfig.openai_api_base = data.get('openai_api_base', LibsConfig.openai_api_base)
        LibsConfig.model_name = data.get('model_name', LibsConfig.model_name)
        LibsConfig.timeout = data.get('timeout', LibsConfig.timeout)

    def load_settings(self) -> Dict[str, Any]:
        """加载设置"""
        settings_file = config.get_settings_path()
        
        if not os.path.exists(settings_file):
            # 创建默认设置
            default_settings = self.get_libsconfig()
            with open(settings_file, 'w', encoding='utf-8') as f:
                json.dump(default_settings, f, ensure_ascii=False, indent=2)
            
            return default_settings
        
        with open(settings_file, 'r', encoding='utf-8') as f:
            settings = json.load(f)
        
        self.set_libsconfig(settings)

        return settings
    
    def add_routes(self, app: web.Application) -> None:
        """添加设置相关路由"""
        app.router.add_get('/api/settings', self.get_settings)
        app.router.add_post('/api/settings', self.update_settings)
    
    async def get_settings(self, request: web.Request) -> web.Response:
        """获取分析设置"""
        try:
            settings = self.get_libsconfig()

            filtered_settings = {k: v for k, v in settings.items() if k not in ['openai_api_key', 'openai_api_base']}
            
            return self.success_response(data={'settings': filtered_settings})
        except Exception as e:
            return await self.handle_error("获取设置", e)
    
    async def update_settings(self, request: web.Request) -> web.Response:
        """更新分析设置"""
        try:
            data = await request.json()
            settings = data.get('settings')

            self.logger.debug(f"设置数据: {settings}")
            
            if not settings:
                return self.error_response('缺少设置数据', status=400)
            
            if settings.get('openai_api_key') or settings.get('openai_api_base'):
                api_key = settings.get('openai_api_key', LibsConfig.openai_api_key)
                api_base = settings.get('openai_api_base', LibsConfig.openai_api_base)
                
                try:
                    # 这里可以使用一个简单的 API 请求来验证
                    client = OpenAI(api_key=api_key, base_url=api_base)
                    client.models.list()
                except Exception as e:
                    return self.error_response(f'OpenAI API 错误: {str(e)}', status=500)

            self.set_libsconfig(settings)

            self.logger.info("设置已更新")

            settings = self.get_libsconfig()
            
            settings_file = config.get_settings_path()
            
            with open(settings_file, 'w', encoding='utf-8') as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
            
            self.logger.info("设置已保存")
            
            return self.success_response('设置已更新')
        except Exception as e:
            return await self.handle_error("更新设置", e) 