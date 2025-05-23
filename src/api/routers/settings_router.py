import os
import json
from aiohttp import web
from typing import Dict, Any, List, Optional

from ..router_base import RouterBase
from ..config import config

class SettingsRouter(RouterBase):
    """设置相关的路由管理器"""
    
    def __init__(self):
        super().__init__()
    
    def add_routes(self, app: web.Application) -> None:
        """添加设置相关路由"""
        app.router.add_get('/api/settings', self.get_settings)
        app.router.add_post('/api/settings', self.update_settings)
    
    async def get_settings(self, request: web.Request) -> web.Response:
        """获取分析设置"""
        try:
            settings_file = config.get_settings_path()
            
            if not os.path.exists(settings_file):
                # 创建默认设置
                default_settings = {
                    "llm": {
                        "apiUrl": "http://localhost:8000/api/chat",
                        "apiKey": "",
                        "model": "gpt-3.5-turbo",
                        "tokenLimit": 4000,
                        "temperature": 0.7
                    },
                    "analysis": {
                        "defaultProjectPath": "",
                        "timeout": 60,
                        "depth": 2,
                        "parallel": True,
                        "maxThreads": 4
                    },
                    "workflow": {
                        "functionParse": "function_parse",
                        "vulnCheck": {
                            "Arbitrary_file_access": "vuln_check_arbitrary_file_access",
                            "Authentication_bypass": "vuln_check_authentication_bypass",
                            "Buffer_overflow": "vuln_check_buffer_overflow",
                            "Command_injection": "vuln_check_command_injection",
                            "Integer_overflow": "vuln_check_integer_overflow",
                            "others": "vuln_check_others"
                        }
                    }
                }
                
                with open(settings_file, 'w', encoding='utf-8') as f:
                    json.dump(default_settings, f, ensure_ascii=False, indent=2)
                
                return self.success_response(data={'settings': default_settings})
            
            with open(settings_file, 'r', encoding='utf-8') as f:
                settings = json.load(f)
            
            return self.success_response(data={'settings': settings})
        except Exception as e:
            return await self.handle_error("获取设置", e)
    
    async def update_settings(self, request: web.Request) -> web.Response:
        """更新分析设置"""
        try:
            data = await request.json()
            settings = data.get('settings')
            
            if not settings:
                return self.error_response('缺少设置数据', status=400)
            
            settings_file = config.get_settings_path()
            
            with open(settings_file, 'w', encoding='utf-8') as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
            
            return self.success_response('设置已更新')
        except Exception as e:
            return await self.handle_error("更新设置", e) 