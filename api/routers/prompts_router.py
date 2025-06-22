import os
import json
from aiohttp import web
from typing import Dict, Any, List, Optional

from ..router_base import RouterBase
from ..config import config

class PromptsRouter(RouterBase):
    """提示词相关的路由管理器"""
    
    def __init__(self):
        super().__init__()
    
    def add_routes(self, app: web.Application) -> None:
        """添加提示词相关路由"""
        app.router.add_get('/api/prompts', self.list_prompts)
        app.router.add_get('/api/prompts/{prompt_name}', self.get_prompt)
        app.router.add_post('/api/prompts/{prompt_name}', self.save_prompt)
        app.router.add_post('/api/prompts', self.create_prompt)
        app.router.add_delete('/api/prompts/{prompt_name}', self.delete_prompt)
    
    async def list_prompts(self, request: web.Request) -> web.Response:
        """获取所有提示词的列表"""
        try:
            prompts = []
            prompt_dir = config.get_prompt_path()
            
            if os.path.exists(prompt_dir):
                for file_name in os.listdir(prompt_dir):
                    if file_name.endswith('.txt') or file_name.endswith('.json'):
                        prompt_name = file_name.split('.')[0]
                        # 尝试检测提示词类别
                        category = 'general'
                        if prompt_name.startswith('function_'):
                            category = 'function'
                        elif prompt_name.startswith('vuln_check_'):
                            category = 'vuln_check'
                        
                        # 获取文件修改时间
                        file_path = os.path.join(prompt_dir, file_name)
                        modified_time = os.path.getmtime(file_path)
                        
                        prompts.append({
                            'name': prompt_name,
                            'file': file_name,
                            'category': category,
                            'modified': modified_time
                        })
            
            # 按类别和名称排序
            prompts.sort(key=lambda x: (x['category'], x['name']))
            
            return self.success_response(data={'prompts': prompts})
        except Exception as e:
            return await self.handle_error("获取提示词列表", e)
    
    async def get_prompt(self, request: web.Request) -> web.Response:
        """获取特定提示词的内容"""
        try:
            prompt_name = request.match_info.get('prompt_name')
            prompt_dir = config.get_prompt_path()
            
            # 检查json和txt两种格式
            json_path = os.path.join(prompt_dir, f"{prompt_name}.json")
            txt_path = os.path.join(prompt_dir, f"{prompt_name}.txt")
            
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    content = json.load(f)
                    file_type = 'json'
            elif os.path.exists(txt_path):
                with open(txt_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    file_type = 'txt'
            else:
                return self.error_response(f'提示词 {prompt_name} 不存在', status=404)
            
            return self.success_response(data={
                'name': prompt_name,
                'content': content,
                'type': file_type
            })
        except Exception as e:
            return await self.handle_error("获取提示词", e)
    
    async def save_prompt(self, request: web.Request) -> web.Response:
        """保存/更新提示词"""
        try:
            prompt_name = request.match_info.get('prompt_name')
            data = await request.json()
            content = data.get('content')
            file_type = data.get('type', 'txt')  # 默认为txt格式
            
            if not content:
                return self.error_response('提示词内容不能为空', status=400)
            
            prompt_dir = config.get_prompt_path()
            
            # 根据文件类型保存
            if file_type == 'json':
                file_path = os.path.join(prompt_dir, f"{prompt_name}.json")
                with open(file_path, 'w', encoding='utf-8') as f:
                    if isinstance(content, str):
                        try:
                            # 尝试将内容解析为JSON
                            content_json = json.loads(content)
                            json.dump(content_json, f, ensure_ascii=False, indent=2)
                        except:
                            # 如果解析失败，直接写入字符串
                            f.write(content)
                    else:
                        json.dump(content, f, ensure_ascii=False, indent=2)
            else:
                # 默认保存为txt
                file_path = os.path.join(prompt_dir, f"{prompt_name}.txt")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content if isinstance(content, str) else json.dumps(content))
            
            return self.success_response(f'提示词 {prompt_name} 已保存')
        except Exception as e:
            return await self.handle_error("保存提示词", e)
    
    async def create_prompt(self, request: web.Request) -> web.Response:
        """创建新的提示词"""
        try:
            data = await request.json()
            name = data.get('name')
            content = data.get('content', '')
            file_type = data.get('type', 'txt')
            
            if not name:
                return self.error_response('提示词名称不能为空', status=400)
            
            # 检查名称是否包含非法字符
            if any(c in name for c in '\\/:*?"<>|'):
                return self.error_response('提示词名称包含非法字符', status=400)
            
            # 检查是否已存在同名文件
            json_path = config.get_prompt_path(name, 'json')
            txt_path = config.get_prompt_path(name, 'txt')
            
            if os.path.exists(json_path) or os.path.exists(txt_path):
                return self.error_response(f'提示词 {name} 已存在', status=400)
            
            # 保存文件
            if file_type == 'json':
                with open(json_path, 'w', encoding='utf-8') as f:
                    if isinstance(content, str):
                        try:
                            content_json = json.loads(content)
                            json.dump(content_json, f, ensure_ascii=False, indent=2)
                        except:
                            f.write(content)
                    else:
                        json.dump(content, f, ensure_ascii=False, indent=2)
            else:
                with open(txt_path, 'w', encoding='utf-8') as f:
                    f.write(content if isinstance(content, str) else json.dumps(content))
            
            return self.success_response(f'提示词 {name} 已创建')
        except Exception as e:
            return await self.handle_error("创建提示词", e)
    
    async def delete_prompt(self, request: web.Request) -> web.Response:
        """删除提示词"""
        try:
            prompt_name = request.match_info.get('prompt_name')
            
            # 检查两种格式文件
            json_path = config.get_prompt_path(prompt_name, 'json')
            txt_path = config.get_prompt_path(prompt_name, 'txt')
            
            deleted = False
            
            if os.path.exists(json_path):
                os.remove(json_path)
                deleted = True
            
            if os.path.exists(txt_path):
                os.remove(txt_path)
                deleted = True
            
            if not deleted:
                return self.error_response(f'提示词 {prompt_name} 不存在', status=404)
            
            return self.success_response(f'提示词 {prompt_name} 已删除')
        except Exception as e:
            return await self.handle_error("删除提示词", e) 