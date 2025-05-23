import os
import shutil
from aiohttp import web
from typing import Dict, Any, List, Optional

from ..router_base import RouterBase
from ..config import config

class ProjectsRouter(RouterBase):
    """项目管理相关的路由管理器"""
    
    def __init__(self):
        super().__init__()
    
    def add_routes(self, app: web.Application) -> None:
        """添加项目管理路由"""
        app.router.add_get('/api/list-challenges', self.list_challenges)
        app.router.add_delete('/api/delete-project/{project_name}', self.delete_project)
        app.router.add_post('/api/upload-folder', self.upload_folder)
    
    async def list_challenges(self, request: web.Request) -> web.Response:
        """列出challenges目录下的所有项目"""
        try:
            challenges_dir = config.challenges_dir
            projects = []
            
            if os.path.exists(challenges_dir):
                for item in os.listdir(challenges_dir):
                    item_path = os.path.join(challenges_dir, item)
                    if os.path.isdir(item_path):
                        # 计算项目大小
                        try:
                            project_size = sum(
                                os.path.getsize(os.path.join(dirpath, filename))
                                for dirpath, _, filenames in os.walk(item_path)
                                for filename in filenames
                            )
                        except:
                            # 处理权限问题或其他可能的错误
                            project_size = 0
                        
                        projects.append({
                            'name': item,
                            'size': project_size,
                            'created': os.path.getctime(item_path)
                        })
            
            return self.success_response(data={'projects': projects})
        except Exception as e:
            return await self.handle_error("获取项目列表", e)
    
    async def delete_project(self, request: web.Request) -> web.Response:
        """删除指定项目"""
        try:
            project_name = request.match_info.get('project_name')
            
            # 验证项目名称
            if not self._validate_project_name(project_name):
                return self.error_response('项目名称包含非法字符', status=400)
            
            project_path = config.get_challenge_path(project_name)
            
            if not os.path.exists(project_path):
                return self.error_response(f'项目 {project_name} 不存在', status=404)
            
            # 删除项目目录
            shutil.rmtree(project_path)
            
            # 尝试删除相关调用图文件
            graph_path = config.get_call_graph_path(project_name)
            if os.path.exists(graph_path):
                shutil.rmtree(graph_path)
            
            self.logger.info(f"成功删除项目: {project_name}")
            return self.success_response(f'项目 {project_name} 已删除')
        except Exception as e:
            return await self.handle_error("删除项目", e)
    
    async def upload_folder(self, request: web.Request) -> web.Response:
        """上传文件夹到服务器"""
        reader = await request.multipart()
        
        try:
            # 获取项目名称
            field = await reader.next()
            if field.name == 'folder_name':
                project_name = await field.text()
            else:
                return self.error_response('缺少项目名称', status=400)
            
            # 验证项目名称
            if not self._validate_project_name(project_name):
                return self.error_response('项目名称包含非法字符', status=400)
            
            # 创建项目目录
            project_dir = config.get_challenge_path(project_name)
            
            # 如果目录已存在，先删除
            if os.path.exists(project_dir):
                shutil.rmtree(project_dir)
            
            os.makedirs(project_dir, exist_ok=True)
            
            # 读取并保存文件
            file_count = 0
            field = await reader.next()
            while field:
                if field.name == 'files[]':
                    filename = field.filename
                    file_content = await field.read()
                    
                    if '/' in filename:
                        # 创建子目录
                        dir_path = os.path.dirname(filename)
                        os.makedirs(os.path.join(project_dir, dir_path), exist_ok=True)
                    
                    # 保存文件
                    file_path = os.path.join(project_dir, filename)
                    with open(file_path, 'wb') as f:
                        f.write(file_content)
                    
                    file_count += 1
                
                try:
                    field = await reader.next()
                except StopAsyncIteration:
                    break
            
            self.logger.info(f"成功上传项目: {project_name}，共{file_count}个文件")
            return self.success_response(f'项目 {project_name} 上传成功，共 {file_count} 个文件')
        except Exception as e:
            return await self.handle_error("上传文件夹", e)