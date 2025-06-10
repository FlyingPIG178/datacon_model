import os
import json
from aiohttp import web
from typing import Dict, Any, List, Optional

from ..router_base import RouterBase
from ..config import config
from ..analysis_queue import analysis_queue, vulTypes
from ..terminal_service import terminal_service

class AnalysisRouter(RouterBase):
    """分析相关的路由管理器"""
    
    def __init__(self):
        super().__init__()
    
    def add_routes(self, app: web.Application) -> None:
        """添加分析相关路由"""
        app.router.add_post('/api/start-analysis', self.start_analysis)
        app.router.add_post('/api/stop-analysis', self.stop_analysis)
        app.router.add_get('/api/analysis-status', self.get_analysis_status)
        app.router.add_get('/api/call-graph/{project_name}', self.get_call_graph)
        app.router.add_get('/api/get-vul-types', self.list_vul_types)
    
    async def list_vul_types(self, request: web.Request) -> web.Response:
        """列出所有可用的漏洞类型"""
        try:
            return self.success_response(data={'vulTypes': vulTypes})
        except Exception as e:
            return await self.handle_error("列出漏洞类型", e)

    async def start_analysis(self, request: web.Request) -> web.Response:
        """启动分析任务"""
        try:
            data = await request.json()
            project_name = data.get('project_name')
            vul_type = data.get('vul_type', 'all')
            
            if not project_name:
                return self.error_response('项目名称不能为空', status=400)
            
            # 验证项目名称是否合法
            if not self._validate_project_name(project_name):
                return self.error_response('项目名称包含非法字符', status=400)
            
            # 检查项目是否存在
            project_path = config.get_challenge_path(project_name)
            if not os.path.exists(project_path):
                return self.error_response(f'项目 {project_name} 不存在', status=404)
            
            # 将任务添加到队列
            task = analysis_queue.add_task(project_name, vul_type)
            
            return self.success_response(
                message=f'分析任务已添加到队列',
                data={'task': task.to_dict()}
            )
        except Exception as e:
            return await self.handle_error("添加分析任务", e)
    
    async def stop_analysis(self, request: web.Request) -> web.Response:
        """停止当前分析任务"""
        try:
            result = analysis_queue.stop_current_task()
            if result:
                return self.success_response('分析任务已终止')
            else:
                return self.error_response('没有正在执行的分析任务', status=400)
        except Exception as e:
            return await self.handle_error("终止分析任务", e)
    
    async def get_analysis_status(self, request: web.Request) -> web.Response:
        """获取分析状态和日志"""
        try:
            status = analysis_queue.get_status()
            logs = terminal_service.log_handler.logs
            
            return self.success_response(data={
                'current_analysis': status["current_task"],
                'queue': status["queue"],
                'logs': logs
            })
        except Exception as e:
            return await self.handle_error("获取分析状态", e)
    
    async def get_call_graph(self, request: web.Request) -> web.Response:
        """获取项目调用图"""
        try:
            project_name = request.match_info.get('project_name')
            
            # 验证项目名称是否合法
            if not self._validate_project_name(project_name):
                return self.error_response('项目名称包含非法字符', status=400)
            
            graph_path = config.get_call_graph_path(project_name)
            
            if not os.path.exists(graph_path):
                return self.error_response(f'未找到项目 {project_name} 的调用图', status=404)
            
            # 遍历目录下的所有JSON文件
            graph_data_array = [{}]
            for filename in os.listdir(graph_path):
                if filename.endswith('.json'):
                    file_path = os.path.join(graph_path, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            graph_data = json.load(f)
                            graph_data_array.append(graph_data)
                    except Exception as e:
                        # 如果某个文件读取失败，记录错误但继续处理其他文件
                        print(f"读取文件 {file_path} 时出错: {str(e)}")
            
            return self.success_response(data={'graph': graph_data_array})
        except Exception as e:
            return await self.handle_error("读取调用图", e)