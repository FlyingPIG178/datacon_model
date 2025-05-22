import os
import time
import uuid
import threading
import logging
import asyncio
from typing import List, Dict, Optional, Callable, Any
import importlib
import traceback

from main.Challenge import Challenge
from .config import config

# 导入现有的分析功能
# from main.analyze import analyzer

vulTypes = {
    "任意文件访问" : "Arbitrary_file_access_CWE_22",
    "认证绕过" : "Authentication_bypass_CWE_287",
    "缓冲区溢出": "Buffer_overflow_CWE_119",
    "命令注入" : "Command_injection_CWE_78",
    "整数溢出" : "Integer_overflow_CWE_190",
    "其他" : "others"
    }

logger = logging.getLogger(__name__)

class AnalysisTask:
    def __init__(self, project_name: str, vul_type: str):
        self.id = str(uuid.uuid4())
        self.project_name = project_name
        self.vul_type = vul_type
        self.status = "queued"  # queued, running, completed, failed, terminated
        self.start_time = None
        self.end_time = None
        self.progress = 0
        self.results = None
    
    def to_dict(self):
        return {
            "id": self.id,
            "project_name": self.project_name,
            "vul_type": self.vul_type,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "progress": self.progress
        }
    
    def start(self):
        self.status = "running"
        self.start_time = time.time()
        logger.info(f"开始分析任务: {self.project_name}, 类型: {self.vul_type}")
    
    def complete(self, results=None):
        self.status = "completed"
        self.end_time = time.time()
        self.progress = 100
        self.results = results
        logger.info(f"分析任务完成: {self.project_name}")
    
    def fail(self, error=None):
        self.status = "failed"
        self.end_time = time.time()
        logger.error(f"分析任务失败: {self.project_name}, 错误: {error}")
    
    def terminate(self):
        self.status = "terminated"
        self.end_time = time.time()
        logger.warning(f"分析任务终止: {self.project_name}")
    
    def update_progress(self, progress):
        self.progress = progress

class AnalysisQueueManager:
    def __init__(self):
        self.queue: List[AnalysisTask] = []
        self.current_task: Optional[AnalysisTask] = None
        self.lock = threading.Lock()
        self.worker_thread = None
        self.should_stop = threading.Event()
        self.listeners = []
    
    def add_task(self, project_name: str, vul_type: str) -> AnalysisTask:
        task = AnalysisTask(project_name, vul_type)
        with self.lock:
            self.queue.append(task)
            self._notify_queue_updated()
        
        # 如果没有工作线程，启动一个
        if self.worker_thread is None or not self.worker_thread.is_alive():
            self._start_worker()
        
        return task
    
    def _start_worker(self):
        self.should_stop.clear()
        self.worker_thread = threading.Thread(target=self._process_queue)
        self.worker_thread.daemon = True
        self.worker_thread.start()
    
    def _process_queue(self):
        while not self.should_stop.is_set():
            # 获取下一个任务
            with self.lock:
                if not self.queue and not self.current_task:
                    # 队列为空，结束工作
                    break
                
                if not self.current_task and self.queue:
                    # 取出队列中的第一个任务
                    self.current_task = self.queue.pop(0)
                    self._notify_queue_updated()
            
            # 处理当前任务
            if self.current_task and self.current_task.status == "queued":
                try:
                    self.current_task.start()
                    self._notify_status_updated()
                    
                    # 执行分析过程
                    self._perform_analysis(self.current_task)
                    
                    # 完成分析
                    if self.current_task.status == "running":  # 检查任务没有被终止
                        self.current_task.complete()
                    
                except Exception as e:
                    logger.exception(f"分析过程出错: {e}")
                    if self.current_task:
                        self.current_task.fail(str(e))
                finally:
                    self._notify_status_updated()
                    with self.lock:
                        self.current_task = None
            
            # 休眠一小段时间
            time.sleep(0.1)
    
    def _perform_analysis(self, task: AnalysisTask):
        """实际执行分析的方法"""

        def run_single_challenge(challenge: Challenge):
            """
            分析单个 Challenge 实例
            """
            try:
                challenge.parse_files()
                challenge.analysis_functions()
                challenge.generate_call_graph()
                challenge.generate_vul_chains()
                challenge.travel_Params_And_Body()
                challenge.code_chain_generate()
                # challenge.check_vul_chains_by_score_new()
                # challenge.save_result(output_path)
            except Exception as e:
                logging.error(f"解析题目 {challenge.challenge_dir} 失败!")
                logging.error(traceback.format_exc())
                logging.error("开启大力出奇迹模式!!!")
                challenge.da_li_chu_qi_ji()
                challenge.parse_files()
                challenge.analysis_functions()
                challenge.generate_call_graph()

        def get_challenge(file_path, vuln_type) -> Challenge | None:
            """
            获取单个 Challenge 对象
            """
            if not os.path.isdir(file_path):
                logging.error(f"题目路径不存在: {file_path}")
                return None

            logging.debug(f"开始加载 Challenge：{file_path}")
            challenge = Challenge(file_path, vuln_type)
            logging.info(f"Challenge 加载成功：{file_path}")
            return challenge

        
        try:
            project_path = config.get_challenge_path(task.project_name)
            # 实际调用分析函数
            if task.vul_type == "all":
                # 分析所有类型的漏洞
                for vuln_type in vulTypes.values():
                    challenge = get_challenge(project_path, vuln_type)
                    if challenge:
                        run_single_challenge(challenge)
                    
            else:
                # 分析特定类型的漏洞
                challenge = get_challenge(project_path, task.vul_type)
                if challenge:
                    run_single_challenge(challenge)
                pass
            
        except Exception as e:
            logger.exception(f"执行分析任务失败: {e}")
            raise
    
    def stop_current_task(self):
        """终止当前正在执行的任务"""
        with self.lock:
            if self.current_task and self.current_task.status == "running":
                self.current_task.terminate()
                self._notify_status_updated()
                return True
        return False
    
    def clear_queue(self):
        """清空队列"""
        with self.lock:
            self.queue.clear()
            self._notify_queue_updated()
    
    def get_status(self):
        """获取当前状态"""
        with self.lock:
            current = self.current_task.to_dict() if self.current_task else None
            queue = [task.to_dict() for task in self.queue]
            return {
                "current_task": current,
                "queue": queue
            }
    
    def add_listener(self, listener):
        """添加状态监听器"""
        self.listeners.append(listener)
    
    def remove_listener(self, listener):
        """移除状态监听器"""
        if listener in self.listeners:
            self.listeners.remove(listener)
    
    def _notify_status_updated(self):
        """通知状态更新"""
        if self.current_task:
            status_data = {
                "type": "status",
                "analysis": self.current_task.to_dict()
            }
            
            for listener in self.listeners:
                try:
                    # 尝试异步调用
                    if asyncio.iscoroutinefunction(listener):
                        # 获取或创建事件循环
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            # 如果当前线程没有事件循环，则创建一个新的
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                        
                        # 在事件循环中运行协程
                        if loop.is_running():
                            # 如果事件循环正在运行，使用create_task
                            loop.create_task(listener(status_data))
                        else:
                            # 如果事件循环没有运行，直接运行协程
                            loop.run_until_complete(listener(status_data))
                    else:
                        listener(status_data)
                except Exception as e:
                    logger.error(f"通知状态监听器出错: {e}")
    
    def _notify_queue_updated(self):
        """通知队列更新"""
        queue_data = {
            "type": "queue",
            "queue": [task.to_dict() for task in self.queue]
        }
        
        for listener in self.listeners:
            try:
                # 尝试异步调用
                if asyncio.iscoroutinefunction(listener):
                    # 获取或创建事件循环
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        # 如果当前线程没有事件循环，则创建一个新的
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    
                    # 在事件循环中运行协程
                    if loop.is_running():
                        # 如果事件循环正在运行，使用create_task
                        loop.create_task(listener(queue_data))
                    else:
                        # 如果事件循环没有运行，直接运行协程
                        loop.run_until_complete(listener(queue_data))
                else:
                    listener(queue_data)
            except Exception as e:
                logger.error(f"通知队列监听器出错: {e}")

# 创建全局实例
analysis_queue = AnalysisQueueManager()