import os
import time
import uuid
import threading
import logging
import asyncio
from typing import List, Dict, Optional, Callable, Any
import importlib
import traceback

from Challenge import Challenge
from .config import config

# 导入现有的分析功能
# from main.analyze import analyzer

vulTypes = {
    "任意文件访问": "Arbitrary_file_access_CWE_22",
    "认证绕过": "Authentication_bypass_CWE_287",
    "缓冲区溢出": "Buffer_overflow_CWE_119",
    "命令注入": "Command_injection_CWE_78",
    "整数溢出": "Integer_overflow_CWE_190",
    "其他": "others"
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
        self.stop_event = threading.Event()

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
        self.stop_event.set()
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
            current_task_to_process = None
            with self.lock:
                if not self.queue and not self.current_task:
                    break

                if not self.current_task and self.queue:
                    self.current_task = self.queue.pop(0)
                    self._notify_queue_updated()
                    current_task_to_process = self.current_task

            if current_task_to_process and current_task_to_process.status == "queued":
                try:
                    current_task_to_process.start()
                    self._notify_status_updated()

                    self._perform_analysis(current_task_to_process)

                    if current_task_to_process.status == "running":
                        current_task_to_process.complete()

                except Exception as e:
                    logger.exception(f"分析过程出错: {e}")
                    if current_task_to_process:
                        current_task_to_process.fail(str(e))
                finally:
                    self._notify_status_updated()
                    time.sleep(1)
                    with self.lock:
                        self.current_task = None
            time.sleep(0.1)

    def _perform_analysis(self, task: AnalysisTask):
        """实际执行分析的方法"""

        class AnalysisTerminatedException(Exception):
            """自定义异常，用于中断分析流程"""
            pass

        def check_for_termination():
            if task.stop_event.is_set():
                raise AnalysisTerminatedException(f"任务 {task.project_name} 已被用户终止。")

        def run_single_challenge(challenge: Challenge):
            try:
                challenge.parse_files()
                check_for_termination()

                challenge.analysis_functions()
                check_for_termination()

                challenge.generate_call_graph()
                check_for_termination()

                challenge.generate_vul_chains()
                check_for_termination()

                challenge.travel_Params_And_Body()
                check_for_termination()

                challenge.code_chain_generate()
                check_for_termination()

            except AnalysisTerminatedException:
                raise
            except Exception as e:
                logging.error(f"解析题目 {challenge.challenge_dir} 失败!")
                logging.error(traceback.format_exc())
                logging.error("开启大力出奇迹模式!!!")
                challenge.da_li_chu_qi_ji()
                check_for_termination()
                challenge.parse_files()
                check_for_termination()
                challenge.analysis_functions()
                check_for_termination()
                challenge.generate_call_graph()

        def get_challenge(file_path, vuln_type) -> Challenge | None:
            if not os.path.isdir(file_path):
                logging.error(f"题目路径不存在: {file_path}")
                return None
            logging.debug(f"开始加载 Challenge：{file_path}")
            challenge = Challenge(file_path, vuln_type)
            logging.info(f"Challenge 加载成功：{file_path}")
            return challenge

        try:
            project_path = config.get_challenge_path(task.project_name)
            if task.vul_type == "all":
                for vuln_type in vulTypes.values():
                    check_for_termination()
                    challenge = get_challenge(project_path, vuln_type)
                    if challenge:
                        run_single_challenge(challenge)
            else:
                challenge = get_challenge(project_path, task.vul_type)
                if challenge:
                    run_single_challenge(challenge)

        except AnalysisTerminatedException as e:
            logger.warning(str(e))
            return
        except Exception as e:
            logger.exception(f"执行分析任务失败: {e}")
            raise

    def stop_current_task(self):
        with self.lock:
            if self.current_task and self.current_task.status == "running":
                self.current_task.terminate()
                self._notify_status_updated()
                return True
        return False

    def clear_queue(self):
        with self.lock:
            self.queue.clear()
            self._notify_queue_updated()

    def get_status(self):
        with self.lock:
            current = self.current_task.to_dict() if self.current_task else None
            queue = [task.to_dict() for task in self.queue]
            return {
                "current_task": current,
                "queue": queue
            }

    def add_listener(self, listener):
        self.listeners.append(listener)

    def remove_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)

    def _notify_status_updated(self):
        if self.current_task:
            status_data = {"type": "status", "analysis": self.current_task.to_dict()}
            for listener in self.listeners:
                try:
                    if asyncio.iscoroutinefunction(listener):
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                        if loop.is_running():
                            loop.create_task(listener(status_data))
                        else:
                            loop.run_until_complete(listener(status_data))
                    else:
                        listener(status_data)
                except Exception as e:
                    logger.error(f"通知状态监听器出错: {e}")

    def _notify_queue_updated(self):
        queue_data = {"type": "queue", "queue": [task.to_dict() for task in self.queue]}
        for listener in self.listeners:
            try:
                if asyncio.iscoroutinefunction(listener):
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    if loop.is_running():
                        loop.create_task(listener(queue_data))
                    else:
                        loop.run_until_complete(listener(queue_data))
                else:
                    listener(queue_data)
            except Exception as e:
                logger.error(f"通知队列监听器出错: {e}")


analysis_queue = AnalysisQueueManager()