import os
import sys
import logging

# 配置日志
logger = logging.getLogger(__name__)

class Config:
    """配置管理器，负责管理应用程序的各种配置和路径"""
    
    def __init__(self):
        # 获取基础目录
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # 添加 main 目录到 Python 路径
        self.main_dir = os.path.join(self.root_dir, "main")
        if self.main_dir not in sys.path:
            sys.path.append(self.main_dir)
            
        # 定义各种目录路径
        self.challenges_dir = os.path.join(self.root_dir, "challenges")
        self.results_dir = os.path.join(self.root_dir, "results")
        self.prompt_dir = os.path.join(self.root_dir, "prompt")
        self.settings_dir = os.path.join(self.root_dir, "settings")
        
        # 确保目录存在
        self._ensure_directories()
    
    def _ensure_directories(self):
        """确保所有必要的目录都存在"""
        directories = [
            self.challenges_dir,
            self.results_dir,
            self.prompt_dir,
            self.settings_dir
        ]
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                logger.info(f"创建目录: {directory}")
                
    def get_challenge_path(self, project_name):
        """获取指定项目的挑战路径"""
        return os.path.join(self.challenges_dir, project_name)
        
    def get_call_graph_path(self, project_name):
        """获取指定记录的路径"""
        return os.path.join(self.results_dir, project_name)
        
    def get_settings_path(self):
        """获取设置文件路径"""
        return os.path.join(self.settings_dir, "settings.json")
        
    def get_prompt_path(self, prompt_name, file_type="txt"):
        """获取指定提示词的路径"""
        return os.path.join(self.prompt_dir, f"{prompt_name}.{file_type}")
        
# 创建全局配置实例
config = Config() 