from typing import List

import networkx as nx
import matplotlib.pyplot as plt
import logging
import os


class ChallengeFile:
    """表示challenge中的一个文件"""
    def __init__(self,file_path,file_content):
        logging.info(f"开始初始化文件{file_path}...")
        self.file_path = file_path
        self.file_content :str = file_content
        self.file_type =  os.path.splitext(file_path)[1]
        self.function_list :list[Function]= []
        logging.info(f"文件 {file_path} 初始化成功，文件类型设置为{self.file_type}")




# 表征一个方法
class Function:
    """
    challenge中的一个文件中的方法的详情
    """
    def __init__(self, name: str, body: str):
        self.name = name
        self.body = body
        self.call_site_list = []
        self.type = {
            "input": False, 
            "file_read": False, 
            "authentication": False,
            "memoryOP": False, 
            "command": False, 
            "integer": False, 
            "other": False}
        self.mini_body = ""
        self.node = ""  # 存储相对于当前函数的污点函数有关的代码片段
        self.tainted_params = []  # 存当前函数的污点参数
        logging.info(f"方法初始化完毕！！！！")
        """
        input：是否包含处理 Web 请求或网络输入。
        file_read：是否包含文件读取操作。
        authentication：是否包含身份验证操作。
        memoryOP：是否包含容易导致缓冲区溢出的内存操作。
        command：是否包含命令执行操作。
        integer：是否包含整数溢出操作。
        other：是否包含其他类型的漏洞风险。
        """
    # 设置函数的类型，即哪些功能:
    # 0. 是否包含处理web请求或处理网络输入 
    # 1. 是否包含文件读取操作
    # 2. 是否存在身份验证操作
    # 3. 是否存在容易导致缓冲区溢出的内存操作
    # 4. 是否存在命令执行操作
    # 5. 是否存在整数溢出操作
    # 6. 是否存在其他类型漏洞风险
    # type类型为字典，字典格式如下:
    #   {"web": true, "fileAccess": true, "memoryOP": true, "command": true, "integer": true}
    def setType(self, type_dict: dict):
        self.type.update(type_dict)
        logging.debug(f"设置函数 {self.name} 的类型: {type_dict}")

    def set_all_type(self,bool:bool):
        for key in self.type.keys():
            self.type[key] = bool

    def get_all_type(self):
        return self.type

    def setCallSites(self, call_sites: list[str]):
        self.call_site_list.extend(call_sites)
        logging.debug(f"设置函数 {self.name} 的调用站点: {call_sites}")

    def setmini_body(self, mini_body: str):
        self.mini_body = mini_body
        logging.debug(f"设置函数 {self.name} 的迷你体: {mini_body}")

    def add_tainted_param(self, param: [list]):
        if param not in self.tainted_params:
            self.tainted_params.append(param)

class VulnChain:
    """
    表征一个同一个函数的所有漏洞利用链条，
    vuln_function_name是存在漏洞的函数的函数名
    vuln_chain_function是这里存链上的函数结构
    vuln_chain_function_list是链上的所有函数名
    """

    def __init__(self, vuln_function_name: str, vuln_chain_function: list[Function],
                 vuln_chain_function_list: list[str]):  # list[str]
        self.vuln_function_name: str = vuln_function_name
        self.vuln_chain_function = vuln_chain_function  # 改动,这里存链上的函数结构
        self.vuln_chain_function_list = vuln_chain_function_list  # 漏洞调用链，从输入源函数到漏洞函数
        self.mini_chain=''
        self.score = 0

    def set_score(self, score):
        self.score = score

    def generate_mini_chain(self):
        """
        遍历 vuln_chain_function，提取每个 Function 的 node 属性，并添加到 mini_chain 中。
        """
        nodes = [func.node for func in self.vuln_chain_function if func.node]  # 确保 node 不为空
        self.mini_chain = ' -> '.join(nodes)  # 使用 ' -> ' 拼接节点信息
        logging.debug(f"生成的 mini_chain: {self.mini_chain}")




