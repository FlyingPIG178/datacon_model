import logging
import os
from typing import List


class ChallengeFile:
    """表示challenge中的一个文件"""

    def __init__(self, file_path, file_content):
        logging.info(f"开始初始化文件{file_path}...")
        self.file_path = file_path
        self.file_content: str = file_content
        self.file_type = os.path.splitext(file_path)[1]
        self.function_list: list[Function] = []
        logging.info(f"文件 {file_path} 初始化成功，文件类型设置为{self.file_type}")


class Function:
    def __init__(self, name: str, body: str):
        self.name = name
        self.body = body
        self.call_site_list = []
        self.type = {"input": False, "file_read": False, "authentication": False,
                     "memoryOP": False, "command": False, "integer": False, "other": False}
        self.mini_body = ""
        self.node = ""  # 存储相对于当前函数的污点函数有关的代码片段
        self.tainted_params = []  # 存当前函数的污点参数

    def setType(self, type_dict: dict):
        self.type.update(type_dict)

    def setCallSites(self, call_sites: list[str]):
        self.call_site_list.extend(call_sites)

    def setmini_body(self, mini_body: str):
        self.mini_body = mini_body

    def add_tainted_param(self, param: str):
        if param not in self.tainted_params:
            self.tainted_params.append(param)


def reverse_traverse(child: Function, parent: Function, ):
    """
    反向递归遍历，传递当前子节点的污点参数给父节点。这里还要处理，如何让ai明白形参和实参的区别并联系起来
    只会处理一个父节点（vuln_chain是单链表结构）。
    这里需要在处理节点代码处反向遍历vuln_chain,将相邻节点传给这个函数
    越界判断（parent是否存在）在处理节点处处理
    结果:为父节点添加五点参数列表
    现在直接把child和parent传进去，具体需要什么值具体调用
    """
    if parent:
        # 将当前子节点的污点参数传递给父节点
        for child_param in child.tainted_params:
            """
            传入参数为child.tainted_params,parent
            """
            parent_param = "1(child.tainted_params,parent)"  # 大模型判断parent中和child的污点参数有关的参数parent_param
            parent.add_tainted_param(parent_param)


def forward_traverse(function: Function):
    """
    正向遍历，提取与污点参数相关的代码片段
    实际是调用self. extract_tainted_code
    将当前Fuction的污点参数数组和代码片段交给大模型提取相关代码片段
    所得代码片段加入self.node
    参数为当前函数体，当前函数污点参数，提示词
    结果:为当前函数添加污点参数相关代码
    """
    function.extract_tainted_code()


def audit_vulnerability_chain(all_functions: dict):
    """
    先反转vuln_chain因为vuln_chain是单链结构所以直接顺序遍历找父节点
    reverse_traverse越界判断（parent是否存在）在处理节点处处理：抛出异常说明到结尾

    然后正向遍历forward_traverse
    """
    # 获取 all_functions 的所有键，反转顺序
    keys = list(all_functions.keys())
    keys.reverse()  # 也可以使用 reversed(list(all_functions.keys()))
    # 创建一个迭代器
    keys_iter = iter(keys)
    # 反向遍历vuln_chain
    for function_name in keys_iter:
        # 获取当前函数
        current_function = all_functions.get(function_name)
        if current_function:
            # 在这里处理当前函数
            print(f"Processing function: {function_name}")
            # 获取下一个键
            try:
                parent_function_name = next(keys_iter)  # 获取下一个函数的名称
                parent_function = all_functions.get(parent_function_name)
                if parent_function:
                    print(f"Next function: {parent_function}")
                    reverse_traverse(current_function, parent_function)
                else:
                    print("parent_function not found.")
            except StopIteration:
                print("No next function.")
    for function_name in all_functions:
        function = all_functions.get(function_name)
        if function:
            forward_traverse(function)
        else:
            print("audit_vulnerability_chains有bug")


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
        self.vuln_chain_body = vuln_chain_function  # 改动,这里存链上的函数结构
        self.vuln_chain_function_list = vuln_chain_function_list  # 漏洞调用链，从输入源函数到漏洞函数
        self.score = 0

    def set_score(self, score):
        self.score = score


class CodeChain:
    def __int__(self, VulnCodes: str):
        self.VulnCodes = VulnCodes

    def add_codes(self, VulnCodes):
        self.VulnCodes += VulnCodes
