import re
import json

import sys
sys.path.append('..')
from extractor import TaintExtractor
from function import VulnChain


class TaintAnalyzer:
    def __init__(self, functions):
        self.all_funtion_list = {func.name: func for func in functions}
        self.processed_functions = set()  # 全局集合，用于记录已处理的函数

    def extract_taint_actions(self, function):
        extractor = TaintExtractor(function)
        extractor.extract()

        # 检查是否为 bytes 类型并转换为字符串
        if isinstance(function.node, bytes):
            function.node = function.node.decode('utf-8')

        if function.node:
            return function.node.splitlines()
        return []

    def build_call_tree(self, function, vuln_chain):
        # 判断是否已经处理过
        if function.name in self.processed_functions:
            print(f"⚠️ Detected duplicate function {function.name}, skipping.")
            return None  # 不再返回任何信息

        # 标记为已处理
        self.processed_functions.add(function.name)
        taint_actions = self.extract_taint_actions(function)

        node = {
            "function": function.name,
            "taint_params": function.tainted_params,
            "taint_actions": taint_actions,
            "calls": []
        }

        # 使用vuln_chain_function_list来确定调用顺序
        if vuln_chain and function.name in vuln_chain.vuln_chain_function_list:
            current_index = vuln_chain.vuln_chain_function_list.index(function.name)
            if current_index + 1 < len(vuln_chain.vuln_chain_function_list):
                next_function_name = vuln_chain.vuln_chain_function_list[current_index + 1]
                if next_function_name in self.all_funtion_list:
                    child_function = self.all_funtion_list[next_function_name]
                    child_node = self.build_call_tree(child_function, vuln_chain)
                    if child_node is not None:
                        node["calls"].append(child_node)

        self.find_and_append_clean_functions(node, function, vuln_chain)
        return node


    def find_and_append_clean_functions(self, node, function, vuln_chain):
        for action in node["taint_actions"]:
            # 使用正则匹配函数调用和参数
            match = re.search(r"(\w+)\(([^)]*)\)", action)
            if match:
                called_function_name = match.group(1)
                param_str = match.group(2).strip()

                # 检查函数是否存在
                if called_function_name in self.all_funtion_list and (
                        not vuln_chain or called_function_name not in vuln_chain.vuln_chain_function_list):
                    clean_function = self.all_funtion_list[called_function_name]

                    # 分割参数并查找污点参数位置
                    params = [p.strip() for p in param_str.split(",")]
                    tainted_param_indices = [i for i, p in enumerate(params) if p in function.tainted_params]

                    if not tainted_param_indices:
                        continue  # 没有污点参数则跳过

                    print(
                        f"✅ Detected function call with tainted parameters: {called_function_name}, Positions: {tainted_param_indices}")

                    # 标记对应位置的参数为污点参数
                    for i in tainted_param_indices:
                        if i < len(clean_function.param_list):
                            param_name = clean_function.param_list[i]
                            print(f"⚠️ Marking {param_name} as tainted in function {called_function_name}.")
                            clean_function.add_tainted_param(param_name)

                    # 构建调用树
                    clean_node = self.build_call_tree(clean_function, vuln_chain)
                    if clean_node is not None:
                        node['calls'].insert(0, clean_node)

    def analyze(self, entry_point, vuln_chain):
        try:
            return self.build_call_tree(entry_point, vuln_chain)
        except RecursionError as e:
            print(f"❗ Fatal RecursionError: {e}")
            return None
